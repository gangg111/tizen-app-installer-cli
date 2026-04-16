package com.tizen.installer.sdb

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Kotlin port of C# SdbTcpDevice.
 * Handles TCP connection to a Tizen TV via SDB protocol.
 */
class SdbTcpDevice(val ipAddress: InetAddress, private val port: Int = 26101) {
    companion object {
        private const val CLIENT_VERSION = 0x01000000u
        private const val DEFAULT_MAX_DATA = 4096u
        private const val SYNC_MAX_DATA = 64 * 1024
        private const val HEADER_SIZE = 24
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val OPEN_TIMEOUT_MS = 10_000
    }

    var deviceId: String = "$ipAddress:$port"
        private set

    var maxData: UInt = DEFAULT_MAX_DATA
        private set

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    private val writeMutex = Mutex()
    private var pumpJob: Job? = null
    private var pumpScope: CoroutineScope? = null
    private val nextLocalId = AtomicInteger('a'.code)
    private val channelsByLocalId = ConcurrentHashMap<UInt, SdbChannel>()
    private val pendingOpens = ConcurrentHashMap<UInt, CompletableDeferred<SdbChannel>>()

    suspend fun connect() {
        if (socket != null) return

        withContext(Dispatchers.IO) {
            val sock = Socket()
            sock.connect(java.net.InetSocketAddress(ipAddress, port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = 0
            socket = sock
            inputStream = sock.getInputStream()
            outputStream = sock.getOutputStream()
        }

        // Send CNXN
        val banner = "host::sdb-net-client".toByteArray(Charsets.UTF_8)
        val cnxn = SdbFrame(SdbCommand.CNXN, CLIENT_VERSION, maxData, banner)
        writeFrame(cnxn)

        // Read response
        val resp = readFrameBlocking()

        if (resp.command == SdbCommand.AUTH) {
            throw IllegalStateException("Remote requested AUTH but client does not support authentication")
        }
        if (resp.command != SdbCommand.CNXN) {
            throw IllegalStateException("Expected CNXN; got ${resp.command}")
        }

        if (resp.arg1 != 0u) {
            maxData = minOf(maxData, resp.arg1)
        }
        if (resp.payload.isNotEmpty()) {
            deviceId = resp.payload.toString(Charsets.UTF_8)
        }

        // Start background pump
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        pumpScope = scope
        pumpJob = scope.launch { pumpLoop() }
    }

    suspend fun disconnect() {
        pumpJob?.cancel()
        pumpScope?.cancel()
        pumpJob = null
        pumpScope = null
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        inputStream = null
        outputStream = null
    }

    internal suspend fun writeFrame(frame: SdbFrame) {
        val out = outputStream ?: throw IllegalStateException("Not connected")
        val headerBuf = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        headerBuf.putInt(frame.command.value.toInt())
        headerBuf.putInt(frame.arg0.toInt())
        headerBuf.putInt(frame.arg1.toInt())
        headerBuf.putInt(frame.payload.size)
        headerBuf.putInt(frame.dataChecksum.toInt())
        headerBuf.putInt(frame.magic.toInt())
        val header = headerBuf.array()

        writeMutex.withLock {
            withContext(Dispatchers.IO) {
                out.write(header)
                if (frame.payload.isNotEmpty()) {
                    out.write(frame.payload)
                }
                out.flush()
            }
        }
    }

    private suspend fun readFrameBlocking(): SdbFrame {
        val inp = inputStream ?: throw IllegalStateException("Not connected")
        return withContext(Dispatchers.IO) {
            val header = ByteArray(HEADER_SIZE)
            readExactlyFromStream(inp, header, HEADER_SIZE)
            val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            val cmdVal = buf.int.toUInt()
            val arg0 = buf.int.toUInt()
            val arg1 = buf.int.toUInt()
            val dataLen = buf.int.toUInt()
            val checksum = buf.int.toUInt()
            val magic = buf.int.toUInt()

            val cmd = SdbCommand.fromValue(cmdVal) ?: throw IllegalStateException("Unknown command: $cmdVal")
            val payload = if (dataLen > 0u) {
                val p = ByteArray(dataLen.toInt())
                readExactlyFromStream(inp, p, dataLen.toInt())
                p
            } else {
                ByteArray(0)
            }

            val frame = SdbFrame(cmd, arg0, arg1, payload)
            if (!frame.validateHeader(magic)) {
                throw IllegalStateException("Invalid SDB frame magic")
            }
            frame
        }
    }

    private fun readExactlyFromStream(inp: InputStream, buf: ByteArray, size: Int) {
        var pos = 0
        while (pos < size) {
            val read = inp.read(buf, pos, size - pos)
            if (read < 0) throw java.io.EOFException("Unexpected EOF")
            pos += read
        }
    }

    private suspend fun pumpLoop() {
        val inp = inputStream ?: return
        try {
            while (currentCoroutineContext().isActive) {
                val frame = withContext(Dispatchers.IO) {
                    val header = ByteArray(HEADER_SIZE)
                    try {
                        readExactlyFromStream(inp, header, HEADER_SIZE)
                    } catch (_: Exception) {
                        return@withContext null
                    }
                    val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
                    val cmdVal = buf.int.toUInt()
                    val arg0 = buf.int.toUInt()
                    val arg1 = buf.int.toUInt()
                    val dataLen = buf.int.toUInt()
                    val checksum = buf.int.toUInt()
                    val magic = buf.int.toUInt()

                    val cmd = SdbCommand.fromValue(cmdVal) ?: return@withContext null
                    val payload = if (dataLen > 0u) {
                        val p = ByteArray(dataLen.toInt())
                        try {
                            readExactlyFromStream(inp, p, dataLen.toInt())
                        } catch (_: Exception) {
                            return@withContext null
                        }
                        p
                    } else {
                        ByteArray(0)
                    }
                    SdbFrame(cmd, arg0, arg1, payload)
                } ?: break

                when (frame.command) {
                    SdbCommand.OKAY -> {
                        val remoteId = frame.arg0
                        val localId = frame.arg1
                        channelsByLocalId[localId]?.let { ch ->
                            ch.remoteId = remoteId
                            pendingOpens.remove(localId)?.complete(ch)
                        }
                    }

                    SdbCommand.WRTE -> {
                        val localId = frame.arg1
                        val remoteId = frame.arg0
                        val ch = channelsByLocalId[localId]
                        if (ch != null) {
                            ch.enqueueIncoming(frame.payload)
                            // Send ACK
                            val ack = SdbFrame(SdbCommand.OKAY, localId, remoteId)
                            try { writeFrame(ack) } catch (_: Exception) {}
                        } else {
                            val clse = SdbFrame(SdbCommand.CLSE, localId, remoteId)
                            try { writeFrame(clse) } catch (_: Exception) {}
                        }
                    }

                    SdbCommand.CLSE -> {
                        val remoteId = frame.arg0
                        val localId = frame.arg1
                        pendingOpens.remove(localId)?.completeExceptionally(
                            IllegalStateException("Remote closed channel before OKAY")
                        )
                        channelsByLocalId.remove(localId)?.let { ch ->
                            ch.enqueueIncoming(ByteArray(0))
                        }
                        val clse = SdbFrame(SdbCommand.CLSE, localId, remoteId)
                        try { writeFrame(clse) } catch (_: Exception) {}
                    }

                    SdbCommand.OPEN -> {
                        val clse = SdbFrame(SdbCommand.CLSE, frame.arg1, frame.arg0)
                        try { writeFrame(clse) } catch (_: Exception) {}
                    }

                    SdbCommand.CNXN -> { /* ignore */ }
                    SdbCommand.AUTH -> { /* ignore */ }
                }
            }
        } finally {
            channelsByLocalId.values.forEach { it.enqueueIncoming(ByteArray(0)) }
        }
    }

    suspend fun open(service: String): SdbChannel {
        if (socket == null) throw IllegalStateException("Not connected")
        val localId = nextLocalId.getAndIncrement().toUInt()
        val channel = SdbChannel(this, localId, service)
        val deferred = CompletableDeferred<SdbChannel>()

        channelsByLocalId[localId] = channel
        pendingOpens[localId] = deferred

        val openFrame = SdbFrame(
            command = SdbCommand.OPEN,
            arg0 = localId,
            arg1 = 0u,
            payload = SdbFrame.stringToAsciiPayload(service)
        )

        try {
            writeFrame(openFrame)
            withTimeout(OPEN_TIMEOUT_MS.toLong()) {
                deferred.await()
            }
            return channel
        } catch (e: Exception) {
            channelsByLocalId.remove(localId)
            pendingOpens.remove(localId)
            throw e
        }
    }

    /**
     * Execute a shell command and return the full output as a String.
     */
    suspend fun shellCommand(command: String): String {
        val ch = open("shell:$command\u0000")
        val sb = StringBuilder()
        val buf = ByteArray(maxData.toInt())
        try {
            while (true) {
                val read = ch.read(buf)
                if (read == 0) break
                sb.append(buf.toString(0, read, Charsets.UTF_8))
            }
        } finally {
            ch.close()
        }
        return sb.toString()
    }

    /**
     * Execute a shell command and emit lines via a Flow.
     */
    fun shellCommandLines(command: String): kotlinx.coroutines.flow.Flow<String> =
        kotlinx.coroutines.flow.flow {
            val ch = open("shell:$command\u0000")
            val buf = ByteArray(8192)
            val sb = StringBuilder()
            try {
                while (true) {
                    val read = ch.read(buf)
                    if (read == 0) break
                    sb.append(buf.toString(0, read, Charsets.UTF_8))
                    val lastNewline = sb.lastIndexOf('\n')
                    if (lastNewline >= 0) {
                        val toProcess = sb.substring(0, lastNewline + 1)
                        sb.delete(0, lastNewline + 1)
                        toProcess.split('\n', '\r').filter { it.isNotEmpty() }.forEach { emit(it) }
                    }
                }
                if (sb.isNotEmpty()) {
                    sb.toString().split('\n', '\r').filter { it.isNotEmpty() }.forEach { emit(it) }
                }
            } finally {
                ch.close()
            }
        }

    /**
     * Query device capabilities and return as a key-value map.
     */
    suspend fun capability(): Map<String, String> {
        val ch = open("capability:\u0000")
        val allBytes = mutableListOf<Byte>()
        val buf = ByteArray(maxData.toInt())
        try {
            while (true) {
                val read = ch.read(buf)
                if (read == 0) break
                for (i in 0 until read) allBytes.add(buf[i])
            }
        } finally {
            ch.close()
        }

        if (allBytes.size < 2) return emptyMap()

        // Skip first 2 bytes (hex length prefix)
        val response = allBytes.drop(2).toByteArray().toString(Charsets.UTF_8)
        val result = mutableMapOf<String, String>()
        response.split('\n').forEach { line ->
            val parts = line.split(':')
            if (parts.size >= 2) {
                result[parts[0]] = parts.drop(1).joinToString(":")
            }
        }
        return result
    }

    /**
     * Push a file to the device using the sync protocol.
     */
    suspend fun push(
        data: ByteArray,
        remotePath: String,
        onProgress: ((Float) -> Unit)? = null
    ) {
        val ch = open("sync:\u0000")
        try {
            // Build SEND packet: "SEND" + 4-byte LE length + path bytes
            val pathBytes = remotePath.toByteArray(Charsets.UTF_8)
            sendSyncPacket(ch, "SEND", pathBytes)

            // Send DATA packets
            var offset = 0
            val total = data.size.toLong()
            var sent = 0L
            while (offset < data.size) {
                val chunkSize = minOf(SYNC_MAX_DATA, data.size - offset)
                val chunk = data.copyOfRange(offset, offset + chunkSize)
                sendSyncPacket(ch, "DATA", chunk)
                offset += chunkSize
                sent += chunkSize
                if (onProgress != null && total > 0) {
                    onProgress(sent.toFloat() / total.toFloat() * 100f)
                }
            }

            // Send DONE
            val mtime = (System.currentTimeMillis() / 1000).toUInt()
            val mtimeBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            mtimeBuf.putInt(mtime.toInt())
            sendSyncPacket(ch, "DONE", mtimeBuf.array())

            // Read response
            while (true) {
                val (id, payload) = readSyncResponse(ch)
                when (id) {
                    "OKAY" -> {
                        onProgress?.invoke(100f)
                        return
                    }
                    "FAIL" -> {
                        val msg = if (payload.isNotEmpty()) payload.toString(Charsets.UTF_8) else "unknown"
                        throw IllegalStateException("sdb sync FAIL: $msg")
                    }
                }
            }
        } finally {
            ch.close()
        }
    }

    private suspend fun sendSyncPacket(ch: SdbChannel, id: String, payload: ByteArray) {
        val idBytes = id.toByteArray(Charsets.US_ASCII)
        require(idBytes.size == 4) { "Sync ID must be 4 bytes" }
        val buf = ByteBuffer.allocate(8 + payload.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(idBytes)
        buf.putInt(payload.size)
        buf.put(payload)
        ch.write(buf.array())
    }

    private suspend fun readSyncResponse(ch: SdbChannel): Pair<String, ByteArray> {
        val header = readExactlyFromChannel(ch, 8)
        val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val id = header.copyOf(4).toString(Charsets.US_ASCII)
        buf.position(4)
        val len = buf.int.toUInt()
        val payload = if (len > 0u) readExactlyFromChannel(ch, len.toInt()) else ByteArray(0)
        return Pair(id, payload)
    }

    private suspend fun readExactlyFromChannel(ch: SdbChannel, size: Int): ByteArray {
        val result = ByteArray(size)
        var pos = 0
        val tmpBuf = ByteArray(size)
        while (pos < size) {
            val needed = size - pos
            val slice = ByteArray(needed)
            val r = ch.read(slice)
            if (r == 0) throw java.io.EOFException("Unexpected EOF from channel")
            System.arraycopy(slice, 0, result, pos, r)
            pos += r
        }
        return result
    }
}
