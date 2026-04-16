package com.tizen.installer.sdb

import kotlinx.coroutines.channels.Channel as KChannel

/**
 * A logical SDB channel (multiplexed over a single TCP connection).
 * Mirrors the C# SdbChannel class.
 */
class SdbChannel internal constructor(
    private val device: SdbTcpDevice,
    private val localId: UInt,
    val service: String
) {
    var remoteId: UInt = 0u
        internal set

    private val incoming = KChannel<ByteArray>(KChannel.UNLIMITED)
    private var closed = false
    private var currentChunk: ByteArray? = null
    private var readCursor = 0

    internal fun enqueueIncoming(bytes: ByteArray) {
        incoming.trySend(bytes)
    }

    suspend fun write(buffer: ByteArray, ct: kotlinx.coroutines.Job? = null) {
        check(!closed) { "Channel is closed" }
        var offset = 0
        while (offset < buffer.size) {
            val chunkSize = minOf(device.maxData.toInt(), buffer.size - offset)
            val chunk = buffer.copyOfRange(offset, offset + chunkSize)
            val frame = SdbFrame(
                command = SdbCommand.WRTE,
                arg0 = localId,
                arg1 = remoteId,
                payload = chunk
            )
            device.writeFrame(frame)
            offset += chunkSize
        }
    }

    /**
     * Read bytes into [buffer]. Returns number of bytes read, or 0 when channel is closed.
     */
    suspend fun read(buffer: ByteArray): Int {
        while (true) {
            val chunk = currentChunk
            if (chunk != null) {
                val available = chunk.size - readCursor
                if (available > 0) {
                    val toCopy = minOf(available, buffer.size)
                    System.arraycopy(chunk, readCursor, buffer, 0, toCopy)
                    readCursor += toCopy
                    if (readCursor >= chunk.size) {
                        currentChunk = null
                        readCursor = 0
                    }
                    return toCopy
                }
                currentChunk = null
                readCursor = 0
            }

            val next = incoming.tryReceive().getOrNull()
            if (next != null) {
                if (next.isEmpty()) {
                    closed = true
                    return 0
                }
                currentChunk = next
                readCursor = 0
                continue
            }

            if (closed) return 0

            val received = incoming.receive()
            if (received.isEmpty()) {
                closed = true
                return 0
            }
            currentChunk = received
            readCursor = 0
        }
    }

    suspend fun close() {
        if (closed) return
        closed = true
        val frame = SdbFrame(
            command = SdbCommand.CLSE,
            arg0 = localId,
            arg1 = remoteId,
            payload = ByteArray(0)
        )
        try { device.writeFrame(frame) } catch (_: Exception) {}
        incoming.trySend(ByteArray(0))
        incoming.close()
    }
}
