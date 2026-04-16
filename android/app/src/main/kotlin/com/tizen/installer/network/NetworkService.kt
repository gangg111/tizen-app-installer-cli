package com.tizen.installer.network

import com.tizen.installer.sdb.SdbTcpDevice
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.NetworkInterface

data class TvDevice(val sdbDevice: SdbTcpDevice) {
    val displayName: String get() = sdbDevice.deviceId
    val ipAddress: String get() = sdbDevice.ipAddress.hostAddress ?: ""
}

/**
 * Kotlin port of C# NetworkService.
 * Scans the local network for Tizen TVs listening on SDB port 26101.
 */
object NetworkService {
    private const val SDB_PORT = 26101
    private const val SCAN_TIMEOUT_MS = 1000L

    suspend fun validateManualAddress(ip: String): TvDevice? {
        return try {
            withTimeout(SCAN_TIMEOUT_MS * 3) {
                val addr = InetAddress.getByName(ip)
                val device = SdbTcpDevice(addr, SDB_PORT)
                device.connect()
                TvDevice(device)
            }
        } catch (_: Exception) {
            null
        }
    }

    suspend fun findTizenTvs(
        onProgress: ((Int, Int) -> Unit)? = null
    ): List<TvDevice> {
        val localIps = getRelevantLocalIPs()
        val networks = localIps.map { getNetworkPrefix(it) }.distinct()

        val found = mutableListOf<TvDevice>()
        val mutex = kotlinx.coroutines.sync.Mutex()

        val totalHosts = networks.size * 254
        var scanned = 0

        coroutineScope {
            val jobs = networks.flatMap { prefix ->
                (1..254).map { i ->
                    async(Dispatchers.IO) {
                        val ip = "$prefix.$i"
                        try {
                            withTimeout(SCAN_TIMEOUT_MS) {
                                val addr = InetAddress.getByName(ip)
                                val device = SdbTcpDevice(addr, SDB_PORT)
                                device.connect()
                                mutex.withLock { found.add(TvDevice(device)) }
                            }
                        } catch (_: Exception) { }
                        mutex.withLock {
                            scanned++
                            onProgress?.invoke(scanned, totalHosts)
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        return found
    }

    fun getLocalIpAddress(): String {
        return try {
            NetworkInterface.getNetworkInterfaces()
                ?.asSequence()
                ?.filter { it.isUp && !it.isLoopback }
                ?.flatMap { it.inetAddresses.asSequence() }
                ?.filterIsInstance<java.net.Inet4Address>()
                ?.filter { !it.isLoopbackAddress }
                ?.map { it.hostAddress ?: "" }
                ?.firstOrNull() ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private fun getRelevantLocalIPs(): List<InetAddress> {
        return try {
            NetworkInterface.getNetworkInterfaces()
                ?.asSequence()
                ?.filter { it.isUp && !it.isLoopback }
                ?.filter {
                    it.name.startsWith("wlan") ||
                    it.name.startsWith("eth") ||
                    it.name.startsWith("en") ||
                    it.displayName.contains("Wi-Fi", ignoreCase = true) ||
                    it.displayName.contains("Ethernet", ignoreCase = true)
                }
                ?.flatMap { it.inetAddresses.asSequence() }
                ?.filterIsInstance<java.net.Inet4Address>()
                ?.filter { !it.isLoopbackAddress }
                ?.toList() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun getNetworkPrefix(addr: InetAddress): String {
        val bytes = addr.address
        return "${bytes[0].toInt() and 0xFF}.${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}"
    }
}
