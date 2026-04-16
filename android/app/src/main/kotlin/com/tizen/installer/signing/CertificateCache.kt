package com.tizen.installer.signing

import android.content.Context
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * Handles caching of Samsung signing certificates as PKCS12 files in app-internal storage.
 * Mirrors the C# SamsungCertificateCreator cache functionality.
 */
class CertificateCache(context: Context) {
    private val cacheDir = File(context.filesDir, "cert_cache").also { it.mkdirs() }

    data class CertBundle(
        val authorKeyStore: KeyStore,
        val distributorKeyStore: KeyStore
    )

    fun loadCached(privilegeLevel: String, duidList: List<String>): CertBundle? {
        val aliasPath = getDeviceAliasFile(privilegeLevel, duidList)
        if (!aliasPath.exists()) return null
        val cacheKey = aliasPath.readText().trim()
        if (cacheKey.isEmpty()) {
            aliasPath.delete()
            return null
        }
        return tryLoadByCacheKey(cacheKey)
    }

    fun save(
        email: String,
        privilegeLevel: String,
        duidList: List<String>,
        authorKeyStore: KeyStore,
        distributorKeyStore: KeyStore
    ) {
        val cacheKey = buildCacheKey(email, privilegeLevel, duidList)
        val dir = File(cacheDir, cacheKey).also { it.mkdirs() }
        val tmpDir = File(cacheDir, "$cacheKey.tmp").also { it.mkdirs() }

        saveKeyStore(authorKeyStore, File(tmpDir, "author.p12"))
        saveKeyStore(distributorKeyStore, File(tmpDir, "distributor.p12"))

        if (dir.exists()) dir.deleteRecursively()
        tmpDir.renameTo(dir)

        val aliasFile = getDeviceAliasFile(privilegeLevel, duidList)
        aliasFile.writeText(cacheKey)
    }

    private fun tryLoadByCacheKey(cacheKey: String): CertBundle? {
        val dir = File(cacheDir, cacheKey)
        if (!dir.exists()) return null
        val authorFile = File(dir, "author.p12")
        val distributorFile = File(dir, "distributor.p12")
        if (!authorFile.exists() || !distributorFile.exists()) return null

        return try {
            val authorKs = loadKeyStore(authorFile)
            val distributorKs = loadKeyStore(distributorFile)

            if (!isUsable(authorKs) || !isUsable(distributorKs)) {
                dir.deleteRecursively()
                return null
            }
            CertBundle(authorKs, distributorKs)
        } catch (_: Exception) {
            dir.deleteRecursively()
            null
        }
    }

    private fun saveKeyStore(ks: KeyStore, file: File) {
        file.outputStream().use { ks.store(it, "".toCharArray()) }
    }

    private fun loadKeyStore(file: File): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        file.inputStream().use { ks.load(it, "".toCharArray()) }
        return ks
    }

    private fun isUsable(ks: KeyStore): Boolean {
        val aliases = ks.aliases()?.toList() ?: return false
        val now = java.util.Date()
        return aliases.any { alias ->
            val cert = ks.getCertificate(alias) as? X509Certificate
            val key = ks.getKey(alias, "".toCharArray())
            cert != null && key != null && now.before(cert.notAfter) && now.after(cert.notBefore)
        }
    }

    private fun getDeviceAliasFile(privilegeLevel: String, duidList: List<String>): File {
        val key = buildDeviceCacheKey(privilegeLevel, duidList)
        return File(cacheDir, "$key.alias")
    }

    private fun buildCacheKey(email: String, privilegeLevel: String, duidList: List<String>): String {
        val normalized = "${email.trim().lowercase()}\n${privilegeLevel.trim().lowercase()}\n" +
                duidList.filter { it.isNotBlank() }.map { it.trim() }.sorted().joinToString("\n")
        val hash = MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun buildDeviceCacheKey(privilegeLevel: String, duidList: List<String>): String {
        val normalized = "${privilegeLevel.trim().lowercase()}\n" +
                duidList.filter { it.isNotBlank() }.map { it.trim() }.sorted().joinToString("\n")
        val hash = MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }
}
