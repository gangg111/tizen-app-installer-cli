package com.tizen.installer.installer

import android.content.Context
import com.tizen.installer.network.TvDevice
import com.tizen.installer.signing.SamsungAuth
import com.tizen.installer.signing.SamsungCertificateCreator
import com.tizen.installer.signing.TizenResigner
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Kotlin port of C# TizenInstaller.
 * Orchestrates the full install flow: find package ID, sign if needed, push, and install.
 */
class TizenInstaller(
    private val context: Context,
    private val packageBytes: ByteArray,
    private val device: TvDevice
) {
    var packageId: String? = null
        private set

    /**
     * Full install flow.
     * @param auth Samsung auth (required for Tizen >= 7.0)
     * @param onUploadProgress upload progress 0-100
     * @param onInstallProgress install progress 0-100
     * @param onStatus status message updates
     */
    suspend fun install(
        auth: SamsungAuth?,
        onUploadProgress: ((Float) -> Unit)? = null,
        onInstallProgress: ((Float) -> Unit)? = null,
        onStatus: ((String) -> Unit)? = null
    ) {
        val sdb = device.sdbDevice

        onStatus?.invoke("Reading package…")
        val appId = findPackageId()

        onStatus?.invoke("Querying device capabilities…")
        val caps = sdb.capability()
        val platformVersion = caps["platform_version"] ?: "9.0"
        val sdkToolPath = (caps["sdk_toolpath"] ?: "/home/owner/share/tmp/sdk_tools/tmp").trimEnd('/')
        val remotePath = "$sdkToolPath/app.wgt"

        val installBytes: ByteArray
        if (compareVersions(platformVersion, "7.0") >= 0) {
            onStatus?.invoke("Signing package…")
            installBytes = signPackage(auth, sdb.shellCommand("0 getduid").trim())
        } else {
            installBytes = packageBytes
        }

        onStatus?.invoke("Uploading package (${installBytes.size / 1024} KB)…")
        sdb.push(installBytes, remotePath) { progress ->
            onUploadProgress?.invoke(progress)
        }

        onStatus?.invoke("Installing app…")
        val progressRegex = Regex("""\[(\d{1,3})]""")
        sdb.shellCommandLines("0 vd_appinstall $appId $remotePath").collect { line ->
            progressRegex.find(line)?.groupValues?.get(1)?.toIntOrNull()?.let { pct ->
                onInstallProgress?.invoke(pct.coerceIn(0, 100).toFloat())
            }
        }
        onStatus?.invoke("Done!")
    }

    suspend fun isAlreadyInstalled(): Boolean {
        val id = findPackageId()
        val appList = device.sdbDevice.shellCommand("0 vd_applist")
        return appList.contains(id)
    }

    suspend fun uninstall(onProgress: ((Float) -> Unit)? = null) {
        val id = findPackageId()
        val progressRegex = Regex("""\[(\d{1,3})]""")
        device.sdbDevice.shellCommandLines("0 vd_appuninstall $id").collect { line ->
            progressRegex.find(line)?.groupValues?.get(1)?.toIntOrNull()?.let { pct ->
                onProgress?.invoke(pct.coerceIn(0, 100).toFloat())
            }
        }
    }

    private suspend fun signPackage(auth: SamsungAuth?, duid: String): ByteArray {
        if (auth == null) throw IllegalStateException("Samsung login required for Tizen >= 7.0")
        val creator = SamsungCertificateCreator(context)
        val result = creator.getOrCreateCertificates(auth, listOf(duid))
        return TizenResigner.resignPackage(packageBytes, result.authorKeyStore, result.distributorKeyStore)
    }

    fun findPackageId(): String {
        packageId?.let { return it }

        ZipInputStream(ByteArrayInputStream(packageBytes)).use { zis ->
            var configXml: String? = null
            var manifestXml: String? = null
            var entry = zis.nextEntry
            while (entry != null) {
                when (entry.name.lowercase()) {
                    "config.xml" -> configXml = zis.readBytes().toString(Charsets.UTF_8)
                    "tizen-manifest.xml" -> manifestXml = zis.readBytes().toString(Charsets.UTF_8)
                }
                entry = zis.nextEntry
            }

            val (xmlText, isWgt) = when {
                configXml != null -> Pair(configXml, true)
                manifestXml != null -> Pair(manifestXml, false)
                else -> throw IllegalArgumentException("Invalid App: no config.xml or tizen-manifest.xml found")
            }

            val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(ByteArrayInputStream(xmlText.toByteArray()))
            doc.documentElement.normalize()

            val id = if (isWgt) {
                extractWgtPackageId(doc)
            } else {
                extractTpkPackageId(doc)
            } ?: throw IllegalArgumentException("Invalid App: could not find package ID")

            packageId = id.trim()
            return packageId!!
        }
    }

    private fun extractWgtPackageId(doc: org.w3c.dom.Document): String? {
        // Try <application id="...">
        val appNodes = doc.getElementsByTagName("application")
        for (i in 0 until appNodes.length) {
            val el = appNodes.item(i) as? Element
            val id = el?.getAttribute("id")
            if (!id.isNullOrEmpty()) return id
        }
        // Try widget id="..."
        val root = doc.documentElement
        val id = root?.getAttribute("id")
        if (!id.isNullOrEmpty()) return id
        return null
    }

    private fun extractTpkPackageId(doc: org.w3c.dom.Document): String? {
        val root = doc.documentElement
        val pkg = root?.getAttribute("package")
        if (!pkg.isNullOrEmpty()) return pkg
        val manifestNodes = doc.getElementsByTagName("manifest")
        for (i in 0 until manifestNodes.length) {
            val el = manifestNodes.item(i) as? Element
            val id = el?.getAttribute("package")
            if (!id.isNullOrEmpty()) return id
        }
        return null
    }

    private fun compareVersions(v1: String, v2: String): Int {
        val p1 = v1.split('.').mapNotNull { it.trim().toIntOrNull() }
        val p2 = v2.split('.').mapNotNull { it.trim().toIntOrNull() }
        for (i in 0 until maxOf(p1.size, p2.size)) {
            val a = p1.getOrElse(i) { 0 }
            val b = p2.getOrElse(i) { 0 }
            if (a != b) return a.compareTo(b)
        }
        return 0
    }
}
