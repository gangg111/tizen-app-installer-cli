package com.tizen.installer.signing

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Kotlin port of C# TizenResigner.
 * Re-signs a Tizen widget (.wgt) package with Samsung author and distributor certificates.
 */
object TizenResigner {
    private const val AUTHOR_PROP_DIGEST =
        "aXbSAVgmAz0GsBUeZ1UmNDRrxkWhDUVGb45dZcNRq429wX3X+x6kaXT3NdNDTSNVTU+ypkysPMGvQY10fG1EWQ=="
    private const val DISTRIBUTOR_PROP_DIGEST =
        "/r5npk2VVA46QFJnejgONBEh4BWtjrtu9x/IFeLksjWyGmB/cMWKSJWQl7aU3YRQRZ3AesG8gF7qGyvKX9Snig=="

    private const val XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
    private const val RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    private const val SHA512_URI = "http://www.w3.org/2001/04/xmlenc#sha512"
    private const val EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    private const val C14N11 = "http://www.w3.org/2006/12/xml-c14n11"

    data class FileEntry(val uriEscaped: String, val data: ByteArray)

    /**
     * Re-sign a .wgt package using the provided author and distributor keystores.
     * The leaf certificate (with private key) must be first in the keystore chain.
     */
    fun resignPackage(packageBytes: ByteArray, authorKs: KeyStore, distributorKs: KeyStore): ByteArray {
        // Read all files from input zip, skip existing signature XMLs
        val files = mutableListOf<FileEntry>()
        ZipInputStream(ByteArrayInputStream(packageBytes)).use { zis ->
            var entry: ZipEntry? = zis.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val nameLower = entry.name.lowercase()
                    val isSignature = nameLower.contains("signature") && nameLower.endsWith(".xml")
                    if (!isSignature) {
                        val data = zis.readBytes()
                        files.add(FileEntry(Uri.encode(entry.name), data))
                    }
                }
                entry = zis.nextEntry
            }
        }

        // Build AuthorSignature
        val filesWithAuthor = buildSignature("AuthorSignature", files, authorKs)

        // Build DistributorSignature (covers all files including AuthorSignature)
        val filesWithBoth = buildSignature("DistributorSignature", filesWithAuthor, distributorKs)

        // Write output zip
        val outStream = ByteArrayOutputStream()
        ZipOutputStream(outStream).use { zos ->
            for (file in filesWithBoth) {
                val entryName = Uri.decode(file.uriEscaped)
                zos.putNextEntry(ZipEntry(entryName))
                zos.write(file.data)
                zos.closeEntry()
            }
        }
        return outStream.toByteArray()
    }

    private fun buildSignature(id: String, inputFiles: List<FileEntry>, ks: KeyStore): List<FileEntry> {
        // Find signing entry (first alias with a private key)
        val alias = ks.aliases().asSequence().firstOrNull { ks.isKeyEntry(it) }
            ?: throw IllegalStateException("No signing key found in keystore for $id")
        val privateKey = ks.getKey(alias, "".toCharArray()) as PrivateKey
        val certChain = ks.getCertificateChain(alias)?.map { it as X509Certificate }
            ?: throw IllegalStateException("No certificate chain for $id")

        // Build References
        val sb = StringBuilder()
        for (file in inputFiles) {
            val digest = computeSha512Base64(file.data)
            sb.append(createReferenceXml(digest, file.uriEscaped, includeTransform = false))
        }
        val propDigest = if (id == "AuthorSignature") AUTHOR_PROP_DIGEST else DISTRIBUTOR_PROP_DIGEST
        sb.append(createReferenceXml(propDigest, "#prop", includeTransform = true))

        // Build SignedInfo
        val signedInfo = buildString {
            appendLine("<SignedInfo xmlns=\"$XMLDSIG_NS\">")
            appendLine("<CanonicalizationMethod Algorithm=\"$EXC_C14N\"></CanonicalizationMethod>")
            appendLine("<SignatureMethod Algorithm=\"$RSA_SHA512\"></SignatureMethod>")
            append(sb.toString().trimEnd())
            appendLine()
            append("</SignedInfo>")
        }

        // Canonicalize SignedInfo: since we build it with explicit namespace, UTF-8 bytes ≈ exclusive C14N
        val canonicalBytes = signedInfo.trim().toByteArray(Charsets.UTF_8)

        // Sign with RSA-SHA512
        val sig = Signature.getInstance("SHA512withRSA")
        sig.initSign(privateKey)
        sig.update(canonicalBytes)
        val sigBytes = sig.sign()
        val sigBase64 = splitBase64Lines(Base64.encodeToString(sigBytes, Base64.NO_WRAP))

        // Build KeyInfo
        val keyInfo = buildString {
            appendLine("<KeyInfo>")
            appendLine("<X509Data>")
            for (cert in certChain) {
                val certB64 = splitBase64Lines(Base64.encodeToString(cert.encoded, Base64.NO_WRAP))
                appendLine("<X509Certificate>")
                appendLine(certB64)
                appendLine("</X509Certificate>")
            }
            appendLine("</X509Data>")
            append("</KeyInfo>")
        }

        // Build Object prop
        val role = if (id == "AuthorSignature") "author" else "distributor"
        val objProp = buildString {
            append("<Object Id=\"prop\">")
            append("<SignatureProperties xmlns:dsp=\"http://www.w3.org/2009/xmldsig-properties\">")
            append("<SignatureProperty Id=\"profile\" Target=\"#$id\">")
            append("<dsp:Profile URI=\"http://www.w3.org/ns/widgets-digsig#profile\"></dsp:Profile>")
            append("</SignatureProperty>")
            append("<SignatureProperty Id=\"role\" Target=\"#$id\">")
            append("<dsp:Role URI=\"http://www.w3.org/ns/widgets-digsig#role-$role\"></dsp:Role>")
            append("</SignatureProperty>")
            append("<SignatureProperty Id=\"identifier\" Target=\"#$id\">")
            append("<dsp:Identifier></dsp:Identifier>")
            append("</SignatureProperty>")
            append("</SignatureProperties>")
            append("</Object>")
        }

        // Compose final XML
        val finalXml = buildString {
            appendLine("<Signature xmlns=\"$XMLDSIG_NS\" Id=\"$id\">")
            appendLine(signedInfo.trim())
            appendLine("<SignatureValue>")
            appendLine(sigBase64)
            appendLine("</SignatureValue>")
            appendLine(keyInfo.trim())
            appendLine(objProp.trim())
            append("</Signature>")
        }

        val fileName = if (id == "AuthorSignature") "author-signature.xml" else "signature1.xml"
        val sigEntry = FileEntry(Uri.encode(fileName), finalXml.toByteArray(Charsets.UTF_8))

        return listOf(sigEntry) + inputFiles
    }

    private fun createReferenceXml(digestBase64: String, uri: String, includeTransform: Boolean): String {
        return buildString {
            appendLine("<Reference URI=\"${escapeXml(uri)}\">")
            if (includeTransform) {
                appendLine("<Transforms>")
                appendLine("<Transform Algorithm=\"$C14N11\"></Transform>")
                appendLine("</Transforms>")
            }
            appendLine("<DigestMethod Algorithm=\"$SHA512_URI\"></DigestMethod>")
            appendLine("<DigestValue>${splitBase64Lines(digestBase64)}</DigestValue>")
            append("</Reference>")
            appendLine()
        }
    }

    private fun escapeXml(s: String): String =
        s.replace("&", "&amp;").replace("\"", "&quot;").replace("'", "&apos;")
            .replace("<", "&lt;").replace(">", "&gt;")

    private fun computeSha512Base64(data: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-512").digest(data)
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    private fun splitBase64Lines(base64: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < base64.length) {
            val len = minOf(76, base64.length - i)
            sb.append(base64.substring(i, i + len))
            if (i + len < base64.length) sb.append('\n')
            i += len
        }
        return sb.toString()
    }

    // Simple URI encode/decode helpers (avoids Android Uri dependency in this class)
    private object Uri {
        fun encode(s: String): String = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        fun decode(s: String): String = java.net.URLDecoder.decode(s, "UTF-8")
    }
}
