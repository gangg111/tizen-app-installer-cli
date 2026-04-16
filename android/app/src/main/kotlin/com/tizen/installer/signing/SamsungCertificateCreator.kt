package com.tizen.installer.signing

import android.content.Context
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.io.StringReader
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Kotlin/BouncyCastle port of C# SamsungCertificateCreator.
 * Creates Samsung signing certificates via their CA API.
 */
class SamsungCertificateCreator(private val context: Context) {
    companion object {
        private const val AUTHOR_ENDPOINT = "https://svdca.samsungqbe.com/apis/v3/authors"
        private const val DISTRIBUTOR_ENDPOINT = "https://svdca.samsungqbe.com/apis/v3/distributors"
    }

    private val http = OkHttpClient()
    private val cache = CertificateCache(context)

    data class CertificateResult(
        val authorKeyStore: KeyStore,
        val distributorKeyStore: KeyStore
    )

    /**
     * Load cached certificates if valid, otherwise create new ones via Samsung CA API.
     */
    suspend fun getOrCreateCertificates(
        auth: SamsungAuth,
        duidList: List<String>,
        privilegeLevel: String = "Public"
    ): CertificateResult {
        // Try cache first
        cache.loadCached(privilegeLevel, duidList)?.let { cached ->
            return CertificateResult(cached.authorKeyStore, cached.distributorKeyStore)
        }

        val email = auth.inputEmailID ?: auth.userId

        // Generate author CSR
        val authorKeyPair = generateKeyPair()
        val authorCsrPem = createAuthorCsr(email, authorKeyPair)

        // Generate distributor CSR
        val distributorKeyPair = generateKeyPair()
        val distributorCsrPem = createDistributorCsr(email, distributorKeyPair, duidList)

        // Post CSRs to Samsung CA
        val authorResponseText = postCsr(AUTHOR_ENDPOINT, auth, authorCsrPem, "author.csr")
        val distributorResponseText = postCsr(
            DISTRIBUTOR_ENDPOINT, auth, distributorCsrPem, "distributor.csr",
            extraFields = mapOf("privilege_level" to privilegeLevel, "developer_type" to "Individual")
        )

        // Build PKCS12 keystores
        val authorLeaf = extractLeafCertificate(authorResponseText, authorKeyPair.public)
            ?: throw IllegalStateException("Could not extract author certificate from server response")
        val distributorLeaf = extractLeafCertificate(distributorResponseText, distributorKeyPair.public)
            ?: throw IllegalStateException("Could not extract distributor certificate from server response")

        val authorIntermediate = loadBundledCert("vd_tizen_dev_author_ca.cer")
        val distributorIntermediate = loadBundledCert(
            if (privilegeLevel == "Public") "vd_tizen_dev_public2.crt" else "vd_tizen_dev_partner2.crt"
        )

        val authorKs = buildKeyStore("author", authorKeyPair.private, authorLeaf, authorIntermediate)
        val distributorKs = buildKeyStore("distributor", distributorKeyPair.private, distributorLeaf, distributorIntermediate)

        // Cache
        try {
            cache.save(email, privilegeLevel, duidList, authorKs, distributorKs)
        } catch (_: Exception) {}

        return CertificateResult(authorKs, distributorKs)
    }

    private fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    private fun createAuthorCsr(email: String, keyPair: KeyPair): String {
        val subject = X500Name("CN=$email, OU=, O=, L=, ST=, C=")
        val builder = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
        val signer = JcaContentSignerBuilder("SHA512withRSA").build(keyPair.private)
        val csr = builder.build(signer)
        return encodeToPem("CERTIFICATE REQUEST", csr.encoded)
    }

    private fun createDistributorCsr(email: String, keyPair: KeyPair, duidList: List<String>): String {
        val subject = X500Name("CN=TizenSDK, E=$email")
        val builder = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)

        // Add SAN extension with URN URIs
        val sanUris = mutableListOf<GeneralName>()
        sanUris.add(GeneralName(GeneralName.uniformResourceIdentifier, "URN:tizen:packageid="))
        for (duid in duidList) {
            sanUris.add(GeneralName(GeneralName.uniformResourceIdentifier, "URN:tizen:deviceid=$duid"))
        }
        val generalNames = GeneralNames(sanUris.toTypedArray())
        val extGen = ExtensionsGenerator()
        extGen.addExtension(Extension.subjectAlternativeName, false, generalNames)
        val extensions = extGen.generate()
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions)

        val signer = JcaContentSignerBuilder("SHA512withRSA").build(keyPair.private)
        val csr = builder.build(signer)
        return encodeToPem("CERTIFICATE REQUEST", csr.encoded)
    }

    private fun postCsr(
        url: String,
        auth: SamsungAuth,
        csrPem: String,
        filename: String,
        extraFields: Map<String, String> = emptyMap()
    ): String {
        val multipartBody = MultipartBody.Builder().setType(MultipartBody.FORM).apply {
            addFormDataPart("access_token", auth.accessToken)
            addFormDataPart("user_id", auth.userId)
            addFormDataPart("platform", "VD")
            addFormDataPart(
                "csr", filename,
                csrPem.toByteArray(Charsets.US_ASCII).toRequestBody("application/octet-stream".toMediaTypeOrNull())
            )
            extraFields.forEach { (k, v) -> addFormDataPart(k, v) }
        }.build()

        val request = Request.Builder().url(url).post(multipartBody).build()
        http.newCall(request).execute().use { response ->
            val body = response.body?.string() ?: ""
            if (!response.isSuccessful) {
                throw IllegalStateException("POST to $url failed: ${response.code}\n$body")
            }
            return body
        }
    }

    private fun extractLeafCertificate(responseText: String, publicKey: PublicKey): X509Certificate? {
        val pemBlocks = extractPemBlocks(responseText)
            .ifEmpty { extractCertsFromXml(responseText) }

        val cf = CertificateFactory.getInstance("X.509")
        for (pemOrDerBase64 in pemBlocks) {
            try {
                val derBytes = pemToDer(pemOrDerBase64)
                val cert = cf.generateCertificate(ByteArrayInputStream(derBytes)) as X509Certificate
                // Check if this cert's public key matches ours
                if (cert.publicKey.encoded.contentEquals(publicKey.encoded)) {
                    return cert
                }
            } catch (_: Exception) {}
        }
        // Fallback: first certificate
        return pemBlocks.firstOrNull()?.let {
            try {
                val der = pemToDer(it)
                cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            } catch (_: Exception) { null }
        }
    }

    private fun extractPemBlocks(text: String): List<String> {
        val begin = "-----BEGIN CERTIFICATE-----"
        val end = "-----END CERTIFICATE-----"
        val result = mutableListOf<String>()
        var idx = 0
        while (true) {
            val b = text.indexOf(begin, idx)
            if (b < 0) break
            val e = text.indexOf(end, b)
            if (e < 0) break
            result.add(text.substring(b, e + end.length))
            idx = e + end.length
        }
        return result
    }

    private fun extractCertsFromXml(text: String): List<String> {
        return try {
            val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(ByteArrayInputStream(text.toByteArray()))
            val result = mutableListOf<String>()
            for (tagName in listOf("X509Certificate", "Certificate", "Cert")) {
                val nodes = doc.getElementsByTagName(tagName)
                for (i in 0 until nodes.length) {
                    val inner = (nodes.item(i) as? Element)?.textContent?.trim() ?: continue
                    val clean = inner.filter { !it.isWhitespace() }
                    if (clean.length >= 100) result.add(wrapPem(clean))
                }
            }
            result
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun wrapPem(base64: String): String {
        val sb = StringBuilder("-----BEGIN CERTIFICATE-----\n")
        var i = 0
        while (i < base64.length) {
            sb.append(base64.substring(i, minOf(i + 64, base64.length))).append('\n')
            i += 64
        }
        sb.append("-----END CERTIFICATE-----")
        return sb.toString()
    }

    private fun pemToDer(pem: String): ByteArray {
        val stripped = pem.lines()
            .filter { !it.startsWith("-----") }
            .joinToString("")
            .filter { !it.isWhitespace() }
        return android.util.Base64.decode(stripped, android.util.Base64.DEFAULT)
    }

    private fun encodeToPem(label: String, data: ByteArray): String {
        val b64 = android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP)
        val sb = StringBuilder("-----BEGIN $label-----\n")
        var i = 0
        while (i < b64.length) {
            sb.append(b64.substring(i, minOf(i + 64, b64.length))).append('\n')
            i += 64
        }
        sb.append("-----END $label-----\n")
        return sb.toString()
    }

    private fun loadBundledCert(filename: String): X509Certificate? {
        return try {
            val bytes = context.assets.open("certs/$filename").use { it.readBytes() }
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
        } catch (_: Exception) { null }
    }

    private fun buildKeyStore(
        alias: String,
        privateKey: PrivateKey,
        leaf: X509Certificate,
        intermediate: X509Certificate?
    ): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val chain = if (intermediate != null) {
            arrayOf<java.security.cert.Certificate>(leaf, intermediate)
        } else {
            arrayOf<java.security.cert.Certificate>(leaf)
        }
        ks.setKeyEntry(alias, privateKey, "".toCharArray(), chain)
        return ks
    }
}
