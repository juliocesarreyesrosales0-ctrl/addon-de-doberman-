package com.doberman.antivirus.core

import android.content.pm.PackageInfo
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object Hashing {
    /** Tamaño máximo de archivo que se calcula (los malware conocidos son pequeños). */
    const val MAX_HASH_BYTES: Long = 300L * 1024 * 1024

    fun sha256(file: File, maxBytes: Long = MAX_HASH_BYTES, isCancelled: () -> Boolean = { false }): String? {
        return try {
            if (!file.isFile || !file.canRead() || file.length() > maxBytes) return null
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { input ->
                val buffer = ByteArray(256 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    md.update(buffer, 0, n)
                    if (isCancelled()) return null
                }
            }
            md.digest().toHex()
        } catch (e: Exception) {
            null
        }
    }

    fun digest(algorithm: String, data: ByteArray): String =
        MessageDigest.getInstance(algorithm).digest(data).toHex()

    fun ByteArray.toHex(): String {
        val chars = "0123456789abcdef"
        val sb = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xff
            sb.append(chars[v ushr 4]).append(chars[v and 0x0f])
        }
        return sb.toString()
    }

    /** Certificados de firma de una app instalada o de un APK. */
    @Suppress("DEPRECATION")
    fun signerCertificates(info: PackageInfo): List<ByteArray> {
        val result = ArrayList<ByteArray>()
        if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.let { si ->
                val sigs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
                sigs?.forEach { result.add(it.toByteArray()) }
            }
        }
        if (result.isEmpty()) info.signatures?.forEach { result.add(it.toByteArray()) }
        return result.distinctBy { it.contentHashCode() }
    }

    /** Huella SHA-1 en mayúsculas, el formato que usan las bases de indicadores. */
    fun certSha1(cert: ByteArray): String = digest("SHA-1", cert).uppercase()

    fun isDebugCertificate(cert: ByteArray): Boolean = try {
        val x509 = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(cert)) as X509Certificate
        x509.subjectX500Principal.name.contains("CN=Android Debug", ignoreCase = true)
    } catch (e: Exception) {
        false
    }
}
