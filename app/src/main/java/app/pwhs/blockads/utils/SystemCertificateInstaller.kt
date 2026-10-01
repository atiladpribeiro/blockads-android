package app.pwhs.blockads.utils

import com.topjohnwu.superuser.Shell
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Installs only the public CA certificate. TLS interception is separately
 * controlled by the VPN engine and never enabled by installing this module.
 */
object SystemCertificateInstaller {

    private const val MODULE_ID = "blockads_ca"

    fun isRootAvailable(): Boolean {
        return try {
            Shell.isAppGrantedRoot() == true && Shell.cmd("id -u").exec().out.firstOrNull()?.trim() == "0"
        } catch (e: Exception) {
            Timber.w(e, "Failed to check root availability")
            false
        }
    }

    /**
     * Computes the OpenSSL subject hash (MD5-based, old style used by Android cacerts).
     */
    fun computeSubjectHashOld(cert: X509Certificate): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(cert.subjectX500Principal.encoded)
        val hash = (digest[0].toInt() and 0xFF) or
                ((digest[1].toInt() and 0xFF) shl 8) or
                ((digest[2].toInt() and 0xFF) shl 16) or
                ((digest[3].toInt() and 0xFF) shl 24)
        return String.format(Locale.US, "%08x", hash.toLong() and 0xFFFFFFFFL)
    }

    /**
     * Computes the OpenSSL subject hash (SHA-1 based, newer style used by Conscrypt APEX).
     */
    fun computeSubjectHashSha1(cert: X509Certificate): String {
        val md = MessageDigest.getInstance("SHA-1")
        val digest = md.digest(cert.subjectX500Principal.encoded)
        val hash = (digest[0].toInt() and 0xFF) or
                ((digest[1].toInt() and 0xFF) shl 8) or
                ((digest[2].toInt() and 0xFF) shl 16) or
                ((digest[3].toInt() and 0xFF) shl 24)
        return String.format(Locale.US, "%08x", hash.toLong() and 0xFFFFFFFFL)
    }

    /**
     * Installs the CA certificate directly to the Android User CA Store via root.
     * Path: /data/misc/user/0/cacerts-added/<hash>.0
     *
     * This takes effect IMMEDIATELY without needing a device reboot, because
     * AndroidCAStore dynamically loads user certificates from /data.
     */
    fun installToUserStoreViaRoot(caPem: String): Result<String> {
        if (!isRootAvailable()) {
            return Result.failure(IllegalStateException("Root access is not available"))
        }

        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(
                ByteArrayInputStream(caPem.toByteArray())
            ) as X509Certificate

            val hashOld = computeSubjectHashOld(cert)
            val userStoreDir = "/data/misc/user/0/cacerts-added"
            val certPath = "$userStoreDir/$hashOld.0"
            val removedPath = "/data/misc/user/0/cacerts-removed/$hashOld.0"

            val commands = listOf(
                "mkdir -p $userStoreDir",
                "cat << 'EOF' > $certPath\n$caPem\nEOF",
                "chmod 644 $certPath",
                "chown system:system $certPath 2>/dev/null || true",
                "rm -f $removedPath"
            )

            val res = Shell.cmd(*commands.toTypedArray()).exec()
            if (res.isSuccess) {
                Timber.d("CA installed to user store via root successfully: $certPath")
                Result.success(hashOld)
            } else {
                val err = res.err.joinToString("\n")
                Timber.e("Failed to install CA to user store: $err")
                Result.failure(RuntimeException(err))
            }
        } catch (e: Exception) {
            Timber.e(e, "Exception during user store root install")
            Result.failure(e)
        }
    }

    /** Stage a certificate-only KernelSU module. Reboot and verify system trust separately. */
    fun installToSystemStore(caPem: String, cacheDir: File): Result<String> {
        if (!isRootAvailable()) return Result.failure(IllegalStateException("Root access is not available"))
        return try {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(
                ByteArrayInputStream(caPem.toByteArray())
            ) as X509Certificate
            require(cert.basicConstraints >= 0) { "Certificate is not a CA" }
            cert.checkValidity()
            val hashOld = computeSubjectHashOld(cert)
            val hashSha1 = computeSubjectHashSha1(cert)
            val canonicalPem = java.util.Base64.getMimeEncoder(64, "\n".toByteArray())
                .encodeToString(cert.encoded)
                .let { "-----BEGIN CERTIFICATE-----\n$it\n-----END CERTIFICATE-----\n" }
            val zip = File(cacheDir, "blockads_ca_kernelsu.zip")
            ZipOutputStream(zip.outputStream()).use { out ->
                fun add(name: String, content: String) {
                    out.putNextEntry(ZipEntry(name))
                    out.write(content.toByteArray(Charsets.UTF_8))
                    out.closeEntry()
                }
                add("module.prop", """id=$MODULE_ID
name=BlockAds Certificate
version=2.0
versionCode=3
author=BlockAds
description=Public certificate only; requires explicit HTTPS VPN mode
""")
                for (hash in setOf(hashOld, hashSha1)) {
                    add("system/etc/security/cacerts/$hash.0", canonicalPem)
                }
            }
            try {
                val ksud = Shell.cmd("command -v ksud").exec()
                if (!ksud.isSuccess || ksud.out.firstOrNull().isNullOrBlank()) {
                    return Result.failure(IllegalStateException("KernelSU Next module manager is unavailable"))
                }
                val result = Shell.cmd("ksud module install '${zip.absolutePath}'").exec()
                if (!result.isSuccess) {
                    return Result.failure(IllegalStateException(result.err.joinToString("\n")))
                }
                Result.success(hashOld)
            } finally {
                zip.delete()
            }
        } catch (e: Exception) {
            Timber.e(e, "KernelSU certificate module staging failed")
            Result.failure(e)
        }
    }

}
