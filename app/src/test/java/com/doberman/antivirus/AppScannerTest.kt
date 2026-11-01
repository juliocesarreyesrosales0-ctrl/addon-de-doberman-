package com.doberman.antivirus

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.doberman.antivirus.core.AppScanner
import com.doberman.antivirus.core.Hashing
import com.doberman.antivirus.core.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppScannerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val context: Application = ApplicationProvider.getApplicationContext()
    private val signature = "firma-de-prueba-spyx".toByteArray()
    private lateinit var scanner: AppScanner
    private lateinit var evilApk: java.io.File

    @Before
    fun setUp() {
        evilApk = tmp.newFile("evil.apk").apply { writeText("contenido de una muestra de malware") }
        val db = testDatabase(Hashing.certSha1(signature), Hashing.sha256(evilApk)!!)
        scanner = AppScanner(context, db)
    }

    private fun scan(pkg: String, deep: Boolean = false, ignored: Set<String> = emptySet()) =
        scanner.scanOne(pkg, deep, scanner.gatherEnvironment(ignored = ignored))

    @Test
    fun sideloadedAppDisguisedAsSystemWithSpyPermissionsIsHighRisk() {
        installFakeApp(context, "com.example.update", "System Update", SPY_PERMISSIONS, installer = null, launcher = false)
        val f = scan("com.example.update")
        assertNotNull(f)
        assertEquals(Severity.DANGER, f!!.severity)
        assertTrue(f.sideloaded)
        assertTrue(f.reasons.any { "tienda oficial" in it })
        assertTrue(f.reasons.any { "ícono" in it })
        assertTrue(f.reasons.any { "imita una app del sistema" in it })
        assertTrue(f.reasons.any { "SMS" in it })
    }

    @Test
    fun normalPlayStoreAppIsNotReported() {
        installFakeApp(
            context, "com.whatsapp", "WhatsApp",
            listOf("android.permission.RECEIVE_SMS", "android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
            installer = "com.android.vending",
        )
        assertNull(scan("com.whatsapp"))
    }

    @Test
    fun knownStalkerwarePackageIsDangerEvenFromStore() {
        installFakeApp(context, "com.spyx.app", "Notas", installer = "com.android.vending")
        val f = scan("com.spyx.app")!!
        assertEquals(Severity.DANGER, f.severity)
        assertEquals("SpyX", f.threatName)
    }

    @Test
    fun knownSigningCertificateIsDanger() {
        installFakeApp(context, "com.renamed.tool", "Calculadora", installer = "com.android.vending", signature = signature)
        val f = scan("com.renamed.tool")!!
        assertEquals(Severity.DANGER, f.severity)
        assertEquals("SpyX", f.threatName)
    }

    @Test
    fun apkHashIsOnlyCheckedInDeepScan() {
        installFakeApp(context, "com.hash.match", "Linterna", installer = "com.android.vending", apk = evilApk)
        assertNull(scan("com.hash.match", deep = false))
        val deep = scan("com.hash.match", deep = true)!!
        assertEquals(Severity.DANGER, deep.severity)
        assertEquals(Hashing.sha256(evilApk), deep.sha256)
    }

    @Test
    fun monitoringAppIsSuspiciousNotDanger() {
        installFakeApp(context, "com.kidwatch", "Kid Watch", installer = "com.android.vending")
        val f = scan("com.kidwatch")!!
        assertEquals(Severity.WARNING, f.severity)
        assertEquals("KidWatch", f.threatName)
    }

    @Test
    fun storeCleanerIsMarkedForReview() {
        installFakeApp(context, "com.super.cleaner", "Super Cleaner - Phone Booster", installer = "com.android.vending")
        assertEquals(Severity.INFO, scan("com.super.cleaner")!!.severity)
    }

    @Test
    fun wordsInsideOtherWordsDoNotTrigger() {
        // "Instagram" o "Telegram" contienen "ram" pero no son apps de limpieza.
        installFakeApp(context, "org.telegram.messenger", "Telegram", installer = "com.android.vending")
        assertNull(scan("org.telegram.messenger"))
    }

    @Test
    fun appsCopiedFromAnOldPhoneAreNotFlaggedJustForThat() {
        installFakeApp(context, "com.example.game", "Mi Juego", installer = "com.sec.android.easyMover")
        assertNull(scan("com.example.game"))
    }

    @Test
    fun preinstalledAppsAreOnlyReportedWhenKnown() {
        installFakeApp(context, "com.vendor.service", "System Service", launcher = false, system = true)
        assertNull(scan("com.vendor.service"))
    }

    @Test
    fun trustedAppsAreSkipped() {
        installFakeApp(context, "com.example.update2", "System Update", SPY_PERMISSIONS, launcher = false)
        assertNull(scan("com.example.update2", ignored = setOf("com.example.update2")))
    }

    @Test
    fun fullScanFindsAndSortsThreats() {
        installFakeApp(context, "com.example.update", "System Update", SPY_PERMISSIONS, launcher = false)
        installFakeApp(context, "com.super.cleaner", "Super Cleaner", installer = "com.android.vending")
        installFakeApp(context, "com.whatsapp", "WhatsApp", installer = "com.android.vending")
        val env = scanner.gatherEnvironment()
        var progressCalls = 0
        val (findings, total) = scanner.scanAll(false, env, { _, _, _ -> progressCalls++ }, { false })
        assertTrue(total >= 3)
        assertTrue(progressCalls >= 3)
        assertEquals("com.example.update", findings.first().packageName)
        assertTrue(findings.none { it.packageName == "com.whatsapp" })
        assertTrue(findings.none { it.packageName == context.packageName })
    }
}
