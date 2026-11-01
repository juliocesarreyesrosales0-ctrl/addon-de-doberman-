package com.doberman.antivirus

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Process
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.doberman.antivirus.guard.NotificationGuardService
import com.doberman.antivirus.guard.SpamRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric

@RunWith(AndroidJUnit4::class)
class GuardServiceTest {

    private val context: Application = ApplicationProvider.getApplicationContext()
    private lateinit var service: NotificationGuardService
    private var nextId = 1

    @Before
    fun setUp() {
        SpamRepository.clear(context)
        service = Robolectric.setupService(NotificationGuardService::class.java)
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("x", "x", NotificationManager.IMPORTANCE_DEFAULT))
    }

    @Suppress("DEPRECATION")
    private fun post(pkg: String, channel: String, title: String, text: String, category: String? = null) {
        val n = Notification.Builder(context, channel)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .apply { if (category != null) setCategory(category) }
            .build()
        val sbn = StatusBarNotification(
            pkg, pkg, nextId++, null, 10_000, 0, 0, n, Process.myUserHandle(), System.currentTimeMillis(),
        )
        service.onNotificationPosted(sbn)
    }

    @Test
    fun fakeVirusAlertFromWebsiteIsDetectedWithItsOrigin() {
        post(
            "com.android.chrome", "web:https://limpiador-falso.xyz;1700000000000",
            "⚠️ Tu teléfono tiene 5 virus", "Toca aquí para limpiarlo ahora",
        )
        val src = SpamRepository.sources.value.firstOrNull { it.host == "limpiador-falso.xyz" }
        assertNotNull(src)
        assertTrue(src!!.isScam)
        assertTrue(src.isWeb)
        assertEquals("Chrome", src.appLabel)
        assertEquals("web:https://limpiador-falso.xyz;1700000000000", src.channelId)
        assertEquals(1, src.removedCount)
    }

    @Test
    fun normalWebsiteNotificationIsListedButNotMarkedAsScam() {
        post("com.android.chrome", "web:https://noticias.example;1", "Nuevo artículo", "Las recetas de la semana")
        val src = SpamRepository.sources.value.single { it.host == "noticias.example" }
        assertFalse(src.isScam)
        assertEquals(0, src.removedCount)
    }

    @Test
    fun personalMessagesAreNeverTouched() {
        post(
            "com.whatsapp", "x", "Mamá", "¡Tu teléfono tiene virus! Toca aquí para limpiar ahora",
            category = Notification.CATEGORY_MESSAGE,
        )
        assertNull(SpamRepository.sources.value.firstOrNull { it.packageName == "com.whatsapp" })
    }

    @Test
    fun adwareAppNotificationIsDetected() {
        post("com.fake.booster", "x", "¡Tu teléfono tiene 5 virus!", "Tu batería está 80% dañada. Toca aquí para limpiar ahora")
        val src = SpamRepository.sources.value.single { it.packageName == "com.fake.booster" }
        assertTrue(src.isScam)
        assertFalse(src.isWeb)
        assertTrue(SpamRepository.scamAppPackages(context).contains("com.fake.booster"))
    }

    @Test
    fun browserDownloadNotificationsAreIgnored() {
        post("com.android.chrome", "downloads", "Descarga completa", "documento.pdf")
        assertTrue(SpamRepository.sources.value.isEmpty())
    }
}
