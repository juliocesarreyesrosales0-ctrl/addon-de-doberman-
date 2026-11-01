package com.doberman.antivirus.guard

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.doberman.antivirus.MainActivity
import com.doberman.antivirus.R
import com.doberman.antivirus.core.AppFinding
import com.doberman.antivirus.core.Prefs

/** Avisos propios de Doberman (pocos y agrupados, para no convertirnos en otra molestia). */
object Notifier {
    const val CHANNEL_THREATS = "threats"
    const val CHANNEL_SHIELD = "shield"
    private const val ID_SHIELD = 1001

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_THREATS, "Amenazas detectadas", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Avisos cuando se instala una app peligrosa"
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SHIELD, "Notificaciones falsas bloqueadas", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Resumen silencioso de las alertas falsas que Doberman eliminó"
            },
        )
    }

    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    @SuppressLint("MissingPermission")
    fun notifyBlocked(context: Context, sourceName: String, totalBlocked: Int, removed: Boolean) {
        if (!Prefs.notifyBlocked(context) || !canNotify(context)) return
        val title = if (totalBlocked == 1) "Doberman detectó una notificación falsa" else "Doberman detectó $totalBlocked notificaciones falsas"
        val text = if (removed) {
            "Eliminé la última, de $sourceName. Toca para bloquear ese origen para siempre."
        } else {
            "La última viene de $sourceName. Toca para bloquearla para siempre."
        }
        val n = NotificationCompat.Builder(context, CHANNEL_SHIELD)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(openApp(context, MainActivity.TAB_SHIELD, scan = false, requestCode = 1))
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        runCatching { NotificationManagerCompat.from(context).notify(ID_SHIELD, n) }
    }

    @SuppressLint("MissingPermission")
    fun notifyDangerousApp(context: Context, finding: AppFinding) {
        if (!canNotify(context)) return
        val text = finding.reasons.firstOrNull() ?: "Revísala en Doberman"
        val n = NotificationCompat.Builder(context, CHANNEL_THREATS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("App ${finding.severity.label.lowercase()}: ${finding.label}")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$text\n\nToca para revisarla y desinstalarla."))
            .setContentIntent(openApp(context, MainActivity.TAB_RESULTS, scan = true, requestCode = 2))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .build()
        runCatching {
            NotificationManagerCompat.from(context).notify(2000 + (finding.packageName.hashCode() and 0xffff), n)
        }
    }

    private fun openApp(context: Context, tab: String, scan: Boolean, requestCode: Int): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_TAB, tab)
            .putExtra(MainActivity.EXTRA_SCAN, scan)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(
            context, requestCode, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
