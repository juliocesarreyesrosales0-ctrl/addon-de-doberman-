package com.doberman.antivirus.core

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.core.net.toUri
import com.doberman.antivirus.guard.NotificationGuardService

/** Atajos a pantallas del sistema. Cada uno prueba alternativas porque cada fabricante es distinto. */
object SystemIntents {

    fun start(context: Context, vararg intents: Intent): Boolean = startAny(context, true, *intents)

    private fun startAny(context: Context, toastOnFail: Boolean, vararg intents: Intent): Boolean {
        for (intent in intents) {
            try {
                if (context !is Activity) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                return true
            } catch (e: ActivityNotFoundException) {
                continue
            } catch (e: SecurityException) {
                continue
            } catch (e: IllegalArgumentException) {
                continue
            }
        }
        if (toastOnFail) Toast.makeText(context, "No se pudo abrir esa pantalla en este teléfono", Toast.LENGTH_LONG).show()
        return false
    }

    fun uninstallIntent(pkg: String) = Intent(Intent.ACTION_DELETE, Uri.fromParts("package", pkg, null))

    fun appDetailsIntent(pkg: String) =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null))

    fun openAppDetails(context: Context, pkg: String) = start(context, appDetailsIntent(pkg), Intent(Settings.ACTION_SETTINGS))

    fun openAppNotificationSettings(context: Context, pkg: String) {
        val intents = ArrayList<Intent>()
        if (Build.VERSION.SDK_INT >= 26) {
            intents += Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, pkg)
        }
        val uid = runCatching { context.packageManager.getApplicationInfo(pkg, 0).uid }.getOrDefault(0)
        intents += Intent("android.settings.APP_NOTIFICATION_SETTINGS")
            .putExtra("app_package", pkg).putExtra("app_uid", uid)
        intents += appDetailsIntent(pkg)
        start(context, *intents.toTypedArray())
    }

    /** Abre directamente el interruptor de notificaciones de un sitio web (canal de Chrome). */
    fun openSiteNotificationSettings(context: Context, browserPkg: String, channelId: String?) {
        if (Build.VERSION.SDK_INT >= 26 && channelId != null) {
            val ok = startAny(
                context,
                false,
                Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, browserPkg)
                    .putExtra(Settings.EXTRA_CHANNEL_ID, channelId),
            )
            if (ok) return
        }
        openAppNotificationSettings(context, browserPkg)
    }

    fun openNotificationAccess(context: Context) {
        val intents = ArrayList<Intent>()
        if (Build.VERSION.SDK_INT >= 30) {
            intents += Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS).putExtra(
                Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
                ComponentName(context, NotificationGuardService::class.java).flattenToString(),
            )
        }
        intents += Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        intents += Intent(Settings.ACTION_SETTINGS)
        start(context, *intents.toTypedArray())
    }

    fun openAllFilesAccess(context: Context) {
        if (Build.VERSION.SDK_INT >= 30) {
            start(
                context,
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.fromParts("package", context.packageName, null)),
                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION),
                appDetailsIntent(context.packageName),
            )
        } else {
            openAppDetails(context, context.packageName)
        }
    }

    fun openDeviceAdmins(context: Context) = start(
        context,
        Intent().setComponent(ComponentName("com.android.settings", "com.android.settings.Settings\$DeviceAdminSettingsActivity")),
        Intent().setComponent(ComponentName("com.android.settings", "com.android.settings.DeviceAdminSettings")),
        Intent(Settings.ACTION_SECURITY_SETTINGS),
        Intent(Settings.ACTION_SETTINGS),
    )

    fun openAccessibility(context: Context) =
        start(context, Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS), Intent(Settings.ACTION_SETTINGS))

    fun openSecurity(context: Context) =
        start(context, Intent(Settings.ACTION_SECURITY_SETTINGS), Intent(Settings.ACTION_SETTINGS))

    fun openDeveloperOptions(context: Context) = start(
        context,
        Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
        Intent(Settings.ACTION_DEVICE_INFO_SETTINGS),
        Intent(Settings.ACTION_SETTINGS),
    )

    fun openUnknownSources(context: Context) = if (Build.VERSION.SDK_INT >= 26) {
        start(context, Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES), Intent(Settings.ACTION_SECURITY_SETTINGS))
    } else {
        openSecurity(context)
    }

    fun openSystemUpdate(context: Context) = start(
        context,
        Intent("android.settings.SYSTEM_UPDATE_SETTINGS"),
        Intent(Settings.ACTION_DEVICE_INFO_SETTINGS),
        Intent(Settings.ACTION_SETTINGS),
    )

    fun openNetworkSettings(context: Context) = start(
        context,
        Intent(Settings.ACTION_WIRELESS_SETTINGS),
        Intent(Settings.ACTION_SETTINGS),
    )

    fun openPlayProtect(context: Context): Boolean {
        val pm = context.packageManager
        val intents = listOfNotNull(
            Intent("com.google.android.gms.security.settings.VerifyAppsSettingsActivity")
                .setPackage("com.google.android.gms"),
            Intent().setClassName("com.google.android.gms", "com.google.android.gms.security.settings.VerifyAppsSettingsActivity"),
            pm.getLaunchIntentForPackage("com.android.vending"),
        )
        return start(context, *intents.toTypedArray())
    }

    fun openUrl(context: Context, url: String) = start(context, Intent(Intent.ACTION_VIEW, url.toUri()))

    fun virusTotalUrl(sha256: String) = "https://www.virustotal.com/gui/file/$sha256"
}
