package com.doberman.antivirus.core

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

/** Revisa ajustes del teléfono que facilitan infecciones o espionaje. */
class SystemChecker(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    fun check(
        env: AppScanner.Environment,
        apps: List<AppFinding>,
        shieldEnabled: Boolean,
        storageAccess: Boolean,
        deep: Boolean,
    ): List<SettingFinding> {
        val out = ArrayList<SettingFinding>()

        if (!shieldEnabled) {
            out += SettingFinding(
                "shield", "El escudo anti-notificaciones falsas está apagado",
                "Actívalo para que Doberman borre automáticamente las alertas falsas de «limpia tu teléfono» o «tienes virus» y te diga qué página las envía.",
                Severity.WARNING, FixAction.ENABLE_SHIELD, "Activar escudo",
            )
        }

        val keyguard = context.getSystemService(KeyguardManager::class.java)
        if (keyguard != null && !keyguard.isDeviceSecure) {
            out += SettingFinding(
                "lock", "Tu teléfono no tiene bloqueo de pantalla",
                "Sin PIN, patrón o contraseña, cualquiera que tome tu teléfono puede instalarte una app espía en segundos.",
                Severity.WARNING, FixAction.SCREEN_LOCK, "Poner bloqueo",
            )
        }

        val adb = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1 }
            .getOrDefault(false)
        if (adb) {
            out += SettingFinding(
                "adb", "La depuración USB está activada",
                "Permite instalar apps desde una computadora sin que lo notes. Si no eres desarrollador, desactívala en Opciones de desarrollador.",
                Severity.WARNING, FixAction.DEVELOPER_OPTIONS, "Abrir opciones",
            )
        }

        if (Build.VERSION.SDK_INT < 26) {
            @Suppress("DEPRECATION")
            val unknown = runCatching {
                Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            }.getOrDefault(false)
            if (unknown) {
                out += SettingFinding(
                    "unknown", "Está permitido instalar apps de origen desconocido",
                    "Cualquier página puede hacerte instalar una app falsa. Desactiva «Orígenes desconocidos».",
                    Severity.WARNING, FixAction.UNKNOWN_SOURCES, "Abrir ajustes",
                )
            }
        } else if (apps.any { it.sideloaded }) {
            out += SettingFinding(
                "unknown", "Hay apps instaladas fuera de tiendas oficiales",
                "Revisa qué apps (navegador, WhatsApp, administrador de archivos…) tienen permiso para «Instalar apps desconocidas» y quítaselo.",
                Severity.INFO, FixAction.UNKNOWN_SOURCES, "Revisar permiso",
            )
        }

        val thirdPartyAdmins = env.activeAdmins.filter { isThirdParty(it) && it != context.packageName }
        if (thirdPartyAdmins.isNotEmpty()) {
            out += SettingFinding(
                "admins", "Apps con permiso de administrador: ${labels(thirdPartyAdmins)}",
                "Un administrador puede bloquear la pantalla, borrar datos e impedir que lo desinstales. Si no reconoces alguna, desactívala aquí y luego desinstálala.",
                Severity.WARNING, FixAction.DEVICE_ADMINS, "Ver administradores",
            )
        }

        val a11y = env.accessibilityEnabled.filter { isThirdParty(it) && it != context.packageName }
        if (a11y.isNotEmpty()) {
            out += SettingFinding(
                "a11y", "Apps que controlan tu pantalla (Accesibilidad): ${labels(a11y)}",
                "La Accesibilidad deja a una app leer todo lo que ves y tocar por ti. Es lo que usan los troyanos bancarios. Desactiva las que no reconozcas.",
                Severity.INFO, FixAction.ACCESSIBILITY, "Revisar accesibilidad",
            )
        }

        val listeners = env.listenersEnabled.filter { isThirdParty(it) && it != context.packageName }
        if (listeners.isNotEmpty()) {
            out += SettingFinding(
                "listeners", "Apps que leen tus notificaciones: ${labels(listeners)}",
                "Pueden ver tus mensajes y códigos de verificación. Quita el acceso a las que no reconozcas.",
                Severity.INFO, FixAction.NOTIFICATION_ACCESS, "Revisar acceso",
            )
        }

        if (isRooted()) {
            out += SettingFinding(
                "root", "El teléfono tiene acceso «root»",
                "Las apps con permisos de root pueden saltarse toda la seguridad de Android. Si no lo hiciste tú, puede ser malware: considera restablecer el teléfono.",
                Severity.WARNING, FixAction.NONE, "",
            )
        }

        patchAgeMonths()?.let { months ->
            if (months >= 12) {
                out += SettingFinding(
                    "patch", "Tu teléfono no recibe parches de seguridad desde hace ${months / 12} año(s) o más",
                    "Instala las actualizaciones del sistema disponibles. Si el fabricante ya no las publica, ten más cuidado con lo que instalas.",
                    Severity.INFO, FixAction.SYSTEM_UPDATE, "Buscar actualizaciones",
                )
            }
        }

        if (deep && !storageAccess) {
            out += SettingFinding(
                "storage", "No se analizaron tus archivos",
                "Concede «Acceso a todos los archivos» para que el análisis profundo revise Descargas, WhatsApp, Telegram y la tarjeta SD.",
                Severity.INFO, FixAction.STORAGE_PERMISSION, "Dar acceso",
            )
        }
        return out
    }

    private fun isThirdParty(pkg: String): Boolean = runCatching {
        (pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM) == 0
    }.getOrDefault(false)

    private fun labels(pkgs: List<String>): String = pkgs.joinToString(", ") { pkg ->
        runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
    }

    private fun isRooted(): Boolean {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/debug_ramdisk/su",
        )
        if (paths.any { runCatching { File(it).exists() }.getOrDefault(false) }) return true
        val magisk = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser", "me.weishu.kernelsu")
        return magisk.any { runCatching { pm.getPackageInfo(it, 0) }.isSuccess }
    }

    private fun patchAgeMonths(): Int? {
        val patch = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() } ?: return null
        val date = runCatching { SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch) }.getOrNull() ?: return null
        val then = Calendar.getInstance().apply { time = date }
        val now = Calendar.getInstance()
        return (now.get(Calendar.YEAR) - then.get(Calendar.YEAR)) * 12 + (now.get(Calendar.MONTH) - then.get(Calendar.MONTH))
    }
}
