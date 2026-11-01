package com.doberman.antivirus.core

import android.content.pm.PackageManager

/** Listas de referencia usadas por los análisis. */
object Known {

    /** Tiendas oficiales: las apps instaladas desde aquí pasaron revisiones de seguridad. */
    val TRUSTED_INSTALLERS: Map<String, String> = mapOf(
        "com.android.vending" to "Google Play",
        "com.google.android.feedback" to "Google Play",
        "com.sec.android.app.samsungapps" to "Galaxy Store",
        "com.huawei.appmarket" to "Huawei AppGallery",
        "com.hihonor.appmarket" to "HONOR App Market",
        "com.xiaomi.mipicks" to "Xiaomi GetApps",
        "com.xiaomi.market" to "Xiaomi GetApps",
        "com.heytap.market" to "OPPO / realme App Market",
        "com.oppo.market" to "OPPO App Market",
        "com.bbk.appstore" to "vivo App Store",
        "com.amazon.venezia" to "Amazon Appstore",
        "org.fdroid.fdroid" to "F-Droid",
        "com.aurora.store" to "Aurora Store",
    )

    /** Herramientas que copian apps desde el teléfono anterior (no son una descarga nueva). */
    val MIGRATION_INSTALLERS: Map<String, String> = mapOf(
        "com.sec.android.easyMover" to "Smart Switch",
        "com.google.android.apps.restore" to "Restauración de Google",
        "com.google.android.apps.pixelmigrate" to "Copiar apps y datos (Google)",
        "com.android.managedprovisioning" to "Configuración del dispositivo",
        "com.huawei.KoBackup" to "Copia de seguridad de Huawei",
        "com.hihonor.KoBackup" to "Copia de seguridad de HONOR",
        "com.miui.backup" to "Copia de seguridad de Xiaomi",
        "com.coloros.backuprestore" to "Clonar teléfono (OPPO)",
        "com.oplus.backuprestore" to "Clonar teléfono (OPPO/realme)",
        "com.vivo.easyshare" to "EasyShare (vivo)",
        "com.motorola.migrate" to "Migrar (Motorola)",
    )

    private val PACKAGE_INSTALLERS = setOf(
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.miui.packageinstaller",
    )

    fun installerLabel(installer: String?, pm: PackageManager): String {
        if (installer.isNullOrBlank()) return "Origen desconocido"
        TRUSTED_INSTALLERS[installer]?.let { return it }
        MIGRATION_INSTALLERS[installer]?.let { return "Transferida desde otro teléfono ($it)" }
        if (installer in PACKAGE_INSTALLERS) return "Archivo APK descargado"
        if (installer == "com.android.shell") return "Instalada desde una computadora (ADB)"
        val label = runCatching {
            pm.getApplicationLabel(pm.getApplicationInfo(installer, 0)).toString()
        }.getOrNull()
        return if (label != null) "Instalada mediante «$label»" else "Instalada por $installer"
    }

    /** Navegadores: sus notificaciones suelen venir de páginas web con permiso de notificar. */
    val BROWSERS: Map<String, String> = mapOf(
        "com.android.chrome" to "Chrome",
        "com.chrome.beta" to "Chrome Beta",
        "com.chrome.dev" to "Chrome Dev",
        "com.chrome.canary" to "Chrome Canary",
        "com.google.android.apps.chrome" to "Chrome",
        "com.sec.android.app.sbrowser" to "Samsung Internet",
        "com.sec.android.app.sbrowser.beta" to "Samsung Internet Beta",
        "org.mozilla.firefox" to "Firefox",
        "org.mozilla.firefox_beta" to "Firefox Beta",
        "org.mozilla.fenix" to "Firefox Nightly",
        "org.mozilla.focus" to "Firefox Focus",
        "com.opera.browser" to "Opera",
        "com.opera.browser.beta" to "Opera Beta",
        "com.opera.mini.native" to "Opera Mini",
        "com.opera.gx" to "Opera GX",
        "com.brave.browser" to "Brave",
        "com.microsoft.emmx" to "Microsoft Edge",
        "com.UCMobile.intl" to "UC Browser",
        "com.uc.browser.en" to "UC Browser",
        "com.mi.globalbrowser" to "Mi Browser",
        "com.android.browser" to "Navegador",
        "com.huawei.browser" to "Huawei Browser",
        "com.hihonor.baidu.browser" to "HONOR Browser",
        "com.heytap.browser" to "Navegador OPPO",
        "com.vivo.browser" to "Navegador vivo",
        "com.yandex.browser" to "Yandex Browser",
        "com.duckduckgo.mobile.android" to "DuckDuckGo",
        "com.vivaldi.browser" to "Vivaldi",
        "com.kiwibrowser.browser" to "Kiwi Browser",
        "com.ecosia.android" to "Ecosia",
        "mark.via.gp" to "Via",
        "com.transsion.phoenix" to "Phoenix Browser",
        "com.cloudmosa.puffinFree" to "Puffin",
    )

    /** Nunca se tocan las notificaciones de estas apps (sistema, llamadas, Play Protect). */
    val PROTECTED_NOTIFIERS: Set<String> = setOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.phone",
        "com.android.server.telecom",
        "com.android.dialer",
        "com.google.android.dialer",
        "com.samsung.android.dialer",
        "com.google.android.gms",
        "com.android.vending",
        "com.google.android.apps.messaging",
        "com.android.mms",
        "com.samsung.android.messaging",
        "com.android.cellbroadcastreceiver",
        "com.google.android.cellbroadcastreceiver",
    )

    /** Antivirus y utilidades reconocidas: no se marcan por su nombre ni por sus avisos. */
    private val REPUTABLE_SECURITY_PREFIXES = listOf(
        "com.avast.", "com.avg.", "com.bitdefender.", "com.kms.", "com.kaspersky.", "org.malwarebytes.",
        "com.wsandroid.", "com.mcafee.", "com.eset.", "com.symantec.", "com.nortonlifelock.",
        "com.trendmicro.", "com.sophos.", "com.lookout", "com.zimperium.", "com.fsecure.", "com.f_secure.",
        "com.google.android.apps.nbu.files", "com.piriform.ccleaner", "com.doberman.antivirus",
    )

    fun isReputableSecurity(pkg: String): Boolean = REPUTABLE_SECURITY_PREFIXES.any { pkg.startsWith(it) }

    /** Prefijos de paquete que solo deberían usar el sistema o el fabricante. */
    val SYSTEM_LIKE_PREFIXES = listOf(
        "com.android.", "android.", "com.google.android.", "com.google.", "com.samsung.", "com.sec.",
        "com.miui.", "com.xiaomi.", "com.huawei.", "com.hihonor.", "com.motorola.", "com.oppo.",
        "com.coloros.", "com.vivo.", "com.qualcomm.", "com.mediatek.", "com.lge.", "com.sonymobile.",
    )

    /** Palabras de nombres que imitan componentes del sistema (texto ya normalizado sin acentos). */
    private val SYSTEM_LIKE_NAME = Regex(
        "\\b(system|sistema|android|google|update|updates|actualizacion|actualizaciones|actualizar|" +
            "service|services|servicio|servicios|settings|ajustes|configuracion|security|seguridad|" +
            "wi-?fi|bluetooth|framework|sync|sincronizacion|device|dispositivo|play store|play protect|" +
            "sim toolkit|process|proceso|kernel|firmware|flash player|adobe flash|system ui)\\b"
    )

    fun looksLikeSystemName(normalizedLabel: String): Boolean = SYSTEM_LIKE_NAME.containsMatchIn(normalizedLabel)

    /** Apps de "limpieza", "acelerador", "ahorro de batería" o antivirus desconocidos. */
    private val CLEANER_NAME = Regex(
        "\\b(cleaner|clean master|phone clean|limpiador|limpieza|limpiar|booster|boost|acelerador|" +
            "optimizador|optimizer|speed ?up|ram|junk|basura|battery saver|ahorro de bateria|" +
            "ahorrador|battery doctor|cpu cooler|enfriador|phone master|virus cleaner|antivirus|" +
            "anti-?virus|virus|security master|max cleaner)\\b"
    )

    fun isCleanerName(normalizedLabel: String): Boolean = CLEANER_NAME.containsMatchIn(normalizedLabel)

    val SMS_PERMISSIONS = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    )

    /** Permisos típicos de apps espía cuando aparecen todos juntos. */
    val SPY_PERMISSIONS = setOf(
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
    )

    const val PERM_OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
    const val PERM_INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES"
    const val PERM_BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    const val PERM_BIND_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
    const val PERM_BIND_LISTENER = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
}
