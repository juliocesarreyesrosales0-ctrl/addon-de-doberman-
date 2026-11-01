package com.doberman.antivirus.core

/** Nivel de riesgo de un hallazgo. El orden importa: primero lo más grave. */
enum class Severity(val label: String) {
    DANGER("Alto riesgo"),
    WARNING("Sospechoso"),
    INFO("Revisar"),
}

/** Puntos mínimos para reportar algo y para cada nivel. */
object Thresholds {
    const val DANGER = 60
    const val WARNING = 30
    const val INFO = 12

    fun severityFor(score: Int): Severity? = when {
        score >= DANGER -> Severity.DANGER
        score >= WARNING -> Severity.WARNING
        score >= INFO -> Severity.INFO
        else -> null
    }
}

data class AppFinding(
    val packageName: String,
    val label: String,
    val severity: Severity,
    val score: Int,
    val reasons: List<String>,
    /** Nombre de la familia de malware si coincide con la base de firmas. */
    val threatName: String?,
    val isSystem: Boolean,
    val sideloaded: Boolean,
    val installerLabel: String,
    val firstInstallTime: Long,
    val versionName: String?,
    val apkPath: String?,
    val apkSize: Long,
    val sha256: String?,
    val isDeviceAdmin: Boolean,
)

data class FileFinding(
    val path: String,
    val name: String,
    val size: Long,
    val lastModified: Long,
    val severity: Severity,
    val score: Int,
    val reasons: List<String>,
    val threatName: String?,
    val sha256: String?,
    val apkPackage: String?,
    val apkLabel: String?,
)

/** Acción que resuelve un problema de configuración del teléfono. */
enum class FixAction {
    SCREEN_LOCK,
    DEVELOPER_OPTIONS,
    ACCESSIBILITY,
    DEVICE_ADMINS,
    NOTIFICATION_ACCESS,
    UNKNOWN_SOURCES,
    SYSTEM_UPDATE,
    ENABLE_SHIELD,
    STORAGE_PERMISSION,
    NONE,
}

data class SettingFinding(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val action: FixAction,
    val actionLabel: String,
)

data class ScanReport(
    val deep: Boolean,
    val startedAt: Long,
    val finishedAt: Long,
    val appsScanned: Int,
    val filesScanned: Int,
    val storageScanned: Boolean,
    val apps: List<AppFinding>,
    val files: List<FileFinding>,
    val settings: List<SettingFinding>,
) {
    /** Amenazas reales (alto riesgo o sospechosas), sin contar lo que solo hay que revisar. */
    val threatCount: Int
        get() = apps.count { it.severity != Severity.INFO } + files.count { it.severity != Severity.INFO }

    val reviewCount: Int
        get() = apps.count { it.severity == Severity.INFO } + files.count { it.severity == Severity.INFO } +
            settings.size

    val worst: Severity?
        get() = (apps.map { it.severity } + files.map { it.severity } + settings.map { it.severity })
            .minByOrNull { it.ordinal }
}

data class ScanProgress(
    val phase: String,
    val detail: String,
    val done: Int,
    val total: Int,
) {
    val fraction: Float? get() = if (total > 0) (done.toFloat() / total).coerceIn(0f, 1f) else null
}
