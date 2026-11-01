package com.doberman.antivirus.core

import android.Manifest
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.storage.StorageManager
import androidx.core.content.ContextCompat
import java.io.File

/**
 * Recorre el almacenamiento (memoria interna y tarjeta SD) buscando instaladores de apps (APK),
 * archivos disfrazados con doble extensión y archivos idénticos a malware conocido.
 */
class FileScanner(private val context: Context, private val db: ThreatDatabase = ThreatDatabase.get(context)) {

    private val pm: PackageManager = context.packageManager

    fun hasAccess(): Boolean = hasStorageAccess(context)

    fun roots(): List<File> {
        val result = LinkedHashSet<File>()
        if (Build.VERSION.SDK_INT >= 30) {
            context.getSystemService(StorageManager::class.java)?.storageVolumes?.forEach { v ->
                v.directory?.let(result::add)
            }
        }
        @Suppress("DEPRECATION")
        result += Environment.getExternalStorageDirectory()
        context.getExternalFilesDirs(null).filterNotNull().forEach { dir ->
            val path = dir.absolutePath
            val idx = path.indexOf("/Android/data/")
            if (idx > 0) result += File(path.substring(0, idx))
        }
        return result.filter { it.isDirectory && it.canRead() }.distinctBy { runCatching { it.canonicalPath }.getOrDefault(it.path) }
    }

    fun scan(
        ignored: Set<String>,
        onProgress: (filesSeen: Int, path: String) -> Unit,
        isCancelled: () -> Boolean,
    ): Pair<List<FileFinding>, Int> {
        val findings = ArrayList<FileFinding>()
        val visited = HashSet<String>()
        val stack = ArrayDeque<Pair<File, Int>>()
        roots().forEach { stack.addLast(it to 0) }
        var count = 0
        while (stack.isNotEmpty()) {
            if (isCancelled()) break
            val (dir, depth) = stack.removeLast()
            val canonical = runCatching { dir.canonicalPath }.getOrDefault(dir.absolutePath)
            if (!visited.add(canonical)) continue
            val children = dir.listFiles() ?: continue
            for (f in children) {
                if (isCancelled()) break
                if (f.isDirectory) {
                    if (depth < MAX_DEPTH && !isSkipped(f)) stack.addLast(f to depth + 1)
                    continue
                }
                count++
                if (count % 25 == 0) onProgress(count, f.absolutePath)
                if (f.absolutePath in ignored) continue
                analyze(f, isCancelled)?.let(findings::add)
                if (count >= MAX_FILES) return findings.sortedForDisplay() to count
            }
        }
        onProgress(count, "")
        return findings.sortedForDisplay() to count
    }

    private fun isSkipped(dir: File): Boolean {
        val p = dir.absolutePath
        return p.endsWith("/Android/data") || p.endsWith("/Android/obb") || dir.name == ".thumbnails"
    }

    fun analyze(file: File, isCancelled: () -> Boolean = { false }): FileFinding? {
        val name = file.name
        val lower = name.lowercase()
        val ext = lower.substringAfterLast('.', "")
        val isApk = ext in APK_EXT
        val disguised = DOUBLE_EXT.containsMatchIn(lower)
        val isWindows = ext in WINDOWS_EXT
        val isCode = ext in CODE_EXT
        if (!isApk && !disguised && !isWindows && !isCode) return null

        var score = 0
        val reasons = ArrayList<String>()
        fun add(points: Int, reason: String) {
            score += points
            reasons += reason
        }
        var threat: ThreatDatabase.Family? = null
        fun matched(f: ThreatDatabase.Family, how: String) {
            if (threat == null || (threat!!.isMonitoringOnly && !f.isMonitoringOnly)) threat = f
            add(if (f.isMonitoringOnly) 45 else 100, "$how «${f.name}» (${f.typeLabel})")
        }

        val sha = Hashing.sha256(file, isCancelled = isCancelled)
        sha?.let { db.byHash(it) }?.let { matched(it, "Es idéntico a una muestra de") }

        var apkPackage: String? = null
        var apkLabel: String? = null
        if (isApk) {
            add(12, "Es un instalador de apps (APK). Si no lo descargaste tú a propósito, bórralo")
            if (ext == "apk") {
                val info = archiveInfo(file)
                if (info != null) {
                    apkPackage = info.packageName
                    info.applicationInfo?.let { ai ->
                        ai.sourceDir = file.absolutePath
                        ai.publicSourceDir = file.absolutePath
                        apkLabel = runCatching { ai.loadLabel(pm).toString() }.getOrNull()
                    }
                    db.byPackage(info.packageName)?.let { matched(it, "Instala la app conocida") }
                    Hashing.signerCertificates(info).firstNotNullOfOrNull { db.byCert(Hashing.certSha1(it)) }
                        ?.let { matched(it, "Está firmado con el certificado de") }
                    analyzeApkBehaviour(info, apkLabel.orEmpty(), ::add)
                } else {
                    add(5, "No se pudo leer su contenido (puede estar dañado o protegido)")
                }
            }
        }
        if (disguised) add(35, "Tiene doble extensión para parecer una foto, video o documento")
        if (isWindows) add(12, "Es un programa de Windows: no afecta a Android, pero no lo abras en una computadora si no confías en él")
        if (isCode) add(12, "Es código ejecutable suelto, algo poco común fuera de las apps")
        if ("/." in file.absolutePath) add(10, "Está guardado en una carpeta oculta")

        val severity = when {
            threat != null && !threat!!.isMonitoringOnly -> Severity.DANGER
            else -> Thresholds.severityFor(score)
        } ?: return null

        return FileFinding(
            path = file.absolutePath,
            name = name,
            size = file.length(),
            lastModified = file.lastModified(),
            severity = severity,
            score = score,
            reasons = reasons,
            threatName = threat?.name,
            sha256 = sha,
            apkPackage = apkPackage,
            apkLabel = apkLabel,
        )
    }

    private fun analyzeApkBehaviour(info: PackageInfo, label: String, add: (Int, String) -> Unit) {
        val perms = info.requestedPermissions?.toSet().orEmpty()
        val services = info.services.orEmpty()
        val receivers = info.receivers.orEmpty()
        if (services.any { it.permission == Known.PERM_BIND_ACCESSIBILITY }) {
            add(15, "La app pediría control de Accesibilidad (ver y tocar tu pantalla)")
        }
        if (receivers.any { it.permission == Known.PERM_BIND_ADMIN }) {
            add(15, "La app pediría ser administradora del dispositivo")
        }
        if (services.any { it.permission == Known.PERM_BIND_LISTENER }) {
            add(8, "La app pediría leer tus notificaciones")
        }
        if (perms.any { it in Known.SMS_PERMISSIONS }) add(15, "La app pediría leer o enviar SMS")
        if (Known.PERM_OVERLAY in perms) add(8, "La app podría mostrarse encima de otras apps")
        val norm = ScamDetector.normalize(label)
        if (label.isNotBlank() && Known.looksLikeSystemName(norm)) add(25, "Su nombre imita una app del sistema («$label»)")
        if (Known.SYSTEM_LIKE_PREFIXES.any { info.packageName.startsWith(it) }) {
            add(25, "Su identificador (${info.packageName}) imita a una app del sistema")
        }
        if (Known.isCleanerName(norm) && !Known.isReputableSecurity(info.packageName)) {
            add(10, "Es una app de «limpieza/acelerar/antivirus» de origen desconocido")
        }
        val installed = runCatching { pm.getPackageInfo(info.packageName, 0) }.isSuccess
        if (installed) add(0, "Esta app está instalada en tu teléfono")
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(file: File): PackageInfo? = runCatching {
        var flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_SIGNATURES
        if (Build.VERSION.SDK_INT >= 28) flags = flags or PackageManager.GET_SIGNING_CERTIFICATES
        pm.getPackageArchiveInfo(file.absolutePath, flags)
    }.getOrNull()

    private fun List<FileFinding>.sortedForDisplay() =
        sortedWith(compareBy<FileFinding> { it.severity.ordinal }.thenByDescending { it.score })

    companion object {
        private const val MAX_DEPTH = 14
        private const val MAX_FILES = 400_000
        private val APK_EXT = setOf("apk", "apks", "xapk", "apkm")
        private val WINDOWS_EXT = setOf("exe", "scr", "bat", "cmd", "vbs", "msi", "ps1")
        private val CODE_EXT = setOf("dex", "jar")
        private val DOUBLE_EXT = Regex(
            "\\.(jpe?g|png|gif|webp|mp4|mp3|avi|mkv|pdf|docx?|xlsx?|pptx?|txt|zip|rar)\\s*\\.(apk|apks|xapk|exe|scr|bat|cmd|vbs|js|jar)$"
        )

        fun hasStorageAccess(context: Context): Boolean = runCatching {
            if (Build.VERSION.SDK_INT >= 30) {
                Environment.isExternalStorageManager()
            } else {
                ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
                    PackageManager.PERMISSION_GRANTED
            }
        }.getOrDefault(false)
    }
}
