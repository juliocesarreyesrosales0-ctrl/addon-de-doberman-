package com.doberman.antivirus.core

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import java.io.File

/**
 * Analiza las apps instaladas: busca coincidencias con la base de firmas (paquete, certificado y
 * huella SHA-256 del APK) y comportamientos típicos de malware, adware y apps espía.
 */
class AppScanner(private val context: Context, private val db: ThreatDatabase = ThreatDatabase.get(context)) {

    private val pm: PackageManager = context.packageManager

    /** Información del sistema que se consulta una sola vez por análisis. */
    data class Environment(
        val launcherPackages: Set<String>,
        val activeAdmins: Set<String>,
        val adminCapable: Set<String>,
        val accessibilityEnabled: Set<String>,
        val accessibilityCapable: Set<String>,
        val listenersEnabled: Set<String>,
        val keyboardsEnabled: Set<String>,
        val defaultSms: String?,
        val spamApps: Set<String>,
        val ignored: Set<String>,
    )

    fun gatherEnvironment(spamApps: Set<String> = emptySet(), ignored: Set<String> = emptySet()): Environment {
        val launcher = queryActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER))
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val admins = runCatching { dpm?.activeAdmins?.map { it.packageName }?.toSet() }.getOrNull().orEmpty()
        val adminCapable = queryReceivers(Intent("android.app.action.DEVICE_ADMIN_ENABLED"))
        val accessibilityCapable = queryServices(Intent(AccessibilityService.SERVICE_INTERFACE))

        val a11y = HashSet<String>()
        runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
                ?.split(':')?.mapNotNull { ComponentName.unflattenFromString(it)?.packageName }?.let(a11y::addAll)
        }
        runCatching {
            context.getSystemService(AccessibilityManager::class.java)
                ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                ?.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }?.let(a11y::addAll)
        }
        val listeners = runCatching {
            Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
                ?.split(':')?.mapNotNull { ComponentName.unflattenFromString(it)?.packageName }?.toSet()
        }.getOrNull() ?: emptySet()
        val keyboards = runCatching {
            context.getSystemService(InputMethodManager::class.java)?.enabledInputMethodList
                ?.map { it.packageName }?.toSet()
        }.getOrNull().orEmpty()
        val sms = runCatching { Telephony.Sms.getDefaultSmsPackage(context) }.getOrNull()

        return Environment(
            launcherPackages = launcher,
            activeAdmins = admins,
            adminCapable = adminCapable,
            accessibilityEnabled = a11y,
            accessibilityCapable = accessibilityCapable,
            listenersEnabled = listeners,
            keyboardsEnabled = keyboards,
            defaultSms = sms,
            spamApps = spamApps,
            ignored = ignored,
        )
    }

    /** Analiza todas las apps. Devuelve los hallazgos y la cantidad de apps revisadas. */
    fun scanAll(
        deep: Boolean,
        env: Environment,
        onProgress: (done: Int, total: Int, label: String) -> Unit,
        isCancelled: () -> Boolean,
    ): Pair<List<AppFinding>, Int> {
        val packages = installedPackageNames()
        val findings = ArrayList<AppFinding>()
        packages.forEachIndexed { i, pkg ->
            if (isCancelled()) return findings.sortedForDisplay() to i
            val info = packageInfo(pkg) ?: return@forEachIndexed
            val label = info.applicationInfo?.let { labelOf(it) } ?: pkg
            onProgress(i + 1, packages.size, label)
            analyze(info, label, deep, env, isCancelled)?.let(findings::add)
        }
        return findings.sortedForDisplay() to packages.size
    }

    /** Analiza una sola app (por ejemplo, recién instalada). */
    fun scanOne(pkg: String, deep: Boolean, env: Environment = gatherEnvironment()): AppFinding? {
        val info = packageInfo(pkg) ?: return null
        val label = info.applicationInfo?.let { labelOf(it) } ?: pkg
        return analyze(info, label, deep, env) { false }
    }

    fun isInstalled(pkg: String): Boolean = packageInfo(pkg, 0) != null

    private fun analyze(
        info: PackageInfo,
        label: String,
        deep: Boolean,
        env: Environment,
        isCancelled: () -> Boolean,
    ): AppFinding? {
        val ai = info.applicationInfo ?: return null
        val pkg = info.packageName
        if (pkg == context.packageName || pkg in env.ignored) return null

        val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val installer = installerOf(pkg)
        val fromStore = installer != null && installer in Known.TRUSTED_INSTALLERS
        val sideloaded = !isSystem && !fromStore
        val perms = info.requestedPermissions?.toSet().orEmpty()

        var score = 0
        val reasons = ArrayList<String>()
        fun add(points: Int, reason: String) {
            if (points <= 0) return
            score += points
            reasons += reason
        }

        // 1) Base de firmas: nombre de paquete, certificado y huella del APK.
        var threat: ThreatDatabase.Family? = null
        fun matched(f: ThreatDatabase.Family, how: String) {
            if (threat == null || (threat!!.isMonitoringOnly && !f.isMonitoringOnly)) threat = f
            add(if (f.isMonitoringOnly) 45 else 100, "$how «${f.name}» (${f.typeLabel})")
        }
        if (!isSystem) db.byPackage(pkg)?.let { matched(it, "Coincide con la app conocida") }
        val certs = Hashing.signerCertificates(info)
        certs.firstNotNullOfOrNull { db.byCert(Hashing.certSha1(it)) }
            ?.let { matched(it, "Está firmada con el certificado de") }

        val apkFile = ai.sourceDir?.let(::File)
        var sha256: String? = null
        if (deep && !isSystem && apkFile != null) {
            sha256 = Hashing.sha256(apkFile, isCancelled = isCancelled)
            sha256?.let { db.byHash(it) }?.let { matched(it, "Su archivo es idéntico a una muestra de") }
        }

        // Las apps preinstaladas solo se reportan si coinciden con la base de firmas.
        if (isSystem && threat == null) return null

        val isAdmin = pkg in env.activeAdmins
        if (!isSystem) {
            val migrated = installer != null && installer in Known.MIGRATION_INSTALLERS
            if (sideloaded && !migrated) add(15, "Se instaló fuera de una tienda oficial (${Known.installerLabel(installer, pm)})")

            if (pkg !in env.launcherPackages) {
                add(if (sideloaded) 25 else 6, "No tiene ícono en el menú de apps (puede estar escondida)")
            }
            if (isAdmin) {
                add(if (sideloaded) 40 else 10, "Es administradora del dispositivo (así evita que la desinstales)")
            } else if (sideloaded && pkg in env.adminCapable) {
                add(8, "Puede pedir permisos de administrador del dispositivo")
            }
            if (pkg in env.accessibilityEnabled) {
                add(if (sideloaded) 35 else 8, "Tiene la Accesibilidad activada: puede ver y tocar todo en tu pantalla")
            } else if (sideloaded && pkg in env.accessibilityCapable) {
                add(10, "Puede pedir control de Accesibilidad (ver y tocar tu pantalla)")
            }
            if (pkg in env.listenersEnabled) {
                add(if (sideloaded) 15 else 3, "Puede leer todas tus notificaciones")
            }
            if (pkg in env.keyboardsEnabled) {
                add(if (sideloaded) 20 else 0, "Es un teclado activado: podría registrar lo que escribes")
            }
            if (perms.any { it in Known.SMS_PERMISSIONS } && pkg != env.defaultSms) {
                add(if (sideloaded) 20 else 4, "Puede leer o enviar SMS (se usa para robar códigos o cobrarte servicios)")
            }
            if (Known.PERM_OVERLAY in perms) {
                add(if (sideloaded) 12 else 0, "Puede mostrarse encima de otras apps (anuncios o pantallas falsas)")
            }
            if (sideloaded && Known.PERM_INSTALL in perms) add(10, "Puede instalar otras apps")
            if (sideloaded && perms.count { it in Known.SPY_PERMISSIONS } >= 6) {
                add(15, "Pide cámara, micrófono, ubicación, contactos y mensajes a la vez (patrón de app espía)")
            }

            val normLabel = ScamDetector.normalize(label)
            if (sideloaded && Known.looksLikeSystemName(normLabel)) {
                add(30, "Su nombre imita una app del sistema («$label»)")
            }
            if (sideloaded && Known.SYSTEM_LIKE_PREFIXES.any { pkg.startsWith(it) }) {
                add(30, "Su identificador ($pkg) imita a una app del sistema")
            }
            if (label.isBlank() || label == pkg || label.none { it.isLetterOrDigit() }) {
                add(if (sideloaded) 15 else 5, "No tiene un nombre visible")
            }
            if (!Known.isReputableSecurity(pkg) && Known.isCleanerName(normLabel)) {
                add(
                    if (sideloaded) 20 else 12,
                    "Las apps de «limpieza», «acelerar» o «antivirus» desconocidas suelen llenar el teléfono de anuncios y alertas falsas",
                )
            }
            if (pkg in env.spamApps) add(45, "Ha enviado notificaciones engañosas (por ejemplo, «tu teléfono tiene virus»)")
            if (sideloaded && ai.targetSdkVersion in 1..22) {
                add(10, "Está hecha para Android antiguo (así evita pedirte permisos)")
            }
            if (sideloaded && certs.any(Hashing::isDebugCertificate)) add(5, "Está firmada con un certificado de pruebas")
        }

        val severity = when {
            threat != null && !threat!!.isMonitoringOnly -> Severity.DANGER
            else -> Thresholds.severityFor(score)
        } ?: return null

        return AppFinding(
            packageName = pkg,
            label = label,
            severity = severity,
            score = score,
            reasons = reasons,
            threatName = threat?.name,
            isSystem = isSystem,
            sideloaded = sideloaded,
            installerLabel = if (isSystem) "Preinstalada" else Known.installerLabel(installer, pm),
            firstInstallTime = info.firstInstallTime,
            versionName = info.versionName,
            apkPath = ai.sourceDir,
            apkSize = apkFile?.length() ?: 0L,
            sha256 = sha256,
            isDeviceAdmin = isAdmin,
        )
    }

    private fun List<AppFinding>.sortedForDisplay() =
        sortedWith(compareBy<AppFinding> { it.severity.ordinal }.thenByDescending { it.score })

    private fun labelOf(ai: ApplicationInfo): String =
        runCatching { ai.loadLabel(pm).toString().trim() }.getOrDefault(ai.packageName)

    @Suppress("DEPRECATION")
    private fun installedPackageNames(): List<String> = runCatching {
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            pm.getInstalledPackages(0)
        }
        list.map { it.packageName }
    }.getOrDefault(emptyList())

    @Suppress("DEPRECATION")
    private fun packageInfo(pkg: String, flags: Int = DETAIL_FLAGS): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageInfo(pkg, flags)
        }
    } catch (e: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val src = pm.getInstallSourceInfo(pkg)
            src.installingPackageName ?: src.initiatingPackageName
        } else {
            pm.getInstallerPackageName(pkg)
        }
    } catch (e: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun queryActivities(intent: Intent): Set<String> = runCatching {
        val flags = PackageManager.MATCH_ALL
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
        } else {
            pm.queryIntentActivities(intent, flags)
        }
        list.mapNotNull { it.activityInfo?.packageName }.toSet()
    }.getOrDefault(emptySet())

    @Suppress("DEPRECATION")
    private fun queryServices(intent: Intent): Set<String> = runCatching {
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentServices(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            pm.queryIntentServices(intent, 0)
        }
        list.mapNotNull { it.serviceInfo?.packageName }.toSet()
    }.getOrDefault(emptySet())

    @Suppress("DEPRECATION")
    private fun queryReceivers(intent: Intent): Set<String> = runCatching {
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryBroadcastReceivers(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            pm.queryBroadcastReceivers(intent, 0)
        }
        list.mapNotNull { it.activityInfo?.packageName }.toSet()
    }.getOrDefault(emptySet())

    companion object {
        @Suppress("DEPRECATION")
        private val DETAIL_FLAGS: Int = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES or
            (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
    }
}
