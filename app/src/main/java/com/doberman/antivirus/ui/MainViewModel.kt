package com.doberman.antivirus.ui

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.doberman.antivirus.core.AppScanner
import com.doberman.antivirus.core.FileFinding
import com.doberman.antivirus.core.FileScanner
import com.doberman.antivirus.core.Prefs
import com.doberman.antivirus.core.ScanProgress
import com.doberman.antivirus.core.ScanReport
import com.doberman.antivirus.core.Severity
import com.doberman.antivirus.core.SystemChecker
import com.doberman.antivirus.core.ThreatDatabase
import com.doberman.antivirus.core.ThreatDbUpdater
import com.doberman.antivirus.guard.NotificationGuardService
import com.doberman.antivirus.guard.Notifier
import com.doberman.antivirus.guard.SpamRepository
import com.doberman.antivirus.guard.SpamSource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

enum class Tab(val id: String, val title: String) {
    HOME("home", "Inicio"),
    RESULTS("results", "Amenazas"),
    SHIELD("shield", "Notificaciones"),
    HELP("help", "Ayuda"),
}

data class DbInfo(val version: String, val packages: Int, val certs: Int, val hashes: Int)

data class UiState(
    val tab: Tab = Tab.HOME,
    val scanning: Boolean = false,
    val scanDeep: Boolean = false,
    val progress: ScanProgress? = null,
    val report: ScanReport? = null,
    val shieldEnabled: Boolean = false,
    val shieldConnected: Boolean = false,
    val storageAccess: Boolean = false,
    val notificationsAllowed: Boolean = true,
    val autoBlock: Boolean = true,
    val notifyBlocked: Boolean = true,
    val blockedTotal: Int = 0,
    val db: DbInfo? = null,
    val dbUpdating: Boolean = false,
    val lastScanTime: Long = 0L,
    val lastScanThreats: Int = 0,
    val uninstallQueue: List<String> = emptyList(),
    val pendingUninstall: String? = null,
    val message: String? = null,
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val ctx: Application get() = getApplication()
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()
    val spamSources: StateFlow<List<SpamSource>> = SpamRepository.sources
    private var scanJob: Job? = null

    init {
        refreshStatus()
        viewModelScope.launch(Dispatchers.IO) {
            loadDbInfo()
            maybeAutoUpdateDb()
        }
        viewModelScope.launch {
            NotificationGuardService.connected.collect { c -> _state.update { it.copy(shieldConnected = c) } }
        }
    }

    fun openTab(id: String) {
        Tab.entries.firstOrNull { it.id == id }?.let { t -> _state.update { it.copy(tab = t) } }
    }

    fun selectTab(tab: Tab) = _state.update { it.copy(tab = tab) }

    fun consumeMessage() = _state.update { it.copy(message = null) }

    private fun say(msg: String) = _state.update { it.copy(message = msg) }

    fun refreshStatus() {
        _state.update {
            it.copy(
                shieldEnabled = NotificationGuardService.isEnabled(ctx),
                storageAccess = FileScanner.hasStorageAccess(ctx),
                notificationsAllowed = Notifier.canNotify(ctx),
                autoBlock = Prefs.autoBlock(ctx),
                notifyBlocked = Prefs.notifyBlocked(ctx),
                blockedTotal = Prefs.blockedTotal(ctx),
                lastScanTime = Prefs.lastScanTime(ctx),
                lastScanThreats = Prefs.lastScanThreats(ctx),
            )
        }
        NotificationGuardService.requestRebindIfNeeded(ctx)
        viewModelScope.launch(Dispatchers.IO) { pruneReport() }
    }

    /** Quita del informe las apps desinstaladas y los archivos borrados. */
    private fun pruneReport() {
        val report = _state.value.report ?: return
        val scanner = AppScanner(ctx)
        val apps = report.apps.filter { scanner.isInstalled(it.packageName) }
        val files = report.files.filter { File(it.path).exists() }
        if (apps.size != report.apps.size || files.size != report.files.size) {
            val pruned = report.copy(apps = apps, files = files)
            _state.update { it.copy(report = pruned, lastScanThreats = pruned.threatCount) }
            Prefs.saveLastScan(ctx, report.finishedAt, pruned.threatCount, report.deep)
        }
    }

    // ---------------------------------------------------------------- Análisis

    fun startScan(deep: Boolean) {
        if (scanJob?.isActive == true) return
        _state.update {
            it.copy(scanning = true, scanDeep = deep, progress = ScanProgress("Preparando", "", 0, 0), tab = Tab.HOME)
        }
        scanJob = viewModelScope.launch(Dispatchers.Default) {
            val started = System.currentTimeMillis()
            var lastEmit = 0L
            fun emit(p: ScanProgress, force: Boolean = false) {
                val now = SystemClock.uptimeMillis()
                if (force || now - lastEmit > 80) {
                    lastEmit = now
                    _state.update { it.copy(progress = p) }
                }
            }
            try {
                val db = ThreatDatabase.get(ctx)
                val scanner = AppScanner(ctx, db)
                val env = scanner.gatherEnvironment(SpamRepository.scamAppPackages(ctx), Prefs.ignoredApps(ctx))
                val phase = if (deep) "Analizando apps a fondo" else "Analizando apps"
                val (apps, appCount) = scanner.scanAll(
                    deep = deep,
                    env = env,
                    onProgress = { done, total, label -> emit(ScanProgress(phase, label, done, total)) },
                    isCancelled = { !isActive },
                )
                ensureActive()

                val storage = FileScanner.hasStorageAccess(ctx)
                var files: List<FileFinding> = emptyList()
                var fileCount = 0
                if (deep && storage) {
                    emit(ScanProgress("Analizando archivos", "", 0, 0), force = true)
                    val result = FileScanner(ctx, db).scan(
                        ignored = Prefs.ignoredFiles(ctx),
                        onProgress = { n, path -> emit(ScanProgress("Analizando archivos", path, n, 0)) },
                        isCancelled = { !isActive },
                    )
                    files = result.first
                    fileCount = result.second
                }
                ensureActive()

                emit(ScanProgress("Revisando ajustes del teléfono", "", 0, 0), force = true)
                val settings = SystemChecker(ctx).check(
                    env = env,
                    apps = apps,
                    shieldEnabled = NotificationGuardService.isEnabled(ctx),
                    storageAccess = storage,
                    deep = deep,
                )
                val report = ScanReport(
                    deep = deep,
                    startedAt = started,
                    finishedAt = System.currentTimeMillis(),
                    appsScanned = appCount,
                    filesScanned = fileCount,
                    storageScanned = deep && storage,
                    apps = apps,
                    files = files,
                    settings = settings,
                )
                Prefs.saveLastScan(ctx, report.finishedAt, report.threatCount, deep)
                _state.update {
                    it.copy(
                        scanning = false,
                        progress = null,
                        report = report,
                        tab = Tab.RESULTS,
                        lastScanTime = report.finishedAt,
                        lastScanThreats = report.threatCount,
                    )
                }
            } catch (e: CancellationException) {
                _state.update { it.copy(scanning = false, progress = null, message = "Análisis cancelado") }
                throw e
            } catch (e: Exception) {
                _state.update {
                    it.copy(scanning = false, progress = null, message = "Error durante el análisis: ${e.message}")
                }
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
    }

    // ---------------------------------------------------------------- Eliminar

    /** Borra los archivos peligrosos y desinstala, una por una, las apps peligrosas o sospechosas. */
    fun removeAllThreats() {
        val report = _state.value.report ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val files = report.files.filter { it.severity != Severity.INFO }
            val deleted = files.count { runCatching { File(it.path).delete() }.getOrDefault(false) }
            val apps = report.apps.filter { it.severity != Severity.INFO && !it.isSystem }
                .sortedBy { it.isDeviceAdmin } // las administradoras al final (requieren un paso extra)
                .map { it.packageName }
            pruneReport()
            val fileMsg = when {
                files.isEmpty() -> null
                deleted == files.size -> "Se borraron $deleted archivo(s) peligroso(s)."
                else -> "Se borraron $deleted de ${files.size} archivos. Para los demás da «Acceso a todos los archivos»."
            }
            _state.update {
                it.copy(
                    uninstallQueue = apps,
                    pendingUninstall = apps.firstOrNull(),
                    message = fileMsg ?: if (apps.isEmpty()) "No hay amenazas que eliminar." else null,
                )
            }
        }
    }

    fun uninstall(pkg: String) = _state.update { it.copy(uninstallQueue = listOf(pkg), pendingUninstall = pkg) }

    /** La pantalla ya lanzó el diálogo del sistema para [pkg]. */
    fun onUninstallLaunched() = _state.update { it.copy(pendingUninstall = null) }

    /** Se cerró el diálogo de desinstalación: comprobar y seguir con la siguiente. */
    fun onUninstallFinished() {
        viewModelScope.launch(Dispatchers.IO) {
            val queue = _state.value.uninstallQueue
            val current = queue.firstOrNull() ?: return@launch
            val finding = _state.value.report?.apps?.firstOrNull { it.packageName == current }
            val name = finding?.label ?: current
            val scanner = AppScanner(ctx)
            var removed = false
            for (i in 0 until 10) {
                if (!scanner.isInstalled(current)) {
                    removed = true
                    break
                }
                delay(400)
            }
            pruneReport()
            if (!removed) {
                val msg = if (finding?.isDeviceAdmin == true) {
                    "«$name» es administradora del dispositivo. Pulsa «Quitar administrador», desactívala y vuelve a intentarlo."
                } else {
                    "No se desinstaló «$name»."
                }
                _state.update { it.copy(uninstallQueue = emptyList(), pendingUninstall = null, message = msg) }
                return@launch
            }
            val rest = queue.drop(1)
            _state.update {
                it.copy(
                    uninstallQueue = rest,
                    pendingUninstall = rest.firstOrNull(),
                    message = if (rest.isEmpty()) "«$name» se eliminó correctamente." else null,
                )
            }
        }
    }

    fun deleteFile(f: FileFinding) {
        viewModelScope.launch(Dispatchers.IO) {
            val ok = runCatching { File(f.path).delete() }.getOrDefault(false)
            pruneReport()
            say(if (ok) "Se borró «${f.name}»." else "No se pudo borrar «${f.name}». Da «Acceso a todos los archivos» e inténtalo de nuevo.")
        }
    }

    fun ignoreApp(pkg: String, label: String) {
        Prefs.ignoreApp(ctx, pkg)
        _state.update { s ->
            val r = s.report ?: return@update s
            val pruned = r.copy(apps = r.apps.filterNot { it.packageName == pkg })
            s.copy(report = pruned, lastScanThreats = pruned.threatCount, message = "No volveremos a marcar «$label».")
        }
    }

    fun ignoreFile(path: String) {
        Prefs.ignoreFile(ctx, path)
        _state.update { s ->
            val r = s.report ?: return@update s
            val pruned = r.copy(files = r.files.filterNot { it.path == path })
            s.copy(report = pruned, lastScanThreats = pruned.threatCount, message = "No volveremos a marcar ese archivo.")
        }
    }

    fun resetIgnored() {
        Prefs.clearIgnored(ctx)
        say("Se restableció la lista de elementos de confianza. Vuelve a analizar.")
    }

    // ---------------------------------------------------------------- Escudo

    fun setAutoBlock(v: Boolean) {
        Prefs.setAutoBlock(ctx, v)
        _state.update { it.copy(autoBlock = v) }
    }

    fun setNotifyBlocked(v: Boolean) {
        Prefs.setNotifyBlocked(ctx, v)
        _state.update { it.copy(notifyBlocked = v) }
    }

    fun markSourceBlocked(key: String) = SpamRepository.markBlocked(ctx, key)

    fun removeSource(key: String) = SpamRepository.remove(ctx, key)

    fun clearSpamLog() {
        SpamRepository.clear(ctx)
        say("Se borró el historial de notificaciones.")
    }

    // ---------------------------------------------------------------- Base de firmas

    private fun loadDbInfo() {
        val db = ThreatDatabase.get(ctx)
        _state.update { it.copy(db = DbInfo(db.version, db.packageCount, db.certCount, db.hashCount)) }
    }

    private fun maybeAutoUpdateDb() {
        val week = 7L * 24 * 60 * 60 * 1000
        if (System.currentTimeMillis() - Prefs.lastDbCheck(ctx) > week && ThreatDbUpdater.isOnUnmeteredNetwork(ctx)) {
            updateDb(silent = true)
        }
    }

    fun updateDb(silent: Boolean = false) {
        if (_state.value.dbUpdating) return
        _state.update { it.copy(dbUpdating = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val result = ThreatDbUpdater.update(ctx)
            Prefs.setLastDbCheck(ctx, System.currentTimeMillis())
            loadDbInfo()
            val msg = when (result) {
                is ThreatDbUpdater.Result.Updated ->
                    if (result.added > 0) "Base actualizada: ${result.added} firmas nuevas." else "La base de firmas ya estaba al día."
                is ThreatDbUpdater.Result.Failed -> result.message
            }
            _state.update { it.copy(dbUpdating = false, message = if (silent) it.message else msg) }
        }
    }
}
