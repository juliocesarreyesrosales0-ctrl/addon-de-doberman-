package com.doberman.antivirus.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.doberman.antivirus.core.AppFinding
import com.doberman.antivirus.core.FileFinding
import com.doberman.antivirus.core.FixAction
import com.doberman.antivirus.core.Hashing
import com.doberman.antivirus.core.ScanReport
import com.doberman.antivirus.core.SettingFinding
import com.doberman.antivirus.core.Severity
import com.doberman.antivirus.core.SystemIntents
import com.doberman.antivirus.ui.theme.DangerRed
import com.doberman.antivirus.ui.theme.SafeGreen
import com.doberman.antivirus.ui.theme.color
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

@Composable
fun ResultsScreen(state: UiState, vm: MainViewModel, requestStorage: () -> Unit) {
    val report = state.report
    if (report == null) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            ShieldBadge(MaterialTheme.colorScheme.primary, 96.dp)
            Spacer(Modifier.size(16.dp))
            Text("Todavía no hay resultados", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Haz un análisis para ver aquí las apps, archivos y ajustes peligrosos.",
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.size(16.dp))
            Button(onClick = { vm.startScan(deep = true) }) { Text("Iniciar análisis profundo") }
        }
        return
    }

    var confirmRemoveAll by remember { mutableStateOf(false) }
    var fileToDelete by remember { mutableStateOf<FileFinding?>(null) }
    val removableApps = report.apps.count { it.severity != Severity.INFO && !it.isSystem }
    val removableFiles = report.files.count { it.severity != Severity.INFO }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { SummaryCard(report, removableApps + removableFiles) { confirmRemoveAll = true } }

        if (report.apps.isNotEmpty()) {
            item { SectionTitle("Apps (${report.apps.size})") }
            items(report.apps, key = { "app:" + it.packageName }) { AppCard(it, vm) }
        }
        if (report.files.isNotEmpty()) {
            item { SectionTitle("Archivos (${report.files.size})") }
            items(report.files, key = { "file:" + it.path }) { f -> FileCard(f, vm) { fileToDelete = f } }
        }
        if (report.settings.isNotEmpty()) {
            item { SectionTitle("Ajustes del teléfono (${report.settings.size})") }
            items(report.settings, key = { "set:" + it.id }) { SettingCard(it, vm, requestStorage) }
        }
        item {
            val files = if (report.storageScanned) " y ${formatCount(report.filesScanned)} archivos" else ""
            val secs = ((report.finishedAt - report.startedAt) / 1000).coerceAtLeast(1)
            Muted(
                "Se analizaron ${formatCount(report.appsScanned)} apps$files en $secs s " +
                    "(${if (report.deep) "análisis profundo" else "análisis rápido"}, ${formatDateTime(report.finishedAt)}).",
                Modifier.padding(top = 4.dp),
            )
        }
    }

    if (confirmRemoveAll) {
        AlertDialog(
            onDismissRequest = { confirmRemoveAll = false },
            title = { Text("¿Eliminar las amenazas?") },
            text = {
                Text(
                    buildString {
                        if (removableFiles > 0) append("Se borrarán $removableFiles archivo(s) peligroso(s). ")
                        if (removableApps > 0) {
                            append(
                                "Luego Android te pedirá confirmar la desinstalación de $removableApps app(s): pulsa «Aceptar» o «Desinstalar» en cada una. ",
                            )
                        }
                        append("Lo marcado como «Revisar» no se toca.")
                    },
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        confirmRemoveAll = false
                        vm.removeAllThreats()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
                ) { Text("Eliminar") }
            },
            dismissButton = { TextButton(onClick = { confirmRemoveAll = false }) { Text("Cancelar") } },
        )
    }

    fileToDelete?.let { f ->
        AlertDialog(
            onDismissRequest = { fileToDelete = null },
            title = { Text("¿Borrar este archivo?") },
            text = { Text("«${f.name}» se borrará para siempre.") },
            confirmButton = {
                Button(
                    onClick = {
                        fileToDelete = null
                        vm.deleteFile(f)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
                ) { Text("Borrar") }
            },
            dismissButton = { TextButton(onClick = { fileToDelete = null }) { Text("Cancelar") } },
        )
    }
}

@Composable
private fun SummaryCard(report: ScanReport, removable: Int, onRemoveAll: () -> Unit) {
    val threats = report.threatCount
    val color = when {
        threats > 0 -> report.worst?.color() ?: DangerRed
        report.reviewCount > 0 -> MaterialTheme.colorScheme.primary
        else -> SafeGreen
    }
    DobermanCard(accent = color) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (threats > 0) Icons.Filled.Warning else Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(40.dp),
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    when (threats) {
                        0 -> "No se encontraron amenazas"
                        1 -> "1 amenaza encontrada"
                        else -> "$threats amenazas encontradas"
                    },
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = color,
                )
                if (report.reviewCount > 0) Text("${report.reviewCount} elemento(s) para revisar")
            }
        }
        if (removable > 0) {
            Button(
                onClick = onRemoveAll,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
            ) {
                Icon(Icons.Filled.Delete, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Eliminar todas las amenazas ($removable)")
            }
            Muted("Android no permite que ninguna app borre otras apps a escondidas: tú confirmas cada desinstalación.")
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppCard(f: AppFinding, vm: MainViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    DobermanCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppIcon(f.packageName)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(f.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Muted(f.packageName)
            }
            Spacer(Modifier.width(8.dp))
            SeverityChip(f.severity)
        }
        f.threatName?.let {
            Text("Amenaza conocida: $it", color = f.severity.color(), fontWeight = FontWeight.Bold)
        }
        f.reasons.forEach { Bullet(it) }
        Muted(
            buildString {
                append(f.installerLabel)
                if (f.firstInstallTime > 0) append(" · instalada el ${formatDate(f.firstInstallTime)}")
                f.versionName?.let { append(" · versión $it") }
                if (f.apkSize > 0) append(" · ${formatSize(f.apkSize)}")
            },
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (f.isDeviceAdmin) {
                FilledTonalButton(onClick = { SystemIntents.openDeviceAdmins(context) }) { Text("1. Quitar administrador") }
            }
            if (!f.isSystem) {
                Button(
                    onClick = { vm.uninstall(f.packageName) },
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
                ) { Text(if (f.isDeviceAdmin) "2. Desinstalar" else "Desinstalar") }
            } else {
                Button(onClick = { SystemIntents.openAppDetails(context, f.packageName) }) { Text("Desactivar") }
            }
            OutlinedButton(onClick = { SystemIntents.openAppDetails(context, f.packageName) }) { Text("Detalles") }
            TextButton(
                onClick = {
                    scope.launch {
                        val sha = f.sha256 ?: f.apkPath?.let { withContext(Dispatchers.IO) { Hashing.sha256(File(it)) } }
                        if (sha != null) SystemIntents.openUrl(context, SystemIntents.virusTotalUrl(sha))
                    }
                },
            ) { Text("VirusTotal") }
            TextButton(onClick = { vm.ignoreApp(f.packageName, f.label) }) { Text("Es de confianza") }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FileCard(f: FileFinding, vm: MainViewModel, onDelete: () -> Unit) {
    val context = LocalContext.current
    DobermanCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (f.severity == Severity.INFO) Icons.Filled.Info else Icons.Filled.Warning,
                contentDescription = null,
                tint = f.severity.color(),
                modifier = Modifier.size(36.dp),
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(f.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Muted(f.path.substringBeforeLast('/'))
            }
            Spacer(Modifier.width(8.dp))
            SeverityChip(f.severity)
        }
        f.threatName?.let {
            Text("Amenaza conocida: $it", color = f.severity.color(), fontWeight = FontWeight.Bold)
        }
        if (f.apkLabel != null || f.apkPackage != null) {
            Text("Instala: ${f.apkLabel ?: "?"} (${f.apkPackage ?: "?"})", style = MaterialTheme.typography.bodyMedium)
        }
        f.reasons.forEach { Bullet(it) }
        Muted("${formatSize(f.size)} · modificado el ${formatDate(f.lastModified)}")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onDelete, colors = ButtonDefaults.buttonColors(containerColor = DangerRed)) { Text("Borrar") }
            f.sha256?.let { sha ->
                TextButton(onClick = { SystemIntents.openUrl(context, SystemIntents.virusTotalUrl(sha)) }) { Text("VirusTotal") }
            }
            TextButton(onClick = { vm.ignoreFile(f.path) }) { Text("Ignorar") }
        }
    }
}

@Composable
private fun SettingCard(s: SettingFinding, vm: MainViewModel, requestStorage: () -> Unit) {
    val context = LocalContext.current
    DobermanCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(s.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Spacer(Modifier.width(8.dp))
            SeverityChip(s.severity)
        }
        Text(s.description, style = MaterialTheme.typography.bodyMedium)
        if (s.action != FixAction.NONE) {
            FilledTonalButton(
                onClick = {
                    when (s.action) {
                        FixAction.SCREEN_LOCK -> SystemIntents.openSecurity(context)
                        FixAction.DEVELOPER_OPTIONS -> SystemIntents.openDeveloperOptions(context)
                        FixAction.ACCESSIBILITY -> SystemIntents.openAccessibility(context)
                        FixAction.DEVICE_ADMINS -> SystemIntents.openDeviceAdmins(context)
                        FixAction.NOTIFICATION_ACCESS -> SystemIntents.start(
                            context,
                            android.content.Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS),
                        )
                        FixAction.UNKNOWN_SOURCES -> SystemIntents.openUnknownSources(context)
                        FixAction.SYSTEM_UPDATE -> SystemIntents.openSystemUpdate(context)
                        FixAction.ENABLE_SHIELD -> vm.selectTab(Tab.SHIELD)
                        FixAction.STORAGE_PERMISSION -> requestStorage()
                        FixAction.NONE -> Unit
                    }
                },
            ) { Text(s.actionLabel) }
        }
    }
}
