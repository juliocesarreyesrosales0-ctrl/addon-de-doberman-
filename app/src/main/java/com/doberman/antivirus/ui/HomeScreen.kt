package com.doberman.antivirus.ui

import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.doberman.antivirus.core.SystemIntents
import com.doberman.antivirus.guard.SpamSource
import com.doberman.antivirus.ui.theme.DangerRed
import com.doberman.antivirus.ui.theme.SafeGreen
import com.doberman.antivirus.ui.theme.WarningOrange

@Composable
fun HomeScreen(state: UiState, sources: List<SpamSource>, vm: MainViewModel, requestStorage: () -> Unit) {
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { StatusCard(state, vm) }
        if (!state.scanning) item { ScanButtons(state, vm, requestStorage) }
        item { ShieldSummaryCard(state, sources, vm) }
        if (!state.notificationsAllowed) item { NotificationsPermissionCard() }
        item { DatabaseCard(state, vm) }
        item { ToolsCard(vm) }
    }
}

@Composable
private fun StatusCard(state: UiState, vm: MainViewModel) {
    val progress = state.progress
    if (state.scanning && progress != null) {
        DobermanCard {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(contentAlignment = Alignment.Center) {
                    val fraction = progress.fraction
                    if (fraction != null) {
                        CircularProgressIndicator(progress = { fraction }, modifier = Modifier.size(120.dp), strokeWidth = 8.dp)
                    } else {
                        CircularProgressIndicator(modifier = Modifier.size(120.dp), strokeWidth = 8.dp)
                    }
                    ShieldBadge(MaterialTheme.colorScheme.primary, size = 80.dp)
                }
                Spacer(Modifier.height(12.dp))
                Text(progress.phase, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                val counter = when {
                    progress.total > 0 -> "${formatCount(progress.done)} de ${formatCount(progress.total)}"
                    progress.done > 0 -> "${formatCount(progress.done)} archivos revisados"
                    else -> ""
                }
                if (counter.isNotEmpty()) Text(counter, style = MaterialTheme.typography.bodyMedium)
                if (progress.detail.isNotEmpty()) {
                    Text(
                        progress.detail.substringAfter("/emulated/0/"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                    )
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = vm::cancelScan) { Text("Cancelar") }
            }
        }
        return
    }

    val report = state.report
    val threats = report?.threatCount ?: state.lastScanThreats
    val scannedBefore = report != null || state.lastScanTime > 0
    val (color, title, body) = when {
        !scannedBefore -> Triple(
            MaterialTheme.colorScheme.primary,
            "Analiza tu teléfono",
            "Toca «Análisis profundo» para revisar todas tus apps, tus archivos y los ajustes de seguridad.",
        )
        threats > 0 -> Triple(
            DangerRed,
            if (threats == 1) "Se encontró 1 amenaza" else "Se encontraron $threats amenazas",
            if (report != null) "Revísalas y elimínalas desde la pestaña «Amenazas»." else "Vuelve a analizar para ver el detalle.",
        )
        report != null && report.reviewCount > 0 -> Triple(
            WarningOrange,
            "Sin amenazas graves",
            "Hay ${report.reviewCount} cosa(s) que conviene revisar.",
        )
        else -> Triple(
            SafeGreen,
            "No se encontraron amenazas",
            "Último análisis: ${formatDateTime(report?.finishedAt ?: state.lastScanTime)}.",
        )
    }
    DobermanCard(accent = color) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ShieldBadge(color)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = color)
                Text(body, style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (report != null && (report.threatCount > 0 || report.reviewCount > 0)) {
            Button(onClick = { vm.selectTab(Tab.RESULTS) }, modifier = Modifier.fillMaxWidth()) {
                Text(if (report.threatCount > 0) "Ver y eliminar" else "Ver detalles")
            }
        }
    }
}

@Composable
private fun ScanButtons(state: UiState, vm: MainViewModel, requestStorage: () -> Unit) {
    DobermanCard {
        Button(onClick = { vm.startScan(deep = true) }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Search, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Análisis profundo (recomendado)")
        }
        Muted("Revisa cada app con su huella digital y firma, todos tus archivos (Descargas, WhatsApp, tarjeta SD) y los ajustes de seguridad. Puede tardar unos minutos.")
        if (!state.storageAccess) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Lock, contentDescription = null, tint = WarningOrange, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    "Para revisar tus archivos, Doberman necesita acceso a ellos.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = requestStorage) { Text("Dar acceso") }
            }
        }
        OutlinedButton(onClick = { vm.startScan(deep = false) }, modifier = Modifier.fillMaxWidth()) {
            Text("Análisis rápido (solo apps y ajustes)")
        }
    }
}

@Composable
private fun ShieldSummaryCard(state: UiState, sources: List<SpamSource>, vm: MainViewModel) {
    val context = LocalContext.current
    val scamSites = sources.count { it.isScam }
    when {
        state.shieldEnabled -> DobermanCard(accent = SafeGreen) {
            Text("Escudo anti-notificaciones: ACTIVO", fontWeight = FontWeight.Bold, color = SafeGreen)
            Text(
                if (state.blockedTotal > 0) {
                    "Ha detectado ${formatCount(state.blockedTotal)} notificación(es) falsa(s) de $scamSites origen(es)."
                } else {
                    "Vigilando. Si una página te manda alertas falsas de «virus» o «limpia tu teléfono», se borrarán solas."
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            if (!state.shieldConnected) {
                Muted("Android pausó el escudo. Si no reacciona, desactívalo y vuelve a activarlo en el acceso a notificaciones.")
            }
            FilledTonalButton(onClick = { vm.selectTab(Tab.SHIELD) }) { Text("Ver páginas y apps detectadas") }
        }
        else -> DobermanCard(accent = WarningOrange) {
            Text("Escudo anti-notificaciones: APAGADO", fontWeight = FontWeight.Bold, color = WarningOrange)
            Text(
                "Actívalo para borrar automáticamente las notificaciones falsas («tu teléfono tiene virus», «limpia tu teléfono») y descubrir qué página las envía.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = { SystemIntents.openNotificationAccess(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("Activar escudo")
            }
            if (Build.VERSION.SDK_INT >= 33) {
                TextButton(onClick = { vm.selectTab(Tab.SHIELD) }) { Text("¿Dice «Ajuste restringido»? Ver solución") }
            }
        }
    }
}

@Composable
private fun NotificationsPermissionCard() {
    val context = LocalContext.current
    DobermanCard {
        Text("Permite que Doberman te avise", fontWeight = FontWeight.Bold)
        Text(
            "Así te avisará al instante si se instala una app peligrosa.",
            style = MaterialTheme.typography.bodyMedium,
        )
        FilledTonalButton(onClick = { SystemIntents.openAppNotificationSettings(context, context.packageName) }) {
            Text("Permitir avisos")
        }
    }
}

@Composable
private fun DatabaseCard(state: UiState, vm: MainViewModel) {
    val db = state.db
    DobermanCard {
        Text("Base de firmas de malware", fontWeight = FontWeight.Bold)
        if (db != null) {
            Text(
                "${formatCount(db.packages)} apps espía y malware · ${formatCount(db.certs)} certificados · " +
                    "${formatCount(db.hashes)} huellas de archivos maliciosos",
                style = MaterialTheme.typography.bodyMedium,
            )
            Muted("Versión ${db.version}. Fuentes: Echap Stalkerware Indicators (CC BY 4.0) y MVT / Amnesty Tech (MIT).")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            FilledTonalButton(onClick = { vm.updateDb() }, enabled = !state.dbUpdating) {
                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(if (state.dbUpdating) "Actualizando…" else "Actualizar firmas")
            }
            if (state.dbUpdating) {
                Spacer(Modifier.width(12.dp))
                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 3.dp)
            }
        }
    }
}

@Composable
private fun ToolsCard(vm: MainViewModel) {
    val context = LocalContext.current
    DobermanCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Build, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(8.dp))
            Text("Herramientas de seguridad", fontWeight = FontWeight.Bold)
        }
        ToolButton("Analizar también con Google Play Protect") { SystemIntents.openPlayProtect(context) }
        ToolButton("Apps administradoras del dispositivo") { SystemIntents.openDeviceAdmins(context) }
        ToolButton("Apps que controlan la pantalla (Accesibilidad)") { SystemIntents.openAccessibility(context) }
        ToolButton("Apps que pueden instalar otras apps") { SystemIntents.openUnknownSources(context) }
        ToolButton("Apps que leen tus notificaciones") {
            SystemIntents.start(context, Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
        ToolButton("Volver a revisar lo que marqué como «de confianza»") { vm.resetIgnored() }
    }
}

@Composable
private fun ToolButton(text: String, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Text(text, textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}
