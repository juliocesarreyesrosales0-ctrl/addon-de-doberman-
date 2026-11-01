package com.doberman.antivirus.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.doberman.antivirus.core.SystemIntents
import com.doberman.antivirus.guard.SpamSource
import com.doberman.antivirus.ui.theme.DangerRed
import com.doberman.antivirus.ui.theme.SafeGreen
import com.doberman.antivirus.ui.theme.WarningOrange

private const val PRIVATE_DNS = "dns.adguard-dns.com"

@Composable
fun ShieldScreen(state: UiState, sources: List<SpamSource>, vm: MainViewModel) {
    val web = sources.filter { it.isWeb }.sortedWith(compareByDescending<SpamSource> { it.isScam }.thenByDescending { it.lastSeen })
    val apps = sources.filter { !it.isWeb }
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { ShieldStatus(state) }
        if (!state.shieldEnabled && Build.VERSION.SDK_INT >= 33) item { RestrictedSettingsHelp() }
        item { ShieldOptions(state, vm) }

        item { SectionTitle("Páginas web que te envían notificaciones (${web.size})") }
        if (web.isEmpty()) {
            item {
                Muted(
                    if (state.shieldEnabled) {
                        "Todavía no llegó ninguna. Cuando una página te mande una notificación aparecerá aquí con un botón para bloquearla."
                    } else {
                        "Activa el escudo para ver qué páginas te envían notificaciones."
                    },
                )
            }
        }
        items(web, key = { it.key }) { SourceCard(it, vm) }

        if (apps.isNotEmpty()) {
            item { SectionTitle("Apps con notificaciones engañosas (${apps.size})") }
            items(apps, key = { it.key }) { SourceCard(it, vm) }
        }

        item { BrowserGuide() }
        if (Build.VERSION.SDK_INT >= 28) item { PrivateDnsTip() }
        if (sources.isNotEmpty()) {
            item { TextButton(onClick = vm::clearSpamLog) { Text("Borrar historial de notificaciones") } }
        }
    }
}

@Composable
private fun ShieldStatus(state: UiState) {
    val context = LocalContext.current
    val color = if (state.shieldEnabled) SafeGreen else WarningOrange
    DobermanCard(accent = color) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ShieldBadge(color, 60.dp)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    if (state.shieldEnabled) "Escudo activo" else "Escudo apagado",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = color,
                )
                Text(
                    if (state.shieldEnabled) {
                        "Borra las alertas falsas («tienes virus», «tu batería está dañada», «limpia tu teléfono», «ganaste un premio») y te dice quién las manda."
                    } else {
                        "Las páginas web no pueden detectar virus en tu teléfono: esas alertas son anuncios engañosos. Activa el escudo para borrarlas."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        if (!state.shieldEnabled) {
            Button(onClick = { SystemIntents.openNotificationAccess(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("Activar escudo")
            }
            Muted("En la lista que se abre, busca «Doberman» y actívalo. Doberman revisa las notificaciones solo dentro de tu teléfono: no envía nada a internet.")
        }
    }
}

@Composable
private fun RestrictedSettingsHelp() {
    val context = LocalContext.current
    DobermanCard {
        Text("¿Aparece «Ajuste restringido» o el interruptor está gris?", fontWeight = FontWeight.Bold)
        Text(
            "Android bloquea este permiso en apps instaladas desde un archivo APK. Se desbloquea así:",
            style = MaterialTheme.typography.bodyMedium,
        )
        Bullet("1. Pulsa «Abrir información de Doberman».")
        Bullet("2. Toca los tres puntos ⋮ (arriba a la derecha) y elige «Permitir ajustes restringidos». Te pedirá tu PIN o huella.")
        Bullet("3. Vuelve aquí y pulsa «Activar escudo» otra vez.")
        Muted("Si no ves los tres puntos, primero intenta activar el escudo una vez (aparecerá el aviso) y luego vuelve a la información de la app.")
        FilledTonalButton(onClick = { SystemIntents.openAppDetails(context, context.packageName) }) {
            Text("Abrir información de Doberman")
        }
    }
}

@Composable
private fun ShieldOptions(state: UiState, vm: MainViewModel) {
    DobermanCard {
        SwitchRow(
            title = "Borrar automáticamente las notificaciones falsas",
            subtitle = "Si lo apagas, solo se registran para que decidas tú.",
            checked = state.autoBlock,
            onChange = vm::setAutoBlock,
        )
        SwitchRow(
            title = "Avisarme cuando detecte una",
            subtitle = "Un aviso silencioso con un acceso directo para bloquear la página.",
            checked = state.notifyBlocked,
            onChange = vm::setNotifyBlocked,
        )
    }
}

@Composable
private fun SwitchRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Muted(subtitle)
        }
        Spacer(Modifier.width(8.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SourceCard(s: SpamSource, vm: MainViewModel) {
    val context = LocalContext.current
    DobermanCard(accent = if (s.isScam && !s.markedBlocked) DangerRed else null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (s.isWeb) {
                Icon(
                    if (s.isScam) Icons.Filled.Warning else Icons.Filled.Notifications,
                    contentDescription = null,
                    tint = if (s.isScam) DangerRed else MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp),
                )
            } else {
                AppIcon(s.packageName, 36.dp)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(s.displayName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Muted(
                    (if (s.isWeb) "Vía ${s.appLabel} · " else "") +
                        "${formatCount(s.total)} notificación(es) · última ${relativeTime(s.lastSeen)}",
                )
            }
            if (s.isScam) {
                Spacer(Modifier.width(8.dp))
                Chip("Engañosa", DangerRed)
            }
        }
        val sample = listOf(s.lastTitle, s.lastText).filter { it.isNotBlank() }.joinToString(" — ")
        if (sample.isNotBlank()) {
            Text("“$sample”", style = MaterialTheme.typography.bodyMedium, fontStyle = FontStyle.Italic, maxLines = 3)
        }
        if (s.isScam && s.reasons.isNotEmpty()) Muted("Por qué: " + s.reasons.take(4).joinToString(" · "))
        if (s.removedCount > 0) Muted("Doberman borró ${formatCount(s.removedCount)} de sus notificaciones.")
        if (s.markedBlocked) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = SafeGreen, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    "Marcado como bloqueado. Si vuelve a notificar, aparecerá de nuevo aquí.",
                    style = MaterialTheme.typography.bodySmall,
                    color = SafeGreen,
                )
            }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.isWeb) {
                Button(
                    onClick = {
                        SystemIntents.openSiteNotificationSettings(context, s.packageName, s.channelId)
                        vm.markSourceBlocked(s.key)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = if (s.isScam) DangerRed else MaterialTheme.colorScheme.primary),
                ) { Text("Bloquear esta página") }
            } else {
                Button(
                    onClick = {
                        SystemIntents.openAppNotificationSettings(context, s.packageName)
                        vm.markSourceBlocked(s.key)
                    },
                ) { Text("Silenciar app") }
                if (!isSystemApp(context, s.packageName)) {
                    Button(
                        onClick = { vm.uninstall(s.packageName) },
                        colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
                    ) { Text("Desinstalar") }
                }
            }
            TextButton(onClick = { vm.removeSource(s.key) }) { Text("Quitar de la lista") }
        }
        if (s.isWeb) {
            Muted(
                when {
                    s.channelId?.startsWith("web:") == true ->
                        "Se abrirá el ajuste de notificaciones de esta página: apaga el interruptor."
                    s.host == null ->
                        "${s.appLabel} no dice qué página fue. Se abrirán sus notificaciones; usa también la guía de abajo para quitar el permiso a las páginas que no conozcas."
                    else ->
                        "Se abrirán las notificaciones de ${s.appLabel}: busca «${s.host}» y desactívala, o sigue la guía de abajo."
                },
            )
        }
    }
}

@Composable
private fun BrowserGuide() {
    val context = LocalContext.current
    val chromeInstalled = remember(context) { isInstalled(context, "com.android.chrome") }
    ExpandableCard("Guía: quitar el permiso de notificaciones a las páginas web") {
        Text(
            "El método más rápido: cuando llegue una notificación falsa, mantenla presionada, toca ⚙ o «Desactivar notificaciones» y apaga esa página.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text("Chrome", fontWeight = FontWeight.Bold)
        Bullet("⋮ → Configuración → Configuración de sitios → Notificaciones. Toca cada página que no reconozcas y elige «Bloquear» o «Restablecer permisos».")
        Bullet("Para que ninguna página vuelva a pedirlo, apaga «Notificaciones» en esa misma pantalla.")
        Text("Samsung Internet", fontWeight = FontWeight.Bold)
        Bullet("Menú ☰ → Configuración → Sitios y descargas (o Privacidad) → Notificaciones → elimina las páginas de la lista.")
        Text("Firefox", fontWeight = FontWeight.Bold)
        Bullet("⋮ → Configuración → Permisos de sitios → Notificaciones → «Bloqueado». En «Excepciones» borra las páginas.")
        Text("Opera, Edge, Brave y otros", fontWeight = FontWeight.Bold)
        Bullet("Configuración → Configuración de sitios (o Permisos del sitio) → Notificaciones.")
        Text("Navegador de Xiaomi, Huawei u OPPO", fontWeight = FontWeight.Bold)
        Bullet("Configuración → Privacidad y seguridad / Avanzado → Notificaciones de sitios web.")
        if (chromeInstalled) {
            OutlinedButton(onClick = { SystemIntents.openAppNotificationSettings(context, "com.android.chrome") }) {
                Text("Abrir notificaciones de Chrome")
            }
            Muted("En la sección «Sitios» verás cada página que tiene permiso: apaga las que no conozcas.")
        }
    }
}

@Composable
private fun PrivateDnsTip() {
    val context = LocalContext.current
    ExpandableCard("Extra: bloquear páginas engañosas y anuncios en todo el teléfono") {
        Text(
            "Activa un «DNS privado» que bloquea anuncios y páginas engañosas antes de que se abran, en todas las apps:",
            style = MaterialTheme.typography.bodyMedium,
        )
        Bullet("Ajustes → Conexiones / Red e Internet → DNS privado (a veces en «Más ajustes de conexión»).")
        Bullet("Elige «Nombre de host del proveedor» y escribe: $PRIVATE_DNS")
        Muted("Es el servicio gratuito AdGuard DNS. Si alguna página deja de cargar, vuelve a ponerlo en «Automático».")
        Row {
            FilledTonalButton(onClick = { copy(context, PRIVATE_DNS) }) { Text("Copiar dirección") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { SystemIntents.openNetworkSettings(context) }) { Text("Abrir ajustes") }
        }
    }
}

private fun isSystemApp(context: Context, pkg: String): Boolean = runCatching {
    (context.packageManager.getApplicationInfo(pkg, 0).flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
}.getOrDefault(false)

private fun isInstalled(context: Context, pkg: String): Boolean =
    runCatching { context.packageManager.getPackageInfo(pkg, 0) }.isSuccess

private fun copy(context: Context, text: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText("DNS", text))
    Toast.makeText(context, "Copiado: $text", Toast.LENGTH_SHORT).show()
}
