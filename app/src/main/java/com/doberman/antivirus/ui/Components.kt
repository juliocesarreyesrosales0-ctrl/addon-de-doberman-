package com.doberman.antivirus.ui

import android.content.Context
import android.text.format.DateUtils
import android.util.LruCache
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.doberman.antivirus.R
import com.doberman.antivirus.core.Severity
import com.doberman.antivirus.ui.theme.color
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date
import java.util.Locale

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        modifier = modifier.padding(top = 8.dp, bottom = 2.dp),
    )
}

@Composable
fun DobermanCard(
    modifier: Modifier = Modifier,
    accent: Color? = null,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = accent?.copy(alpha = 0.10f) ?: MaterialTheme.colorScheme.surfaceContainer,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = if (accent == null) 1.dp else 0.dp),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { content() }
    }
}

@Composable
fun SeverityChip(severity: Severity) {
    val c = severity.color()
    Surface(color = c.copy(alpha = 0.15f), shape = RoundedCornerShape(50)) {
        Text(
            severity.label,
            color = c,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}

@Composable
fun Chip(text: String, color: Color) {
    Surface(color = color.copy(alpha = 0.15f), shape = RoundedCornerShape(50)) {
        Text(
            text,
            color = color,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}

@Composable
fun Bullet(text: String, color: Color = MaterialTheme.colorScheme.onSurface) {
    Row(verticalAlignment = Alignment.Top) {
        Text("•", color = color, modifier = Modifier.width(16.dp), style = MaterialTheme.typography.bodyMedium)
        Text(text, color = color, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
fun Muted(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = modifier)
}

/** Insignia circular con el escudo de Doberman. */
@Composable
fun ShieldBadge(color: Color, size: Dp = 72.dp) {
    Box(
        Modifier
            .size(size)
            .clip(CircleShape)
            .background(color.copy(alpha = 0.15f)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painterResource(R.drawable.ic_stat_shield),
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(size * 0.62f),
        )
    }
}

/** Tarjeta que se expande al tocar el título (para guías largas). */
@Composable
fun ExpandableCard(title: String, initiallyExpanded: Boolean = false, content: @Composable () -> Unit) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    DobermanCard {
        Row(
            Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f),
            )
            Icon(if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown, contentDescription = null)
        }
        AnimatedVisibility(expanded) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) { content() }
        }
    }
}

@Composable
fun AppIcon(packageName: String, size: Dp = 44.dp) {
    val context = LocalContext.current
    val bitmap by produceState(initialValue = IconCache.peek(packageName), packageName) {
        if (value == null) value = withContext(Dispatchers.IO) { IconCache.load(context, packageName) }
    }
    val b = bitmap
    if (b != null) {
        Image(b, contentDescription = null, modifier = Modifier.size(size))
    } else {
        Box(
            Modifier
                .size(size)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        )
    }
}

object IconCache {
    private val cache = LruCache<String, ImageBitmap>(80)
    fun peek(pkg: String): ImageBitmap? = cache.get(pkg)
    fun load(context: Context, pkg: String): ImageBitmap? = runCatching {
        context.packageManager.getApplicationIcon(pkg).toBitmap(128, 128).asImageBitmap()
    }.getOrNull()?.also { cache.put(pkg, it) }
}

@Composable
fun VSpace(h: Dp) = Spacer(Modifier.size(h))

private val spanish: Locale = Locale.forLanguageTag("es")

fun formatSize(bytes: Long): String = when {
    bytes >= 1L shl 30 -> String.format(spanish, "%.1f GB", bytes / 1073741824.0)
    bytes >= 1L shl 20 -> String.format(spanish, "%.1f MB", bytes / 1048576.0)
    bytes >= 1L shl 10 -> String.format(spanish, "%d KB", bytes / 1024)
    else -> "$bytes B"
}

fun formatDate(ms: Long): String =
    if (ms <= 0) "fecha desconocida" else DateFormat.getDateInstance(DateFormat.MEDIUM, spanish).format(Date(ms))

fun formatDateTime(ms: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, spanish).format(Date(ms))

fun relativeTime(ms: Long): String =
    DateUtils.getRelativeTimeSpanString(ms, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString()

fun formatCount(n: Int): String = String.format(spanish, "%,d", n)
