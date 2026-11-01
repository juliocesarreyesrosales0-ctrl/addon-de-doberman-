package com.doberman.antivirus.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.doberman.antivirus.core.Severity

private val LightColors = lightColorScheme(
    primary = Color(0xFFB45309),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFFE6C7),
    onPrimaryContainer = Color(0xFF3E1C00),
    secondary = Color(0xFF334155),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE2E8F0),
    onSecondaryContainer = Color(0xFF0F172A),
    tertiary = Color(0xFF0F766E),
    onTertiary = Color.White,
    background = Color(0xFFF6F7FB),
    onBackground = Color(0xFF111827),
    surface = Color(0xFFF6F7FB),
    onSurface = Color(0xFF111827),
    surfaceVariant = Color(0xFFE9ECF2),
    onSurfaceVariant = Color(0xFF4B5563),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFFCFCFE),
    surfaceContainer = Color.White,
    surfaceContainerHigh = Color.White,
    surfaceContainerHighest = Color.White,
    surfaceBright = Color.White,
    surfaceDim = Color(0xFFDCDFE6),
    error = Color(0xFFDC2626),
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
    outline = Color(0xFFCBD5E1),
    outlineVariant = Color(0xFFE2E8F0),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFF59E0B),
    onPrimary = Color(0xFF261300),
    primaryContainer = Color(0xFF5C3300),
    onPrimaryContainer = Color(0xFFFFDDB3),
    secondary = Color(0xFF94A3B8),
    onSecondary = Color(0xFF0F172A),
    secondaryContainer = Color(0xFF1E293B),
    onSecondaryContainer = Color(0xFFE2E8F0),
    tertiary = Color(0xFF2DD4BF),
    onTertiary = Color(0xFF042F2E),
    background = Color(0xFF0B1220),
    onBackground = Color(0xFFE5E7EB),
    surface = Color(0xFF0B1220),
    onSurface = Color(0xFFE5E7EB),
    surfaceVariant = Color(0xFF1C2740),
    onSurfaceVariant = Color(0xFFA7B0C0),
    surfaceContainerLowest = Color(0xFF070C16),
    surfaceContainerLow = Color(0xFF0F1729),
    surfaceContainer = Color(0xFF131C30),
    surfaceContainerHigh = Color(0xFF172036),
    surfaceContainerHighest = Color(0xFF1C263D),
    surfaceBright = Color(0xFF2A354C),
    surfaceDim = Color(0xFF0B1220),
    error = Color(0xFFF87171),
    onError = Color(0xFF450A0A),
    errorContainer = Color(0xFF7F1D1D),
    onErrorContainer = Color(0xFFFEE2E2),
    outline = Color(0xFF334155),
    outlineVariant = Color(0xFF1E293B),
)

val SafeGreen = Color(0xFF16A34A)
val DangerRed = Color(0xFFDC2626)
val WarningOrange = Color(0xFFEA580C)
val InfoBlue = Color(0xFF2563EB)

fun Severity.color(): Color = when (this) {
    Severity.DANGER -> DangerRed
    Severity.WARNING -> WarningOrange
    Severity.INFO -> InfoBlue
}

@Composable
fun DobermanTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
