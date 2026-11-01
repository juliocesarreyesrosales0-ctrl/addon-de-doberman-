package com.doberman.antivirus.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.doberman.antivirus.R
import com.doberman.antivirus.core.Prefs
import com.doberman.antivirus.core.SystemIntents

private fun Tab.icon(): ImageVector = when (this) {
    Tab.HOME -> Icons.Filled.Home
    Tab.RESULTS -> Icons.Filled.Warning
    Tab.SHIELD -> Icons.Filled.Notifications
    Tab.HELP -> Icons.Filled.Info
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(vm: MainViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val sources by vm.spamSources.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }

    // Permiso para mostrar avisos (Android 13+): se pide una sola vez.
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        vm.refreshStatus()
    }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33 && !Prefs.askedNotifications(context)) {
            Prefs.setAskedNotifications(context)
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    // Acceso a archivos para el análisis profundo.
    val storagePermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        vm.refreshStatus()
    }
    val requestStorage: () -> Unit = {
        if (Build.VERSION.SDK_INT >= 30) {
            SystemIntents.openAllFilesAccess(context)
        } else {
            storagePermission.launch(
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE),
            )
        }
    }

    // Desinstalación: Android muestra su propio diálogo de confirmación.
    val uninstallLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        vm.onUninstallFinished()
    }
    LaunchedEffect(state.pendingUninstall) {
        val pkg = state.pendingUninstall ?: return@LaunchedEffect
        vm.onUninstallLaunched()
        try {
            uninstallLauncher.launch(SystemIntents.uninstallIntent(pkg))
        } catch (e: ActivityNotFoundException) {
            SystemIntents.openAppDetails(context, pkg)
        }
    }

    LaunchedEffect(state.message) {
        val msg = state.message ?: return@LaunchedEffect
        snackbar.showSnackbar(msg, withDismissAction = true, duration = SnackbarDuration.Long)
        vm.consumeMessage()
    }

    BackHandler(enabled = state.tab != Tab.HOME) { vm.selectTab(Tab.HOME) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painterResource(R.drawable.ic_stat_shield),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(26.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("Doberman Antivirus", fontWeight = FontWeight.Bold)
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = state.tab == tab,
                        onClick = { vm.selectTab(tab) },
                        icon = {
                            val threats = state.report?.threatCount ?: 0
                            val spam = sources.count { it.isScam && !it.markedBlocked }
                            BadgedBox(
                                badge = {
                                    when {
                                        tab == Tab.RESULTS && threats > 0 -> Badge { Text("$threats") }
                                        tab == Tab.SHIELD && spam > 0 -> Badge { Text("$spam") }
                                    }
                                },
                            ) { Icon(tab.icon(), contentDescription = tab.title) }
                        },
                        label = { Text(tab.title) },
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(
            Modifier
                .padding(padding)
                .fillMaxSize(),
        ) {
            when (state.tab) {
                Tab.HOME -> HomeScreen(state, sources, vm, requestStorage)
                Tab.RESULTS -> ResultsScreen(state, vm, requestStorage)
                Tab.SHIELD -> ShieldScreen(state, sources, vm)
                Tab.HELP -> HelpScreen(state, vm)
            }
        }
    }
}
