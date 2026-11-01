package com.doberman.antivirus

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.doberman.antivirus.ui.AppRoot
import com.doberman.antivirus.ui.MainViewModel
import com.doberman.antivirus.ui.theme.DobermanTheme

class MainActivity : ComponentActivity() {

    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) handleIntent(intent)
        setContent {
            DobermanTheme {
                AppRoot(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        vm.refreshStatus()
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        intent.getStringExtra(EXTRA_TAB)?.let(vm::openTab)
        if (intent.getBooleanExtra(EXTRA_SCAN, false)) vm.startScan(deep = false)
        intent.removeExtra(EXTRA_TAB)
        intent.removeExtra(EXTRA_SCAN)
    }

    companion object {
        const val EXTRA_TAB = "tab"
        const val EXTRA_SCAN = "scan"
        const val TAB_HOME = "home"
        const val TAB_RESULTS = "results"
        const val TAB_SHIELD = "shield"
        const val TAB_HELP = "help"
    }
}
