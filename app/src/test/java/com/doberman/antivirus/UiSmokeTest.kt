package com.doberman.antivirus

import android.app.Application
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.doberman.antivirus.core.Prefs
import com.doberman.antivirus.ui.AppRoot
import com.doberman.antivirus.ui.MainViewModel
import com.doberman.antivirus.ui.Tab
import com.doberman.antivirus.ui.theme.DobermanTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UiSmokeTest {

    @get:Rule
    val compose = createComposeRule()

    private val app: Application = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        // Sin descargas ni diálogos de permisos durante la prueba.
        Prefs.setLastDbCheck(app, System.currentTimeMillis())
        Prefs.setAskedNotifications(app)
    }

    @Test
    fun navigatesAllTabsAndQuickScanFindsTheFakeSpyApp() {
        installFakeApp(app, "com.example.update", "System Update", SPY_PERMISSIONS, launcher = false)
        installFakeApp(app, "com.whatsapp", "WhatsApp", installer = "com.android.vending")
        val vm = MainViewModel(app)
        compose.setContent { DobermanTheme { AppRoot(vm) } }

        compose.onNodeWithText("Análisis profundo (recomendado)").assertIsDisplayed()
        compose.onNodeWithText("Analiza tu teléfono").assertIsDisplayed()

        compose.onNodeWithText("Notificaciones").performClick()
        compose.onNodeWithText("Escudo apagado").assertIsDisplayed()

        compose.onNodeWithText("Ayuda").performClick()
        compose.onNodeWithText("¿Qué hace Doberman?").assertIsDisplayed()

        compose.onNodeWithText("Amenazas").performClick()
        compose.onNodeWithText("Todavía no hay resultados").assertIsDisplayed()

        compose.onNodeWithText("Inicio").performClick()
        compose.onNodeWithText("Análisis rápido (solo apps y ajustes)").performClick()
        compose.waitUntil(timeoutMillis = 30_000) { vm.state.value.report != null }
        compose.waitForIdle()

        val report = vm.state.value.report
        assertNotNull(report)
        assertEquals(Tab.RESULTS, vm.state.value.tab)
        assertEquals("com.example.update", report!!.apps.first().packageName)
        assertFalse(report.apps.any { it.packageName == "com.whatsapp" })
        compose.onNodeWithText("System Update").assertIsDisplayed()
        compose.onNodeWithText("Eliminar todas las amenazas (1)").assertIsDisplayed()
        compose.onNodeWithText("1 amenaza encontrada").assertIsDisplayed()
    }

    @Test
    fun deepScanWithoutStorageAccessExplainsWhatIsMissing() {
        val vm = MainViewModel(app)
        compose.setContent { DobermanTheme { AppRoot(vm) } }
        compose.onNodeWithText("Análisis profundo (recomendado)").performClick()
        compose.waitUntil(timeoutMillis = 30_000) { vm.state.value.report != null }
        val report = vm.state.value.report!!
        assertTrue(report.settings.any { it.id == "storage" })
        assertTrue(report.settings.any { it.id == "shield" })
    }
}

@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    @Test
    fun mainActivityStartsAndOpensRequestedTab() {
        val app: Application = ApplicationProvider.getApplicationContext()
        Prefs.setLastDbCheck(app, System.currentTimeMillis())
        Prefs.setAskedNotifications(app)
        val intent = android.content.Intent(app, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_TAB, MainActivity.TAB_SHIELD)
        ActivityScenario.launch<MainActivity>(intent).use { scenario ->
            scenario.onActivity { activity -> assertFalse(activity.isFinishing) }
        }
    }
}
