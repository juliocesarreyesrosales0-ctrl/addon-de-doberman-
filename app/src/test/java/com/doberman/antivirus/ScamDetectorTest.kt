package com.doberman.antivirus

import com.doberman.antivirus.core.ScamDetector
import com.doberman.antivirus.core.WebOrigin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScamDetectorTest {

    private fun webScam(title: String, text: String = "") =
        ScamDetector.analyze(title, text).isScam(ScamDetector.WEB_THRESHOLD)

    private fun appScam(title: String, text: String = "") =
        ScamDetector.analyze(title, text).isScam(ScamDetector.APP_THRESHOLD)

    @Test
    fun detectsTypicalFakeCleanerAlertsInSpanish() {
        assertTrue(webScam("⚠️ Tu teléfono está infectado con (4) virus", "Toca para eliminarlos ahora"))
        assertTrue(webScam("Tu batería está 87% dañada", "Toca aquí para repararla"))
        assertTrue(webScam("Limpieza necesaria", "Tu celular está lento. Limpia la basura ahora mismo"))
        assertTrue(webScam("¡Alerta de seguridad!", "Se detectaron 3 virus en tu Android"))
        assertTrue(webScam("Tu Android está en riesgo", "Protégelo ahora"))
        assertTrue(webScam("Has ganado un iPhone 17 Pro", "Reclama tu premio"))
        assertTrue(webScam("Memoria llena", "Tu dispositivo está lento: optimízalo ahora"))
    }

    @Test
    fun detectsEnglishAndPortugueseScams() {
        assertTrue(webScam("Your phone is infected!", "Remove the virus now"))
        assertTrue(webScam("Battery damaged", "Your battery is 72% damaged. Clean now"))
        assertTrue(webScam("Congratulations! You have won", "Claim your free gift"))
        assertTrue(webScam("Seu celular está infectado", "Toque para limpar agora"))
    }

    @Test
    fun ignoresNormalNotifications() {
        assertFalse(webScam("Nuevo artículo", "Las mejores recetas de la semana"))
        assertFalse(webScam("Alerta de tsunami", "Revisa las indicaciones de Protección Civil"))
        assertFalse(webScam("Tu pedido llegó", "Tu paquete fue entregado"))
        assertFalse(appScam("Security alert", "New sign-in to your Google Account"))
        assertFalse(appScam("Batería baja", "Conecta el cargador"))
        assertFalse(appScam("Juan", "¿Ya limpiaste tu cuarto?"))
        assertFalse(appScam("Recompensa diaria", "¡Reclama tu premio gratis en el juego!"))
        assertFalse(appScam("Hay virus en la escuela", "Ten cuidado y lávate las manos"))
    }

    @Test
    fun appThresholdIsStricterThanWeb() {
        assertTrue(ScamDetector.APP_THRESHOLD > ScamDetector.WEB_THRESHOLD)
        // Una app que imita a un limpiador sí se detecta.
        assertTrue(appScam("¡Tu teléfono tiene 5 virus!", "Toca aquí para limpiar ahora"))
    }

    @Test
    fun normalizeRemovesAccentsAndCase() {
        assertEquals("telefono danado", ScamDetector.normalize("Teléfono DAÑADO"))
    }

    @Test
    fun extractsChromeSiteOrigin() {
        assertEquals("spam.example.com", WebOrigin.extractHost("web:https://spam.example.com;1700000000000"))
        assertEquals("ofertas-falsas.xyz", WebOrigin.extractHost(null, "www.ofertas-falsas.xyz"))
        assertEquals("sitio.com", WebOrigin.extractHost("sites", "https://sitio.com/push"))
        assertNull(WebOrigin.extractHost(null, "Descarga completa", "video.mp4"))
    }

    @Test
    fun separatesSiteNotificationsFromBrowserOwnOnes() {
        assertTrue(WebOrigin.isSiteNotification("web:https://a.com;1"))
        assertTrue(WebOrigin.isSiteNotification("sites"))
        assertFalse(WebOrigin.isSiteNotification("downloads"))
        assertFalse(WebOrigin.isSiteNotification("incognito"))
    }
}
