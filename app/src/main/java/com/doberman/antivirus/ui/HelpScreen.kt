package com.doberman.antivirus.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.doberman.antivirus.BuildConfig
import com.doberman.antivirus.core.SystemIntents

@Composable
fun HelpScreen(state: UiState, vm: MainViewModel) {
    val context = LocalContext.current
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            ExpandableCard("¿Qué hace Doberman?", initiallyExpanded = true) {
                Bullet("Revisa todas tus apps: las compara con una base de miles de firmas de apps espía y malware (nombre, certificado y huella digital del archivo) y busca comportamientos peligrosos: apps escondidas, que se hacen administradoras, que controlan tu pantalla, leen tus SMS o imitan apps del sistema.")
                Bullet("El análisis profundo también revisa tus archivos (Descargas, WhatsApp, Telegram, tarjeta SD) buscando instaladores APK peligrosos y archivos disfrazados.")
                Bullet("El escudo borra las notificaciones falsas de páginas web y apps («tienes virus», «limpia tu teléfono», «tu batería está dañada») y te lleva directo al interruptor para bloquear esa página.")
                Bullet("Te avisa al momento si se instala una app peligrosa (con el escudo activado).")
                Bullet("Todo se analiza dentro de tu teléfono. Doberman solo usa internet para descargar firmas nuevas.")
            }
        }
        item {
            ExpandableCard("Lo que ninguna app puede hacer (tampoco Doberman)") {
                Bullet("Ningún antivirus detecta el 100 % de las amenazas: aparecen nuevas cada día. Doberman combina firmas conocidas y señales de comportamiento, pero úsalo junto con Google Play Protect y el sentido común.")
                Bullet("Android no permite que una app borre otras apps a escondidas. Doberman te muestra la ventana oficial de desinstalación y tú confirmas.")
                Bullet("Las notificaciones falsas vienen de páginas web a las que, sin querer, les diste «Permitir». Doberman las borra y te lleva al ajuste, pero el permiso solo lo puedes quitar tú (un toque).")
                Bullet("Ninguna página web puede analizar tu teléfono. Si un sitio dice que tienes virus, es un anuncio engañoso.")
            }
        }
        item {
            ExpandableCard("Si una app no se deja desinstalar") {
                Bullet("Si es «administradora del dispositivo», pulsa «Quitar administrador», desactívala y luego desinstálala.")
                Bullet("Si se vuelve a activar o la pantalla se llena de anuncios, usa el Modo seguro: mantén presionado el botón de encendido, luego mantén presionado «Apagar» hasta que aparezca «Modo seguro» y acepta.")
                Bullet("En Modo seguro las apps descargadas no pueden ejecutarse: ve a Ajustes → Aplicaciones, busca la app y desinstálala. Reinicia para salir del Modo seguro.")
                Bullet("Si nada funciona: guarda tus fotos y contactos (Google Fotos / cuenta de Google) y restablece el teléfono a los valores de fábrica desde Ajustes → Sistema → Restablecer.")
            }
        }
        item {
            ExpandableCard("Si siguen apareciendo anuncios o alertas") {
                Bullet("Revisa las apps instaladas en los días en que empezaron los anuncios (en «Amenazas» se muestra la fecha de instalación).")
                Bullet("Desinstala apps de «limpieza», «acelerar», «ahorro de batería», linternas o fondos de pantalla que no uses: suelen ser adware.")
                Bullet("Quita el permiso de notificaciones a las páginas web (pestaña «Notificaciones» → guía).")
                Bullet("Si el anuncio aparece al desbloquear el teléfono, mira qué app tiene el permiso «Mostrar sobre otras apps».")
                Bullet("En Chrome: ⋮ → Configuración → Privacidad y seguridad → Borrar datos de navegación (cookies y datos de sitios).")
            }
        }
        item {
            ExpandableCard("Señales de que algo anda mal") {
                Bullet("Anuncios a pantalla completa fuera de las apps, o al desbloquear.")
                Bullet("Apps que no instalaste, o que desaparecen del menú después de abrirlas.")
                Bullet("Batería o datos que se gastan de golpe, el teléfono caliente sin usarlo.")
                Bullet("Cobros o suscripciones por SMS que no reconoces.")
                Bullet("Códigos de verificación que llegan sin que los pidas.")
            }
        }
        item {
            ExpandableCard("Cómo no volver a infectarte") {
                Bullet("Instala apps solo desde Google Play o la tienda de tu marca.")
                Bullet("Nunca instales una «actualización» o «antivirus» que te ofrezca una página web o un mensaje.")
                Bullet("Cuando una página pregunte «¿Permitir notificaciones?», toca «Bloquear».")
                Bullet("Mantén Google Play Protect activado y el sistema actualizado.")
                Bullet("Pon PIN o huella al teléfono y no se lo prestes a desconocidos.")
            }
        }
        item {
            ExpandableCard("Fuentes y créditos") {
                Text("Base de firmas", fontWeight = FontWeight.Bold)
                Bullet("Stalkerware Indicators, de la asociación Echap (licencia CC BY 4.0): github.com/AssoEchap/stalkerware-indicators")
                Bullet("MVT indicators, de Amnesty Tech y colaboradores (licencia MIT): github.com/mvt-project/mvt-indicators")
                state.db?.let { Muted("Versión de la base: ${it.version}") }
                Muted("Doberman Antivirus ${BuildConfig.VERSION_NAME}")
                OutlinedButton(onClick = { SystemIntents.openUrl(context, "https://github.com/AssoEchap/stalkerware-indicators") }) {
                    Text("Ver la base de Echap")
                }
            }
        }
        item {
            Text(
                "Si crees que alguien te espía con una app instalada a propósito, ten en cuenta que al desinstalarla esa persona podría notarlo. Busca apoyo en stopstalkerware.org antes de actuar.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
