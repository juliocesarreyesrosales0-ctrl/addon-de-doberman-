# Doberman Antivirus 🛡️🐕

App para Android (gratis y sin anuncios) que **busca y elimina apps peligrosas, archivos maliciosos y notificaciones falsas** del tipo
«Tu teléfono tiene 13 virus», «Tu batería está 87 % dañada» o «Limpia tu teléfono ahora».

Todo se analiza **dentro del teléfono**. La app solo usa internet para descargar firmas nuevas de malware.

## Qué hace

| Función | Cómo funciona |
|---|---|
| **Análisis de apps** | Revisa cada app instalada contra una base de firmas reales (≈680 paquetes, ≈490 certificados y ≈3.400 huellas SHA-256 de apps espía y malware) y busca señales de peligro: apps escondidas (sin ícono), administradoras del dispositivo, con Accesibilidad activada, que leen SMS o notificaciones, que se muestran encima de otras apps, que imitan apps del sistema («System Update», `com.android.…`), teclados de origen desconocido, «limpiadores/aceleradores» y apps que te mandaron notificaciones engañosas. |
| **Análisis profundo** | Además calcula la huella digital de cada app y recorre **todo el almacenamiento** (Descargas, WhatsApp, Telegram, tarjeta SD) buscando instaladores APK peligrosos, archivos con doble extensión (`foto.jpg.apk`) y archivos idénticos a malware conocido. |
| **Eliminar** | Un botón borra los archivos peligrosos y abre, una por una, la ventana oficial de desinstalación de Android. Si una app es «administradora del dispositivo», te guía para quitarle ese permiso primero. |
| **Escudo anti-notificaciones falsas** | Lee las notificaciones nuevas (solo en el teléfono), **borra automáticamente** las engañosas (español, inglés y portugués), te dice **qué página web** las envía y te lleva directo al interruptor para **bloquearla para siempre**. |
| **Protección en tiempo real** | Con el escudo activo, analiza al instante cada app nueva que instales y te avisa si es peligrosa. |
| **Ajustes de seguridad** | Revisa bloqueo de pantalla, depuración USB, root, parches de seguridad, administradores, Accesibilidad y acceso a notificaciones, con un botón para corregir cada cosa. |
| **VirusTotal** | Para cualquier app o archivo sospechoso, abre su informe en VirusTotal (más de 70 antivirus) usando solo su huella SHA-256. |

### Límites honestos

- **Ningún antivirus detecta el 100 %** de las amenazas. Doberman combina firmas conocidas con señales de comportamiento; úsalo junto con Google Play Protect.
- **Android no permite que una app borre otras apps a escondidas**: tú confirmas cada desinstalación (es una protección del sistema).
- Las notificaciones de «limpia tu teléfono» vienen de **páginas web a las que se les dio permiso de notificar**. Doberman las borra y te lleva al ajuste exacto, pero quitar el permiso es un toque tuyo.
- **Ninguna página web puede analizar tu teléfono**: si un sitio dice que tienes virus, es un anuncio engañoso.

## Instalar en tu teléfono

1. Descarga `DobermanAntivirus.apk`:
   - desde la pestaña **Actions** de este repositorio → la última ejecución de «Compilar APK» → sección *Artifacts*, o
   - compílalo tú (ver abajo).
2. Ábrelo en el teléfono. Si Android pregunta, permite **«Instalar apps desconocidas»** para tu navegador o administrador de archivos (puedes volver a desactivarlo después).
3. Google Play Protect puede avisar que la app es de un desarrollador desconocido: es normal en apps que no vienen de la Play Store. Toca *Más detalles → Instalar de todas formas*.
4. Abre **Doberman**, permite los avisos y toca **Análisis profundo**. Para revisar tus archivos te pedirá **«Acceso a todos los archivos»**.
5. En la pestaña **Notificaciones**, toca **Activar escudo** y activa *Doberman* en la lista.

### ¿Dice «Ajuste restringido» al activar el escudo? (Android 13 o superior)

Android bloquea ese permiso en apps instaladas desde un APK. Para desbloquearlo:

1. Ajustes → Aplicaciones → **Doberman Antivirus** (o el botón «Abrir información de Doberman» dentro de la app).
2. Toca los tres puntos **⋮** (arriba a la derecha) → **Permitir ajustes restringidos** y confirma con tu PIN o huella.
3. Vuelve a la app y toca **Activar escudo** otra vez.

### Si una app no se deja desinstalar

1. Quítale el permiso de administrador (botón «Quitar administrador» en Doberman).
2. Si sigue apareciendo, entra en **Modo seguro** (mantén presionado el botón de encendido y luego «Apagar» hasta que aparezca «Modo seguro»), desinstálala desde Ajustes → Aplicaciones y reinicia.
3. Último recurso: respalda fotos y contactos y restablece el teléfono de fábrica.

## Compilar

Requisitos: JDK 17 o superior (se recomienda 21) y el SDK de Android (plataforma 36).

```bash
./gradlew testDebugUnitTest   # 30+ pruebas: detector, firmas, análisis de apps/archivos, escudo e interfaz
./gradlew assembleRelease     # APK en app/build/outputs/apk/release/app-release.apk
```

Sin configuración extra, el APK se firma con la clave de depuración de tu computadora. Para usar tu propia clave crea
`keystore.properties` en la raíz (no lo subas al repositorio):

```properties
storeFile=/ruta/a/mi-clave.jks
storePassword=...
keyAlias=...
keyPassword=...
```

(o las variables de entorno `DOBERMAN_KEYSTORE_FILE`, `DOBERMAN_KEYSTORE_PASSWORD`, `DOBERMAN_KEY_ALIAS`, `DOBERMAN_KEY_PASSWORD`).
Si instalas un APK firmado con otra clave, Android pedirá desinstalar la versión anterior primero.

### Actualizar la base de firmas incluida

```bash
python3 tools/build_threat_db.py
```

La app también se actualiza sola (una vez por semana con Wi-Fi) o con el botón **Actualizar firmas**.

## Estructura

```
app/src/main/java/com/doberman/antivirus/
├── core/      # AppScanner, FileScanner, SystemChecker, ScamDetector, ThreatDatabase (+ actualizador)
├── guard/     # NotificationGuardService (escudo), SpamRepository, Notifier
└── ui/        # Pantallas en Jetpack Compose (Inicio, Amenazas, Notificaciones, Ayuda)
tools/build_threat_db.py   # genera app/src/main/assets/threat_db.json
```

## Fuentes de la base de firmas

- [Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators) de la asociación Echap — licencia [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- [MVT indicators](https://github.com/mvt-project/mvt-indicators) de Amnesty Tech y colaboradores — licencia MIT.

Si crees que alguien te espía con una app instalada a propósito, ten en cuenta que esa persona podría notar que la desinstalas.
Busca apoyo en [stopstalkerware.org](https://stopstalkerware.org/) antes de actuar.
