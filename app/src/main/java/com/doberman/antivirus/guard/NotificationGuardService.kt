package com.doberman.antivirus.guard

import android.annotation.SuppressLint
import android.app.Notification
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.doberman.antivirus.core.AppScanner
import com.doberman.antivirus.core.Known
import com.doberman.antivirus.core.Prefs
import com.doberman.antivirus.core.ScamDetector
import com.doberman.antivirus.core.Severity
import com.doberman.antivirus.core.WebOrigin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Escudo de notificaciones. Cuando el usuario le da acceso:
 *  - revisa cada notificación nueva y borra las engañosas ("tu teléfono tiene virus", "limpia tu teléfono"...),
 *  - anota qué página web o app la envió para poder bloquearla para siempre,
 *  - analiza al instante cada app nueva que se instale.
 * Todo se procesa dentro del teléfono; no se envía nada a internet.
 */
class NotificationGuardService : NotificationListenerService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var packageReceiver: BroadcastReceiver? = null
    private val recentKeys = object : LinkedHashMap<String, Long>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > 256
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        _connected.value = true
        registerPackageReceiver()
        // Revisar también lo que ya está en la barra de notificaciones.
        runCatching { activeNotifications }.getOrNull()?.forEach { handle(it) }
    }

    override fun onListenerDisconnected() {
        _connected.value = false
        unregisterPackageReceiver()
        super.onListenerDisconnected()
    }

    override fun onDestroy() {
        _connected.value = false
        unregisterPackageReceiver()
        scope.cancel()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return
        runCatching { handle(sbn) }
    }

    private fun handle(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        if (pkg == packageName || pkg in Known.PROTECTED_NOTIFIERS || Known.isReputableSecurity(pkg)) return
        val n = sbn.notification ?: return
        if ((n.flags and Notification.FLAG_GROUP_SUMMARY) != 0) return

        val extras = n.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
        val bigText = extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val subText = extras?.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
        val ticker = n.tickerText?.toString()
        if (title.isBlank() && text.isBlank() && bigText.isNullOrBlank() && ticker.isNullOrBlank()) return

        val isBrowser = pkg in Known.BROWSERS
        if (!isBrowser) {
            // Nunca analizar conversaciones personales, llamadas, correos ni alarmas.
            if (n.category in PERSONAL_CATEGORIES) return
            if (extras?.containsKey(Notification.EXTRA_MESSAGES) == true) return
        }

        val channelId = if (Build.VERSION.SDK_INT >= 26) n.channelId else null
        val fromWebSite = isBrowser && WebOrigin.isSiteNotification(channelId)
        val host = if (fromWebSite) WebOrigin.extractHost(channelId, subText, title, text) else null
        val verdict = ScamDetector.analyze(title, text, bigText, subText, ticker)
        // Avisos de páginas web: umbral bajo. Avisos propios del navegador o de apps: más estricto.
        val threshold = if (fromWebSite) ScamDetector.WEB_THRESHOLD else ScamDetector.APP_THRESHOLD
        val isScam = verdict.isScam(threshold)

        // De las apps solo interesan las engañosas; de las webs, también se lista quién notifica.
        if (!isScam && !(fromWebSite && host != null)) return

        var removed = false
        if (isScam && Prefs.autoBlock(this) && sbn.isClearable) {
            removed = runCatching { cancelNotification(sbn.key) }.isSuccess
        }

        val now = System.currentTimeMillis()
        val firstTime = synchronized(recentKeys) {
            val last = recentKeys[sbn.key]
            val isNew = last == null || now - last > DEDUPE_WINDOW_MS
            if (isNew) recentKeys[sbn.key] = now
            isNew
        }
        if (!firstTime) return

        val appLabel = Known.BROWSERS[pkg] ?: appLabel(pkg)
        SpamRepository.record(
            context = this,
            isWeb = fromWebSite,
            host = host,
            packageName = pkg,
            appLabel = appLabel,
            channelId = channelId,
            isScam = isScam,
            removed = removed,
            title = title,
            text = bigText?.takeIf { it.isNotBlank() } ?: text,
            reasons = verdict.reasons,
        )
        if (isScam) {
            val total = Prefs.incrementBlocked(this)
            val source = host ?: appLabel
            Notifier.notifyBlocked(this, source, total, removed)
        }
    }

    private fun appLabel(pkg: String): String = runCatching {
        val pm = packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    }.getOrDefault(pkg)

    /** Analiza en el momento cada app nueva que se instala. */
    private fun registerPackageReceiver() {
        if (packageReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                val pkg = intent.data?.schemeSpecificPart ?: return
                val pending = goAsync()
                scope.launch {
                    try {
                        val appContext = applicationContext
                        val isSystem = runCatching {
                            (appContext.packageManager.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        }.getOrDefault(true)
                        if (!isSystem) {
                            val scanner = AppScanner(appContext)
                            val env = scanner.gatherEnvironment(
                                spamApps = SpamRepository.scamAppPackages(appContext),
                                ignored = Prefs.ignoredApps(appContext),
                            )
                            val finding = scanner.scanOne(pkg, deep = true, env = env)
                            if (finding != null && finding.severity != Severity.INFO) {
                                Notifier.notifyDangerousApp(appContext, finding)
                            }
                        }
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        runCatching {
            ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
            packageReceiver = receiver
        }
    }

    private fun unregisterPackageReceiver() {
        packageReceiver?.let { runCatching { unregisterReceiver(it) } }
        packageReceiver = null
    }

    companion object {
        private const val DEDUPE_WINDOW_MS = 30L * 60 * 1000

        // Son constantes de texto copiadas al compilar: compararlas es seguro en cualquier versión.
        @SuppressLint("InlinedApi")
        private val PERSONAL_CATEGORIES = setOf(
            Notification.CATEGORY_MESSAGE,
            Notification.CATEGORY_CALL,
            Notification.CATEGORY_EMAIL,
            Notification.CATEGORY_ALARM,
            Notification.CATEGORY_NAVIGATION,
            Notification.CATEGORY_TRANSPORT,
            Notification.CATEGORY_REMINDER,
            Notification.CATEGORY_EVENT,
        )

        private val _connected = MutableStateFlow(false)
        val connected: StateFlow<Boolean> = _connected.asStateFlow()

        fun isEnabled(context: Context): Boolean =
            NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)

        /** Pide al sistema que vuelva a conectar el escudo si lo detuvo (algunos fabricantes lo hacen). */
        fun requestRebindIfNeeded(context: Context) {
            if (isEnabled(context) && !_connected.value) {
                runCatching {
                    requestRebind(ComponentName(context, NotificationGuardService::class.java))
                }
            }
        }
    }
}
