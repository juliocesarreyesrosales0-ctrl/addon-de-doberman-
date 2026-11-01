package com.doberman.antivirus.core

import java.text.Normalizer
import java.util.Locale

/**
 * Detecta notificaciones engañosas del tipo "Tu teléfono tiene 13 virus", "Tu batería está 87% dañada",
 * "Limpia tu teléfono ahora" o "Ganaste un iPhone". Funciona en español, inglés y portugués.
 *
 * Ninguna página web puede analizar tu teléfono: cualquier sitio que diga que encontró virus miente.
 */
object ScamDetector {

    /** Puntos necesarios para considerar engañosa una notificación de un navegador (página web). */
    const val WEB_THRESHOLD = 4

    /** Las apps normales necesitan más evidencia para evitar falsos positivos. */
    const val APP_THRESHOLD = 6

    data class Verdict(val score: Int, val reasons: List<String>) {
        fun isScam(threshold: Int): Boolean = score >= threshold
    }

    private class Rule(pattern: String, val points: Int, val reason: String) {
        val regex = Regex(pattern)
    }

    private val rules = listOf(
        Rule("\\bvirus(es)?\\b", 3, "Dice que hay virus"),
        Rule("infectad[oa]s?|infeccion|\\binfected\\b|\\binfection", 3, "Dice que tu teléfono está infectado"),
        Rule(
            "malware|troyano|trojan|spyware|adware|ransomware|hackead[oa]s?|\\bhacked\\b|\\bhackers?\\b",
            3, "Habla de malware o de hackeo",
        ),
        Rule(
            "(bateria|battery)[^.!?\\n]{0,30}(danad|damage|corrupt|danific|destrui|desgastad)|" +
                "(telefono|celular|movil|dispositivo|phone|device|aparelho|android)[^.!?\\n]{0,25}" +
                "(danad|damage|danific|destrui|roto|broken|averiad)",
            3, "Dice que tu batería o tu teléfono están dañados",
        ),
        Rule(
            "\\d{1,3}\\s?%[^.!?\\n]{0,30}(danad|damage|infect|virus|bateria|battery|basura|junk|llen|full|desgast|lent)",
            3, "Usa porcentajes alarmantes",
        ),
        Rule(
            "has ganado|ganaste|\\bganador|you('ve| have)? won|\\bwinner\\b|you are the [0-9.,]+(th|st|nd|rd)? visitor|" +
                "seleccionad[oa] para|been selected|voce ganhou|\\bganhou\\b",
            3, "Dice que ganaste algo",
        ),
        Rule("premio|\\bprize\\b|reclama|\\bclaim\\b|recompensa|\\breward", 2, "Promete premios"),
        Rule("\\b(gratis|free|regalo|gift|sorteo|giveaway|gratuito)\\b", 1, "Ofrece regalos"),
        Rule(
            "\\blimpia(r|lo|la|rlo)?\\b|limpieza|limpiador|\\bclean(er|ing| up| now)?\\b|\\blimpar\\b|limpeza",
            2, "Te pide limpiar el teléfono",
        ),
        Rule(
            "basura|\\bjunk\\b|archivos? (inutiles|residuales)|\\blixo\\b|\\bcache\\b",
            2, "Habla de archivos basura",
        ),
        Rule("amenaza|\\bthreats?\\b|en riesgo|at risk|em risco|peligro|\\bdanger|ameaca", 2, "Habla de amenazas o peligro"),
        Rule(
            "\\bacelera(r|lo)?\\b|\\blent[oa]\\b|\\bslow\\b|\\bboost|\\boptimiza(r|lo)?\\b|speed up|" +
                "memoria (llena|insuficiente)|almacenamiento (lleno|insuficiente)|storage (is )?(almost )?full|\\bram\\b",
            2, "Dice que tu teléfono está lento o lleno",
        ),
        Rule(
            "\\b(escane|elimin|repar|limpi|actualiz|instal|descarg|toc|puls|presion|click|tap|cliqu|toqu|proteg|" +
                "optimiz|aceler|verific|revis|remov|fix|scan|clean|install|download)\\w*\\s+(\\w+\\s+)?" +
                "(aqui|ahora|ya|here|now|agora)\\b|" +
                "\\b(toca|pulsa|presiona|toque|clique|haz clic|haga clic|click|tap) (para|to|aqui|here)\\b|" +
                "ahora mismo|inmediatamente|urgente|\\bimmediately\\b|\\burgent\\b|act now|right now",
            2, "Te presiona para actuar de inmediato",
        ),
        Rule("\\b(bateria|battery)\\b", 1, "Menciona la batería"),
        Rule(
            "\\b(tu|su|your|seu|sua) (telefono|celular|movil|dispositivo|android|samsung|smartphone|phone|device|" +
                "mobile|aparelho|equipo)\\b",
            1, "Se dirige a tu teléfono",
        ),
        Rule("\\balerta|\\balert|advertencia|\\bwarning|atencion|attention|\\baviso|cuidado|alarma", 1, "Usa palabras de alarma"),
        Rule("seguridad|security|\\bproteg|protection|escaneo|escanear|\\bscan|antivirus", 1, "Simula ser un aviso de seguridad"),
    )

    private val ALARM_SYMBOLS = listOf(
        "⚠", "🚨", "❗", "‼", "☢", "🔴", "❌", "💀",
        "🦠", "🧹", "🔋", "🛑", "⛔",
    )

    private val MARKS = Regex("\\p{Mn}+")

    /** Minúsculas y sin acentos ("Teléfono" -> "telefono", "dañada" -> "danada"). */
    fun normalize(text: String): String =
        Normalizer.normalize(text.lowercase(Locale.ROOT), Normalizer.Form.NFD).replace(MARKS, "")

    fun analyze(vararg parts: CharSequence?): Verdict {
        val raw = parts.filterNotNull().map { it.toString() }.filter { it.isNotBlank() }.distinct().joinToString("\n")
        if (raw.isBlank()) return Verdict(0, emptyList())
        val text = normalize(raw)
        var score = 0
        val reasons = ArrayList<String>()
        for (rule in rules) {
            if (rule.regex.containsMatchIn(text)) {
                score += rule.points
                reasons += rule.reason
            }
        }
        if (ALARM_SYMBOLS.any { raw.contains(it) }) {
            score += 1
            reasons += "Usa emojis de alarma"
        }
        return Verdict(score, reasons)
    }
}

/** Utilidades para identificar la página web que envía una notificación a través del navegador. */
object WebOrigin {
    private const val CHROME_SITE_PREFIX = "web:"
    private val HOST_RE = Regex(
        "(?<![a-z0-9.-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24})(?![a-z0-9-])(?::\\d+)?(?:/\\S*)?"
    )
    private val NON_WEB_CHANNEL = Regex("download|incognito|media|browser|update|sharing|permission|announcement|general|tab|price", RegexOption.IGNORE_CASE)

    /** ¿La notificación del navegador viene de una página web y no del propio navegador? */
    fun isSiteNotification(channelId: String?): Boolean {
        if (channelId == null) return true
        if (channelId.startsWith(CHROME_SITE_PREFIX) || channelId == "sites" || channelId.startsWith("twa_")) return true
        return !NON_WEB_CHANNEL.containsMatchIn(channelId)
    }

    /** Devuelve el dominio (ej. "ejemplo.com") a partir del canal de Chrome o del texto visible. */
    fun extractHost(channelId: String?, vararg texts: CharSequence?): String? {
        if (channelId != null && channelId.startsWith(CHROME_SITE_PREFIX)) {
            val origin = channelId.removePrefix(CHROME_SITE_PREFIX).substringBefore(';')
            hostOf(origin)?.let { return it }
        }
        for (t in texts) {
            val s = t?.toString()?.trim()?.lowercase(Locale.ROOT) ?: continue
            if (s.isEmpty()) continue
            hostOf(s)?.let { return it }
        }
        return null
    }

    fun hostOf(text: String): String? {
        val m = HOST_RE.find(text.lowercase(Locale.ROOT)) ?: return null
        val host = m.groupValues[1].removePrefix("www.")
        // Evita confundir nombres de archivo o versiones con dominios.
        val tld = host.substringAfterLast('.')
        if (tld in setOf("apk", "jpg", "png", "mp4", "pdf", "txt", "zip", "exe", "html")) return null
        return host
    }
}
