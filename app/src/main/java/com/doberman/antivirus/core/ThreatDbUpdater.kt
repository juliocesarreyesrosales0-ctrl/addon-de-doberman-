package com.doberman.antivirus.core

import android.content.Context
import android.net.ConnectivityManager
import android.util.JsonReader
import android.util.JsonToken
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Descarga los indicadores más recientes de stalkerware (Echap) y actualiza la base local. */
object ThreatDbUpdater {
    private const val ECHAP_STIX =
        "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2"
    private const val MAX_DOWNLOAD_BYTES = 40L * 1024 * 1024

    val ECHAP_SOURCE = ThreatDatabase.Source(
        id = "echap",
        name = "Stalkerware Indicators – Echap",
        url = "https://github.com/AssoEchap/stalkerware-indicators",
        license = "CC BY 4.0",
    )

    sealed interface Result {
        data class Updated(val added: Int, val db: ThreatDatabase) : Result
        data class Failed(val message: String) : Result
    }

    fun isOnUnmeteredNetwork(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        @Suppress("DEPRECATION")
        val connected = cm.activeNetworkInfo?.isConnected == true
        return connected && !cm.isActiveNetworkMetered
    }

    /** Operación bloqueante: llamar desde un hilo de fondo. */
    fun update(context: Context): Result {
        val current = ThreatDatabase.get(context)
        val entries = try {
            download(ECHAP_STIX) { parseStix(it, defaultType = "stalkerware") }
        } catch (e: Exception) {
            return Result.Failed("No se pudo descargar la base de firmas. Revisa tu conexión a internet.")
        }
        if (entries.size < 500) return Result.Failed("La descarga parece incompleta; inténtalo más tarde.")
        val now = Date()
        val version = SimpleDateFormat("yyyy.MM.dd.HHmm", Locale.US).format(now)
        val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(now)
        val updated = current.replaceSource(ECHAP_SOURCE, entries, version, iso)
        ThreatDatabase.install(context, updated)
        return Result.Updated(updated.totalIndicators - current.totalIndicators, updated)
    }

    private fun <T> download(url: String, block: (InputStream) -> T): T {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 15_000
            conn.readTimeout = 30_000
            conn.setRequestProperty("User-Agent", "DobermanAntivirus")
            if (conn.responseCode != HttpURLConnection.HTTP_OK) error("HTTP ${conn.responseCode}")
            if (conn.contentLengthLong > MAX_DOWNLOAD_BYTES) error("Archivo demasiado grande")
            return conn.inputStream.buffered().use(block)
        } finally {
            conn.disconnect()
        }
    }

    private val PATTERN_RE = Regex("^\\[([a-z0-9:._-]+)\\s*=\\s*'(.*)']$")

    /** Lee un bundle STIX2 en modo streaming (poca memoria) y devuelve los indicadores de apps. */
    fun parseStix(input: InputStream, defaultType: String): List<ThreatDatabase.Indicator> {
        val malware = HashMap<String, Pair<String, String>>()
        val indicators = HashMap<String, Pair<ThreatDatabase.Field, String>>()
        val relations = ArrayList<Pair<String, String>>()
        JsonReader(InputStreamReader(input, Charsets.UTF_8)).use { r ->
            r.beginObject()
            while (r.hasNext()) {
                if (r.nextName() != "objects") {
                    r.skipValue()
                    continue
                }
                r.beginArray()
                while (r.hasNext()) readObject(r, defaultType, malware, indicators, relations)
                r.endArray()
            }
            r.endObject()
        }
        val out = ArrayList<ThreatDatabase.Indicator>()
        for ((src, dst) in relations) {
            val ind = indicators[src] ?: continue
            val fam = malware[dst] ?: continue
            out += ThreatDatabase.Indicator(fam.first, fam.second, ind.first, ind.second)
        }
        if (out.isEmpty() && malware.size == 1) {
            val fam = malware.values.first()
            indicators.values.forEach { out += ThreatDatabase.Indicator(fam.first, fam.second, it.first, it.second) }
        }
        return out
    }

    private fun readObject(
        r: JsonReader,
        defaultType: String,
        malware: MutableMap<String, Pair<String, String>>,
        indicators: MutableMap<String, Pair<ThreatDatabase.Field, String>>,
        relations: MutableList<Pair<String, String>>,
    ) {
        var type: String? = null
        var id: String? = null
        var name: String? = null
        var description: String? = null
        var pattern: String? = null
        var source: String? = null
        var target: String? = null
        r.beginObject()
        while (r.hasNext()) {
            when (r.nextName()) {
                "type" -> type = r.stringOrNull()
                "id" -> id = r.stringOrNull()
                "name" -> name = r.stringOrNull()
                "description" -> description = r.stringOrNull()
                "pattern" -> pattern = r.stringOrNull()
                "source_ref" -> source = r.stringOrNull()
                "target_ref" -> target = r.stringOrNull()
                else -> r.skipValue()
            }
        }
        r.endObject()
        when (type) {
            "malware" -> if (id != null) {
                val d = description.orEmpty().lowercase(Locale.ROOT)
                val kind = when {
                    "watchware" in d -> "watchware"
                    "stalkerware" in d -> "stalkerware"
                    else -> defaultType
                }
                malware[id] = (name ?: "Desconocido") to kind
            }
            "indicator" -> if (id != null && pattern != null) {
                val m = PATTERN_RE.find(pattern.trim()) ?: return
                val field = when (m.groupValues[1]) {
                    "app:id" -> ThreatDatabase.Field.PACKAGE
                    "app:cert.sha1" -> ThreatDatabase.Field.CERT_SHA1
                    "file:hashes.sha256" -> ThreatDatabase.Field.SHA256
                    else -> return
                }
                indicators[id] = field to m.groupValues[2]
            }
            "relationship" -> if (source != null && target != null) relations += source to target
        }
    }

    private fun JsonReader.stringOrNull(): String? = when (peek()) {
        JsonToken.NULL -> {
            nextNull()
            null
        }
        JsonToken.STRING, JsonToken.NUMBER -> nextString()
        else -> {
            skipValue()
            null
        }
    }
}
