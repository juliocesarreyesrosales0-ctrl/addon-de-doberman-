package com.doberman.antivirus.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Base de firmas de amenazas conocidas: nombres de paquete, certificados de firma (SHA-1)
 * y huellas SHA-256 de APKs maliciosos. Se genera con tools/build_threat_db.py a partir de
 * fuentes públicas (Echap stalkerware-indicators, MVT) y puede actualizarse desde la app.
 */
class ThreatDatabase(
    val version: String,
    val generated: String,
    val sources: List<Source>,
    val families: List<Family>,
    private val packages: Map<String, Int>,
    private val certs: Map<String, Int>,
    private val hashes: Map<String, Int>,
) {
    data class Family(val name: String, val type: String, val source: String) {
        val typeLabel: String
            get() = when (type) {
                "stalkerware" -> "app espía (stalkerware)"
                "watchware" -> "app de monitoreo"
                "spyware" -> "spyware"
                else -> "malware"
            }

        /** Apps de monitoreo visibles (control parental): sospechosas, no necesariamente maliciosas. */
        val isMonitoringOnly: Boolean get() = type == "watchware"
    }

    data class Source(val id: String, val name: String, val url: String, val license: String)

    enum class Field { PACKAGE, CERT_SHA1, SHA256 }

    data class Indicator(val familyName: String, val familyType: String, val field: Field, val value: String)

    val packageCount: Int get() = packages.size
    val certCount: Int get() = certs.size
    val hashCount: Int get() = hashes.size
    val totalIndicators: Int get() = packages.size + certs.size + hashes.size

    fun byPackage(packageName: String): Family? = packages[packageName]?.let(families::getOrNull)
    fun byCert(sha1: String): Family? = certs[sha1.uppercase()]?.let(families::getOrNull)
    fun byHash(sha256: String): Family? = hashes[sha256.lowercase()]?.let(families::getOrNull)

    fun toJson(): String {
        val o = JSONObject()
        o.put("format", FORMAT)
        o.put("version", version)
        o.put("generated", generated)
        o.put("sources", JSONArray().apply {
            sources.forEach {
                put(JSONObject().put("id", it.id).put("name", it.name).put("url", it.url).put("license", it.license))
            }
        })
        o.put("families", JSONArray().apply {
            families.forEach { put(JSONArray().put(it.name).put(it.type).put(it.source)) }
        })
        o.put("packages", JSONObject(packages.toSortedMap() as Map<*, *>))
        o.put("certs", JSONObject(certs.toSortedMap() as Map<*, *>))
        o.put("sha256", JSONObject(hashes.toSortedMap() as Map<*, *>))
        return o.toString()
    }

    /** Devuelve una base nueva donde todo lo de [source] se sustituye por [entries]. */
    fun replaceSource(source: Source, entries: List<Indicator>, newVersion: String, newGenerated: String): ThreatDatabase {
        val newFamilies = ArrayList<Family>()
        val remap = HashMap<Int, Int>()
        families.forEachIndexed { i, f ->
            if (f.source != source.id) {
                remap[i] = newFamilies.size
                newFamilies += f
            }
        }

        fun keep(m: Map<String, Int>): HashMap<String, Int> {
            val r = HashMap<String, Int>(m.size)
            m.forEach { (k, v) -> remap[v]?.let { r[k] = it } }
            return r
        }

        val p = keep(packages)
        val c = keep(certs)
        val h = keep(hashes)
        val famIndex = HashMap<Pair<String, String>, Int>()
        for (e in entries) {
            val key: String
            val table: HashMap<String, Int>
            when (e.field) {
                Field.PACKAGE -> {
                    key = e.value.trim()
                    if (!PACKAGE_RE.matches(key)) continue
                    table = p
                }
                Field.CERT_SHA1 -> {
                    key = e.value.trim().uppercase().replace(":", "")
                    if (!SHA1_RE.matches(key)) continue
                    table = c
                }
                Field.SHA256 -> {
                    key = e.value.trim().lowercase()
                    if (!SHA256_RE.matches(key)) continue
                    table = h
                }
            }
            val idx = famIndex.getOrPut(e.familyName to e.familyType) {
                newFamilies += Family(e.familyName, e.familyType, source.id)
                newFamilies.size - 1
            }
            val prev = table[key]
            if (prev == null || rank(newFamilies[idx].type) > rank(newFamilies[prev].type)) table[key] = idx
        }
        val newSources = sources.filter { it.id != source.id } + source
        return ThreatDatabase(newVersion, newGenerated, newSources, newFamilies, p, c, h)
    }

    companion object {
        const val FORMAT = 1
        const val FILE_NAME = "threat_db.json"

        private val PACKAGE_RE = Regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$")
        private val SHA1_RE = Regex("^[0-9A-F]{40}$")
        private val SHA256_RE = Regex("^[0-9a-f]{64}$")

        private fun rank(type: String) = when (type) {
            "spyware" -> 3
            "stalkerware" -> 2
            "watchware" -> 1
            else -> 0
        }

        fun empty() = ThreatDatabase("0", "", emptyList(), emptyList(), emptyMap(), emptyMap(), emptyMap())

        fun parse(json: String): ThreatDatabase {
            val o = JSONObject(json)
            require(o.optInt("format") == FORMAT) { "Formato de base desconocido" }
            val famArray = o.getJSONArray("families")
            val families = List(famArray.length()) { i ->
                val f = famArray.getJSONArray(i)
                Family(f.getString(0), f.getString(1), f.optString(2, ""))
            }
            val sourcesArray = o.optJSONArray("sources") ?: JSONArray()
            val sources = List(sourcesArray.length()) { i ->
                val s = sourcesArray.getJSONObject(i)
                Source(s.optString("id"), s.optString("name"), s.optString("url"), s.optString("license"))
            }

            fun table(key: String, normalize: (String) -> String): Map<String, Int> {
                val obj = o.optJSONObject(key) ?: return emptyMap()
                val m = HashMap<String, Int>(obj.length())
                val it = obj.keys()
                while (it.hasNext()) {
                    val k = it.next()
                    val v = obj.getInt(k)
                    if (v in families.indices) m[normalize(k)] = v
                }
                return m
            }
            return ThreatDatabase(
                version = o.optString("version", "0"),
                generated = o.optString("generated", ""),
                sources = sources,
                families = families,
                packages = table("packages") { it },
                certs = table("certs") { it.uppercase() },
                hashes = table("sha256") { it.lowercase() },
            )
        }

        @Volatile
        private var cached: ThreatDatabase? = null

        fun get(context: Context): ThreatDatabase {
            cached?.let { return it }
            synchronized(this) {
                cached?.let { return it }
                val db = loadBest(context.applicationContext)
                cached = db
                return db
            }
        }

        /** Usa la base más reciente entre la incluida en la app y la descargada. */
        private fun loadBest(context: Context): ThreatDatabase {
            val bundled = runCatching {
                context.assets.open(FILE_NAME).bufferedReader().use { parse(it.readText()) }
            }.getOrNull()
            val downloaded = runCatching {
                File(context.filesDir, FILE_NAME).takeIf { it.isFile }?.let { parse(it.readText()) }
            }.getOrNull()
            return listOfNotNull(bundled, downloaded).maxByOrNull { it.version } ?: empty()
        }

        /** Guarda la base de forma atómica y la deja activa. */
        fun install(context: Context, db: ThreatDatabase) {
            val dir = context.applicationContext.filesDir
            val tmp = File(dir, "$FILE_NAME.tmp")
            tmp.writeText(db.toJson())
            val target = File(dir, FILE_NAME)
            if (!tmp.renameTo(target)) {
                target.delete()
                tmp.renameTo(target)
            }
            synchronized(this) { cached = db }
        }
    }
}
