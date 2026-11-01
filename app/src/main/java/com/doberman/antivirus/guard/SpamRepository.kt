package com.doberman.antivirus.guard

import android.content.Context
import com.doberman.antivirus.core.Known
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

/** Página web o app que envió notificaciones (agrupadas por origen). Solo se guarda en el teléfono. */
data class SpamSource(
    val key: String,
    val isWeb: Boolean,
    val host: String?,
    val packageName: String,
    val appLabel: String,
    val channelId: String?,
    val total: Int,
    val scamCount: Int,
    val removedCount: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val lastTitle: String,
    val lastText: String,
    val reasons: List<String>,
    val userBlockedAt: Long,
) {
    val isScam: Boolean get() = scamCount > 0
    val displayName: String
        get() = host ?: if (isWeb) "Página web desconocida (vía $appLabel)" else appLabel
    val markedBlocked: Boolean get() = userBlockedAt > lastSeen
}

object SpamRepository {
    private const val FILE = "spam_sources.json"
    private const val MAX_SOURCES = 300
    private const val MAX_TEXT = 220

    private val lock = Any()
    private val io = Executors.newSingleThreadExecutor()
    private var loaded = false
    private val _sources = MutableStateFlow<List<SpamSource>>(emptyList())
    val sources: StateFlow<List<SpamSource>> = _sources.asStateFlow()

    fun init(context: Context) {
        synchronized(lock) {
            if (loaded) return
            _sources.value = load(context.applicationContext)
            loaded = true
        }
    }

    fun record(
        context: Context,
        isWeb: Boolean,
        host: String?,
        packageName: String,
        appLabel: String,
        channelId: String?,
        isScam: Boolean,
        removed: Boolean,
        title: String,
        text: String,
        reasons: List<String>,
    ) {
        synchronized(lock) {
            init(context)
            val key = if (isWeb) "web:${host ?: "?"}|$packageName" else "app:$packageName"
            val now = System.currentTimeMillis()
            val list = _sources.value.toMutableList()
            val idx = list.indexOfFirst { it.key == key }
            val prev = list.getOrNull(idx)
            val keepPrevSample = prev != null && prev.isScam && !isScam
            val updated = SpamSource(
                key = key,
                isWeb = isWeb,
                host = if (isWeb) host else null,
                packageName = packageName,
                appLabel = appLabel,
                channelId = channelId ?: prev?.channelId,
                total = (prev?.total ?: 0) + 1,
                scamCount = (prev?.scamCount ?: 0) + if (isScam) 1 else 0,
                removedCount = (prev?.removedCount ?: 0) + if (removed) 1 else 0,
                firstSeen = prev?.firstSeen ?: now,
                lastSeen = now,
                lastTitle = if (keepPrevSample) prev!!.lastTitle else title.take(MAX_TEXT),
                lastText = if (keepPrevSample) prev!!.lastText else text.take(MAX_TEXT),
                reasons = if (isScam) reasons else prev?.reasons.orEmpty(),
                userBlockedAt = prev?.userBlockedAt ?: 0L,
            )
            if (idx >= 0) list[idx] = updated else list.add(updated)
            _sources.value = list.sortedByDescending { it.lastSeen }.take(MAX_SOURCES)
            persist(context)
        }
    }

    fun markBlocked(context: Context, key: String) = mutate(context) { list ->
        list.map { if (it.key == key) it.copy(userBlockedAt = System.currentTimeMillis()) else it }
    }

    fun remove(context: Context, key: String) = mutate(context) { list -> list.filterNot { it.key == key } }

    fun clear(context: Context) = mutate(context) { emptyList() }

    /** Apps (no navegadores: en ellos la culpa es de la página web) que enviaron notificaciones engañosas. */
    fun scamAppPackages(context: Context): Set<String> {
        init(context)
        return _sources.value
            .filter { !it.isWeb && it.isScam && it.packageName !in Known.BROWSERS }
            .map { it.packageName }
            .toSet()
    }

    private fun mutate(context: Context, block: (List<SpamSource>) -> List<SpamSource>) {
        synchronized(lock) {
            init(context)
            _sources.value = block(_sources.value)
            persist(context)
        }
    }

    private fun persist(context: Context) {
        val snapshot = _sources.value
        val dir = context.applicationContext.filesDir
        io.execute {
            runCatching {
                val arr = JSONArray()
                snapshot.forEach { s ->
                    arr.put(
                        JSONObject()
                            .put("key", s.key).put("isWeb", s.isWeb).put("host", s.host ?: JSONObject.NULL)
                            .put("pkg", s.packageName).put("label", s.appLabel).put("channel", s.channelId ?: JSONObject.NULL)
                            .put("total", s.total).put("scam", s.scamCount).put("removed", s.removedCount)
                            .put("first", s.firstSeen).put("last", s.lastSeen)
                            .put("title", s.lastTitle).put("text", s.lastText)
                            .put("reasons", JSONArray(s.reasons)).put("blockedAt", s.userBlockedAt),
                    )
                }
                val tmp = File(dir, "$FILE.tmp")
                tmp.writeText(arr.toString())
                val target = File(dir, FILE)
                if (!tmp.renameTo(target)) {
                    target.delete()
                    tmp.renameTo(target)
                }
            }
        }
    }

    private fun load(context: Context): List<SpamSource> = runCatching {
        val f = File(context.filesDir, FILE)
        if (!f.isFile) return emptyList()
        val arr = JSONArray(f.readText())
        List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            val reasonsArr = o.optJSONArray("reasons") ?: JSONArray()
            SpamSource(
                key = o.getString("key"),
                isWeb = o.optBoolean("isWeb"),
                host = o.optString("host").takeIf { !o.isNull("host") && it.isNotBlank() },
                packageName = o.optString("pkg"),
                appLabel = o.optString("label"),
                channelId = o.optString("channel").takeIf { !o.isNull("channel") && it.isNotBlank() },
                total = o.optInt("total"),
                scamCount = o.optInt("scam"),
                removedCount = o.optInt("removed"),
                firstSeen = o.optLong("first"),
                lastSeen = o.optLong("last"),
                lastTitle = o.optString("title"),
                lastText = o.optString("text"),
                reasons = List(reasonsArr.length()) { j -> reasonsArr.optString(j) },
                userBlockedAt = o.optLong("blockedAt"),
            )
        }
    }.getOrDefault(emptyList())
}
