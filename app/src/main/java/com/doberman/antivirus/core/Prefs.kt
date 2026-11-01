package com.doberman.antivirus.core

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/** Preferencias simples de la app. */
object Prefs {
    private const val NAME = "doberman"
    private const val IGNORED_APPS = "ignored_apps"
    private const val IGNORED_FILES = "ignored_files"
    private const val AUTO_BLOCK = "auto_block_spam"
    private const val NOTIFY_BLOCKED = "notify_blocked"
    private const val LAST_SCAN_TIME = "last_scan_time"
    private const val LAST_SCAN_THREATS = "last_scan_threats"
    private const val LAST_SCAN_DEEP = "last_scan_deep"
    private const val LAST_DB_CHECK = "last_db_check"
    private const val ASKED_NOTIFICATIONS = "asked_post_notifications"
    private const val BLOCKED_TOTAL = "blocked_total"

    private fun p(c: Context): SharedPreferences = c.applicationContext.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    fun ignoredApps(c: Context): Set<String> = p(c).getStringSet(IGNORED_APPS, emptySet())!!.toSet()
    fun ignoreApp(c: Context, pkg: String) = p(c).edit { putStringSet(IGNORED_APPS, ignoredApps(c) + pkg) }

    fun ignoredFiles(c: Context): Set<String> = p(c).getStringSet(IGNORED_FILES, emptySet())!!.toSet()
    fun ignoreFile(c: Context, path: String) = p(c).edit { putStringSet(IGNORED_FILES, ignoredFiles(c) + path) }

    fun clearIgnored(c: Context) = p(c).edit { remove(IGNORED_APPS).remove(IGNORED_FILES) }

    fun autoBlock(c: Context): Boolean = p(c).getBoolean(AUTO_BLOCK, true)
    fun setAutoBlock(c: Context, v: Boolean) = p(c).edit { putBoolean(AUTO_BLOCK, v) }

    fun notifyBlocked(c: Context): Boolean = p(c).getBoolean(NOTIFY_BLOCKED, true)
    fun setNotifyBlocked(c: Context, v: Boolean) = p(c).edit { putBoolean(NOTIFY_BLOCKED, v) }

    fun lastScanTime(c: Context): Long = p(c).getLong(LAST_SCAN_TIME, 0L)
    fun lastScanThreats(c: Context): Int = p(c).getInt(LAST_SCAN_THREATS, 0)
    fun lastScanDeep(c: Context): Boolean = p(c).getBoolean(LAST_SCAN_DEEP, false)
    fun saveLastScan(c: Context, time: Long, threats: Int, deep: Boolean) =
        p(c).edit { putLong(LAST_SCAN_TIME, time).putInt(LAST_SCAN_THREATS, threats).putBoolean(LAST_SCAN_DEEP, deep) }

    fun lastDbCheck(c: Context): Long = p(c).getLong(LAST_DB_CHECK, 0L)
    fun setLastDbCheck(c: Context, t: Long) = p(c).edit { putLong(LAST_DB_CHECK, t) }

    fun askedNotifications(c: Context): Boolean = p(c).getBoolean(ASKED_NOTIFICATIONS, false)
    fun setAskedNotifications(c: Context) = p(c).edit { putBoolean(ASKED_NOTIFICATIONS, true) }

    fun blockedTotal(c: Context): Int = p(c).getInt(BLOCKED_TOTAL, 0)
    fun incrementBlocked(c: Context): Int {
        val v = blockedTotal(c) + 1
        p(c).edit { putInt(BLOCKED_TOTAL, v) }
        return v
    }
}
