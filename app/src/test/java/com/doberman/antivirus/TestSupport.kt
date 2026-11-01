package com.doberman.antivirus

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.ResolveInfo
import android.content.pm.Signature
import com.doberman.antivirus.core.ThreatDatabase
import org.robolectric.Shadows.shadowOf
import java.io.File

/** Instala una app falsa en el PackageManager simulado de Robolectric. */
fun installFakeApp(
    context: Context,
    pkg: String,
    label: String,
    permissions: List<String> = emptyList(),
    installer: String? = null,
    launcher: Boolean = true,
    system: Boolean = false,
    signature: ByteArray? = null,
    apk: File? = null,
) {
    val spm = shadowOf(context.packageManager)
    val ai = ApplicationInfo().apply {
        packageName = pkg
        nonLocalizedLabel = label
        flags = if (system) ApplicationInfo.FLAG_SYSTEM else 0
        targetSdkVersion = 34
        sourceDir = apk?.absolutePath
        publicSourceDir = apk?.absolutePath
    }
    @Suppress("DEPRECATION")
    val pi = PackageInfo().apply {
        packageName = pkg
        applicationInfo = ai
        requestedPermissions = permissions.toTypedArray()
        versionName = "1.0"
        firstInstallTime = 1_700_000_000_000L
        signatures = signature?.let { arrayOf(Signature(it)) }
    }
    spm.installPackage(pi)
    if (installer != null) spm.setInstallSourceInfo(pkg, installer, installer)
    if (launcher) {
        spm.addResolveInfoForIntent(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
            ResolveInfo().apply {
                activityInfo = ActivityInfo().apply {
                    packageName = pkg
                    name = "$pkg.MainActivity"
                    applicationInfo = ai
                }
            },
        )
    }
}

/** Base de firmas mínima y controlada para las pruebas. */
fun testDatabase(certSha1: String, apkSha256: String): ThreatDatabase = ThreatDatabase.parse(
    """
    {"format":1,"version":"test","generated":"",
     "families":[["SpyX","stalkerware","echap"],["KidWatch","watchware","echap"]],
     "packages":{"com.spyx.app":0,"com.kidwatch":1},
     "certs":{"$certSha1":0},
     "sha256":{"$apkSha256":0}}
    """.trimIndent(),
)

val SPY_PERMISSIONS = listOf(
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
)
