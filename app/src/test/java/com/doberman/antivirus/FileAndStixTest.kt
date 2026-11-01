package com.doberman.antivirus

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.doberman.antivirus.core.FileScanner
import com.doberman.antivirus.core.Hashing
import com.doberman.antivirus.core.Severity
import com.doberman.antivirus.core.ThreatDatabase
import com.doberman.antivirus.core.ThreatDbUpdater
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class FileAndStixTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val context: Application = ApplicationProvider.getApplicationContext()

    @Test
    fun fileScannerFlagsDangerousFiles() {
        val evil = tmp.newFile("regalo.apk").apply { writeText("muestra maliciosa") }
        val db = testDatabase("0".repeat(40), Hashing.sha256(evil)!!)
        val scanner = FileScanner(context, db)

        val known = scanner.analyze(evil)!!
        assertEquals(Severity.DANGER, known.severity)
        assertEquals("SpyX", known.threatName)

        val disguised = scanner.analyze(tmp.newFile("foto.jpg.apk").apply { writeText("x") })!!
        assertEquals(Severity.WARNING, disguised.severity)
        assertTrue(disguised.reasons.any { "doble extensión" in it })

        val windows = scanner.analyze(tmp.newFile("setup.exe").apply { writeText("MZ") })!!
        assertEquals(Severity.INFO, windows.severity)

        val hiddenDir = tmp.newFolder(".oculto")
        val hidden = scanner.analyze(File(hiddenDir, "app.apk").apply { writeText("y") })!!
        assertTrue(hidden.reasons.any { "oculta" in it })

        assertNull(scanner.analyze(tmp.newFile("notas.txt").apply { writeText("hola") }))
        assertNull(scanner.analyze(tmp.newFile("foto.jpg").apply { writeText("jpg") }))
    }

    @Test
    fun stixParserReadsAppIndicators() {
        val stix = """
            {"type":"bundle","id":"bundle--1","objects":[
              {"type":"malware","id":"malware--1","name":"SpyA","description":"Stalkerware application","is_family":false},
              {"type":"malware","id":"malware--2","name":"KidsB","description":"Watchware application"},
              {"type":"indicator","id":"indicator--1","pattern":"[app:id='com.spy.a']","pattern_type":"stix"},
              {"type":"indicator","id":"indicator--2","pattern":"[app:cert.sha1='AABBCCDDEEFF00112233445566778899AABBCCDD']"},
              {"type":"indicator","id":"indicator--3","pattern":"[domain-name:value='spy.example']"},
              {"type":"indicator","id":"indicator--4","pattern":"[file:hashes.sha256='${"ab".repeat(32)}']","labels":null},
              {"type":"indicator","id":"indicator--5","pattern":"[app:id='com.kids.b']","extra":{"nested":[1,2,3]}},
              {"type":"relationship","id":"r1","source_ref":"indicator--1","target_ref":"malware--1"},
              {"type":"relationship","id":"r2","source_ref":"indicator--2","target_ref":"malware--1"},
              {"type":"relationship","id":"r3","source_ref":"indicator--3","target_ref":"malware--1"},
              {"type":"relationship","id":"r4","source_ref":"indicator--4","target_ref":"malware--1"},
              {"type":"relationship","id":"r5","source_ref":"indicator--5","target_ref":"malware--2"}
            ]}
        """.trimIndent()
        val out = ThreatDbUpdater.parseStix(stix.byteInputStream(), "stalkerware")
        assertEquals(4, out.size)
        val kids = out.single { it.value == "com.kids.b" }
        assertEquals("watchware", kids.familyType)
        assertEquals(ThreatDatabase.Field.PACKAGE, kids.field)
        assertTrue(out.any { it.field == ThreatDatabase.Field.CERT_SHA1 && it.familyName == "SpyA" })
        assertTrue(out.any { it.field == ThreatDatabase.Field.SHA256 && it.familyType == "stalkerware" })
    }

    /** Prueba opcional con el archivo real de Echap: DOBERMAN_STIX_FILE=/ruta/stalkerware.stix2 */
    @Test
    fun parsesRealEchapFileWhenAvailable() {
        val path = System.getenv("DOBERMAN_STIX_FILE")
        assumeTrue(path != null && File(path).isFile)
        val entries = File(path!!).inputStream().buffered().use { ThreatDbUpdater.parseStix(it, "stalkerware") }
        assertTrue("indicadores: ${entries.size}", entries.size > 3000)
        val db = ThreatDatabase.empty().replaceSource(ThreatDbUpdater.ECHAP_SOURCE, entries, "t", "t")
        assertNotNull(db.byPackage("com.apspy.app"))
        assertTrue(db.packageCount > 500)
    }
}
