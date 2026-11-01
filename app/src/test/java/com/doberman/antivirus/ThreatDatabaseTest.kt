package com.doberman.antivirus

import com.doberman.antivirus.core.ThreatDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ThreatDatabaseTest {

    private fun bundled(): ThreatDatabase {
        val candidates = listOf(File("src/main/assets/threat_db.json"), File("app/src/main/assets/threat_db.json"))
        val file = candidates.first { it.isFile }
        return ThreatDatabase.parse(file.readText())
    }

    @Test
    fun bundledDatabaseIsLoadedAndUsable() {
        val db = bundled()
        assertTrue("paquetes: ${db.packageCount}", db.packageCount > 500)
        assertTrue("certificados: ${db.certCount}", db.certCount > 300)
        assertTrue("huellas: ${db.hashCount}", db.hashCount > 2000)
        // Indicadores públicos de TheTruthSpy (Echap).
        assertEquals("TheTruthSpy", db.byPackage("com.apspy.app")?.name)
        assertEquals("TheTruthSpy", db.byCert("31a6ececd97cf39bc4126b8745cd94a7c30bf81c")?.name)
        assertNull(db.byPackage("com.whatsapp"))
        assertNull(db.byPackage("com.android.chrome"))
    }

    @Test
    fun replaceSourceKeepsOtherSourcesAndRoundTrips() {
        val db = bundled()
        val mvtFamilies = db.families.count { it.source == "mvt" }
        val replaced = db.replaceSource(
            ThreatDatabase.Source("echap", "Echap", "https://example.org", "CC BY 4.0"),
            listOf(
                ThreatDatabase.Indicator("FakeSpy", "stalkerware", ThreatDatabase.Field.PACKAGE, "com.fake.spy"),
                ThreatDatabase.Indicator("FakeSpy", "stalkerware", ThreatDatabase.Field.CERT_SHA1, "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"),
                ThreatDatabase.Indicator("FakeSpy", "stalkerware", ThreatDatabase.Field.SHA256, "0".repeat(64)),
                ThreatDatabase.Indicator("FakeSpy", "stalkerware", ThreatDatabase.Field.PACKAGE, "not a package"),
            ),
            "2099.01.01.0000",
            "2099-01-01T00:00:00Z",
        )
        // Lo de Echap se reemplaza, lo de MVT se conserva.
        assertNull(replaced.byPackage("com.apspy.app"))
        assertEquals("FakeSpy", replaced.byPackage("com.fake.spy")?.name)
        assertEquals("FakeSpy", replaced.byCert("AABBCCDDEEFF00112233445566778899AABBCCDD")?.name)
        assertEquals("FakeSpy", replaced.byHash("0".repeat(64))?.name)
        assertNull(replaced.byPackage("not a package"))
        assertEquals(mvtFamilies, replaced.families.count { it.source == "mvt" })
        assertNotNull(replaced.byPackage("com.androidservices.support")) // RCS Lab (MVT)

        val again = ThreatDatabase.parse(replaced.toJson())
        assertEquals(replaced.version, again.version)
        assertEquals(replaced.totalIndicators, again.totalIndicators)
        assertEquals("FakeSpy", again.byPackage("com.fake.spy")?.name)
    }
}
