package com.depanalyzer.update

import com.depanalyzer.core.InputFingerprint
import com.depanalyzer.parser.Ecosystem
import com.depanalyzer.parser.ProjectType
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class TransactionalUpdateServiceTest {
    @Test
    fun `updates npm manifest and existing lockfile as one transaction`() {
        val dir = Files.createTempDirectory("npm-transaction").toFile()
        val manifest = dir.resolve("package.json").apply {
            writeText("""{"dependencies":{"lodash":"^4.17.20"}}""")
        }
        val lockfile = dir.resolve("package-lock.json").apply { writeText("""{"lockfileVersion":3}""") }
        val suggestion = UpdateSuggestion(
            "npm", "lodash", "4.17.20", "4.17.21", UpdateReason.OUTDATED,
            ecosystem = Ecosystem.NPM
        )
        val plan = UpdatePlan(
            ProjectType.NPM,
            manifest,
            listOf(suggestion),
            InputFingerprint.compute(dir.toPath(), ProjectType.NPM)
        )
        val service = TransactionalUpdateService(
            updaterFactory = { NpmPackageJsonBuildFileUpdater() },
            npmLockfileSynchronizer = { project -> project.resolve("package-lock.json").writeText("""{"synced":true}""") }
        )

        val result = service.apply(dir, plan, setOf(suggestion.suggestionId))

        assertEquals("APPLIED", result.status)
        assertEquals("UPDATED", result.lockfileStatus)
        assertTrue(manifest.readText().contains("^4.17.21"))
        assertTrue(lockfile.readText().contains("synced"))
        assertTrue(result.backupFiles.all { File(it).isFile })
    }

    @Test
    fun `rolls back manifest and lockfile when npm synchronization fails`() {
        val dir = Files.createTempDirectory("npm-rollback").toFile()
        val manifest = dir.resolve("package.json").apply {
            writeText("""{"dependencies":{"lodash":"^4.17.20"}}""")
        }
        val lockfile = dir.resolve("package-lock.json").apply { writeText("""{"lockfileVersion":3}""") }
        val originalManifest = manifest.readText()
        val originalLockfile = lockfile.readText()
        val suggestion = UpdateSuggestion(
            "npm", "lodash", "4.17.20", "4.17.21", UpdateReason.OUTDATED,
            ecosystem = Ecosystem.NPM
        )
        val plan = UpdatePlan(
            ProjectType.NPM,
            manifest,
            listOf(suggestion),
            InputFingerprint.compute(dir.toPath(), ProjectType.NPM)
        )
        val service = TransactionalUpdateService(
            updaterFactory = { NpmPackageJsonBuildFileUpdater() },
            npmLockfileSynchronizer = { error("network unavailable") }
        )

        assertFailsWith<IllegalStateException> {
            service.apply(dir, plan, setOf(suggestion.suggestionId))
        }
        assertEquals(originalManifest, manifest.readText())
        assertEquals(originalLockfile, lockfile.readText())
    }
}
