package com.depanalyzer.repository

import com.depanalyzer.parser.DependencySection
import com.depanalyzer.parser.Ecosystem
import com.depanalyzer.parser.ParsedDependency
import com.depanalyzer.report.VulnerabilitySeverity
import com.depanalyzer.report.VulnerabilitySource
import org.junit.jupiter.api.Test
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NpmAuditClientTest {
    private fun projectDir() = Files.createTempDirectory("npm-audit-client").toFile().apply {
        resolve("package-lock.json").writeText("""{"lockfileVersion":3}""")
    }

    @Test
    fun `accepts exit one and maps GHSA metadata to direct and transitive packages`() {
        val json = """
            {
              "auditReportVersion": 2,
              "vulnerabilities": {
                "express": {
                  "name": "express",
                  "severity": "high",
                  "isDirect": true,
                  "via": ["body-parser"],
                  "nodes": ["node_modules/express"]
                },
                "body-parser": {
                  "name": "body-parser",
                  "severity": "high",
                  "isDirect": false,
                  "via": [{
                    "source": 123,
                    "name": "body-parser",
                    "title": "Denial of service",
                    "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                    "severity": "high",
                    "cwe": ["CWE-400"],
                    "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/..."},
                    "range": "<2.0.0"
                  }],
                  "nodes": ["node_modules/body-parser"]
                }
              },
              "metadata": {"vulnerabilities": {"total": 2}}
            }
        """.trimIndent()
        val client = NpmAuditClient { NpmAuditProcessResult(1, json, "") }
        val dependencies = listOf(
            npmDependency("express", "1.0.0"),
            npmDependency("body-parser", "1.0.0")
        )

        val result = client.getVulnerabilities(projectDir(), dependencies)

        val direct = result.getValue("npm:express:1.0.0").single()
        val transitive = result.getValue("npm:body-parser:1.0.0").single()
        assertEquals("GHSA-aaaa-bbbb-cccc", direct.advisoryId)
        assertEquals(VulnerabilitySeverity.HIGH, transitive.severity)
        assertEquals(7.5, transitive.cvssScore)
        assertEquals(listOf("CWE-400"), transitive.cwes)
        assertEquals(VulnerabilitySource.NPM_AUDIT, transitive.source)
    }

    @Test
    fun `accepts clean exit with no vulnerabilities`() {
        val client = NpmAuditClient {
            NpmAuditProcessResult(0, """{"auditReportVersion":2,"vulnerabilities":{}}""", "")
        }

        assertTrue(client.getVulnerabilities(projectDir(), listOf(npmDependency("safe", "1.0.0"))).isEmpty())
    }

    @Test
    fun `rejects npm execution errors`() {
        val client = NpmAuditClient { NpmAuditProcessResult(2, "{}", "registry unavailable") }

        assertFailsWith<IllegalArgumentException> {
            client.getVulnerabilities(projectDir(), listOf(npmDependency("safe", "1.0.0")))
        }
    }

    private fun npmDependency(name: String, version: String) = ParsedDependency(
        groupId = "npm",
        artifactId = name,
        version = version,
        scope = "dependencies",
        section = DependencySection.DEPENDENCIES,
        ecosystem = Ecosystem.NPM
    )
}
