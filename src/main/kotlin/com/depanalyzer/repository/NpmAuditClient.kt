package com.depanalyzer.repository

import com.depanalyzer.parser.Ecosystem
import com.depanalyzer.parser.ParsedDependency
import com.depanalyzer.report.AffectedDependency
import com.depanalyzer.report.Vulnerability
import com.depanalyzer.report.VulnerabilitySeverity
import com.depanalyzer.report.VulnerabilitySource
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.File
import java.time.Instant
import java.util.concurrent.TimeUnit

data class NpmAuditProcessResult(val exitCode: Int, val stdout: String, val stderr: String)

class NpmAuditClient(
    private val runner: (File) -> NpmAuditProcessResult = ::runNpmAudit
) {
    private val mapper = JsonMapper.builder().build()

    fun getVulnerabilities(
        projectDir: File,
        dependencies: List<ParsedDependency>
    ): Map<String, List<Vulnerability>> {
        require(File(projectDir, "package-lock.json").isFile) {
            "npm audit requiere package-lock.json"
        }
        val result = runner(projectDir)
        require(result.exitCode == 0 || result.exitCode == 1) {
            "npm audit fallo con codigo ${result.exitCode}: ${result.stderr.takeLast(1000)}"
        }
        val root = mapper.readTree(result.stdout)
        require(root.path("auditReportVersion").intValue() == 2) {
            "npm audit devolvio un formato no compatible"
        }
        val entries = root.path("vulnerabilities")
        if (!entries.isObject) return emptyMap()
        val byName = entries.properties().associate { it.key to it.value }
        val dependenciesByName = dependencies
            .filter { it.ecosystem == Ecosystem.NPM && !it.version.isNullOrBlank() }
            .groupBy(ParsedDependency::packageName)

        val resultMap = mutableMapOf<String, MutableList<Vulnerability>>()
        byName.forEach { (packageName, entry) ->
            val advisories = resolveAdvisories(packageName, byName, mutableSetOf())
            dependenciesByName[packageName].orEmpty().forEach { dependency ->
                val version = requireNotNull(dependency.version)
                val affected = AffectedDependency(
                    dependency.groupId,
                    dependency.artifactId,
                    version,
                    Ecosystem.NPM
                )
                val key = "${dependency.groupId}:${dependency.artifactId}:$version"
                val mapped = advisories.map { advisory -> advisory.toVulnerability(affected, entry) }
                if (mapped.isNotEmpty()) {
                    resultMap.getOrPut(key) { mutableListOf() }.addAll(mapped)
                }
            }
        }
        return resultMap.mapValues { (_, values) -> values.distinctBy(Vulnerability::cveId) }
    }

    private fun resolveAdvisories(
        packageName: String,
        entries: Map<String, JsonNode>,
        visiting: MutableSet<String>
    ): List<JsonNode> {
        if (!visiting.add(packageName)) return emptyList()
        val entry = entries[packageName] ?: return emptyList()
        val result = mutableListOf<JsonNode>()
        entry.path("via").forEach { via ->
            if (via.isTextual) {
                result.addAll(resolveAdvisories(via.stringValue(), entries, visiting))
            } else if (via.isObject) {
                result.add(via)
            }
        }
        visiting.remove(packageName)
        return result.distinctBy { advisoryId(it) }
    }

    private fun JsonNode.toVulnerability(
        affected: AffectedDependency,
        packageEntry: JsonNode
    ): Vulnerability {
        val id = advisoryId(this)
        val score = path("cvss").path("score").takeUnless { it.isMissingNode || it.isNull }?.doubleValue()
        val severityText = path("severity").textOrBlank().ifBlank { packageEntry.path("severity").textOrBlank() }
        val severity = when (severityText.lowercase()) {
            "critical" -> VulnerabilitySeverity.CRITICAL
            "high" -> VulnerabilitySeverity.HIGH
            "moderate", "medium" -> VulnerabilitySeverity.MEDIUM
            "low", "info" -> VulnerabilitySeverity.LOW
            else -> VulnerabilitySeverity.fromCvssScore(score)
        }
        val title = path("title").textOrBlank().ifBlank { "Vulnerabilidad reportada por npm audit" }
        return Vulnerability(
            cveId = id,
            severity = severity,
            cvssScore = score,
            description = title,
            affectedDependency = affected,
            source = VulnerabilitySource.NPM_AUDIT,
            retrievedAt = Instant.now(),
            referenceUrl = path("url").textOrBlank().ifBlank { null },
            advisoryId = id,
            title = title,
            cwes = path("cwe").mapNotNull { it.textOrBlank().ifBlank { null } },
            aliases = emptyList()
        )
    }

    private fun advisoryId(node: JsonNode): String {
        val url = node.path("url").textOrBlank()
        val fromUrl = url.substringAfterLast('/').takeIf { it.startsWith("GHSA-") || it.startsWith("CVE-") }
        return fromUrl ?: "NPM-${node.path("source").textOrBlank().ifBlank { "UNKNOWN" }}"
    }

    private fun JsonNode.textOrBlank(): String =
        if (isMissingNode || isNull) "" else stringValue().trim()

    companion object {
        private fun runNpmAudit(projectDir: File): NpmAuditProcessResult {
            val npm = if (System.getProperty("os.name").lowercase().contains("win")) "npm.cmd" else "npm"
            val process = ProcessBuilder(npm, "audit", "--json", "--ignore-scripts")
                .directory(projectDir)
                .start()
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            if (!process.waitFor(5, TimeUnit.MINUTES)) {
                process.destroyForcibly()
                error("npm audit excedio 5 minutos")
            }
            return NpmAuditProcessResult(process.exitValue(), stdout, stderr)
        }
    }
}
