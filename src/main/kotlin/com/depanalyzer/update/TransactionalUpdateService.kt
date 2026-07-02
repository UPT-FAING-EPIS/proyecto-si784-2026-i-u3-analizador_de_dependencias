package com.depanalyzer.update

import com.depanalyzer.core.InputFingerprint
import com.depanalyzer.parser.ProjectType
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

data class UpdateExecutionResult(
    val status: String,
    val buildFile: String,
    val backupFiles: List<String>,
    val changedFiles: List<String>,
    val applied: List<UpdateSuggestion>,
    val lockfileStatus: String,
    val durationMs: Long,
    val warnings: List<String> = emptyList()
)

class TransactionalUpdateService(
    private val updaterFactory: (ProjectType) -> BuildFileUpdater,
    private val npmLockfileSynchronizer: (File) -> Unit = ::syncNpmLockfile
) {
    fun apply(projectDir: File, plan: UpdatePlan, selectedIds: Set<String>): UpdateExecutionResult {
        val startedAt = System.currentTimeMillis()
        require(selectedIds.isNotEmpty()) { "Selecciona al menos una actualizacion" }
        require(plan.inputFingerprint.isNotBlank()) { "El plan no contiene una huella de entrada" }
        require(InputFingerprint.compute(projectDir.toPath(), plan.projectType) == plan.inputFingerprint) {
            "El plan esta desactualizado: los archivos de dependencias cambiaron"
        }
        val selected = plan.suggestions.filter { it.suggestionId in selectedIds }
        require(selected.size == selectedIds.size) { "El plan no contiene todas las sugerencias seleccionadas" }

        val buildFile = plan.buildFile.canonicalFile
        val projectRoot = projectDir.canonicalFile
        require(buildFile.toPath().startsWith(projectRoot.toPath())) {
            "El plan referencia un archivo fuera del proyecto"
        }

        val lockFile = if (plan.projectType == ProjectType.NPM) File(projectRoot, "package-lock.json")
            .takeIf { it.isFile } else null
        val originals = linkedMapOf(buildFile to buildFile.readBytes())
        lockFile?.let { originals[it] = it.readBytes() }
        val backupDir = File(projectRoot, ".depanalyzer-backups").apply { mkdirs() }
        val stamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now()).replace(':', '-')
        val backups = originals.map { (file, bytes) ->
            File(backupDir, "$stamp-${file.name}.bak").also { it.writeBytes(bytes) }
        }

        try {
            val updater = updaterFactory(plan.projectType)
            selected.forEach { suggestion ->
                require(updater.applyUpdate(buildFile, suggestion)) {
                    "No se encontro una coincidencia editable para ${suggestion.coordinate}"
                }
            }
            var lockStatus = "NOT_APPLICABLE"
            if (plan.projectType == ProjectType.NPM) {
                lockStatus = if (lockFile != null) {
                    npmLockfileSynchronizer(projectRoot)
                    "UPDATED"
                } else {
                    "NOT_PRESENT"
                }
            }
            val changed = originals.keys.filter { file ->
                !file.readBytes().contentEquals(originals.getValue(file))
            }.map { it.absolutePath }
            return UpdateExecutionResult(
                status = "APPLIED",
                buildFile = buildFile.absolutePath,
                backupFiles = backups.map { it.absolutePath },
                changedFiles = changed,
                applied = selected,
                lockfileStatus = lockStatus,
                durationMs = System.currentTimeMillis() - startedAt
            )
        } catch (error: Exception) {
            originals.forEach { (file, bytes) -> file.writeBytes(bytes) }
            throw IllegalStateException("La actualizacion fallo y se revirtieron todos los archivos: ${error.message}", error)
        }
    }

    companion object {
        private fun syncNpmLockfile(projectDir: File) {
            val npm = if (System.getProperty("os.name").lowercase().contains("win")) "npm.cmd" else "npm"
            val process = ProcessBuilder(
                npm,
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund"
            )
                .directory(projectDir)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            if (!process.waitFor(5, TimeUnit.MINUTES)) {
                process.destroyForcibly()
                error("npm excedio 5 minutos al sincronizar package-lock.json")
            }
            require(process.exitValue() == 0) { "npm no pudo sincronizar package-lock.json: ${output.takeLast(2000)}" }
        }
    }
}
