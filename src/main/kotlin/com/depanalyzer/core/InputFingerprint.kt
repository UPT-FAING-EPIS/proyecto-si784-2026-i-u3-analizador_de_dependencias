package com.depanalyzer.core

import com.depanalyzer.parser.ProjectType
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

object InputFingerprint {
    fun compute(projectDir: Path, projectType: ProjectType): String {
        val files = when (projectType) {
            ProjectType.MAVEN -> listOf("pom.xml")
            ProjectType.GRADLE_GROOVY -> listOf("build.gradle", "gradle.lockfile")
            ProjectType.GRADLE_KOTLIN -> listOf("build.gradle.kts", "gradle/libs.versions.toml", "gradle.lockfile")
            ProjectType.NPM -> listOf("package.json", "package-lock.json")
            ProjectType.PYTHON_POETRY -> listOf("pyproject.toml", "poetry.lock")
            ProjectType.PYTHON_REQUIREMENTS -> listOf("requirements.txt")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        files.map(projectDir::resolve)
            .filter(Files::isRegularFile)
            .sortedBy { it.toString().replace('\\', '/') }
            .forEach { file ->
                digest.update(projectDir.relativize(file).toString().replace('\\', '/').toByteArray(StandardCharsets.UTF_8))
                digest.update(0)
                digest.update(Files.readAllBytes(file))
                digest.update(0)
            }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
