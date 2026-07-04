package com.depanalyzer.tui

import com.github.ajalt.mordant.rendering.AnsiLevel
import java.nio.charset.Charset
import java.util.concurrent.TimeUnit

private const val UTF8_CODE_PAGE = 65001

private fun detectWindowsCodePage(): Int? {
    return runCatching {
        val process = ProcessBuilder("cmd", "/c", "chcp")
            .redirectErrorStream(true)
            .start()
        if (!process.waitFor(1, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return@runCatching null
        }

        val output = process.inputStream.bufferedReader().use { it.readText() }
        Regex("""\d+""").findAll(output).lastOrNull()?.value?.toIntOrNull()
    }.getOrNull()
}

data class TerminalCapabilities(
    val ansiLevel: AnsiLevel,
    val isTty: Boolean,
    val isCi: Boolean,
    val supportsInteractiveTui: Boolean,
    val supportsUnicodeGlyphs: Boolean
)

class TerminalCapabilitiesDetector(
    private val envProvider: (String) -> String? = { System.getenv(it) },
    private val hasConsole: () -> Boolean = { System.console() != null },
    private val consoleCharsetProvider: () -> Charset? = { System.console()?.charset() },
    private val osNameProvider: () -> String = { System.getProperty("os.name").orEmpty() },
    private val windowsCodePageProvider: () -> Int? = ::detectWindowsCodePage
) {
    fun detect(noColor: Boolean = false): TerminalCapabilities {
        val isTty = hasConsole()
        val isCi = isCiEnvironment()
        val noColorEnv = envProvider("NO_COLOR") != null
        val dumbTerm = envProvider("TERM").equals("dumb", ignoreCase = true)

        val ansiLevel = if (noColor || noColorEnv || dumbTerm || isCi || !isTty) {
            AnsiLevel.NONE
        } else {
            AnsiLevel.TRUECOLOR
        }

        return TerminalCapabilities(
            ansiLevel = ansiLevel,
            isTty = isTty,
            isCi = isCi,
            supportsInteractiveTui = isTty && !isCi,
            supportsUnicodeGlyphs = supportsUnicodeGlyphs(isTty, isCi)
        )
    }

    private fun supportsUnicodeGlyphs(isTty: Boolean, isCi: Boolean): Boolean {
        val forced = envProvider("DEPANALYZER_TUI_UNICODE")?.trim()?.lowercase()
        if (forced in setOf("1", "true", "yes", "on")) return true
        if (forced in setOf("0", "false", "no", "off")) return false
        if (!isTty || isCi) return false

        val osName = osNameProvider()
        if (!osName.contains("windows", ignoreCase = true)) {
            return true
        }

        val codePage = windowsCodePageProvider()
        if (codePage != null) {
            return codePage == UTF8_CODE_PAGE
        }

        val charset = consoleCharsetProvider()?.name().orEmpty()
        return charset.equals("UTF-8", ignoreCase = true) || charset.equals("UTF8", ignoreCase = true)
    }

    private fun isCiEnvironment(): Boolean {
        val ci = envProvider("CI")
        if (ci != null && ci != "0" && !ci.equals("false", ignoreCase = true)) {
            return true
        }

        if (envProvider("GITHUB_ACTIONS").equals("true", ignoreCase = true)) {
            return true
        }

        return envProvider("JENKINS_URL") != null || envProvider("BUILD_NUMBER") != null
    }
}
