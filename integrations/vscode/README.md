# DepAnalyzer Security

Analiza dependencias vulnerables y desactualizadas sin salir de Visual Studio Code.

## Funciones

- Vista **DepAnalyzer** en la barra de actividad.
- Resumen compacto en la barra lateral y dashboard central reutilizable.
- Pestañas de resumen, hallazgos, dependencias y actualizaciones con búsqueda, filtros y paginación.
- Hallazgos agrupados por dependencia y versión, con todos sus CVE/GHSA en un inspector desplazable.
- Gráficos del estado actual y árbol sin repeticiones, con ruta principal y consulta de rutas alternativas.
- Centro de actualizaciones transaccional para revisar y seleccionar cambios individuales o múltiples.
- Confirmacion, copia previa, comparacion visual y reanalisis despues de actualizar.
- Accesos rapidos para abrir el archivo afectado, ver la referencia CVE o preparar una actualizacion.
- Ayuda para activar el analisis dinamico cuando una version no puede detectarse.
- Análisis manual, automático y al guardar.
- Diagnósticos directamente en archivos Maven, Gradle, npm y Python.
- Información de CVE, severidad, CVSS y enlaces desde el editor.
- Quick Fix para aplicar actualizaciones directas aprobadas.
- Proveedores OSS Index y NVD mediante el CLI de DepAnalyzer.
- Fallback a `npm audit` para proyectos npm cuando OSS Index no está configurado.
- Identificadores CVE/GHSA, cobertura visible y guía segura para guardar el token de OSS Index.

## CLI incluido

La extensión 0.4.0 incluye el CLI 2.3.0 compatible y lo selecciona automáticamente. No es necesario
instalar ni configurar `depanalyzer` por separado. Se requiere Java 25 o posterior.

`depanalyzer.executablePath` queda disponible únicamente para desarrollo o para reemplazar
explícitamente el CLI incluido.

### Instalación externa opcional

### Windows

Con Scoop:

```powershell
scoop bucket add andre https://github.com/andre-carbajal/scoop-bucket
scoop install andre/depanalyzer
scoop update depanalyzer
```

También puedes descargar `depanalyzer-windows-amd64.zip` desde
[GitHub Releases](https://github.com/UPT-FAING-EPIS/proyecto-si784-2026-i-u2-analizador-de-dependencias-2/releases),
descomprimirlo y configurar:

```json
{
  "depanalyzer.executablePath": "C:\\ruta\\depanalyzer.exe"
}
```

### macOS y Linux

```bash
brew tap andre-carbajal/homebrew-tap
brew install depanalyzer
```

También puedes usar Snap:

```bash
sudo snap install depanalyzer
```

Si el ejecutable está disponible en `PATH`, no necesitas configurar `depanalyzer.executablePath`.

## Primer análisis

1. Abre un proyecto que contenga `pom.xml`, `build.gradle`, `build.gradle.kts`, `package.json`,
   `pyproject.toml` o `requirements.txt`.
2. Selecciona el icono **DepAnalyzer** de la barra lateral.
3. Ejecuta `DepAnalyzer: Analizar Workspace` desde la paleta de comandos.
4. Elige **analisis preciso** para ejecutar Maven/Gradle y obtener las mismas versiones, transitivas y cadenas que la TUI.
5. Revisa el dashboard; abre cada hallazgo en el inspector y expande solo las raíces necesarias.
6. Usa las acciones del inspector para saltar al archivo o revisar la referencia CVE.

## Actualizar dependencias

1. Abre el dashboard y selecciona **Actualizaciones**.
2. El CLI reutiliza el último reporte válido para generar el plan sin repetir consultas.
3. Marca explicitamente las propuestas que deseas aplicar. Las correcciones de seguridad aparecen primero.
4. Revisa la version actual, la version nueva, el tipo de cambio y el archivo afectado.
5. Pulsa **Aplicar seleccionadas** y confirma la lista exacta de cambios.
6. DepAnalyzer crea backups únicos, sincroniza el lockfile npm sin ejecutar scripts, abre una comparación y
   reanaliza el workspace en segundo plano. Si algo falla, revierte todos los archivos.

Tambien puedes abrir una dependencia y usar **Preparar actualizacion** para llegar al centro con esa propuesta
preseleccionada. Si aparece **Version no detectada**, activa el analisis dinamico antes de actualizar; la extension
no aplicara un cambio cuyo origen no pueda verificar.

## Configuración

| Propiedad | Valor inicial | Descripción |
|-----------|---------------|-------------|
| `depanalyzer.executablePath` | vacío | Ruta al ejecutable; vacío utiliza `PATH`. |
| `depanalyzer.autoAnalyze` | `true` | Analiza al activar la extensión. |
| `depanalyzer.scanOnSave` | `true` | Reanaliza al guardar manifiestos. |
| `depanalyzer.analysisMode` | `ask` | `ask` pregunta una vez; `precise` ejecuta Maven/Gradle; `fast` usa archivos. |
| `depanalyzer.dynamic` | `false` | Opcion anterior, conservada solo para migracion. |
| `depanalyzer.provider` | `auto` | Selecciona `auto`, `oss` o `nvd`. |
| `depanalyzer.timeoutSeconds` | `1800` | Tiempo máximo del análisis. |

El modo preciso solo se ejecuta en workspaces confiables y con consentimiento persistido. La notificacion permite
cancelar, muestra las fases y las lineas de Maven/Gradle, y descarta resultados antiguos si empieza otro analisis.
Los reportes se guardan temporalmente fuera del proyecto y se eliminan al terminar.

Si aparece el banner de CLI antiguo, ejecuta **DepAnalyzer: Actualizar CLI** y luego
**DepAnalyzer: Volver a Detectar CLI**.

Para análisis completos se recomienda configurar `OSS_INDEX_TOKEN` y, opcionalmente, `NVD_API_KEY` en el entorno donde
se inicia Visual Studio Code.

## Privacidad

La extensión ejecuta el CLI con `--no-telemetry`. Las consultas de vulnerabilidades pueden comunicarse con OSS Index o
NVD según la configuración elegida.

## Problemas y código fuente

- [Reportar un problema](https://github.com/UPT-FAING-EPIS/proyecto-si784-2026-i-u2-analizador-de-dependencias-2/issues)
- [Código fuente](https://github.com/UPT-FAING-EPIS/proyecto-si784-2026-i-u2-analizador-de-dependencias-2)
- [Documentación](https://upt-faing-epis.github.io/proyecto-si784-2026-i-u2-analizador-de-dependencias-2/)
