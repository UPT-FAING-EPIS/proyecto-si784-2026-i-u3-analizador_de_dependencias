# Changelog

## 0.4.1

- Corrige el guardado de `analysisMode` en la configuración de cada carpeta del workspace.

## 0.4.0

- Fallback automático a `npm audit` cuando OSS Index no está disponible.
- Cobertura de vulnerabilidades explícita: completa, alternativa o no evaluada.
- Clasificación directa/transitiva mediante el árbol y rutas hasta la dependencia raíz.
- Colores semánticos, identificadores CVE/GHSA e inspector educativo.
- Token de OSS Index almacenado con SecretStorage.
- Revisión única de actualizaciones con accesos “Solo seguridad” y “Solo parches”.
- Hallazgos agrupados por dependencia y versión, conservando cada CVE/GHSA en el inspector.
- Árbol canónico sin nodos repetidos, con ruta principal y consulta de rutas alternativas.
- Filas alineadas con chevron propio e inspectores desplazables solo cuando desbordan la vista.

## 0.3.0

- Nuevo dashboard único con resumen gráfico, hallazgos paginados, inspector y árbol expandible.
- Barra lateral reducida a métricas, prioridades y navegación.
- Planes reutilizables con huella de entrada y progreso cancelable.
- Aplicación transaccional sin recalcular versiones, con backups únicos y rollback.
- Sincronización segura de `package-lock.json` sin ejecutar scripts de npm.
- Reanálisis posterior en segundo plano.

## 0.2.1

- Unidad 2 pasa a ser la fuente oficial del CLI, la extension y sus integraciones.
- Requiere CLI 2.2.1 para paridad completa, planes seguros y arboles de dependencias.
- Actualiza enlaces de Marketplace, documentacion y distribucion al repositorio de Unidad 2.

## 0.2.0

- Paridad de analisis preciso con la TUI mediante CLI 2.2.0 y reporte 1.1.
- Progreso cancelable de 30 minutos, salida real de Maven/Gradle y reportes temporales grandes.
- Resultados independientes para workspaces con varias carpetas y control de ejecuciones obsoletas.
- Hallazgos separados en CVE directas/transitivas, desactualizadas y versiones no resueltas.
- Arbol de dependencias jerarquico con filtros y cadenas completas en el panel de detalle.
- Estado del modo, proveedores, advertencias, hora y duracion del ultimo analisis.
- Compatibilidad limitada con CLI antiguo, actualizacion guiada y redeteccion de capacidades.

## 0.1.3

- Centro visual para seleccionar y preparar una o varias actualizaciones.
- Confirmacion explicita, copia temporal, comparacion de cambios y reanalisis posterior.
- Versiones desconocidas presentadas como `Version no detectada`, sin actualizaciones inseguras.
- Accion para activar el analisis dinamico y resolver versiones administradas por Maven o Gradle.
- Panel de detalle ampliado con impacto, recomendacion, datos tecnicos y colores por severidad.
- Mensajes claros cuando el CLI instalado no permite planes de actualizacion seguros.

## 0.1.2

- Vista lateral agrupada por severidad, dependencias desactualizadas y hallazgos sin ubicacion.
- Panel visual de detalle para vulnerabilidades y actualizaciones.
- Acciones desde la vista para abrir archivo, ver referencia CVE y aplicar actualizaciones sugeridas.
- Estados vacios y errores mas claros.
- Icono monocromatico optimizado para la barra de actividad de VS Code.

## 0.1.1

- Compatibilidad automática con versiones del CLI que generan `dependency-report.json`.
- Mensajes claros cuando el CLI todavía no admite planes o aplicación de actualizaciones.

## 0.1.0

- Primera publicación pública de DepAnalyzer Security.
- Vista lateral de dependencias.
- Diagnósticos, hover y Quick Fix.
- Análisis automático, manual y al guardar.
- Soporte para Maven, Gradle, npm, Poetry y requirements.
