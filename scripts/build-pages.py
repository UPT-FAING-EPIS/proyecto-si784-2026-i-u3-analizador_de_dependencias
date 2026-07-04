from __future__ import annotations

import argparse
import json
from collections import Counter
import html
import shutil
import sys
from pathlib import Path

import markdown


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
SITE_DIR = ROOT / "build" / "pages-site"


def load_json(path: Path) -> object | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def relative_stylesheet(index_path: Path) -> str:
    relative_root = "../" * len(index_path.relative_to(SITE_DIR).parents[:-1])
    return f"{relative_root}assets/site.css"


def raw_links(destination: Path, files: list[tuple[str, str]]) -> str:
    links = [
        f'<li><a href="{html.escape(filename)}">{html.escape(label)}</a></li>'
        for filename, label in files
        if (destination / filename).exists()
    ]
    if not links:
        return ""
    return f"<h2>Artefactos publicados</h2><ul>{''.join(links)}</ul>"


def table_from_counts(headers: tuple[str, str], counts: Counter[str]) -> str:
    if not counts:
        return "<p>No hay datos para mostrar.</p>"
    rows = "\n".join(
        f"<tr><td>{html.escape(name)}</td><td>{count}</td></tr>"
        for name, count in counts.most_common()
    )
    return f"""<table>
  <thead><tr><th>{html.escape(headers[0])}</th><th>{html.escape(headers[1])}</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def write_html_page(destination: Path, title: str, body: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    index_path = destination / "index.html"
    index_path.write_text(
        f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <link rel="stylesheet" href="{relative_stylesheet(index_path)}">
</head>
<body>
  <main class="page">
    <h1>{html.escape(title)}</h1>
    {body}
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


def title_for(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.startswith("**Informe") and line.endswith("**"):
            return line.removeprefix("**").removesuffix("**").strip()
    for line in lines:
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem.replace("-", " ")


def render_markdown(source: Path, destination: Path) -> None:
    raw = source.read_text(encoding="utf-8")
    raw = raw.replace(
        "<center>",
        '<section class="document-cover" markdown="1">',
    ).replace("</center>", "</section>")
    body = markdown.markdown(
        raw,
        extensions=["extra", "md_in_html", "toc", "tables", "fenced_code", "sane_lists"],
        output_format="html5",
    )
    title = html.escape(title_for(source))
    relative_root = "../" * len(destination.relative_to(SITE_DIR).parents[:-1])
    stylesheet = f"{relative_root}assets/site.css"
    page = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <link rel="stylesheet" href="{stylesheet}">
</head>
<body>
  <main class="page">
    {body}
  </main>
</body>
</html>
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(page, encoding="utf-8")


def copy_tree_if_exists(source: Path, destination: Path) -> None:
    if source.exists():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)


def write_status_page(destination: Path, title: str, body: str) -> None:
    write_html_page(destination, title, f"<p>{html.escape(body)}</p>")


def write_sonar_report(destination: Path) -> None:
    data = load_json(destination / "status.json")
    artifact_links = raw_links(destination, [("status.json", "Estado JSON")])
    if not isinstance(data, dict):
        body = """
<p>El estado de SonarCloud todavia no fue publicado para esta ejecucion.</p>
"""
        write_html_page(destination, "Reporte Sonar", body + artifact_links)
        return

    status = str(data.get("status", "unknown"))
    if status == "submitted":
        url = str(data.get("url", ""))
        link = (
            f'<p><a href="{html.escape(url)}">Abrir proyecto en SonarCloud</a></p>'
            if url
            else ""
        )
        body = f"""
<p class="status-ok">Quality Gate enviado a SonarCloud.</p>
{link}
"""
    elif status == "not-configured":
        secret = html.escape(str(data.get("requiredSecret", "SONAR_TOKEN")))
        body = f"""
<p class="status-warn">SonarCloud no se ejecuto porque falta el secreto <code>{secret}</code>.</p>
<p>Configura el token en GitHub Actions y vuelve a ejecutar el workflow de Pages para publicar el resultado real.</p>
"""
    else:
        body = f"""
<p>Estado reportado por SonarCloud: <code>{html.escape(status)}</code>.</p>
"""
    write_html_page(destination, "Reporte Sonar", body + artifact_links)


def write_semgrep_report(destination: Path) -> None:
    data = load_json(destination / "semgrep.json")
    artifact_links = raw_links(
        destination,
        [("semgrep.json", "Resultado JSON"), ("semgrep.sarif", "Resultado SARIF")],
    )
    if not isinstance(data, dict):
        body = """
<p>El resultado de Semgrep todavia no fue publicado para esta ejecucion.</p>
"""
        write_html_page(destination, "Reporte Semgrep", body + artifact_links)
        return

    results = data.get("results", [])
    findings = results if isinstance(results, list) else []
    severity_counts: Counter[str] = Counter()
    check_counts: Counter[str] = Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra", {})
        severity = "UNKNOWN"
        if isinstance(extra, dict):
            metadata = extra.get("metadata", {})
            metadata_severity = metadata.get("severity") if isinstance(metadata, dict) else None
            severity = str(extra.get("severity") or metadata_severity or "UNKNOWN")
        severity_counts[severity] += 1
        check_counts[str(finding.get("check_id", "unknown"))] += 1

    body = f"""
<p>Semgrep encontro <strong>{len(findings)}</strong> hallazgos en el analisis estatico.</p>
<h2>Hallazgos por severidad</h2>
{table_from_counts(("Severidad", "Hallazgos"), severity_counts)}
<h2>Reglas mas frecuentes</h2>
{table_from_counts(("Regla", "Hallazgos"), Counter(dict(check_counts.most_common(10))))}
"""
    write_html_page(destination, "Reporte Semgrep", body + artifact_links)


def snyk_projects(data: object) -> list[dict[str, object]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def write_snyk_report(destination: Path) -> None:
    data = load_json(destination / "snyk.json")
    artifact_links = raw_links(destination, [("snyk.json", "Resultado JSON")])
    if not isinstance(data, (dict, list)):
        body = """
<p>El resultado de Snyk todavia no fue publicado para esta ejecucion.</p>
"""
        write_html_page(destination, "Reporte Snyk", body + artifact_links)
        return

    if isinstance(data, dict) and data.get("status") == "not-configured":
        secret = html.escape(str(data.get("requiredSecret", "SNYK_TOKEN")))
        body = f"""
<p class="status-warn">Snyk no se ejecuto porque falta el secreto <code>{secret}</code>.</p>
<p>Configura el token en GitHub Actions y vuelve a ejecutar el workflow de Pages para publicar vulnerabilidades reales.</p>
"""
        write_html_page(destination, "Reporte Snyk", body + artifact_links)
        return

    projects = snyk_projects(data)
    vulnerabilities: list[dict[str, object]] = []
    for project in projects:
        project_vulnerabilities = project.get("vulnerabilities", [])
        if isinstance(project_vulnerabilities, list):
            vulnerabilities.extend(item for item in project_vulnerabilities if isinstance(item, dict))

    severity_counts = Counter(str(item.get("severity", "unknown")) for item in vulnerabilities)
    unique_ids = {str(item.get("id")) for item in vulnerabilities if item.get("id")}
    body = f"""
<p>Snyk analizo <strong>{len(projects)}</strong> proyecto(s) y reporto <strong>{len(vulnerabilities)}</strong> vulnerabilidades.</p>
<p>Vulnerabilidades unicas: <strong>{len(unique_ids)}</strong>.</p>
<h2>Vulnerabilidades por severidad</h2>
{table_from_counts(("Severidad", "Vulnerabilidades"), severity_counts)}
"""
    write_html_page(destination, "Reporte Snyk", body + artifact_links)


def write_quality_report_pages(reports_root: Path) -> None:
    write_sonar_report(reports_root / "sonar")
    write_semgrep_report(reports_root / "semgrep")
    write_snyk_report(reports_root / "snyk")


def write_reports_index(destination: Path) -> None:
    reports = [
        ("coverage", "Cobertura JaCoCo", "Cobertura de líneas con umbral mínimo del 70%."),
        ("mutation", "Mutación PIT", "Mutation score y mutantes detectados por la suite."),
        ("bdd", "BDD Cucumber", "Escenarios ejecutables en formato Dado/Cuando/Entonces."),
        ("interface", "Interfaz Playwright", "Reporte, trazas y videos de la interfaz documental."),
        ("unit", "Pruebas unitarias", "Resultados JUnit de reglas y componentes aislados."),
        ("integration", "Pruebas de integración", "Resultados de colaboración entre módulos."),
        ("sonar", "Sonar", "Quality Gate y cobertura enviados a SonarCloud."),
        ("semgrep", "Semgrep", "Análisis estático y reporte SARIF/JSON."),
        ("snyk", "Snyk", "Análisis de vulnerabilidades de dependencias."),
    ]
    links = "\n".join(
        f'<li><a href="{slug}/">{html.escape(title)}</a>: {html.escape(description)}</li>'
        for slug, title, description in reports
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "index.html").write_text(
        f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reportes de pruebas y calidad</title>
  <link rel="stylesheet" href="../assets/site.css">
</head>
<body>
  <main class="page">
    <h1>Reportes de pruebas y calidad</h1>
    <p>Índice de evidencias generadas automáticamente para la misma revisión del código.</p>
    <ul class="report-grid">{links}</ul>
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


def main() -> int:
    if SITE_DIR.exists():
        shutil.rmtree(SITE_DIR)
    SITE_DIR.mkdir(parents=True)

    assets_dir = SITE_DIR / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    (assets_dir / "site.css").write_text(
        """
:root { color-scheme: light; font-family: Arial, Helvetica, sans-serif; }
body { margin: 0; background: #f6f7f9; color: #20242a; }
.page { max-width: 1040px; margin: 0 auto; padding: 32px 24px 56px; background: #fff; min-height: 100vh; }
h1, h2, h3 { color: #17202a; line-height: 1.2; }
a { color: #0a58ca; }
.status-ok { color: #146c2e; font-weight: 700; }
.status-warn { color: #8a4b00; font-weight: 700; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; }
th, td { border: 1px solid #d6d9de; padding: 8px 10px; vertical-align: top; }
th { background: #eef1f5; }
pre { overflow: auto; background: #f0f2f5; padding: 12px; border-radius: 6px; }
code { background: #f0f2f5; padding: 1px 4px; border-radius: 4px; }
img { max-width: 100%; }
.document-cover { min-height: 82vh; display: flex; flex-direction: column; justify-content: center; text-align: center; }
.document-cover img { width: min(180px, 45vw); margin: 0 auto 20px; }
.document-cover p { margin: 6px 0; }
.report-grid { display: grid; gap: 12px; padding-left: 20px; }
.report-grid li { padding: 8px; }
@media (max-width: 600px) {
  .page { padding: 20px 14px 40px; overflow-wrap: anywhere; }
  .document-cover { min-height: auto; padding: 24px 0 40px; }
  table { display: block; overflow-x: auto; }
}
""".strip(),
        encoding="utf-8",
    )

    copy_tree_if_exists(DOCS_DIR / "media", SITE_DIR / "media")

    for source in DOCS_DIR.rglob("*.md"):
        rel = source.relative_to(DOCS_DIR)
        destination = SITE_DIR / rel.with_suffix(".html")
        if rel.name.lower() == "readme.md":
            destination = SITE_DIR / rel.parent / "index.html"
        render_markdown(source, destination)

    reports_root = SITE_DIR / "reports"
    write_reports_index(reports_root)
    for name in [
        "coverage",
        "sonar",
        "semgrep",
        "snyk",
        "unit",
        "integration",
        "mutation",
        "interface",
        "bdd",
    ]:
        target = reports_root / name
        if not (target / "index.html").exists():
            write_status_page(
                target,
                f"Reporte {name}",
                "Este reporte se genera durante el workflow de GitHub Pages o requiere configuración de secretos.",
            )

    write_quality_report_pages(reports_root)

    api_docs = SITE_DIR / "api-docs"
    if not (api_docs / "index.html").exists():
        write_status_page(
            api_docs,
            "Documentación autogenerada",
            "La documentación Dokka se copia aquí cuando la tarea de generación finaliza correctamente.",
        )

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--render-quality-reports",
        action="store_true",
        help="Regenerate Sonar, Semgrep, and Snyk report pages in the existing Pages site.",
    )
    args = parser.parse_args()
    if args.render_quality_reports:
        write_quality_report_pages(SITE_DIR / "reports")
        sys.exit(0)
    sys.exit(main())
