import * as vscode from "vscode";
import { countFindings } from "./findings-groups.js";
import type { Finding } from "./models.js";
import type { DependencyReport } from "./models.js";
import {
  ossIndexQueryLabel,
  ossIndexQueryResult,
  type OssIndexQueryResult
} from "./oss-index-status.js";

export class SummaryViewProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private findings: Finding[] = [];
  private projectName = "Workspace";
  private status = "Listo para analizar";
  private coverage: "COMPLETE" | "FALLBACK" | "UNAVAILABLE" = "UNAVAILABLE";
  private ossTokenConfigured = false;
  private ossQueryResult: OssIndexQueryResult = "not-run";

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.onDidReceiveMessage((message: { command?: string }) => {
      if (message.command) void vscode.commands.executeCommand(message.command);
    });
    this.render();
  }

  update(
    projectName: string,
    findings: Finding[],
    report: DependencyReport,
    status = "Análisis completado",
    ossTokenConfigured = this.ossTokenConfigured
  ): void {
    this.projectName = projectName;
    this.findings = findings;
    this.status = status;
    this.coverage = report.analysis?.vulnerabilityCoverage ?? "UNAVAILABLE";
    this.ossTokenConfigured = ossTokenConfigured;
    this.ossQueryResult = ossIndexQueryResult(report);
    this.render();
  }

  updateOssConfiguration(configured: boolean): void {
    this.ossTokenConfigured = configured;
    this.render();
  }

  showStatus(status: string): void {
    this.status = status;
    this.render();
  }

  clear(): void {
    this.findings = [];
    this.projectName = "Workspace";
    this.status = "Listo para analizar";
    this.coverage = "UNAVAILABLE";
    this.ossQueryResult = "not-run";
    this.render();
  }

  private render(): void {
    if (!this.view) return;
    const counts = countFindings(this.findings);
    const urgent = this.findings
      .filter((item) => item.severity === "CRITICAL" || item.severity === "HIGH")
      .slice(0, 3);
    this.view.webview.html = `<!doctype html><html lang="es"><head><meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <style>
        *{box-sizing:border-box}body{margin:0;padding:10px;color:var(--vscode-foreground);font-family:var(--vscode-font-family);font-size:12px}
        .status{display:flex;gap:8px;align-items:center;margin-bottom:10px}.dot{width:8px;height:8px;border-radius:50%;background:var(--vscode-testing-iconPassed)}
        h2{font-size:13px;margin:0 0 2px}.muted{color:var(--vscode-descriptionForeground)}
        .provider{margin:10px 0;padding:9px;border:1px solid var(--vscode-panel-border);border-left:3px solid var(--provider-tone);border-radius:4px}.provider.configured{--provider-tone:var(--vscode-testing-iconPassed)}.provider.unconfigured{--provider-tone:var(--vscode-editorWarning-foreground)}.provider-title{display:flex;justify-content:space-between;align-items:center;gap:6px}.provider strong{font-size:12px}.provider-state{font-weight:700;color:var(--provider-tone)}.provider button{margin-top:8px}
        .metrics{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:10px 0}.metric{padding:8px;border:1px solid var(--vscode-panel-border);border-radius:4px}
        .metric strong{display:block;font-size:17px}.danger{color:var(--vscode-errorForeground)}
        button{width:100%;border:0;padding:7px;background:var(--vscode-button-background);color:var(--vscode-button-foreground);cursor:pointer}
        button:hover{background:var(--vscode-button-hoverBackground)}ul{list-style:none;padding:0;margin:10px 0}li{padding:5px 0;border-bottom:1px solid var(--vscode-panel-border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      </style></head><body>
      <div class="status"><span class="dot"></span><div><h2>${escapeHtml(this.projectName)}</h2><span class="muted">${escapeHtml(this.status)}</span></div></div>
      <div class="provider ${this.ossTokenConfigured ? "configured" : "unconfigured"}">
        <div class="provider-title"><strong>OSS Index</strong><span class="provider-state">${this.ossTokenConfigured ? "Configurado" : "No configurado"}</span></div>
        <div class="muted">${escapeHtml(ossIndexQueryLabel(this.ossQueryResult))}</div>
        ${this.ossTokenConfigured ? "" : '<button data-command="depanalyzer.configureOssIndex">Configurar</button>'}
      </div>
      <div class="metrics">
        <div class="metric"><strong class="${counts.critical ? "danger" : ""}">${this.coverage === "UNAVAILABLE" ? "N/D" : counts.critical}</strong><span>Críticas</span></div>
        <div class="metric"><strong>${counts.high}</strong><span>Altas</span></div>
        <div class="metric"><strong>${this.coverage === "UNAVAILABLE" ? "N/D" : counts.vulnerabilities}</strong><span>Vulnerabilidades</span></div>
        <div class="metric"><strong>${counts.outdated}</strong><span>Desactualizadas</span></div>
      </div>
      ${urgent.length ? `<div class="muted">Prioridad inmediata</div><ul>${urgent.map((item) => `<li title="${escapeHtml(item.coordinate)}">${escapeHtml(item.coordinate)}</li>`).join("")}</ul>` : ""}
      <button data-command="depanalyzer.openDashboard">Abrir dashboard</button>
      <script>const vscode=acquireVsCodeApi();document.querySelectorAll('[data-command]').forEach(b=>b.addEventListener('click',()=>vscode.postMessage({command:b.dataset.command})))</script>
      </body></html>`;
  }
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
