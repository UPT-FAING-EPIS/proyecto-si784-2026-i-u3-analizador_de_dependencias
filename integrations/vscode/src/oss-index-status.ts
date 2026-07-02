import type { DependencyReport } from "./models.js";

export type OssIndexQueryResult = "not-run" | "available" | "fallback" | "failed";

export interface OssIndexStatus {
  configured: boolean;
  queryResult: OssIndexQueryResult;
}

export function ossIndexQueryResult(report?: DependencyReport): OssIndexQueryResult {
  const providers = report?.analysis?.providers;
  if (!providers) return "not-run";
  const status = providers.statuses?.OSS_INDEX;
  if (status === "AVAILABLE") return "available";
  if (
    providers.used.includes("NPM_AUDIT") &&
    (status === "UNAVAILABLE" || status === "DEGRADED" || report.analysis?.vulnerabilityCoverage === "FALLBACK")
  ) {
    return "fallback";
  }
  if (status === "UNAVAILABLE" || status === "DEGRADED") return "failed";
  return "not-run";
}

export function ossIndexQueryLabel(result: OssIndexQueryResult): string {
  switch (result) {
    case "available": return "Última consulta correcta";
    case "fallback": return "Última consulta fallida · usando npm audit";
    case "failed": return "Última consulta fallida";
    case "not-run": return "Análisis todavía no ejecutado";
  }
}
