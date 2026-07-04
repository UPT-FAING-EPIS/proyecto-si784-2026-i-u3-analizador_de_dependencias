import assert from "node:assert/strict";
import test from "node:test";
import type { DependencyReport } from "./models.js";
import { ossIndexQueryLabel, ossIndexQueryResult } from "./oss-index-status.js";

function report(status: string, used: string[], coverage: "COMPLETE" | "FALLBACK" | "UNAVAILABLE"): DependencyReport {
  return {
    schemaVersion: "1.3",
    projectName: "fixture",
    analysis: {
      requestedMode: "STATIC",
      actualMode: "STATIC",
      projectType: "NPM",
      durationMs: 10,
      vulnerabilityCoverage: coverage,
      warnings: [],
      providers: {
        requested: "AUTO",
        used,
        warnings: [],
        statuses: { OSS_INDEX: status }
      }
    }
  };
}

test("OSS Index state is not run before an analysis report exists", () => {
  assert.equal(ossIndexQueryResult(), "not-run");
  assert.equal(ossIndexQueryLabel("not-run"), "Análisis todavía no ejecutado");
});

test("OSS Index state reports a successful consultation", () => {
  assert.equal(ossIndexQueryResult(report("AVAILABLE", ["OSS_INDEX"], "COMPLETE")), "available");
  assert.equal(ossIndexQueryLabel("available"), "Última consulta correcta");
});

test("OSS Index state explains npm audit fallback", () => {
  assert.equal(ossIndexQueryResult(report("UNAVAILABLE", ["NPM_AUDIT"], "FALLBACK")), "fallback");
  assert.equal(ossIndexQueryLabel("fallback"), "Última consulta fallida · usando npm audit");
});

test("OSS Index state keeps a provider failure distinct when no fallback ran", () => {
  assert.equal(ossIndexQueryResult(report("UNAVAILABLE", [], "UNAVAILABLE")), "failed");
  assert.equal(ossIndexQueryLabel("failed"), "Última consulta fallida");
});
