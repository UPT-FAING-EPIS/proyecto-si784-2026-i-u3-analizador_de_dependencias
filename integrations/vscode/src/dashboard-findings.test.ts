import assert from "node:assert/strict";
import test from "node:test";
import {
  dashboardFindingTotals,
  groupDashboardFindings
} from "./dashboard-findings.js";
import type { Finding } from "./models.js";

function vulnerability(id: string, severity: NonNullable<Finding["severity"]>, version = "4.17.4"): Finding {
  return {
    kind: "vulnerability",
    groupId: "npm",
    artifactId: "lodash",
    coordinate: "lodash",
    currentVersion: version,
    ecosystem: "NPM",
    severity,
    relationship: "transitive",
    directRoot: "jquery",
    dependencyChain: ["jquery", `lodash:${version}`],
    vulnerability: {
      cveId: id,
      advisoryId: id,
      title: `Advisory ${id}`,
      severity
    }
  };
}

function outdated(version = "4.17.4"): Finding {
  return {
    kind: "outdated",
    groupId: "npm",
    artifactId: "lodash",
    coordinate: "lodash",
    currentVersion: version,
    latestVersion: "4.18.1",
    ecosystem: "NPM",
    relationship: "transitive"
  };
}

test("groups vulnerabilities and an update for the same dependency version", () => {
  const groups = groupDashboardFindings([
    vulnerability("GHSA-low", "LOW"),
    vulnerability("GHSA-critical", "CRITICAL"),
    outdated()
  ]);

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.vulnerabilities.length, 2);
  assert.equal(groups[0]?.severity, "CRITICAL");
  assert.equal(groups[0]?.tone, "critical");
  assert.equal(groups[0]?.update?.finding.latestVersion, "4.18.1");
  assert.deepEqual(groups[0]?.paths, [["jquery", "lodash:4.17.4"]]);
});

test("keeps different installed versions in separate groups", () => {
  const groups = groupDashboardFindings([
    vulnerability("GHSA-old", "HIGH", "4.17.4"),
    vulnerability("GHSA-new", "LOW", "4.18.0")
  ]);

  assert.equal(groups.length, 2);
  assert.deepEqual(groups.map((group) => group.currentVersion).sort(), ["4.17.4", "4.18.0"]);
});

test("deduplicates the same advisory and preserves real totals", () => {
  const duplicate = vulnerability("GHSA-same", "HIGH");
  const groups = groupDashboardFindings([duplicate, { ...duplicate }, outdated()]);
  const totals = dashboardFindingTotals(groups);

  assert.equal(groups[0]?.vulnerabilities.length, 1);
  assert.equal(totals.affectedDependencies, 1);
  assert.equal(totals.vulnerabilities, 1);
  assert.equal(totals.outdated, 1);
});

test("orders grouped dependencies by risk and then coordinate", () => {
  const critical = { ...vulnerability("GHSA-critical", "CRITICAL"), artifactId: "zeta", coordinate: "zeta" };
  const highA = { ...vulnerability("GHSA-a", "HIGH"), artifactId: "alpha", coordinate: "alpha" };
  const highB = { ...vulnerability("GHSA-b", "HIGH"), artifactId: "beta", coordinate: "beta" };

  assert.deepEqual(
    groupDashboardFindings([highB, critical, highA]).map((group) => group.coordinate),
    ["zeta", "alpha", "beta"]
  );
});
