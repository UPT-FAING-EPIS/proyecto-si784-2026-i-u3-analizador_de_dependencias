import assert from "node:assert/strict";
import test from "node:test";
import {
  filterDashboardTree,
  prepareDashboardTree
} from "./dashboard-tree.js";
import type { DependencyTreeNode } from "./models.js";

function dependency(
  artifactId: string,
  overrides: Partial<DependencyTreeNode> = {}
): DependencyTreeNode {
  return {
    groupId: "npm",
    artifactId,
    currentVersion: "1.0.0",
    isDirectDependency: false,
    isDependencyManagement: false,
    vulnerabilities: [],
    children: [],
    ecosystem: "NPM",
    ...overrides
  };
}

test("prepares leaf nodes without inventing children and labels their relationship", () => {
  const [node] = prepareDashboardTree([
    dependency("leaf", { isDirectDependency: true })
  ]);

  assert.equal(node?.children.length, 0);
  assert.equal(node?.relationshipLabel, "Directa");
  assert.equal(node?.tone, "healthy");
  assert.equal(node?.statusLabel, "Al día");
});

test("vulnerability severity takes visual priority over an available update", () => {
  const [node] = prepareDashboardTree([
    dependency("risky", {
      latestVersion: "2.0.0",
      vulnerabilities: [{ cveId: "CVE-2026-1000", severity: "HIGH" }]
    })
  ]);

  assert.equal(node?.tone, "high");
  assert.equal(node?.statusLabel, "Alta");
  assert.equal(node?.latestVersion, "2.0.0");
});

test("tree search preserves ancestors and prunes unrelated sibling branches", () => {
  const tree = prepareDashboardTree([
    dependency("root", {
      isDirectDependency: true,
      children: [
        dependency("wanted-child"),
        dependency("unrelated-child")
      ]
    }),
    dependency("other-root", { isDirectDependency: true })
  ]);

  const filtered = filterDashboardTree(tree, "wanted");

  assert.equal(filtered.length, 1);
  assert.equal(filtered[0]?.artifactId, "root");
  assert.deepEqual(filtered[0]?.children.map((node) => node.artifactId), ["wanted-child"]);
});

test("tree search includes semantic relationship and advisory fields", () => {
  const tree = prepareDashboardTree([
    dependency("nested", {
      vulnerabilities: [{
        cveId: "",
        advisoryId: "GHSA-abcd-1234",
        title: "Prototype pollution",
        severity: "MEDIUM"
      }]
    })
  ]);

  assert.equal(filterDashboardTree(tree, "transitiva").length, 1);
  assert.equal(filterDashboardTree(tree, "ghsa-abcd").length, 1);
});

test("renders a repeated dependency once using the shortest deterministic route", () => {
  const sharedFromZeta = dependency("shared");
  const sharedFromAlpha = dependency("shared");
  const tree = prepareDashboardTree([
    dependency("zeta-root", {
      isDirectDependency: true,
      children: [sharedFromZeta]
    }),
    dependency("alpha-root", {
      isDirectDependency: true,
      children: [sharedFromAlpha]
    })
  ]);
  const all: typeof tree = [];
  const visit = (nodes: typeof tree): void => {
    for (const node of nodes) {
      all.push(node);
      visit(node.children);
    }
  };
  visit(tree);
  const shared = all.filter((node) => node.artifactId === "shared");

  assert.equal(shared.length, 1);
  assert.equal(shared[0]?.routeCount, 2);
  assert.deepEqual(shared[0]?.primaryPath, ["alpha-root:1.0.0", "shared:1.0.0"]);
  assert.equal(tree.find((node) => node.artifactId === "alpha-root")?.children[0]?.artifactId, "shared");
});

test("stops recursive dependency cycles", () => {
  const alpha = dependency("alpha", { isDirectDependency: true });
  const beta = dependency("beta");
  alpha.children = [beta];
  beta.children = [alpha];

  const tree = prepareDashboardTree([alpha]);

  assert.equal(tree.length, 1);
  assert.equal(tree[0]?.artifactId, "alpha");
  assert.equal(tree[0]?.children[0]?.artifactId, "beta");
  assert.equal(tree[0]?.children[0]?.children.length, 0);
});
