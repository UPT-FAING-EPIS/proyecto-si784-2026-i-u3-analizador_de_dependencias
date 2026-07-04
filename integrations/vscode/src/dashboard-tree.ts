import type { DependencyTreeNode, Finding, Vulnerability } from "./models.js";
import { relationshipLabel, severityLabel } from "./presentation-labels.js";

export type DashboardTreeTone = "critical" | "high" | "medium" | "low" | "unknown" | "outdated" | "healthy";

export interface DashboardTreeNode extends DependencyTreeNode {
  key: string;
  children: DashboardTreeNode[];
  relationship: "direct" | "transitive";
  relationshipLabel: string;
  statusLabel: string;
  tone: DashboardTreeTone;
  primaryPath: string[];
  paths: string[][];
  routeCount: number;
}

interface Occurrence {
  node: DependencyTreeNode;
  key: string;
  parentKey?: string;
  path: string[];
  keyPath: string[];
}

const SEVERITY_PRIORITY: Array<NonNullable<Finding["severity"]>> = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN"
];

export function prepareDashboardTree(nodes: DependencyTreeNode[]): DashboardTreeNode[] {
  const occurrences: Occurrence[] = [];
  collectOccurrences(nodes, [], [], undefined, occurrences, new Set());
  const byKey = new Map<string, Occurrence[]>();
  for (const occurrence of occurrences) {
    const values = byKey.get(occurrence.key) ?? [];
    values.push(occurrence);
    byKey.set(occurrence.key, values);
  }

  const prepared = new Map<string, DashboardTreeNode>();
  const parents = new Map<string, string | undefined>();
  for (const [key, values] of byKey) {
    values.sort(compareOccurrences);
    const primary = values[0]!;
    const vulnerabilities = uniqueVulnerabilities(values.flatMap(({ node }) => node.vulnerabilities ?? []));
    const severity = SEVERITY_PRIORITY.find((candidate) =>
      vulnerabilities.some((vulnerability) => vulnerability.severity === candidate)
    );
    const latestVersion = values.find(({ node }) => node.latestVersion)?.node.latestVersion;
    const direct = values.some(({ node }) => node.isDirectDependency);
    const relationship = direct ? "direct" : "transitive";
    const tone = severity
      ? severity.toLowerCase() as DashboardTreeTone
      : latestVersion
        ? "outdated"
        : "healthy";
    const paths = uniquePaths(values.map(({ path }) => path));
    const node: DashboardTreeNode = {
      ...primary.node,
      key,
      latestVersion,
      isDirectDependency: direct,
      vulnerabilities,
      children: [],
      relationship,
      relationshipLabel: relationshipLabel(relationship),
      statusLabel: severity
        ? severityLabel(severity)
        : latestVersion
          ? "Actualización disponible"
          : "Al día",
      tone,
      primaryPath: primary.path,
      paths,
      routeCount: paths.length
    };
    prepared.set(key, node);
    parents.set(key, direct ? undefined : primary.parentKey);
  }

  const roots: DashboardTreeNode[] = [];
  for (const [key, node] of prepared) {
    const parentKey = parents.get(key);
    const parent = parentKey && parentKey !== key ? prepared.get(parentKey) : undefined;
    if (parent && !wouldCreateCycle(key, parentKey!, parents)) parent.children.push(node);
    else roots.push(node);
  }
  sortTree(roots);
  return roots;
}

/**
 * Keeps the complete matching node and only the ancestor branches needed to
 * reach descendant matches. It is self-contained because the same function is
 * serialized into the dashboard webview.
 */
export function filterDashboardTree(nodes: DashboardTreeNode[], rawQuery: string): DashboardTreeNode[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return nodes;
  return nodes.flatMap((node) => {
    const searchable = [
      node.groupId,
      node.artifactId,
      node.currentVersion,
      node.latestVersion,
      node.relationshipLabel,
      node.statusLabel,
      ...node.paths.flat(),
      ...node.vulnerabilities.flatMap((vulnerability) => [
        vulnerability.cveId,
        vulnerability.advisoryId,
        vulnerability.title
      ])
    ].filter(Boolean).join(" ").toLowerCase();
    if (searchable.includes(query)) return [node];
    const children = filterDashboardTree(node.children, query);
    return children.length ? [{ ...node, children }] : [];
  });
}

function collectOccurrences(
  nodes: DependencyTreeNode[],
  path: string[],
  keyPath: string[],
  parentKey: string | undefined,
  target: Occurrence[],
  ancestors: Set<string>
): void {
  for (const node of nodes) {
    const key = treeNodeKey(node);
    const coordinate = displayCoordinate(node);
    const nextPath = [...path, `${coordinate}:${node.currentVersion}`];
    const nextKeyPath = [...keyPath, key];
    target.push({ node, key, parentKey, path: nextPath, keyPath: nextKeyPath });
    if (ancestors.has(key)) continue;
    const nextAncestors = new Set(ancestors);
    nextAncestors.add(key);
    collectOccurrences(node.children ?? [], nextPath, nextKeyPath, key, target, nextAncestors);
  }
}

function treeNodeKey(node: DependencyTreeNode): string {
  return [
    node.ecosystem ?? "UNKNOWN",
    node.groupId,
    node.artifactId,
    node.currentVersion
  ].join("|").toLowerCase();
}

function displayCoordinate(node: DependencyTreeNode): string {
  return node.groupId === "npm" ? node.artifactId : `${node.groupId}:${node.artifactId}`;
}

function compareOccurrences(left: Occurrence, right: Occurrence): number {
  return left.path.length - right.path.length ||
    left.path[0]!.localeCompare(right.path[0]!) ||
    left.path.join(" → ").localeCompare(right.path.join(" → "));
}

function uniqueVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
  const seen = new Set<string>();
  return vulnerabilities.filter((vulnerability) => {
    const key = [
      vulnerability.source,
      vulnerability.advisoryId ?? vulnerability.cveId,
      vulnerability.title
    ].join("|").toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function uniquePaths(paths: string[][]): string[][] {
  const seen = new Set<string>();
  return paths.filter((path) => {
    const key = path.join("\u0000");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((left, right) => left.length - right.length || left.join(" → ").localeCompare(right.join(" → ")));
}

function wouldCreateCycle(childKey: string, parentKey: string, parents: Map<string, string | undefined>): boolean {
  const visited = new Set([childKey]);
  let current: string | undefined = parentKey;
  while (current) {
    if (visited.has(current)) return true;
    visited.add(current);
    current = parents.get(current);
  }
  return false;
}

function sortTree(nodes: DashboardTreeNode[]): void {
  nodes.sort((left, right) =>
    left.artifactId.localeCompare(right.artifactId) ||
    left.currentVersion.localeCompare(right.currentVersion)
  );
  nodes.forEach((node) => sortTree(node.children));
}
