import type { DependencyRelationship, Finding } from "./models.js";
import { relationshipLabel, severityLabel } from "./presentation-labels.js";

export interface IndexedFinding {
  finding: Finding;
  originalIndex: number;
}

export interface DashboardFindingGroup {
  key: string;
  coordinate: string;
  ecosystem: string;
  currentVersion: string;
  latestVersion?: string;
  vulnerabilities: IndexedFinding[];
  update?: IndexedFinding;
  severity?: Finding["severity"];
  severityLabel?: string;
  tone: "critical" | "high" | "medium" | "low" | "unknown" | "outdated";
  relationships: DependencyRelationship[];
  relationshipLabels: string[];
  directRoots: string[];
  paths: string[][];
  searchText: string;
}

export interface DashboardFindingTotals {
  affectedDependencies: number;
  vulnerableDependencies: number;
  vulnerabilities: number;
  critical: number;
  high: number;
  outdated: number;
  direct: number;
  transitive: number;
}

const SEVERITY_WEIGHT: Record<NonNullable<Finding["severity"]>, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  UNKNOWN: 1
};

export function groupDashboardFindings(findings: Finding[]): DashboardFindingGroup[] {
  const groups = new Map<string, {
    entries: IndexedFinding[];
    vulnerabilities: Map<string, IndexedFinding>;
    updates: IndexedFinding[];
  }>();

  findings.forEach((finding, originalIndex) => {
    const key = findingGroupKey(finding);
    const group = groups.get(key) ?? {
      entries: [],
      vulnerabilities: new Map<string, IndexedFinding>(),
      updates: []
    };
    const indexed = { finding, originalIndex };
    group.entries.push(indexed);
    if (finding.kind === "vulnerability") {
      const advisoryKey = [
        finding.vulnerability?.source,
        finding.vulnerability?.advisoryId ?? finding.vulnerability?.cveId,
        finding.vulnerability?.title
      ].join("|").toLowerCase();
      if (!group.vulnerabilities.has(advisoryKey)) group.vulnerabilities.set(advisoryKey, indexed);
    } else {
      group.updates.push(indexed);
    }
    groups.set(key, group);
  });

  return [...groups.entries()].map(([key, value]) => {
    const vulnerabilities = [...value.vulnerabilities.values()]
      .sort((left, right) =>
        severityWeight(right.finding.severity) - severityWeight(left.finding.severity) ||
        advisoryId(left.finding).localeCompare(advisoryId(right.finding))
      );
    const update = value.updates.sort((left, right) =>
      String(right.finding.latestVersion).localeCompare(String(left.finding.latestVersion))
    )[0];
    const first = value.entries[0]!.finding;
    const severity = vulnerabilities[0]?.finding.severity;
    const relationships = unique(value.entries.map(({ finding }) => finding.relationship ?? "unknown"))
      .sort(relationshipOrder);
    const paths = uniquePaths(value.entries.flatMap(({ finding }) =>
      finding.dependencyChain?.length ? [finding.dependencyChain] : []
    ));
    const directRoots = unique(value.entries.flatMap(({ finding }) =>
      finding.directRoot ? [finding.directRoot] : []
    )).sort();
    const latestVersion = update?.finding.latestVersion ??
      vulnerabilities.find(({ finding }) => finding.latestVersion)?.finding.latestVersion;
    const searchText = value.entries.map(({ finding }) => [
      finding.coordinate,
      finding.currentVersion,
      finding.latestVersion,
      finding.vulnerability?.advisoryId,
      finding.vulnerability?.cveId,
      finding.vulnerability?.title,
      finding.vulnerability?.description,
      finding.directRoot,
      finding.dependencyChain?.join(" ")
    ].filter(Boolean).join(" ")).join(" ").toLowerCase();

    return {
      key,
      coordinate: first.coordinate,
      ecosystem: first.ecosystem ?? "UNKNOWN",
      currentVersion: first.currentVersion,
      latestVersion,
      vulnerabilities,
      update,
      severity,
      severityLabel: severity ? severityLabel(severity) : undefined,
      tone: severity ? severity.toLowerCase() as DashboardFindingGroup["tone"] : "outdated",
      relationships,
      relationshipLabels: relationships.map(relationshipLabel),
      directRoots,
      paths,
      searchText
    };
  }).sort(compareFindingGroups);
}

export function dashboardFindingTotals(groups: DashboardFindingGroup[]): DashboardFindingTotals {
  const vulnerabilities = groups.flatMap((group) => group.vulnerabilities);
  return {
    affectedDependencies: groups.length,
    vulnerableDependencies: groups.filter((group) => group.vulnerabilities.length > 0).length,
    vulnerabilities: vulnerabilities.length,
    critical: vulnerabilities.filter(({ finding }) => finding.severity === "CRITICAL").length,
    high: vulnerabilities.filter(({ finding }) => finding.severity === "HIGH").length,
    outdated: groups.filter((group) => group.update).length,
    direct: groups.filter((group) => group.relationships.includes("direct")).length,
    transitive: groups.filter((group) => group.relationships.includes("transitive")).length
  };
}

function findingGroupKey(finding: Finding): string {
  return [
    finding.ecosystem ?? "UNKNOWN",
    finding.coordinate,
    finding.currentVersion
  ].join("|").toLowerCase();
}

function advisoryId(finding: Finding): string {
  return finding.vulnerability?.advisoryId ?? finding.vulnerability?.cveId ?? "";
}

function severityWeight(severity?: Finding["severity"]): number {
  return severity ? SEVERITY_WEIGHT[severity] : 0;
}

function compareFindingGroups(left: DashboardFindingGroup, right: DashboardFindingGroup): number {
  return severityWeight(right.severity) - severityWeight(left.severity) ||
    left.coordinate.localeCompare(right.coordinate) ||
    left.currentVersion.localeCompare(right.currentVersion);
}

function relationshipOrder(left: DependencyRelationship, right: DependencyRelationship): number {
  const order: Record<DependencyRelationship, number> = { direct: 0, transitive: 1, unknown: 2 };
  return order[left] - order[right];
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
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
