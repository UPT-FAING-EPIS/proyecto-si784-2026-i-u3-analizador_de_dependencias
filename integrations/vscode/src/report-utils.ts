import type {
  DependencyReport,
  Finding,
  OutdatedDependency,
  Vulnerability,
  VulnerabilityChain,
  VulnerableDependency
} from "./models.js";

const SUPPORTED_FILES = new Set([
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "package.json",
  "pyproject.toml",
  "requirements.txt"
]);

const severityWeight = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  UNKNOWN: 1
} as const;

export function isSupportedDependencyFile(fileName: string): boolean {
  return SUPPORTED_FILES.has(fileName.replace(/\\/g, "/").split("/").pop() ?? "");
}

export function coordinate(groupId: string, artifactId: string, ecosystem = "MAVEN"): string {
  if (ecosystem === "NPM") {
    return groupId === "npm" ? artifactId : `${groupId}/${artifactId}`;
  }
  if (ecosystem === "PYPI") {
    return artifactId;
  }
  return `${groupId}:${artifactId}`;
}

export function flattenFindings(report: DependencyReport, projectPath?: string): Finding[] {
  const treeRelationships = indexTreeRelationships(report);
  const outdatedByKey = new Map<string, OutdatedDependency>();
  for (const dep of report.outdated ?? []) {
    outdatedByKey.set(keyFor(dep.groupId, dep.artifactId, dep.ecosystem), dep);
  }

  const findings: Finding[] = [];
  for (const dep of report.directVulnerable ?? []) {
    for (const vulnerability of dep.vulnerabilities ?? []) {
      const update = outdatedByKey.get(keyFor(dep.groupId, dep.artifactId, dep.ecosystem));
      const chain = findVulnerabilityChain(report.vulnerabilityChains, dep, vulnerability);
      findings.push({
        kind: "vulnerability",
        groupId: dep.groupId,
        artifactId: dep.artifactId,
        coordinate: coordinate(dep.groupId, dep.artifactId, dep.ecosystem),
        currentVersion: dep.version,
        latestVersion: update?.latestVersion,
        ecosystem: dep.ecosystem,
        severity: vulnerability.severity,
        vulnerability,
        sourceLocation: dep.sourceLocation,
        dependencyChain: chain?.chain.map(chainCoordinate) ?? dep.dependencyChain,
        relationship: "direct",
        directRoot: chain?.chain[0] ? chainCoordinate(chain.chain[0]) : undefined,
        chainClassification: chain?.classification,
        projectPath
      });
    }
  }

  for (const dep of report.transitiveVulnerable ?? []) {
    for (const vulnerability of dep.vulnerabilities ?? []) {
      const chain = findVulnerabilityChain(report.vulnerabilityChains, dep, vulnerability);
      findings.push({
        kind: "vulnerability",
        groupId: dep.groupId,
        artifactId: dep.artifactId,
        coordinate: coordinate(dep.groupId, dep.artifactId, dep.ecosystem),
        currentVersion: dep.version,
        ecosystem: dep.ecosystem,
        severity: vulnerability.severity,
        vulnerability,
        dependencyChain: chain?.chain.map(chainCoordinate) ?? dep.dependencyChain,
        relationship: "transitive",
        directRoot: chain?.chain[0] ? chainCoordinate(chain.chain[0]) : undefined,
        chainClassification: chain?.classification,
        projectPath
      });
    }
  }

  for (const dep of report.outdated ?? []) {
    const treeMatch = treeRelationships.get(
      `${keyFor(dep.groupId, dep.artifactId, dep.ecosystem)}:${dep.currentVersion}`
    );
    findings.push({
      kind: "outdated",
      groupId: dep.groupId,
      artifactId: dep.artifactId,
      coordinate: coordinate(dep.groupId, dep.artifactId, dep.ecosystem),
      currentVersion: dep.currentVersion,
      latestVersion: dep.latestVersion,
      ecosystem: dep.ecosystem,
      sourceLocation: dep.sourceLocation,
      relationship: dep.sourceLocation ? "direct" : treeMatch?.relationship ?? "unknown",
      dependencyChain: treeMatch?.chain,
      directRoot: treeMatch?.directRoot,
      projectPath
    });
  }

  return findings.sort(compareFindings);
}

function indexTreeRelationships(report: DependencyReport): Map<
  string,
  { relationship: "direct" | "transitive"; chain?: string[]; directRoot?: string }
> {
  const index = new Map<string, {
    relationship: "direct" | "transitive";
    chain?: string[];
    directRoot?: string;
  }>();
  const visit = (node: NonNullable<DependencyReport["dependencyTree"]>[number], path: string[]): void => {
    const current = `${coordinate(node.groupId, node.artifactId, node.ecosystem)}:${node.currentVersion}`;
    const chain = [...path, current];
    const relationship = node.isDirectDependency ? "direct" : "transitive";
    const key = `${keyFor(node.groupId, node.artifactId, node.ecosystem)}:${node.currentVersion}`;
    const candidate = {
      relationship,
      chain: relationship === "transitive" ? chain : undefined,
      directRoot: relationship === "transitive" ? chain[0] : current
    } as const;
    const existing = index.get(key);
    if (!existing || relationship === "direct" || (chain.length < (existing.chain?.length ?? Number.MAX_SAFE_INTEGER))) {
      index.set(key, candidate);
    }
    for (const child of node.children ?? []) visit(child, chain);
  };
  for (const root of report.dependencyTree ?? []) visit(root, []);
  return index;
}

export function summarizeFindings(findings: Finding[]): string {
  const critical = findings.filter((finding) => finding.severity === "CRITICAL").length;
  const high = findings.filter((finding) => finding.severity === "HIGH").length;
  const cves = findings.filter((finding) => finding.kind === "vulnerability").length;
  const vulnerable = new Set(
    findings
      .filter((finding) => finding.kind === "vulnerability")
      .map((finding) => `${finding.ecosystem ?? "MAVEN"}:${finding.coordinate}`)
  ).size;
  const outdated = findings.filter((finding) => finding.kind === "outdated").length;
  return `${critical} criticas, ${high} altas, ${vulnerable} dependencias vulnerables, ${cves} CVE, ${outdated} desactualizadas`;
}

export function compareFindings(left: Finding, right: Finding): number {
  const leftWeight = left.severity ? severityWeight[left.severity] : 0;
  const rightWeight = right.severity ? severityWeight[right.severity] : 0;
  return rightWeight - leftWeight || left.coordinate.localeCompare(right.coordinate);
}

export function keyFor(groupId: string, artifactId: string, ecosystem = "MAVEN"): string {
  return `${ecosystem}:${groupId}:${artifactId}`;
}

export function keyForVulnerable(dep: VulnerableDependency): string {
  return keyFor(dep.groupId, dep.artifactId, dep.ecosystem);
}

function findVulnerabilityChain(
  chains: VulnerabilityChain[] | undefined,
  dependency: VulnerableDependency,
  vulnerability: Vulnerability
): VulnerabilityChain | undefined {
  return chains?.find((chain) => {
    const target = chain.chain.at(-1);
    return target?.groupId === dependency.groupId &&
      target.artifactId === dependency.artifactId &&
      target.version === dependency.version &&
      chain.cveIds.includes(vulnerability.cveId);
  });
}

function chainCoordinate(node: { groupId: string; artifactId: string; version: string; ecosystem?: string }): string {
  return `${coordinate(node.groupId, node.artifactId, node.ecosystem)}:${node.version}`;
}
