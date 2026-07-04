import type { DependencyRelationship, Finding } from "./models.js";

export const SEVERITY_LABELS: Record<NonNullable<Finding["severity"]>, string> = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Media",
  LOW: "Baja",
  UNKNOWN: "Sin clasificar"
};

export const RELATIONSHIP_LABELS: Record<DependencyRelationship, string> = {
  direct: "Directa",
  transitive: "Transitiva",
  unknown: "Sin clasificar"
};

export function severityLabel(severity?: Finding["severity"]): string {
  return severity ? SEVERITY_LABELS[severity] : SEVERITY_LABELS.UNKNOWN;
}

export function relationshipLabel(relationship?: DependencyRelationship): string {
  return RELATIONSHIP_LABELS[relationship ?? "unknown"];
}
