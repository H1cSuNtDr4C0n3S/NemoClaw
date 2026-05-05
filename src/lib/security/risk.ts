// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type {
  InventoryComponent,
  ReachabilityState,
  RiskClass,
  RiskDecision,
  VulnerabilityRecord,
} from "./types";

export function scoreVulnerabilities(
  vulnerabilities: VulnerabilityRecord[],
  components: InventoryComponent[],
): RiskDecision[] {
  const byId = new Map(components.map((component) => [component.id, component]));
  return vulnerabilities.map((vulnerability) => scoreVulnerabilityRisk(vulnerability, byId.get(vulnerability.affectedComponentId)));
}

export function scoreVulnerabilityRisk(
  vulnerability: VulnerabilityRecord,
  component?: InventoryComponent,
): RiskDecision {
  let score = 0;
  const factors: string[] = [];

  const severityScore = cvssOrSeverityScore(vulnerability);
  score += severityScore.score;
  factors.push(severityScore.factor);

  if (vulnerability.knownExploited) {
    score += 35;
    factors.push("CISA KEV indicates known exploitation in the wild");
  }

  if (vulnerability.epssProbability !== null) {
    if (vulnerability.epssProbability >= 0.5) {
      score += 25;
      factors.push(`EPSS exploit probability is high (${vulnerability.epssProbability})`);
    } else if (vulnerability.epssProbability >= 0.1) {
      score += 15;
      factors.push(`EPSS exploit probability is elevated (${vulnerability.epssProbability})`);
    } else {
      score += 3;
      factors.push(`EPSS exploit probability is currently low (${vulnerability.epssProbability})`);
    }
  } else {
    factors.push("EPSS exploit probability unavailable");
  }

  const reachability = effectiveReachability(vulnerability);
  if (reachability === "REACHABLE_CONFIRMED") {
    score += 25;
    factors.push("Reachability is confirmed");
  } else if (reachability === "REACHABLE_INFERRED") {
    score += 18;
    factors.push("Reachability is inferred from component surfaces");
  } else if (reachability === "UNKNOWN" && mustTreatUnknownAsReachable(vulnerability)) {
    score += 15;
    factors.push("Reachability is unknown and treated as potentially reachable for HIGH/CRITICAL/KEV");
  } else if (reachability === "UNKNOWN") {
    score += 5;
    factors.push("Reachability is unknown");
  } else {
    factors.push("Reachability is inferred not reachable");
  }

  if (component) {
    if (component.scope === "runtime") {
      score += 12;
      factors.push("Runtime dependency");
    } else if (component.scope === "build-time") {
      score += 8;
      factors.push("Build pipeline dependency");
    } else if (component.scope === "dev-only") {
      score -= 8;
      factors.push("Dev-only dependency reduces operational exposure");
    }

    const sensitiveSurfaces = Object.entries(component.affects)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name);
    if (sensitiveSurfaces.length > 0) {
      score += Math.min(22, sensitiveSurfaces.length * 5);
      factors.push(`Sensitive surfaces: ${sensitiveSurfaces.join(", ")}`);
    }

    if (
      component.runtimeLocation === "sandbox-runtime" ||
      component.runtimeLocation === "inference-gateway" ||
      component.runtimeLocation === "host-controller"
    ) {
      score += 10;
      factors.push(`High-impact runtime location: ${component.runtimeLocation}`);
    } else if (component.runtimeLocation === "ci" || component.runtimeLocation === "build-pipeline") {
      score += 7;
      factors.push(`Supply-chain location: ${component.runtimeLocation}`);
    }
  }

  if (vulnerability.fixedVersion) {
    score -= 5;
    factors.push(`Fixed version is available: ${vulnerability.fixedVersion}`);
  } else {
    score += 10;
    factors.push("No fixed version is known, mitigation planning required");
  }

  score = Math.max(0, Math.min(100, score));
  const riskClass = classFromScore(score, vulnerability);
  return {
    vulnerabilityId: vulnerability.id,
    componentId: vulnerability.affectedComponentId,
    riskClass,
    score,
    explanation: explainRisk(vulnerability, component, riskClass, factors),
    factors,
    reachability,
  };
}

function cvssOrSeverityScore(vulnerability: VulnerabilityRecord): { score: number; factor: string } {
  if (vulnerability.cvssScore !== null) {
    if (vulnerability.cvssScore >= 9) return { score: 35, factor: `CVSS theoretical severity is critical (${vulnerability.cvssScore})` };
    if (vulnerability.cvssScore >= 7) return { score: 27, factor: `CVSS theoretical severity is high (${vulnerability.cvssScore})` };
    if (vulnerability.cvssScore >= 4) return { score: 17, factor: `CVSS theoretical severity is medium (${vulnerability.cvssScore})` };
    return { score: 8, factor: `CVSS theoretical severity is low (${vulnerability.cvssScore})` };
  }
  if (vulnerability.severity === "CRITICAL") return { score: 35, factor: "Provider severity is critical" };
  if (vulnerability.severity === "HIGH") return { score: 27, factor: "Provider severity is high" };
  if (vulnerability.severity === "MEDIUM") return { score: 17, factor: "Provider severity is medium" };
  if (vulnerability.severity === "LOW") return { score: 8, factor: "Provider severity is low" };
  return { score: 5, factor: "Provider severity is unavailable" };
}

function classFromScore(score: number, vulnerability: VulnerabilityRecord): RiskClass {
  if (vulnerability.knownExploited && score >= 60) return "CRITICAL";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  if (score >= 15) return "LOW";
  return "INFO";
}

function effectiveReachability(vulnerability: VulnerabilityRecord): ReachabilityState {
  if (vulnerability.reachability === "UNKNOWN" && mustTreatUnknownAsReachable(vulnerability)) {
    return "UNKNOWN";
  }
  return vulnerability.reachability;
}

function mustTreatUnknownAsReachable(vulnerability: VulnerabilityRecord): boolean {
  return (
    vulnerability.knownExploited ||
    vulnerability.severity === "CRITICAL" ||
    vulnerability.severity === "HIGH" ||
    (vulnerability.cvssScore ?? 0) >= 7
  );
}

function explainRisk(
  vulnerability: VulnerabilityRecord,
  component: InventoryComponent | undefined,
  riskClass: RiskClass,
  factors: string[],
): string {
  const componentName = component?.name ?? vulnerability.affectedComponentName;
  return `${riskClass}: ${vulnerability.id} affects ${componentName}. CVSS describes theoretical severity, EPSS describes exploit probability, and CISA KEV indicates confirmed exploitation; decision factors: ${factors.join("; ")}.`;
}
