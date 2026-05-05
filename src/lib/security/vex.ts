// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { findActiveWaiver } from "./policy";
import type {
  PolicyViolation,
  RiskDecision,
  VexStatement,
  VulnerabilityPolicy,
  VulnerabilityRecord,
  VulnerabilityWaiver,
} from "./types";

export interface VexBuildResult {
  statements: VexStatement[];
  violations: PolicyViolation[];
}

export function buildVexStatements(
  vulnerabilities: VulnerabilityRecord[],
  risks: RiskDecision[],
  policy: VulnerabilityPolicy,
  now = new Date(),
): VexBuildResult {
  const riskByKey = new Map(risks.map((risk) => [`${risk.vulnerabilityId}:${risk.componentId}`, risk]));
  const statements: VexStatement[] = [];
  const violations: PolicyViolation[] = [];

  for (const vulnerability of vulnerabilities) {
    const risk = riskByKey.get(`${vulnerability.id}:${vulnerability.affectedComponentId}`);
    const waiver =
      findActiveWaiver(policy, vulnerability.affectedComponentId, vulnerability.id, now) ??
      findActiveWaiver(policy, vulnerability.affectedComponentName, vulnerability.id, now);

    if (waiver?.vexStatus === "not_affected") {
      const waiverViolations = validateNotAffectedWaiver(vulnerability, risk, waiver, policy);
      if (waiverViolations.length === 0) {
        statements.push({
          vulnerabilityId: vulnerability.id,
          componentId: vulnerability.affectedComponentId,
          status: "not_affected",
          justification: waiver.businessJustification,
          evidence: waiver.evidence,
          approvedBy: waiver.approvalRecord?.approvedBy ?? null,
          approvalRecord: waiver.approvalRecord?.approvalId ?? null,
        });
      } else {
        violations.push(...waiverViolations);
        statements.push(defaultStatement(vulnerability));
      }
      continue;
    }

    if (vulnerability.fixedVersion && vulnerability.affectedVersion === vulnerability.fixedVersion) {
      statements.push({
        vulnerabilityId: vulnerability.id,
        componentId: vulnerability.affectedComponentId,
        status: "fixed",
        justification: "Component version matches provider fixed version",
        evidence: [`fixedVersion:${vulnerability.fixedVersion}`],
        approvedBy: null,
        approvalRecord: null,
      });
      continue;
    }

    if (!vulnerability.fixedVersion && risk?.riskClass === "INFO") {
      statements.push({
        vulnerabilityId: vulnerability.id,
        componentId: vulnerability.affectedComponentId,
        status: "under_investigation",
        justification: "No fixed version is known and risk is informational pending review",
        evidence: [],
        approvedBy: null,
        approvalRecord: null,
      });
      continue;
    }

    statements.push(defaultStatement(vulnerability));
  }

  return { statements, violations };
}

function validateNotAffectedWaiver(
  vulnerability: VulnerabilityRecord,
  risk: RiskDecision | undefined,
  waiver: VulnerabilityWaiver,
  policy: VulnerabilityPolicy,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  if (!waiver.businessJustification || waiver.businessJustification.trim().length === 0) {
    violations.push(vexViolation(vulnerability, "not_affected VEX status requires justification"));
  }
  if (!Array.isArray(waiver.evidence) || waiver.evidence.length === 0) {
    violations.push(vexViolation(vulnerability, "not_affected VEX status requires evidence"));
  }
  if (!waiver.approvalRecord) {
    violations.push(vexViolation(vulnerability, "not_affected VEX status requires human approval"));
  }
  const highImpact =
    vulnerability.knownExploited ||
    vulnerability.severity === "CRITICAL" ||
    vulnerability.severity === "HIGH" ||
    risk?.riskClass === "CRITICAL" ||
    risk?.riskClass === "HIGH";
  if (highImpact && !waiver.approvalRecord) {
    violations.push(vexViolation(vulnerability, "HIGH, CRITICAL, or KEV vulnerabilities cannot be marked not_affected automatically"));
  }
  if (
    policy.approvals.requirePrivilegedForKevCriticalWaivers &&
    (vulnerability.knownExploited || risk?.riskClass === "CRITICAL" || vulnerability.severity === "CRITICAL") &&
    !waiver.approvalRecord?.privileged
  ) {
    violations.push(vexViolation(vulnerability, "KEV or CRITICAL not_affected waiver requires privileged approval"));
  }
  return violations;
}

function defaultStatement(vulnerability: VulnerabilityRecord): VexStatement {
  return {
    vulnerabilityId: vulnerability.id,
    componentId: vulnerability.affectedComponentId,
    status: "affected",
    justification: null,
    evidence: [],
    approvedBy: null,
    approvalRecord: null,
  };
}

function vexViolation(vulnerability: VulnerabilityRecord, message: string): PolicyViolation {
  return {
    code: "VEX_NOT_AFFECTED_REQUIRES_APPROVAL",
    message: `${message}: ${vulnerability.id} on ${vulnerability.affectedComponentName}`,
    severity: "HIGH",
    componentId: vulnerability.affectedComponentId,
  };
}
