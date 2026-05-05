// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { sha256File } from "./hash";
import type {
  InventoryComponent,
  MitigationPlanAction,
  PatchOrMitigationPlan,
  PatchPlanAction,
  PolicyViolation,
  RiskDecision,
  SlsaStyleProvenance,
  VulnerabilityPolicy,
  VulnerabilityRecord,
} from "./types";

export interface PlanInput {
  vulnerabilities: VulnerabilityRecord[];
  risks: RiskDecision[];
  components: InventoryComponent[];
  policy: VulnerabilityPolicy;
  provenance: SlsaStyleProvenance;
}

export interface ProvenanceInput {
  rootDir: string;
  sourceCommit: string | null;
  builderIdentity?: string | null;
  buildCommand?: string | null;
  policyHash: string;
  sbomHash: string | null;
  vulnerabilityReportHash: string | null;
  testReportHash?: string | null;
  artifactDigest?: string | null;
  approvalRecordReference?: string | null;
}

export function buildPatchOrMitigationPlan(input: PlanInput): PatchOrMitigationPlan {
  const componentById = new Map(input.components.map((component) => [component.id, component]));
  const riskByKey = new Map(input.risks.map((risk) => [`${risk.vulnerabilityId}:${risk.componentId}`, risk]));
  const patchActions: PatchPlanAction[] = [];
  const mitigationActions: MitigationPlanAction[] = [];
  const warnings: string[] = [];

  for (const vulnerability of input.vulnerabilities) {
    const component = componentById.get(vulnerability.affectedComponentId);
    const risk = riskByKey.get(`${vulnerability.id}:${vulnerability.affectedComponentId}`);
    if (vulnerability.fixedVersion && component) {
      patchActions.push(buildPatchAction(vulnerability, component, risk, input.policy));
    } else {
      mitigationActions.push(...buildMitigationActions(vulnerability, component, risk));
    }
  }

  if (patchActions.length === 0 && mitigationActions.length > 0) {
    warnings.push("No safe fixed version was identified for one or more vulnerabilities; mitigation-only workflow required.");
  }
  if (input.provenance.externalSignatureReference === null) {
    warnings.push("Patch candidates are not signed by NemoClaw; external signer integration is required before rollout.");
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode: patchActions.length > 0 && mitigationActions.length > 0 ? "combined" : patchActions.length > 0 ? "patch-plan" : "mitigation-plan",
    patchActions,
    mitigationActions,
    provenance: input.provenance,
    warnings,
  };
}

export function buildProvenance(input: ProvenanceInput): SlsaStyleProvenance {
  return {
    sourceCommit: input.sourceCommit,
    builderIdentity: input.builderIdentity ?? process.env.USERNAME ?? process.env.USER ?? null,
    buildCommand: input.buildCommand ?? "nemoclaw security scan",
    lockfileHashes: collectLockfileHashes(input.rootDir),
    sbomHash: input.sbomHash,
    policyHash: input.policyHash,
    vulnerabilityReportHash: input.vulnerabilityReportHash,
    testReportHash: input.testReportHash ?? null,
    artifactDigest: input.artifactDigest ?? null,
    approvalRecordReference: input.approvalRecordReference ?? null,
    externalSignerRequired: true,
    externalSignatureReference: null,
  };
}

export function validatePatchCandidate(
  policy: VulnerabilityPolicy,
  candidate: PatchOrMitigationPlan,
  expectedPolicyHash?: string,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  if (candidate.schemaVersion !== 1) {
    violations.push(fail("CANDIDATE_SCHEMA_INVALID", "Patch candidate schemaVersion must be 1"));
  }
  if (!candidate.provenance) {
    violations.push(fail("PROVENANCE_MISSING", "Patch candidate provenance is required"));
    return violations;
  }
  const provenance = candidate.provenance;
  if (!provenance.sourceCommit) violations.push(fail("PROVENANCE_MISSING_SOURCE", "Patch candidate source commit is required"));
  if (!provenance.builderIdentity) violations.push(fail("PROVENANCE_MISSING_BUILDER", "Patch candidate builder identity is required"));
  if (!provenance.buildCommand) violations.push(fail("PROVENANCE_MISSING_BUILD_COMMAND", "Patch candidate build command is required"));
  if (Object.keys(provenance.lockfileHashes ?? {}).length === 0 && policy.requiredLockfiles) {
    violations.push(fail("PROVENANCE_MISSING_LOCKFILE_HASHES", "Patch candidate lockfile hashes are required"));
  }
  if (!provenance.sbomHash && policy.requireSbom) violations.push(fail("SBOM_MISSING", "Patch candidate SBOM hash is required"));
  if (!provenance.policyHash) violations.push(fail("PROVENANCE_MISSING_POLICY_HASH", "Patch candidate policy hash is required"));
  if (expectedPolicyHash && provenance.policyHash && provenance.policyHash !== expectedPolicyHash) {
    violations.push(fail("POLICY_HASH_MISMATCH", "Patch candidate policy hash does not match the active policy"));
  }
  if (!provenance.vulnerabilityReportHash) {
    violations.push(fail("PROVENANCE_MISSING_VULN_REPORT", "Patch candidate vulnerability report hash is required"));
  }
  if (!provenance.testReportHash) violations.push(fail("TEST_REPORT_MISSING", "Patch candidate test report hash is required"));
  if (!provenance.artifactDigest) violations.push(fail("ARTIFACT_DIGEST_MISSING", "Patch candidate artifact digest is required"));
  if (!provenance.approvalRecordReference) {
    violations.push(fail("APPROVAL_MISSING", "Patch candidate approval record reference is required"));
  }
  if (provenance.externalSignerRequired !== true) {
    violations.push(fail("EXTERNAL_SIGNER_REQUIRED", "Patch candidate must require an external signer"));
  }
  if (!provenance.externalSignatureReference) {
    violations.push(fail("EXTERNAL_SIGNATURE_MISSING", "Patch candidate must be signed by an external signer"));
  }
  if (isNemoClawSignatureReference(provenance.externalSignatureReference)) {
    violations.push(fail("EXTERNAL_SIGNATURE_NOT_EXTERNAL", "NemoClaw cannot be used as its own signing root"));
  }
  return violations;
}

function isNemoClawSignatureReference(value: string | null): boolean {
  return typeof value === "string" && /^nemoclaw:/i.test(value.trim());
}

function buildPatchAction(
  vulnerability: VulnerabilityRecord,
  component: InventoryComponent,
  risk: RiskDecision | undefined,
  policy: VulnerabilityPolicy,
): PatchPlanAction {
  const approvalReasons = approvalReasonsFor(vulnerability, component, risk, policy);
  const upgradeKind = versionChangeKind(component.version, vulnerability.fixedVersion);
  if (upgradeKind === "major" || upgradeKind === "minor") approvalReasons.push(`${upgradeKind} version upgrade`);
  return {
    type: component.ecosystem === "container" ? "update-container-image" : "update-dependency",
    componentId: component.id,
    vulnerabilityId: vulnerability.id,
    currentVersion: component.version,
    targetVersion: vulnerability.fixedVersion,
    reason: `Provider reports fixed version ${vulnerability.fixedVersion} for ${vulnerability.id}. Generate a new verified artifact; do not patch the live runtime.`,
    approvalRequired: approvalReasons.length > 0,
    approvalReasons: [...new Set(approvalReasons)],
    requiredTests: requiredTestsFor(component),
    rollback: `Rollback by redeploying the previous signed artifact containing ${component.name}@${component.version ?? "unknown"}.`,
  };
}

function buildMitigationActions(
  vulnerability: VulnerabilityRecord,
  component: InventoryComponent | undefined,
  risk: RiskDecision | undefined,
): MitigationPlanAction[] {
  const componentId = vulnerability.affectedComponentId;
  const requiredTests = requiredTestsFor(component);
  const approvalRequired = true;
  const reason = `No safe fixed version is known for ${vulnerability.id}; restrict capability or quarantine pending human review.`;
  const rollback = `Restore previous policy/capability state after an approved fixed artifact is available and validated.`;
  const actions: MitigationPlanAction[] = [
    {
      type: "quarantine-component",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason,
      approvalRequired,
      requiredTests,
      rollback,
    },
    {
      type: "block-runtime-use",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason,
      approvalRequired,
      requiredTests,
      rollback,
    },
  ];
  if (component?.affects.network || risk?.riskClass === "CRITICAL" || vulnerability.knownExploited) {
    actions.push({
      type: "remove-network-allowlist-binary",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason: "Reduce network exposure for a vulnerable component until review completes.",
      approvalRequired,
      requiredTests,
      rollback,
    });
  }
  if (component?.affects.filesystem) {
    actions.push({
      type: "tighten-filesystem-policy",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason: "Constrain filesystem access for the vulnerable component.",
      approvalRequired,
      requiredTests,
      rollback,
    });
  }
  if (component?.affects.process) {
    actions.push({
      type: "tighten-process-policy",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason: "Constrain process execution for the vulnerable component.",
      approvalRequired,
      requiredTests,
      rollback,
    });
  }
  if (component?.affects.policy) {
    actions.push({
      type: "switch-audit-to-enforce",
      componentId,
      vulnerabilityId: vulnerability.id,
      reason: "Switch applicable policy controls from audit to enforce mode pending review.",
      approvalRequired,
      requiredTests,
      rollback,
    });
  }
  return actions;
}

function approvalReasonsFor(
  vulnerability: VulnerabilityRecord,
  component: InventoryComponent,
  risk: RiskDecision | undefined,
  policy: VulnerabilityPolicy,
): string[] {
  const reasons: string[] = [];
  const highImpact =
    component.runtimeLocation === "sandbox-runtime" ||
    component.runtimeLocation === "host-controller" ||
    component.runtimeLocation === "inference-gateway" ||
    component.container !== undefined ||
    Object.values(component.affects).some(Boolean);
  if (policy.approvals.requireForHighImpact && highImpact) reasons.push("high-impact runtime or security surface");
  if (risk?.riskClass === "CRITICAL" || risk?.riskClass === "HIGH") reasons.push(`${risk.riskClass} risk`);
  if (vulnerability.knownExploited) reasons.push("known exploited vulnerability");
  return reasons;
}

function requiredTestsFor(component?: InventoryComponent): string[] {
  const tests = new Set(["unit tests", "SBOM regeneration", "vulnerability rescan", "audit validation"]);
  if (component?.runtimeLocation === "sandbox-runtime") tests.add("sandbox launch validation");
  if (component?.runtimeLocation === "inference-gateway" || component?.affects.inference) tests.add("inference gateway smoke test");
  if (component?.affects.network) tests.add("network policy validation");
  if (component?.affects.filesystem) tests.add("filesystem policy validation");
  if (component?.affects.process) tests.add("process policy validation");
  return [...tests];
}

function versionChangeKind(current: string | null, target: string | null): "major" | "minor" | "patch" | "unknown" {
  const currentVersion = semverParts(current);
  const targetVersion = semverParts(target);
  if (!currentVersion || !targetVersion) return "unknown";
  if (targetVersion[0] !== currentVersion[0]) return "major";
  if (targetVersion[1] !== currentVersion[1]) return "minor";
  return "patch";
}

function semverParts(value: string | null): [number, number, number] | null {
  const match = value?.match(/(\d+)\.(\d+)\.(\d+)/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function collectLockfileHashes(rootDir: string): Record<string, string> {
  const lockfiles: Record<string, string> = {};
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (![".git", "node_modules", "dist", ".venv"].includes(entry.name)) stack.push(path.join(current, entry.name));
      } else if (/^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock)$/i.test(entry.name)) {
        const filePath = path.join(current, entry.name);
        lockfiles[path.relative(rootDir, filePath).replace(/\\/g, "/")] = sha256File(filePath);
      }
    }
  }
  return Object.fromEntries(Object.entries(lockfiles).sort(([a], [b]) => a.localeCompare(b)));
}

function fail(code: string, message: string): PolicyViolation {
  return { code, message, severity: "CRITICAL" };
}
