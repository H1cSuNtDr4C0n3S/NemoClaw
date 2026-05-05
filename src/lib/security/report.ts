// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import childProcess from "node:child_process";

import { sha256Object } from "./hash";
import { collectDependencyInventory } from "./inventory";
import { buildPatchOrMitigationPlan, buildProvenance } from "./planning";
import { policyViolationsForProviderFailures } from "./policy";
import { correlateVulnerabilities, type ProviderContext, type VulnerabilityProviders } from "./providers";
import { scoreVulnerabilities } from "./risk";
import { generateCycloneDxSbom, type CycloneDxSbom } from "./sbom";
import type {
  DependencyInventory,
  PatchOrMitigationPlan,
  PolicyViolation,
  VulnerabilityPolicy,
  VulnerabilityReport,
} from "./types";
import { buildVexStatements } from "./vex";

export interface SecurityScanInput {
  rootDir: string;
  policy: VulnerabilityPolicy;
  policyHash: string;
  online: boolean;
  providers?: Partial<VulnerabilityProviders>;
}

export interface SecurityScanArtifacts {
  inventory: DependencyInventory;
  sbom: CycloneDxSbom;
  report: VulnerabilityReport;
  plan: PatchOrMitigationPlan;
  violations: PolicyViolation[];
}

export async function runSecurityScan(input: SecurityScanInput): Promise<SecurityScanArtifacts> {
  const timestamp = new Date().toISOString();
  const inventory = collectDependencyInventory(input.rootDir, input.policy);
  const sbom = generateCycloneDxSbom(inventory, { gitCommit: getGitCommit(input.rootDir) });
  const sbomHash = sha256Object(sbom);
  const providerContext: ProviderContext = {
    policy: input.policy,
    cacheDir: input.policy.paths.cacheDir,
    online: Boolean(input.online && input.policy.internetAccessAllowed),
    timestamp,
  };
  const providerResult = await correlateVulnerabilities(inventory.components, providerContext, input.providers);
  const risks = scoreVulnerabilities(providerResult.vulnerabilities, inventory.components);
  const vex = buildVexStatements(providerResult.vulnerabilities, risks, input.policy);
  const report: VulnerabilityReport = {
    schemaVersion: 1,
    generatedAt: timestamp,
    inventoryHash: sha256Object(inventory),
    sbomHash,
    policyHash: input.policyHash,
    vulnerabilities: providerResult.vulnerabilities,
    vex: vex.statements,
    risks,
    waivers: input.policy.waivers,
    providerFailures: providerResult.failures,
  };
  const reportHash = sha256Object(report);
  const provenance = buildProvenance({
    rootDir: input.rootDir,
    sourceCommit: getGitCommit(input.rootDir),
    policyHash: input.policyHash,
    sbomHash,
    vulnerabilityReportHash: reportHash,
  });
  const plan = buildPatchOrMitigationPlan({
    vulnerabilities: providerResult.vulnerabilities,
    risks,
    components: inventory.components,
    policy: input.policy,
    provenance,
  });
  const violations = [
    ...inventory.violations,
    ...policyViolationsForProviderFailures(input.policy, providerResult.failures),
    ...policyViolationsForRiskThresholds(input.policy, risks),
    ...vex.violations,
  ];
  return { inventory, sbom, report, plan, violations };
}

function policyViolationsForRiskThresholds(
  policy: VulnerabilityPolicy,
  risks: VulnerabilityReport["risks"],
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const failOnRisk = new Set(policy.thresholds.failOnRisk);
  for (const risk of risks) {
    if (failOnRisk.has(risk.riskClass)) {
      violations.push({
        code: "RISK_THRESHOLD_EXCEEDED",
        message: `Risk threshold exceeded for ${risk.vulnerabilityId}: ${risk.riskClass}`,
        severity: risk.riskClass,
        componentId: risk.componentId,
      });
    }
    if (policy.thresholds.failOnKnownExploited && risk.factors.some((factor) => factor.includes("known exploitation"))) {
      violations.push({
        code: "KNOWN_EXPLOITED_THRESHOLD_EXCEEDED",
        message: `Known exploited vulnerability requires waiver or mitigation: ${risk.vulnerabilityId}`,
        severity: "CRITICAL",
        componentId: risk.componentId,
      });
    }
  }
  return violations;
}

export function getGitCommit(rootDir: string): string | null {
  try {
    return childProcess
      .execFileSync("git", ["-c", `safe.directory=${rootDir.replace(/\\/g, "/")}`, "rev-parse", "HEAD"], {
        cwd: rootDir,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      })
      .trim();
  } catch {
    return null;
  }
}
