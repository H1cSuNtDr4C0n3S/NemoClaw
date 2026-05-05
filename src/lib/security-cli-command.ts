// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/* v8 ignore start -- thin oclif adapter covered through CLI and module tests. */

import fs from "node:fs";
import path from "node:path";

import { Command } from "@oclif/core";

import { appendSecurityAuditEntry } from "./security/audit";
import { sha256Object } from "./security/hash";
import { collectDependencyInventory } from "./security/inventory";
import { loadVulnerabilityPolicy } from "./security/policy";
import { validatePatchCandidate } from "./security/planning";
import { runSecurityScan, getGitCommit } from "./security/report";
import { generateCycloneDxSbom } from "./security/sbom";
import type { PatchOrMitigationPlan, PolicyViolation, VulnerabilityPolicy } from "./security/types";
import type { RiskDecision } from "./security/types";
import { ensureConfigDir } from "./config-io";

type ParsedSecurityArgs = {
  subcommand: string;
  policyPath?: string;
  outputPath?: string;
  candidatePath?: string;
  json: boolean;
  online: boolean;
};

const COMMANDS = new Set([
  "policy-check",
  "inventory",
  "sbom",
  "scan",
  "vuln-report",
  "patch-plan",
  "mitigation-plan",
  "prepare-patch",
  "test-patch",
  "apply-approved",
]);

function printUsage(): void {
  console.log(
    [
      "Usage: nemoclaw security <command> [--policy <path>] [--output <path>] [--json] [--online]",
      "",
      "Commands:",
      "  policy-check      Validate security policy and inventory constraints",
      "  inventory         Emit normalized dependency inventory JSON",
      "  sbom              Emit CycloneDX JSON SBOM",
      "  scan              Emit vulnerability report with VEX and risk decisions",
      "  vuln-report       Alias for scan",
      "  patch-plan        Emit patch and mitigation planning JSON",
      "  mitigation-plan   Emit mitigation-only planning JSON",
      "  prepare-patch     Emit candidate plan metadata; does not modify tracked files",
      "  test-patch        Validate candidate test/provenance metadata",
      "  apply-approved    Fail closed unless approval, provenance, and external signature exist",
    ].join("\n"),
  );
}

function parseArgs(argv: string[]): ParsedSecurityArgs {
  const subcommand = argv[0] ?? "help";
  const result: ParsedSecurityArgs = {
    subcommand,
    json: false,
    online: false,
  };
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--json") result.json = true;
    else if (arg === "--online") result.online = true;
    else if (arg === "--policy") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error("--policy requires a value");
      result.policyPath = value;
      index += 1;
    } else if (arg === "--output") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error("--output requires a value");
      result.outputPath = value;
      index += 1;
    } else if (arg === "--candidate") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error("--candidate requires a value");
      result.candidatePath = value;
      index += 1;
    } else {
      throw new Error(`Unknown security flag: ${arg}`);
    }
  }
  return result;
}

function writeOrPrint(value: unknown, outputPath?: string): void {
  const text = JSON.stringify(value, null, 2);
  if (outputPath) {
    ensureConfigDir(path.dirname(path.resolve(outputPath)));
    fs.writeFileSync(outputPath, `${text}\n`, { mode: 0o600 });
    console.log(outputPath);
    return;
  }
  console.log(text);
}

export function hasBlockingSecurityViolation(violations: PolicyViolation[]): boolean {
  return violations.some((violation) => violation.severity === "CRITICAL" || violation.severity === "HIGH");
}

function audit(
  policy: VulnerabilityPolicy,
  mode: string,
  policyHash: string,
  payload: {
    inventoryHash?: string;
    sbomHash?: string | null;
    vulnerabilityIds?: string[];
    riskDecisions?: RiskDecision[];
    patches?: PatchOrMitigationPlan["patchActions"];
    mitigations?: PatchOrMitigationPlan["mitigationActions"];
    errors?: Parameters<typeof appendSecurityAuditEntry>[1]["errors"];
    waivers?: Parameters<typeof appendSecurityAuditEntry>[1]["waivers"];
  },
  rootDir: string,
): void {
  appendSecurityAuditEntry(policy, {
    timestamp: new Date().toISOString(),
    actor: process.env.USER || process.env.USERNAME || "unknown",
    mode,
    gitCommit: getGitCommit(rootDir),
    policyHash,
    dependencyInventoryHash: payload.inventoryHash,
    sbomHash: payload.sbomHash ?? null,
    vulnerabilityIds: payload.vulnerabilityIds,
    riskDecisions: payload.riskDecisions,
    proposedPatches: payload.patches,
    proposedMitigations: payload.mitigations,
    approvalStatus: "not-approved",
    appliedChanges: [],
    rollbackMetadata: [],
    waivers: payload.waivers,
    errors: payload.errors,
  });
}

function readCandidate(filePath: string): PatchOrMitigationPlan {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  return parsed as PatchOrMitigationPlan;
}

export default class SecurityCliCommand extends Command {
  static id = "security";
  static strict = false;
  static summary = "Run enterprise vulnerability management workflows";
  static description =
    "Inventory dependencies, generate SBOMs, correlate vulnerabilities, score risk, emit VEX, plan patches/mitigations, and validate approval gates.";
  static usage = ["security <command> [--policy <path>] [--output <path>] [--json] [--online]"];

  public async run(): Promise<void> {
    let args: ParsedSecurityArgs;
    try {
      args = parseArgs(this.argv);
    } catch (error) {
      console.error(`  ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
    if (args.subcommand === "help" || args.subcommand === "--help" || args.subcommand === "-h") {
      printUsage();
      return;
    }
    if (!COMMANDS.has(args.subcommand)) {
      console.error(`  Unknown security command: ${args.subcommand}`);
      printUsage();
      process.exit(2);
    }

    let loaded;
    try {
      loaded = loadVulnerabilityPolicy(this.config.root, args.policyPath);
    } catch (error) {
      console.error(`  ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
    const { policy, policyHash, violations: policyViolations } = loaded;

    if (args.subcommand === "policy-check") {
      const inventory = collectDependencyInventory(this.config.root, policy);
      const violations = [...policyViolations, ...inventory.violations];
      const result = {
        ok: violations.length === 0,
        policyHash,
        violations,
      };
      writeOrPrint(result, args.outputPath);
      if (hasBlockingSecurityViolation(violations)) process.exit(1);
      return;
    }

    if (policyViolations.length > 0) {
      writeOrPrint({ ok: false, policyHash, violations: policyViolations }, args.outputPath);
      process.exit(1);
    }

    if (args.subcommand === "inventory") {
      const inventory = collectDependencyInventory(this.config.root, policy);
      writeOrPrint(inventory, args.outputPath);
      audit(policy, "inventory", policyHash, { inventoryHash: sha256Object(inventory), waivers: policy.waivers }, this.config.root);
      if (hasBlockingSecurityViolation(inventory.violations)) process.exit(1);
      return;
    }

    if (args.subcommand === "sbom") {
      const inventory = collectDependencyInventory(this.config.root, policy);
      const sbom = generateCycloneDxSbom(inventory, { gitCommit: getGitCommit(this.config.root) });
      writeOrPrint(sbom, args.outputPath);
      audit(
        policy,
        "sbom",
        policyHash,
        { inventoryHash: sha256Object(inventory), sbomHash: sha256Object(sbom), waivers: policy.waivers },
        this.config.root,
      );
      if (hasBlockingSecurityViolation(inventory.violations)) process.exit(1);
      return;
    }

    if (
      args.subcommand === "scan" ||
      args.subcommand === "vuln-report" ||
      args.subcommand === "patch-plan" ||
      args.subcommand === "mitigation-plan" ||
      args.subcommand === "prepare-patch"
    ) {
      const artifacts = await runSecurityScan({
        rootDir: this.config.root,
        policy,
        policyHash,
        online: args.online,
      });
      if (args.subcommand === "scan" || args.subcommand === "vuln-report") {
        writeOrPrint({ ...artifacts.report, violations: artifacts.violations }, args.outputPath);
      } else if (args.subcommand === "mitigation-plan") {
        writeOrPrint(
          {
            ...artifacts.plan,
            patchActions: [],
            mode: "mitigation-plan",
          },
          args.outputPath,
        );
      } else {
        writeOrPrint(artifacts.plan, args.outputPath);
      }
      audit(
        policy,
        args.subcommand,
        policyHash,
        {
          inventoryHash: sha256Object(artifacts.inventory),
          sbomHash: sha256Object(artifacts.sbom),
          vulnerabilityIds: artifacts.report.vulnerabilities.map((vuln) => vuln.id),
          riskDecisions: artifacts.report.risks,
          patches: artifacts.plan.patchActions,
          mitigations: artifacts.plan.mitigationActions,
          errors: artifacts.report.providerFailures,
          waivers: policy.waivers,
        },
        this.config.root,
      );
      if (hasBlockingSecurityViolation(artifacts.violations)) process.exit(1);
      return;
    }

    if (args.subcommand === "test-patch" || args.subcommand === "apply-approved") {
      if (!args.candidatePath) {
        console.error("  --candidate is required");
        process.exit(1);
      }
      const candidate = readCandidate(path.resolve(args.candidatePath));
      const violations = validatePatchCandidate(policy, candidate, policyHash);
      writeOrPrint(summarizeCandidateValidation(candidate, violations), args.outputPath);
      if (violations.length > 0 || args.subcommand === "apply-approved") {
        if (args.subcommand === "apply-approved" && violations.length === 0) {
          console.error("  Approved apply is intentionally not implemented in V1; use the approved release pipeline.");
        }
        process.exit(1);
      }
    }
  }
}

function summarizeCandidateValidation(
  candidate: PatchOrMitigationPlan,
  violations: PolicyViolation[],
): Record<string, unknown> {
  const provenance = candidate.provenance;
  return {
    ok: violations.length === 0,
    violations,
    candidateHash: sha256Object(candidate),
    mode: candidate.mode ?? null,
    patchActionCount: Array.isArray(candidate.patchActions) ? candidate.patchActions.length : 0,
    mitigationActionCount: Array.isArray(candidate.mitigationActions) ? candidate.mitigationActions.length : 0,
    provenanceStatus: provenance
      ? {
          hasSourceCommit: Boolean(provenance.sourceCommit),
          hasBuilderIdentity: Boolean(provenance.builderIdentity),
          hasLockfileHashes: Object.keys(provenance.lockfileHashes ?? {}).length > 0,
          hasSbomHash: Boolean(provenance.sbomHash),
          hasVulnerabilityReportHash: Boolean(provenance.vulnerabilityReportHash),
          hasTestReportHash: Boolean(provenance.testReportHash),
          hasArtifactDigest: Boolean(provenance.artifactDigest),
          hasApprovalRecordReference: Boolean(provenance.approvalRecordReference),
          externalSignerRequired: provenance.externalSignerRequired === true,
          hasExternalSignatureReference: Boolean(provenance.externalSignatureReference),
        }
      : null,
  };
}
