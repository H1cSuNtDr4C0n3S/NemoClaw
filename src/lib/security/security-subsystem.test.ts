// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import SecurityCliCommand, { hasBlockingSecurityViolation } from "../security-cli-command";
import { appendSecurityAuditEntry } from "./audit";
import { collectDependencyInventory } from "./inventory";
import { buildPatchOrMitigationPlan, buildProvenance, validatePatchCandidate } from "./planning";
import {
  loadVulnerabilityPolicy,
  policyViolationsForProviderFailures,
  validateVulnerabilityPolicy,
} from "./policy";
import { correlateVulnerabilities, enrichWithEpss, queryOsvProvider } from "./providers";
import { runSecurityScan } from "./report";
import { scoreVulnerabilityRisk } from "./risk";
import { generateCycloneDxSbom } from "./sbom";
import type {
  InventoryComponent,
  PatchOrMitigationPlan,
  PolicyViolation,
  ProviderFailure,
  VulnerabilityPolicy,
  VulnerabilityRecord,
} from "./types";
import { buildVexStatements } from "./vex";

describe("enterprise vulnerability management subsystem", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    process.exitCode = undefined;
  });

  it("parses dependency inventory and flags mutable Docker base images", () => {
    const root = tempRoot();
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ dependencies: { yaml: "^2.8.3" } }),
    );
    fs.writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({
        packages: {
          "": { name: "fixture" },
          "node_modules/yaml": { version: "2.8.3", integrity: "sha512-test" },
        },
      }),
    );
    fs.writeFileSync(path.join(root, "Dockerfile"), "FROM ubuntu:latest\nRUN apt-get install -y curl\n");
    fs.writeFileSync(path.join(root, "install.sh"), "apt-get install -y jq\n");
    fs.writeFileSync(path.join(root, "pnpm-lock.yaml"), "packages:\n  /left-pad@1.3.0:\n    resolution: {}\n");
    fs.writeFileSync(path.join(root, "yarn.lock"), '"is-number@1.0.0":\n  version "1.0.0"\n');
    fs.writeFileSync(path.join(root, "poetry.lock"), '[[package]]\nname = "requests"\nversion = "2.32.3"\n');

    const inventory = collectDependencyInventory(root, policy(root));

    expect(inventory.components.some((component) => component.name === "yaml" && component.version === "2.8.3")).toBe(true);
    expect(inventory.components.some((component) => component.packageManager === "pnpm-lock" && component.name === "left-pad")).toBe(true);
    expect(inventory.components.some((component) => component.packageManager === "yarn-lock" && component.name === "is-number")).toBe(true);
    expect(inventory.components.some((component) => component.packageManager === "poetry-lock" && component.name === "requests")).toBe(true);
    expect(inventory.components.some((component) => component.ecosystem === "container" && component.container?.mutableTag)).toBe(true);
    expect(inventory.violations.some((violation) => violation.code === "MUTABLE_CONTAINER_TAG")).toBe(true);
    expect(inventory.violations.some((violation) => violation.code === "UNPINNED_DEPENDENCY")).toBe(true);
    expect(inventory.violations.some((violation) => violation.code === "RUNTIME_PACKAGE_INSTALL_DENIED")).toBe(true);
  });

  it("generates deterministic CycloneDX SBOMs from inventory", () => {
    const root = tempRoot();
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { yaml: "2.8.3" } }),
    );
    fs.writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/yaml": { version: "2.8.3" } } }),
    );
    const inventory = collectDependencyInventory(root, policy(root));
    const sbom = generateCycloneDxSbom(inventory, { gitCommit: "abc123" });

    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.components.some((component) => component.name === "yaml")).toBe(true);
    expect(sbom.metadata.properties.some((property) => property.name === "nemoclaw:inventoryHash")).toBe(true);
  });

  it("supports mock OSV, CISA KEV, and EPSS providers without network", async () => {
    const root = tempRoot();
    const component = fixtureComponent(root);
    const result = await correlateVulnerabilities(
      [component],
      {
        policy: policy(root),
        cacheDir: path.join(root, ".cache"),
        online: false,
        timestamp: "2026-05-03T00:00:00.000Z",
      },
      {
        queryOsv: async () => ({ vulnerabilities: [fixtureVulnerability(component)], failures: [] }),
        enrichKev: async (vulnerabilities) => ({
          vulnerabilities: vulnerabilities.map((vulnerability) => ({ ...vulnerability, knownExploited: true })),
          failures: [],
        }),
        enrichEpss: async (vulnerabilities) => ({
          vulnerabilities: vulnerabilities.map((vulnerability) => ({
            ...vulnerability,
            epssProbability: 0.73,
            epssPercentile: 0.99,
          })),
          failures: [],
        }),
      },
    );

    expect(result.failures).toEqual([]);
    expect(result.vulnerabilities[0].knownExploited).toBe(true);
    expect(result.vulnerabilities[0].epssProbability).toBe(0.73);
  });

  it("records required provider failures as fail-closed policy violations", () => {
    const root = tempRoot();
    const strict = policy(root);
    strict.providers.epss.required = true;
    const failure: ProviderFailure = {
      provider: "epss",
      error: "offline",
      fatal: true,
      timestamp: "2026-05-03T00:00:00.000Z",
    };

    expect(policyViolationsForProviderFailures(strict, [failure])).toContainEqual(
      expect.objectContaining({ code: "REQUIRED_PROVIDER_FAILURE", severity: "CRITICAL" }),
    );
  });

  it("records malformed and partial provider responses instead of silently accepting them", async () => {
    const root = tempRoot();
    const component = fixtureComponent(root);
    const activePolicy = policy(root);
    activePolicy.internetAccessAllowed = true;

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({}),
      })),
    );

    const malformedOsv = await queryOsvProvider([component], {
      policy: activePolicy,
      cacheDir: path.join(root, ".cache"),
      online: true,
      timestamp: "2026-05-03T00:00:00.000Z",
    });

    expect(malformedOsv.failures).toContainEqual(
      expect.objectContaining({ provider: "osv", error: expect.stringContaining("Malformed OSV response") }),
    );

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ data: [] }),
      })),
    );

    const epssPartial = await enrichWithEpss([fixtureVulnerability(component)], {
      policy: activePolicy,
      cacheDir: path.join(root, ".cache-partial"),
      online: true,
      timestamp: "2026-05-03T00:00:00.000Z",
    });

    expect(epssPartial.failures).toContainEqual(
      expect.objectContaining({ provider: "epss", error: expect.stringContaining("missing data") }),
    );
  });

  it("scores risk with distinct CVSS, EPSS, KEV, reachability, and sensitive surface factors", () => {
    const root = tempRoot();
    const component = fixtureComponent(root);
    const vulnerability = {
      ...fixtureVulnerability(component),
      cvssScore: 9.8,
      severity: "CRITICAL" as const,
      epssProbability: 0.66,
      knownExploited: true,
      reachability: "UNKNOWN" as const,
    };

    const decision = scoreVulnerabilityRisk(vulnerability, component);

    expect(decision.riskClass).toBe("CRITICAL");
    expect(decision.explanation).toContain("CVSS describes theoretical severity");
    expect(decision.factors.some((factor) => factor.includes("EPSS exploit probability is high"))).toBe(true);
    expect(decision.factors.some((factor) => factor.includes("known exploitation"))).toBe(true);
    expect(decision.factors.some((factor) => factor.includes("treated as potentially reachable"))).toBe(true);
  });

  it("requires evidence and privileged approval for HIGH, CRITICAL, or KEV not_affected VEX", () => {
    const root = tempRoot();
    const component = fixtureComponent(root);
    const vulnerability = { ...fixtureVulnerability(component), knownExploited: true };
    const basePolicy = policy(root);
    basePolicy.waivers = [
      {
        waiverId: "W-1",
        component: component.id,
        vulnerabilityId: vulnerability.id,
        owner: "security",
        businessJustification: "Static analysis confirms vulnerable code path is not linked",
        compensatingControls: ["network egress deny-by-default"],
        approvalRecord: {
          approvalId: "APP-1",
          approvedBy: "security-lead",
          approvedAt: "2026-05-03T00:00:00.000Z",
          privileged: false,
        },
        expirationDate: "2026-06-03",
        evidence: ["analysis-report:123"],
        policyHash: "hash",
        vexStatus: "not_affected",
      },
    ];

    const result = buildVexStatements(
      [vulnerability],
      [{ vulnerabilityId: vulnerability.id, componentId: component.id, riskClass: "CRITICAL", score: 99, explanation: "", factors: [], reachability: "UNKNOWN" }],
      basePolicy,
      new Date("2026-05-03T00:00:00.000Z"),
    );

    expect(result.violations).toContainEqual(expect.objectContaining({ code: "VEX_NOT_AFFECTED_REQUIRES_APPROVAL" }));
    expect(result.statements[0].status).toBe("affected");
  });

  it("fails closed for expired waivers and missing audit paths", () => {
    const root = tempRoot();
    const bad = policy(root);
    bad.paths.auditLog = "";
    bad.waivers = [
      {
        waiverId: "W-expired",
        component: "component",
        vulnerabilityId: "CVE-2026-0001",
        owner: "security",
        businessJustification: "temporary exception",
        compensatingControls: ["blocked network"],
        approvalRecord: {
          approvalId: "APP-expired",
          approvedBy: "security",
          approvedAt: "2026-01-01T00:00:00.000Z",
          privileged: true,
        },
        expirationDate: "2026-01-02",
        evidence: ["ticket"],
        policyHash: "hash",
      },
    ];

    const violations = validateVulnerabilityPolicy(bad, "hash", new Date("2026-05-03T00:00:00.000Z"));

    expect(violations).toContainEqual(expect.objectContaining({ message: "Audit log path is required" }));
    expect(violations).toContainEqual(expect.objectContaining({ code: "WAIVER_EXPIRED" }));
  });

  it("throws on invalid policy YAML instead of failing open", () => {
    const root = tempRoot();
    fs.mkdirSync(path.join(root, "security"));
    fs.writeFileSync(path.join(root, "security", "vulnerability-policy.yaml"), "schemaVersion: [");

    expect(() => loadVulnerabilityPolicy(root)).toThrow(/Invalid vulnerability policy YAML/);
  });

  it("generates mitigation-only plans when no fixed version exists", () => {
    const root = tempRoot();
    const component = fixtureComponent(root);
    const vulnerability = { ...fixtureVulnerability(component), fixedVersion: null };
    const plan = buildPatchOrMitigationPlan({
      vulnerabilities: [vulnerability],
      risks: [scoreVulnerabilityRisk(vulnerability, component)],
      components: [component],
      policy: policy(root),
      provenance: buildProvenance({
        rootDir: root,
        sourceCommit: "abc123",
        policyHash: "policy",
        sbomHash: "sbom",
        vulnerabilityReportHash: "report",
      }),
    });

    expect(plan.mode).toBe("mitigation-plan");
    expect(plan.patchActions).toHaveLength(0);
    expect(plan.mitigationActions.some((action) => action.type === "quarantine-component")).toBe(true);
    expect(plan.mitigationActions.every((action) => action.approvalRequired)).toBe(true);
  });

  it("fails closed for missing provenance, missing SBOM, missing approval, and unsigned candidates", () => {
    const root = tempRoot();
    expect(validatePatchCandidate(policy(root), { schemaVersion: 1 } as PatchOrMitigationPlan)).toContainEqual(
      expect.objectContaining({ code: "PROVENANCE_MISSING" }),
    );
    const candidate: PatchOrMitigationPlan = {
      schemaVersion: 1,
      generatedAt: "2026-05-03T00:00:00.000Z",
      mode: "patch-plan",
      patchActions: [],
      mitigationActions: [],
      provenance: {
        sourceCommit: "abc123",
        builderIdentity: "builder",
        buildCommand: "npm test",
        lockfileHashes: {},
        sbomHash: null,
        policyHash: "policy",
        vulnerabilityReportHash: null,
        testReportHash: null,
        artifactDigest: null,
        approvalRecordReference: null,
        externalSignerRequired: true,
        externalSignatureReference: null,
      },
      warnings: [],
    };

    const codes = validatePatchCandidate(policy(root), candidate).map((violation) => violation.code);

    expect(codes).toContain("SBOM_MISSING");
    expect(codes).toContain("APPROVAL_MISSING");
    expect(codes).toContain("PROVENANCE_MISSING_VULN_REPORT");
    expect(codes).toContain("EXTERNAL_SIGNATURE_MISSING");
  });

  it("rejects candidates that disable the external signer or use a stale policy hash", () => {
    const root = tempRoot();
    const activePolicy = policy(root);
    const candidate: PatchOrMitigationPlan = {
      schemaVersion: 1,
      generatedAt: "2026-05-03T00:00:00.000Z",
      mode: "patch-plan",
      patchActions: [],
      mitigationActions: [],
      provenance: {
        sourceCommit: "abc123",
        builderIdentity: "builder",
        buildCommand: "npm test",
        lockfileHashes: { "package-lock.json": "hash" },
        sbomHash: "sbom",
        policyHash: "old-policy",
        vulnerabilityReportHash: "report",
        testReportHash: "tests",
        artifactDigest: "sha256:artifact",
        approvalRecordReference: "APP-1",
        externalSignerRequired: false,
        externalSignatureReference: "nemoclaw:self-signed",
      },
      warnings: [],
    };

    const codes = validatePatchCandidate(activePolicy, candidate, "current-policy").map((violation) => violation.code);

    expect(codes).toContain("POLICY_HASH_MISMATCH");
    expect(codes).toContain("EXTERNAL_SIGNER_REQUIRED");
    expect(codes).toContain("EXTERNAL_SIGNATURE_NOT_EXTERNAL");
  });

  it("appends redacted JSONL audit records and includes waivers", () => {
    const root = tempRoot();
    const activePolicy = policy(root);
    activePolicy.waivers = [
      {
        waiverId: "W-audit",
        component: "component",
        vulnerabilityId: "CVE-2026-0002",
        owner: "security",
        businessJustification: "approved exception",
        compensatingControls: ["isolated network"],
        approvalRecord: {
          approvalId: "APP-audit",
          approvedBy: "security",
          approvedAt: "2026-05-03T00:00:00.000Z",
          privileged: true,
        },
        expirationDate: "2026-06-03",
        evidence: ["https://internal.example/ticket/1?token=secret"],
        policyHash: "hash",
      },
    ];

    appendSecurityAuditEntry(activePolicy, {
      timestamp: "2026-05-03T00:00:00.000Z",
      actor: "tester",
      mode: "scan",
      gitCommit: "abc123",
      policyHash: "hash",
      vulnerabilityIds: ["CVE-2026-0002"],
      waivers: activePolicy.waivers,
      errors: [{ provider: "epss", error: "Bearer secret-token", fatal: false, timestamp: "now" }],
    });

    const line = fs.readFileSync(activePolicy.paths.auditLog, "utf8").trim();
    expect(line).toContain("W-audit");
    expect(line).toContain("<REDACTED>");
    expect(line).toContain("<REDACTED_PRIVATE_URL>");
    expect(line).not.toContain("secret-token");
    expect(line).not.toContain("internal.example");
  });

  it("keeps scan artifacts deterministic and includes waivers/provider failures in reports", async () => {
    const root = tempRoot();
    const activePolicy = policy(root);
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { yaml: "2.8.3" } }),
    );
    fs.writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/yaml": { version: "2.8.3" } } }),
    );
    activePolicy.waivers = [
      {
        waiverId: "W-report",
        component: "yaml",
        vulnerabilityId: "CVE-2026-9999",
        owner: "security",
        businessJustification: "temporary exception",
        compensatingControls: ["blocked egress"],
        approvalRecord: {
          approvalId: "APP-report",
          approvedBy: "security",
          approvedAt: "2026-05-03T00:00:00.000Z",
          privileged: true,
        },
        expirationDate: "2026-06-03",
        evidence: ["ticket"],
        policyHash: "hash",
      },
    ];

    const artifacts = await runSecurityScan({
      rootDir: root,
      policy: activePolicy,
      policyHash: "hash",
      online: false,
      providers: {
        queryOsv: async (components) => ({
          vulnerabilities: [fixtureVulnerability(components.find((component) => component.name === "yaml") ?? fixtureComponent(root))],
          failures: [],
        }),
        enrichKev: async (vulnerabilities) => ({ vulnerabilities, failures: [] }),
        enrichEpss: async (vulnerabilities) => ({
          vulnerabilities,
          failures: [{ provider: "epss", error: "offline", fatal: false, timestamp: "2026-05-03T00:00:00.000Z" }],
        }),
      },
    });

    expect(artifacts.report.waivers).toHaveLength(1);
    expect(artifacts.report.providerFailures).toContainEqual(expect.objectContaining({ provider: "epss" }));
    expect(artifacts.sbom.components.some((component) => component.name === "yaml")).toBe(true);
  });

  it("makes the CLI exit nonzero when scan emits blocking provider violations", async () => {
    const root = tempRoot();
    const activePolicy = policy(root);
    activePolicy.enterpriseMode = false;
    activePolicy.providers.osv.required = true;
    fs.mkdirSync(path.join(root, "security"));
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { yaml: "2.8.3" } }),
    );
    fs.writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/yaml": { version: "2.8.3" } } }),
    );
    fs.writeFileSync(path.join(root, "security", "vulnerability-policy.yaml"), JSON.stringify(activePolicy));
    const outputPath = path.join(root, "report.json");
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number | string | null) => {
      throw new Error(`process.exit:${String(code)}`);
    }) as never);
    vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(SecurityCliCommand.run(["scan", "--output", outputPath], root)).rejects.toThrow("process.exit:1");

    const report = JSON.parse(fs.readFileSync(outputPath, "utf8")) as { violations: PolicyViolation[] };
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(hasBlockingSecurityViolation(report.violations)).toBe(true);
    expect(report.violations).toContainEqual(
      expect.objectContaining({ code: "REQUIRED_PROVIDER_FAILURE", severity: "CRITICAL" }),
    );
  });
});

function tempRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-security-"));
}

function policy(root: string): VulnerabilityPolicy {
  return {
    schemaVersion: 1,
    policyVersion: "test-policy",
    enterpriseMode: true,
    internetAccessAllowed: false,
    requiredLockfiles: true,
    requireSbom: true,
    requireAudit: true,
    denyRuntimePackageInstallation: true,
    denyUnsafeSelfUpdate: true,
    rejectMutableContainerTags: true,
    rejectUnpinnedDependencies: true,
    providers: {
      osv: { enabled: true, required: false, cacheTtlHours: 24 },
      cisaKev: { enabled: true, required: false, cacheTtlHours: 24 },
      epss: { enabled: true, required: false, cacheTtlHours: 24 },
    },
    registryPolicy: {
      denyPublicPackagePulls: false,
      allowedPublicRegistries: [],
      internalMirrorsRequired: false,
      internalMirrors: [],
      allowedContainerRegistries: [],
    },
    thresholds: {
      failOnRisk: ["CRITICAL"],
      failOnKnownExploited: true,
      maxCriticalAgeDays: 7,
      maxHighAgeDays: 30,
    },
    autoPrepare: {
      enabled: false,
      allowPatchLevelOnly: true,
    },
    approvals: {
      requireForHighImpact: true,
      requireForMajorMinor: true,
      requirePrivilegedForKevCriticalWaivers: true,
    },
    emergencyMitigation: {
      enabled: true,
      allowUpgradeWithoutApproval: false,
    },
    paths: {
      cacheDir: path.join(root, ".cache"),
      auditLog: path.join(root, "audit.jsonl"),
      artifactDir: path.join(root, "artifacts"),
    },
    waivers: [],
  };
}

function fixtureComponent(root: string): InventoryComponent {
  return {
    id: "component-1",
    name: "yaml",
    version: "2.8.3",
    ecosystem: "npm",
    packageManager: "npm-lock",
    sourceFile: path.join(root, "package-lock.json"),
    scope: "runtime",
    affects: {
      network: true,
      filesystem: true,
      process: false,
      secrets: false,
      inference: false,
      policy: true,
    },
    hashes: [{ algorithm: "SHA-256", value: "hash", source: "package-lock.json" }],
    purl: "pkg:npm/yaml@2.8.3",
    runtimeLocation: "host-controller",
  };
}

function fixtureVulnerability(component: InventoryComponent): VulnerabilityRecord {
  return {
    id: "CVE-2026-9999",
    aliases: ["GHSA-test"],
    affectedComponentId: component.id,
    affectedComponentName: component.name,
    affectedVersion: component.version,
    affectedVersionRange: "introduced:0",
    fixedVersion: "2.8.4",
    sourceProvider: "osv",
    severity: "HIGH",
    cvssScore: 8.6,
    epssProbability: null,
    epssPercentile: null,
    knownExploited: false,
    references: [{ type: "ADVISORY", url: "https://osv.dev/vulnerability/CVE-2026-9999" }],
    confidence: "HIGH",
    publishedAt: "2026-05-01T00:00:00.000Z",
    modifiedAt: "2026-05-02T00:00:00.000Z",
    scanTimestamp: "2026-05-03T00:00:00.000Z",
    reachability: "UNKNOWN",
  };
}
