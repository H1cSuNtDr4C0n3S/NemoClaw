// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { parse as parseYaml } from "yaml";

import { ensureConfigDir } from "../config-io";
import { sha256Object } from "./hash";
import type {
  PolicyViolation,
  ProviderFailure,
  RiskClass,
  VulnerabilityPolicy,
  VulnerabilityWaiver,
} from "./types";

const DEFAULT_POLICY_PATH = path.join("security", "vulnerability-policy.yaml");
const RISK_CLASSES = new Set<RiskClass>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

export interface LoadedVulnerabilityPolicy {
  policy: VulnerabilityPolicy;
  policyHash: string;
  policyPath: string;
  violations: PolicyViolation[];
}

export function defaultPolicyPath(rootDir: string): string {
  return path.join(rootDir, DEFAULT_POLICY_PATH);
}

export function expandPolicyPath(value: string): string {
  if (value === "~") return os.homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

export function loadVulnerabilityPolicy(rootDir: string, policyPath?: string): LoadedVulnerabilityPolicy {
  const resolvedPolicyPath = path.resolve(rootDir, policyPath ?? DEFAULT_POLICY_PATH);
  if (!fs.existsSync(resolvedPolicyPath)) {
    throw new Error(`Vulnerability policy is required and was not found: ${resolvedPolicyPath}`);
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(fs.readFileSync(resolvedPolicyPath, "utf8"));
  } catch (error) {
    throw new Error(
      `Invalid vulnerability policy YAML: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const policyHash = sha256Object(policyControlsForHash(parsed));
  const policy = normalizePolicy(parsed, rootDir);
  const violations = validateVulnerabilityPolicy(policy, policyHash);
  if (policy.requireAudit && policy.paths.auditLog) {
    ensureConfigDir(path.dirname(policy.paths.auditLog));
  }
  if (policy.paths.cacheDir) ensureConfigDir(policy.paths.cacheDir);
  if (policy.paths.artifactDir) ensureConfigDir(policy.paths.artifactDir);

  return {
    policy,
    policyHash,
    policyPath: resolvedPolicyPath,
    violations,
  };
}

function normalizePolicy(value: unknown, rootDir: string): VulnerabilityPolicy {
  if (!isRecord(value)) {
    throw new Error("Invalid vulnerability policy: expected object");
  }
  const pathsValue = getRecord(value, "paths");
  const normalized = {
    ...value,
    paths: {
      cacheDir: resolveConfiguredPath(rootDir, getString(pathsValue, "cacheDir")),
      auditLog: resolveConfiguredPath(rootDir, getString(pathsValue, "auditLog")),
      artifactDir: resolveConfiguredPath(rootDir, getString(pathsValue, "artifactDir")),
    },
    waivers: Array.isArray(value.waivers) ? value.waivers : [],
  } as VulnerabilityPolicy;
  return normalized;
}

function policyControlsForHash(value: unknown): unknown {
  if (!isRecord(value)) return value;
  return {
    ...value,
    waivers: [],
  };
}

function resolveConfiguredPath(rootDir: string, value: string | null): string {
  if (!value) return "";
  const expanded = expandPolicyPath(value);
  return path.isAbsolute(expanded) ? expanded : path.resolve(rootDir, expanded);
}

export function validateVulnerabilityPolicy(
  policy: VulnerabilityPolicy,
  policyHash: string,
  now = new Date(),
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  requirePolicy(policy.schemaVersion === 1, "policy.schemaVersion must be 1", violations);
  requirePolicy(nonEmpty(policy.policyVersion), "policy.policyVersion is required", violations);
  requirePolicy(Boolean(policy.denyUnsafeSelfUpdate), "Unsafe self-update must be denied", violations);
  requirePolicy(
    Boolean(policy.denyRuntimePackageInstallation),
    "Runtime package installation must be denied",
    violations,
  );
  requirePolicy(Boolean(policy.requireSbom), "SBOM generation must be required", violations);
  requirePolicy(Boolean(policy.requireAudit), "Audit logging must be required", violations);
  if (policy.requireAudit) {
    requirePolicy(nonEmpty(policy.paths?.auditLog), "Audit log path is required", violations);
  }
  if (policy.requireSbom) {
    requirePolicy(nonEmpty(policy.paths?.artifactDir), "Artifact output directory is required", violations);
  }
  requirePolicy(nonEmpty(policy.paths?.cacheDir), "Provider cache directory is required", violations);
  requirePolicy(hasProviderPolicy(policy, "osv"), "OSV provider policy is required", violations);
  requirePolicy(hasProviderPolicy(policy, "cisaKev"), "CISA KEV provider policy is required", violations);
  requirePolicy(hasProviderPolicy(policy, "epss"), "EPSS provider policy is required", violations);

  if (policy.enterpriseMode) {
    requirePolicy(
      Boolean(policy.registryPolicy?.denyPublicPackagePulls),
      "Enterprise mode must deny public package pulls unless explicitly allowed",
      violations,
    );
    requirePolicy(
      Boolean(policy.rejectUnpinnedDependencies),
      "Enterprise mode must reject unpinned dependencies",
      violations,
    );
    requirePolicy(
      Boolean(policy.rejectMutableContainerTags),
      "Enterprise mode must reject mutable container tags",
      violations,
    );
    if (policy.registryPolicy?.internalMirrorsRequired) {
      requirePolicy(
        Array.isArray(policy.registryPolicy.internalMirrors) && policy.registryPolicy.internalMirrors.length > 0,
        "Enterprise mode requires at least one configured internal mirror when internalMirrorsRequired is true",
        violations,
      );
    }
  }

  for (const risk of policy.thresholds?.failOnRisk ?? []) {
    requirePolicy(RISK_CLASSES.has(risk), `Invalid failOnRisk class: ${risk}`, violations);
  }

  for (const waiver of policy.waivers ?? []) {
    violations.push(...validateWaiverGovernance(waiver, policyHash, now));
  }

  return violations;
}

function validateWaiverGovernance(
  waiver: VulnerabilityWaiver,
  policyHash: string,
  now: Date,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const prefix = `Waiver ${waiver.waiverId || "<missing>"}`;
  requirePolicy(nonEmpty(waiver.waiverId), `${prefix} requires waiver ID`, violations);
  requirePolicy(nonEmpty(waiver.component), `${prefix} requires component`, violations);
  requirePolicy(nonEmpty(waiver.vulnerabilityId), `${prefix} requires vulnerability ID`, violations);
  requirePolicy(nonEmpty(waiver.owner), `${prefix} requires owner`, violations);
  requirePolicy(
    nonEmpty(waiver.businessJustification),
    `${prefix} requires business justification`,
    violations,
  );
  requirePolicy(
    Array.isArray(waiver.compensatingControls) && waiver.compensatingControls.length > 0,
    `${prefix} requires compensating controls`,
    violations,
  );
  requirePolicy(
    Array.isArray(waiver.evidence) && waiver.evidence.length > 0,
    `${prefix} requires evidence`,
    violations,
  );
  requirePolicy(Boolean(waiver.approvalRecord), `${prefix} requires approval record`, violations);
  requirePolicy(nonEmpty(waiver.expirationDate), `${prefix} requires expiration date`, violations);
  requirePolicy(waiver.policyHash === policyHash, `${prefix} policy hash does not match`, violations);
  if (waiver.expirationDate && Number.isNaN(Date.parse(waiver.expirationDate))) {
    violations.push(failClosed("WAIVER_INVALID_EXPIRATION", `${prefix} expiration date is invalid`));
  } else if (isWaiverExpired(waiver, now)) {
    violations.push(failClosed("WAIVER_EXPIRED", `${prefix} is expired`));
  }
  return violations;
}

export function isWaiverExpired(waiver: VulnerabilityWaiver, now = new Date()): boolean {
  const expiration = Date.parse(waiver.expirationDate);
  return Number.isNaN(expiration) || expiration <= now.getTime();
}

export function findActiveWaiver(
  policy: VulnerabilityPolicy,
  componentNameOrId: string,
  vulnerabilityId: string,
  now = new Date(),
): VulnerabilityWaiver | null {
  return (
    policy.waivers.find(
      (waiver) =>
        !isWaiverExpired(waiver, now) &&
        waiver.vulnerabilityId === vulnerabilityId &&
        waiver.component === componentNameOrId,
    ) ?? null
  );
}

export function policyViolationsForProviderFailures(
  policy: VulnerabilityPolicy,
  failures: ProviderFailure[],
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  for (const failure of failures) {
    const provider = providerPolicyForFailure(policy, failure.provider);
    if (provider?.required || failure.fatal) {
      violations.push(
        failClosed(
          "REQUIRED_PROVIDER_FAILURE",
          `Required vulnerability provider failed closed: ${failure.provider}: ${failure.error}`,
        ),
      );
    }
  }
  return violations;
}

function providerPolicyForFailure(policy: VulnerabilityPolicy, provider: string) {
  const key = provider.toLowerCase();
  if (key.includes("osv")) return policy.providers.osv;
  if (key.includes("cisa") || key.includes("kev")) return policy.providers.cisaKev;
  if (key.includes("epss")) return policy.providers.epss;
  return null;
}

function hasProviderPolicy(policy: VulnerabilityPolicy, name: "osv" | "cisaKev" | "epss"): boolean {
  const provider = policy.providers?.[name];
  return (
    typeof provider?.enabled === "boolean" &&
    typeof provider?.required === "boolean" &&
    typeof provider?.cacheTtlHours === "number"
  );
}

function requirePolicy(
  condition: boolean,
  message: string,
  violations: PolicyViolation[],
): void {
  if (!condition) {
    violations.push(failClosed("POLICY_INVALID", message));
  }
}

function failClosed(code: string, message: string): PolicyViolation {
  return { code, message, severity: "CRITICAL" };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function getRecord(value: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const child = value[key];
  return isRecord(child) ? child : null;
}

function getString(value: Record<string, unknown> | null, key: string): string | null {
  const child = value?.[key];
  return typeof child === "string" ? child : null;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
