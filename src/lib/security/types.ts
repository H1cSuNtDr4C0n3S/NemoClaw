// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export type DependencyScope = "runtime" | "build-time" | "dev-only" | "unknown";
export type RiskClass = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type VexStatus = "affected" | "not_affected" | "fixed" | "under_investigation";
export type ReachabilityState =
  | "REACHABLE_CONFIRMED"
  | "REACHABLE_INFERRED"
  | "NOT_REACHABLE_INFERRED"
  | "UNKNOWN";

export interface SensitiveSurfaceFlags {
  network: boolean;
  filesystem: boolean;
  process: boolean;
  secrets: boolean;
  inference: boolean;
  policy: boolean;
}

export interface DependencyHash {
  algorithm: "SHA-256" | "SHA-512" | "integrity" | "unknown";
  value: string;
  source: string;
}

export interface PolicyViolation {
  code: string;
  message: string;
  severity: RiskClass;
  sourceFile?: string;
  componentId?: string;
}

export interface InventoryComponent {
  id: string;
  name: string;
  version: string | null;
  ecosystem: string;
  packageManager: string;
  sourceFile: string;
  sourceLine?: number;
  scope: DependencyScope;
  affects: SensitiveSurfaceFlags;
  hashes: DependencyHash[];
  purl?: string;
  runtimeLocation:
    | "host-controller"
    | "sandbox-runtime"
    | "inference-gateway"
    | "installer"
    | "ci"
    | "build-pipeline"
    | "plugin"
    | "docs"
    | "unknown";
  container?: {
    image?: string;
    baseImage?: string;
    digest?: string | null;
    mutableTag: boolean;
    stage?: string | null;
  };
  metadata?: Record<string, string | number | boolean | null>;
}

export interface DependencyInventory {
  schemaVersion: 1;
  generatedAt: string;
  rootDir: string;
  components: InventoryComponent[];
  sourceSummary: Record<string, number>;
  violations: PolicyViolation[];
}

export interface ProviderFailure {
  provider: string;
  error: string;
  fatal: boolean;
  timestamp: string;
}

export interface VulnerabilityReference {
  type: string;
  url: string;
}

export interface VulnerabilityRecord {
  id: string;
  aliases: string[];
  affectedComponentId: string;
  affectedComponentName: string;
  affectedVersion: string | null;
  affectedVersionRange: string | null;
  fixedVersion: string | null;
  sourceProvider: string;
  severity: RiskClass | null;
  cvssScore: number | null;
  epssProbability: number | null;
  epssPercentile: number | null;
  knownExploited: boolean;
  references: VulnerabilityReference[];
  confidence: "HIGH" | "MEDIUM" | "LOW";
  publishedAt: string | null;
  modifiedAt: string | null;
  scanTimestamp: string;
  reachability: ReachabilityState;
}

export interface VexStatement {
  vulnerabilityId: string;
  componentId: string;
  status: VexStatus;
  justification: string | null;
  evidence: string[];
  approvedBy: string | null;
  approvalRecord: string | null;
}

export interface RiskDecision {
  vulnerabilityId: string;
  componentId: string;
  riskClass: RiskClass;
  score: number;
  explanation: string;
  factors: string[];
  reachability: ReachabilityState;
}

export interface VulnerabilityReport {
  schemaVersion: 1;
  generatedAt: string;
  inventoryHash: string;
  sbomHash: string | null;
  policyHash: string;
  vulnerabilities: VulnerabilityRecord[];
  vex: VexStatement[];
  risks: RiskDecision[];
  waivers: VulnerabilityWaiver[];
  providerFailures: ProviderFailure[];
}

export interface PatchPlanAction {
  type: "update-dependency" | "update-container-image" | "manual-review";
  componentId: string;
  vulnerabilityId: string;
  currentVersion: string | null;
  targetVersion: string | null;
  reason: string;
  approvalRequired: boolean;
  approvalReasons: string[];
  requiredTests: string[];
  rollback: string;
}

export interface MitigationPlanAction {
  type:
    | "disable-tool"
    | "remove-network-allowlist-binary"
    | "tighten-network-policy"
    | "tighten-filesystem-policy"
    | "tighten-process-policy"
    | "switch-audit-to-enforce"
    | "revoke-temporary-capability"
    | "quarantine-component"
    | "block-runtime-use"
    | "manual-review";
  componentId: string;
  vulnerabilityId: string;
  reason: string;
  approvalRequired: boolean;
  requiredTests: string[];
  rollback: string;
}

export interface SlsaStyleProvenance {
  sourceCommit: string | null;
  builderIdentity: string | null;
  buildCommand: string | null;
  lockfileHashes: Record<string, string>;
  sbomHash: string | null;
  policyHash: string;
  vulnerabilityReportHash: string | null;
  testReportHash: string | null;
  artifactDigest: string | null;
  approvalRecordReference: string | null;
  externalSignerRequired: boolean;
  externalSignatureReference: string | null;
}

export interface PatchOrMitigationPlan {
  schemaVersion: 1;
  generatedAt: string;
  mode: "patch-plan" | "mitigation-plan" | "combined";
  patchActions: PatchPlanAction[];
  mitigationActions: MitigationPlanAction[];
  provenance: SlsaStyleProvenance;
  warnings: string[];
}

export interface ApprovalRecord {
  approvedBy: string;
  approvedAt: string;
  approvalId: string;
  privileged: boolean;
}

export interface VulnerabilityWaiver {
  waiverId: string;
  component: string;
  vulnerabilityId: string;
  owner: string;
  businessJustification: string;
  compensatingControls: string[];
  approvalRecord: ApprovalRecord | null;
  expirationDate: string;
  evidence: string[];
  policyHash: string;
  vexStatus?: VexStatus;
}

export interface ProviderPolicy {
  enabled: boolean;
  required: boolean;
  cacheTtlHours: number;
  url?: string;
}

export interface VulnerabilityPolicy {
  schemaVersion: 1;
  policyVersion: string;
  enterpriseMode: boolean;
  internetAccessAllowed: boolean;
  requiredLockfiles: boolean;
  requireSbom: boolean;
  requireAudit: boolean;
  denyRuntimePackageInstallation: boolean;
  denyUnsafeSelfUpdate: boolean;
  rejectMutableContainerTags: boolean;
  rejectUnpinnedDependencies: boolean;
  providers: {
    osv: ProviderPolicy;
    cisaKev: ProviderPolicy;
    epss: ProviderPolicy;
  };
  registryPolicy: {
    denyPublicPackagePulls: boolean;
    allowedPublicRegistries: string[];
    internalMirrorsRequired: boolean;
    internalMirrors: string[];
    allowedContainerRegistries: string[];
  };
  thresholds: {
    failOnRisk: RiskClass[];
    failOnKnownExploited: boolean;
    maxCriticalAgeDays: number;
    maxHighAgeDays: number;
  };
  autoPrepare: {
    enabled: boolean;
    allowPatchLevelOnly: boolean;
  };
  approvals: {
    requireForHighImpact: boolean;
    requireForMajorMinor: boolean;
    requirePrivilegedForKevCriticalWaivers: boolean;
  };
  emergencyMitigation: {
    enabled: boolean;
    allowUpgradeWithoutApproval: boolean;
  };
  paths: {
    cacheDir: string;
    auditLog: string;
    artifactDir: string;
  };
  waivers: VulnerabilityWaiver[];
}

export interface SecurityAuditEntry {
  timestamp: string;
  actor: string;
  mode: string;
  gitCommit: string | null;
  policyHash: string;
  dependencyInventoryHash?: string;
  sbomPath?: string | null;
  sbomHash?: string | null;
  vulnerabilityIds?: string[];
  riskDecisions?: RiskDecision[];
  proposedPatches?: PatchPlanAction[];
  proposedMitigations?: MitigationPlanAction[];
  testsRun?: string[];
  approvalStatus?: string;
  appliedChanges?: string[];
  rollbackMetadata?: string[];
  waivers?: VulnerabilityWaiver[];
  errors?: ProviderFailure[];
}
