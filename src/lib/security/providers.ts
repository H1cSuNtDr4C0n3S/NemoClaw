// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { ensureConfigDir } from "../config-io";
import { sha256Object, sha256Text } from "./hash";
import type {
  InventoryComponent,
  ProviderFailure,
  ReachabilityState,
  RiskClass,
  VulnerabilityPolicy,
  VulnerabilityRecord,
  VulnerabilityReference,
} from "./types";

export interface ProviderContext {
  policy: VulnerabilityPolicy;
  cacheDir: string;
  online: boolean;
  timestamp: string;
}

export interface VulnerabilityProviders {
  queryOsv: (components: InventoryComponent[], context: ProviderContext) => Promise<ProviderResult>;
  enrichKev: (vulnerabilities: VulnerabilityRecord[], context: ProviderContext) => Promise<ProviderResult>;
  enrichEpss: (vulnerabilities: VulnerabilityRecord[], context: ProviderContext) => Promise<ProviderResult>;
}

export interface ProviderResult {
  vulnerabilities: VulnerabilityRecord[];
  failures: ProviderFailure[];
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  details?: string;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string; purl?: string };
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
    versions?: string[];
  }>;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ type?: string; url?: string }>;
}

interface CachedPayload<T> {
  createdAt: string;
  value: T;
}

export async function correlateVulnerabilities(
  components: InventoryComponent[],
  context: ProviderContext,
  providers: Partial<VulnerabilityProviders> = {},
): Promise<ProviderResult> {
  let vulnerabilities: VulnerabilityRecord[] = [];
  const failures: ProviderFailure[] = [];

  if (context.policy.providers.osv.enabled) {
    const result = await (providers.queryOsv ?? queryOsvProvider)(components, context);
    vulnerabilities = mergeVulnerabilities(vulnerabilities, result.vulnerabilities);
    failures.push(...result.failures);
  }

  if (context.policy.providers.cisaKev.enabled) {
    const result = await (providers.enrichKev ?? enrichWithCisaKev)(vulnerabilities, context);
    vulnerabilities = result.vulnerabilities;
    failures.push(...result.failures);
  }

  if (context.policy.providers.epss.enabled) {
    const result = await (providers.enrichEpss ?? enrichWithEpss)(vulnerabilities, context);
    vulnerabilities = result.vulnerabilities;
    failures.push(...result.failures);
  }

  vulnerabilities.sort((a, b) => `${a.id}:${a.affectedComponentId}`.localeCompare(`${b.id}:${b.affectedComponentId}`));
  return { vulnerabilities, failures };
}

export async function queryOsvProvider(
  components: InventoryComponent[],
  context: ProviderContext,
): Promise<ProviderResult> {
  const queryable = components.filter((component) => osvEcosystem(component) !== null && component.version);
  const vulnerabilities: VulnerabilityRecord[] = [];
  const failures: ProviderFailure[] = [];
  if (queryable.length === 0) return { vulnerabilities, failures };
  if (!context.online) {
    let cacheHits = 0;
    for (const component of queryable) {
      const cached = readCache<OsvVulnerability[]>(context, "osv", cacheKey(component));
      if (cached) {
        cacheHits += 1;
        vulnerabilities.push(...cached.flatMap((vuln) => osvToRecords(vuln, component, context.timestamp)));
      }
    }
    if (cacheHits < queryable.length) {
      failures.push(providerFailure("osv", "OSV query skipped because scanning is offline and cache is incomplete", context));
    }
    return { vulnerabilities, failures };
  }

  for (const component of queryable) {
    try {
      const cached = readCache<OsvVulnerability[]>(context, "osv", cacheKey(component));
      if (cached) {
        vulnerabilities.push(...cached.flatMap((vuln) => osvToRecords(vuln, component, context.timestamp)));
        continue;
      }
      const response = await fetch(context.policy.providers.osv.url ?? "https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          version: component.version,
          package: {
            name: component.name,
            ecosystem: osvEcosystem(component),
          },
        }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const parsed = (await response.json()) as unknown;
      if (!isRecord(parsed) || !Array.isArray(parsed.vulns)) {
        throw new Error("Malformed OSV response: expected vulns array");
      }
      const vulns = parsed.vulns as OsvVulnerability[];
      writeCache(context, "osv", cacheKey(component), vulns);
      vulnerabilities.push(...vulns.flatMap((vuln) => osvToRecords(vuln, component, context.timestamp)));
    } catch (error) {
      failures.push(providerFailure("osv", error instanceof Error ? error.message : String(error), context));
    }
  }
  return { vulnerabilities, failures };
}

export async function enrichWithCisaKev(
  vulnerabilities: VulnerabilityRecord[],
  context: ProviderContext,
): Promise<ProviderResult> {
  if (vulnerabilities.length === 0) return { vulnerabilities, failures: [] };
  const failures: ProviderFailure[] = [];
  const kevIds = new Set<string>();
  try {
    const cached = readCache<string[]>(context, "cisa-kev", "known-exploited");
    if (cached) {
      for (const id of cached) kevIds.add(id);
    } else if (context.online) {
      const response = await fetch(
        context.policy.providers.cisaKev.url ??
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const parsed = (await response.json()) as unknown;
      if (!isRecord(parsed) || !Array.isArray(parsed.vulnerabilities)) {
        throw new Error("Malformed CISA KEV response: expected vulnerabilities array");
      }
      const entries = parsed.vulnerabilities as Array<{ cveID?: string }>;
      const ids = entries.map((entry) => entry.cveID).filter(isString);
      if (ids.length !== entries.length) {
        throw new Error("Malformed CISA KEV response: vulnerability entry missing cveID");
      }
      writeCache(context, "cisa-kev", "known-exploited", ids);
      for (const id of ids) kevIds.add(id);
    } else {
      failures.push(providerFailure("cisa-kev", "CISA KEV enrichment skipped because scanning is offline and cache is absent", context));
    }
  } catch (error) {
    failures.push(providerFailure("cisa-kev", error instanceof Error ? error.message : String(error), context));
  }

  const enriched = vulnerabilities.map((vuln) => {
    const ids = [vuln.id, ...vuln.aliases];
    if (!ids.some((id) => kevIds.has(id))) return vuln;
    return {
      ...vuln,
      knownExploited: true,
      references: addReference(vuln.references, {
        type: "ADVISORY",
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      }),
    };
  });
  return { vulnerabilities: enriched, failures };
}

export async function enrichWithEpss(
  vulnerabilities: VulnerabilityRecord[],
  context: ProviderContext,
): Promise<ProviderResult> {
  const cves = [...new Set(vulnerabilities.flatMap((vuln) => [vuln.id, ...vuln.aliases]).filter((id) => /^CVE-\d{4}-\d+$/i.test(id)))];
  if (cves.length === 0) return { vulnerabilities, failures: [] };
  const failures: ProviderFailure[] = [];
  const epss = new Map<string, { probability: number; percentile: number }>();
  try {
    const cached = readCache<Record<string, { probability: number; percentile: number }>>(context, "epss", sha256Text(cves.sort().join(",")));
    if (cached) {
      for (const [id, value] of Object.entries(cached)) epss.set(id, value);
    } else if (context.online) {
      const url = new URL(context.policy.providers.epss.url ?? "https://api.first.org/data/v1/epss");
      url.searchParams.set("cve", cves.join(","));
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const parsed = (await response.json()) as unknown;
      if (!isRecord(parsed) || !Array.isArray(parsed.data)) {
        throw new Error("Malformed EPSS response: expected data array");
      }
      const values: Record<string, { probability: number; percentile: number }> = {};
      for (const row of parsed.data as Array<{ cve?: string; epss?: string; percentile?: string }>) {
        if (!row.cve) continue;
        const probability = Number(row.epss);
        const percentile = Number(row.percentile);
        if (Number.isNaN(probability) || Number.isNaN(percentile)) {
          throw new Error(`Malformed EPSS response: invalid numeric values for ${row.cve}`);
        }
        values[row.cve] = {
          probability,
          percentile,
        };
      }
      const missing = cves.filter((cve) => !values[cve]);
      if (missing.length > 0) {
        failures.push(
          providerFailure(
            "epss",
            `EPSS response missing data for ${missing.length} CVE(s): ${missing.slice(0, 5).join(", ")}`,
            context,
          ),
        );
      }
      writeCache(context, "epss", sha256Text(cves.sort().join(",")), values);
      for (const [id, value] of Object.entries(values)) epss.set(id, value);
    } else {
      failures.push(providerFailure("epss", "EPSS enrichment skipped because scanning is offline and cache is absent", context));
    }
  } catch (error) {
    failures.push(providerFailure("epss", error instanceof Error ? error.message : String(error), context));
  }

  return {
    vulnerabilities: vulnerabilities.map((vuln) => {
      const id = [vuln.id, ...vuln.aliases].find((candidate) => epss.has(candidate));
      if (!id) return vuln;
      const value = epss.get(id);
      return {
        ...vuln,
        epssProbability: value?.probability ?? null,
        epssPercentile: value?.percentile ?? null,
        references: addReference(vuln.references, {
          type: "EXPLOITABILITY",
          url: "https://www.first.org/epss/",
        }),
      };
    }),
    failures,
  };
}

function osvToRecords(
  vulnerability: OsvVulnerability,
  component: InventoryComponent,
  timestamp: string,
): VulnerabilityRecord[] {
  const id = vulnerability.id ?? vulnerability.aliases?.[0] ?? `OSV-${sha256Object(vulnerability).slice(0, 12)}`;
  const aliases = (vulnerability.aliases ?? []).filter((alias) => alias !== id);
  const cvssScore = cvssFromOsv(vulnerability);
  return [
    {
      id,
      aliases,
      affectedComponentId: component.id,
      affectedComponentName: component.name,
      affectedVersion: component.version,
      affectedVersionRange: affectedRange(vulnerability),
      fixedVersion: fixedVersion(vulnerability),
      sourceProvider: "osv",
      severity: severityFromOsv(vulnerability, cvssScore),
      cvssScore,
      epssProbability: null,
      epssPercentile: null,
      knownExploited: false,
      references: (vulnerability.references ?? [])
        .filter((ref) => ref.url)
        .map((ref) => ({ type: ref.type ?? "ADVISORY", url: ref.url as string })),
      confidence: "HIGH",
      publishedAt: vulnerability.published ?? null,
      modifiedAt: vulnerability.modified ?? null,
      scanTimestamp: timestamp,
      reachability: inferReachability(component),
    },
  ];
}

function fixedVersion(vulnerability: OsvVulnerability): string | null {
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function affectedRange(vulnerability: OsvVulnerability): string | null {
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      const events = (range.events ?? [])
        .map((event) => {
          if (event.introduced) return `introduced:${event.introduced}`;
          if (event.fixed) return `fixed:${event.fixed}`;
          if (event.last_affected) return `last_affected:${event.last_affected}`;
          return null;
        })
        .filter(isString);
      if (events.length > 0) return events.join(",");
    }
    if ((affected.versions ?? []).length > 0) return `versions:${affected.versions?.join(",")}`;
  }
  return null;
}

function cvssFromOsv(vulnerability: OsvVulnerability): number | null {
  for (const severity of vulnerability.severity ?? []) {
    const score = severity.score ?? "";
    const direct = Number(score);
    if (!Number.isNaN(direct) && direct > 0) return direct;
    const baseScore = score.match(/BASE_SCORE:([0-9.]+)/i)?.[1];
    if (baseScore) return Number(baseScore);
  }
  return null;
}

function severityFromOsv(vulnerability: OsvVulnerability, cvssScore: number | null): RiskClass | null {
  const severity = vulnerability.database_specific?.severity?.toUpperCase();
  if (severity === "CRITICAL" || severity === "HIGH" || severity === "MEDIUM" || severity === "LOW") {
    return severity;
  }
  if (cvssScore === null) return null;
  if (cvssScore >= 9) return "CRITICAL";
  if (cvssScore >= 7) return "HIGH";
  if (cvssScore >= 4) return "MEDIUM";
  return "LOW";
}

function osvEcosystem(component: InventoryComponent): string | null {
  if (component.ecosystem === "npm") return "npm";
  if (component.ecosystem === "PyPI") return "PyPI";
  if (component.ecosystem === "github-actions") return "GitHub Actions";
  return null;
}

export function inferReachability(component: InventoryComponent): ReachabilityState {
  if (component.metadata?.reachability === "REACHABLE_CONFIRMED") return "REACHABLE_CONFIRMED";
  if (component.affects.network || component.affects.process || component.affects.secrets || component.affects.policy || component.affects.inference) {
    return "REACHABLE_INFERRED";
  }
  if (component.scope === "dev-only" && !component.affects.filesystem) return "NOT_REACHABLE_INFERRED";
  return "UNKNOWN";
}

function mergeVulnerabilities(
  existing: VulnerabilityRecord[],
  incoming: VulnerabilityRecord[],
): VulnerabilityRecord[] {
  const byKey = new Map(existing.map((vuln) => [`${vuln.id}:${vuln.affectedComponentId}`, vuln]));
  for (const vuln of incoming) {
    byKey.set(`${vuln.id}:${vuln.affectedComponentId}`, vuln);
  }
  return [...byKey.values()];
}

function readCache<T>(context: ProviderContext, provider: string, key: string): T | null {
  const filePath = cachePath(context, provider, key);
  if (!fs.existsSync(filePath)) return null;
  try {
    const cached = JSON.parse(fs.readFileSync(filePath, "utf8")) as CachedPayload<T>;
    const ttlMs = ttlHours(context, provider) * 60 * 60 * 1000;
    if (Date.now() - Date.parse(cached.createdAt) > ttlMs) return null;
    return cached.value;
  } catch {
    return null;
  }
}

function writeCache<T>(context: ProviderContext, provider: string, key: string, value: T): void {
  const filePath = cachePath(context, provider, key);
  ensureConfigDir(path.dirname(filePath));
  const payload: CachedPayload<T> = { createdAt: new Date().toISOString(), value };
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
}

function cachePath(context: ProviderContext, provider: string, key: string): string {
  return path.join(context.cacheDir, provider, `${sha256Text(key)}.json`);
}

function cacheKey(component: InventoryComponent): string {
  return sha256Object({
    name: component.name,
    version: component.version,
    ecosystem: component.ecosystem,
    purl: component.purl,
  });
}

function ttlHours(context: ProviderContext, provider: string): number {
  if (provider === "osv") return context.policy.providers.osv.cacheTtlHours;
  if (provider === "cisa-kev") return context.policy.providers.cisaKev.cacheTtlHours;
  if (provider === "epss") return context.policy.providers.epss.cacheTtlHours;
  return 24;
}

function providerFailure(provider: string, error: string, context: ProviderContext): ProviderFailure {
  return {
    provider,
    error,
    fatal: providerIsRequired(provider, context.policy),
    timestamp: new Date().toISOString(),
  };
}

function providerIsRequired(provider: string, policy: VulnerabilityPolicy): boolean {
  if (provider === "osv") return policy.providers.osv.required;
  if (provider === "cisa-kev") return policy.providers.cisaKev.required;
  if (provider === "epss") return policy.providers.epss.required;
  return false;
}

function addReference(
  references: VulnerabilityReference[],
  reference: VulnerabilityReference,
): VulnerabilityReference[] {
  if (references.some((existing) => existing.url === reference.url)) return references;
  return [...references, reference];
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
