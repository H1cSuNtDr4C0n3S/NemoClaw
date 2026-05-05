// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { parse as parseYaml } from "yaml";

import { normalizePathForId, sha256File, sha256Text } from "./hash";
import type {
  DependencyHash,
  DependencyInventory,
  DependencyScope,
  InventoryComponent,
  PolicyViolation,
  SensitiveSurfaceFlags,
  VulnerabilityPolicy,
} from "./types";

const SKIP_DIRS = new Set([
  ".git",
  ".pytest_cache",
  ".venv",
  "coverage",
  "dist",
  "node_modules",
  "__pycache__",
]);

const EMPTY_SURFACES: SensitiveSurfaceFlags = {
  network: false,
  filesystem: false,
  process: false,
  secrets: false,
  inference: false,
  policy: false,
};

export function collectDependencyInventory(
  rootDir: string,
  policy: VulnerabilityPolicy,
): DependencyInventory {
  const files = walkFiles(rootDir);
  const components: InventoryComponent[] = [];

  for (const filePath of files) {
    const rel = normalizePathForId(rootDir, filePath);
    const base = path.basename(filePath);
    if (base === "package-lock.json") components.push(...parsePackageLock(rootDir, filePath));
    else if (base === "package.json") components.push(...parsePackageJson(rootDir, filePath));
    else if (base === "pnpm-lock.yaml") components.push(...parsePnpmLock(rootDir, filePath));
    else if (base === "yarn.lock") components.push(...parseYarnLock(rootDir, filePath));
    else if (base === "pyproject.toml") components.push(...parsePyproject(rootDir, filePath));
    else if (base === "uv.lock") components.push(...parseUvLock(rootDir, filePath));
    else if (base === "poetry.lock") components.push(...parsePoetryLock(rootDir, filePath));
    else if (/^requirements.*\.txt$/i.test(base)) components.push(...parseRequirements(rootDir, filePath));
    else if (/^Dockerfile(?:\..+)?$/i.test(base)) components.push(...parseDockerfile(rootDir, filePath));
    else if (rel.startsWith(".github/workflows/") && /\.ya?ml$/i.test(base)) {
      components.push(...parseGitHubActions(rootDir, filePath));
    } else if (rel.startsWith("agents/") && /manifest\.ya?ml$/i.test(base)) {
      components.push(...parseAgentManifest(rootDir, filePath));
    } else if (/\.(?:sh|bash|ps1|cmd)$/i.test(base) || rel === "install.sh" || rel === "uninstall.sh") {
      components.push(...parseInstallerScript(rootDir, filePath));
    }
  }

  components.sort((a, b) => a.id.localeCompare(b.id));
  const inventory: DependencyInventory = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    rootDir,
    components,
    sourceSummary: summarizeSources(components),
    violations: [],
  };
  inventory.violations = validateInventoryAgainstPolicy(rootDir, inventory, policy);
  return inventory;
}

export function validateInventoryAgainstPolicy(
  rootDir: string,
  inventory: DependencyInventory,
  policy: VulnerabilityPolicy,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  if (policy.requiredLockfiles) {
    const packageJsons = new Set(
      inventory.components
        .filter((component) => component.sourceFile.endsWith("package.json"))
        .map((component) => path.dirname(path.resolve(rootDir, component.sourceFile))),
    );
    for (const packageDir of packageJsons) {
      const hasLock =
        fs.existsSync(path.join(packageDir, "package-lock.json")) ||
        fs.existsSync(path.join(packageDir, "pnpm-lock.yaml")) ||
        fs.existsSync(path.join(packageDir, "yarn.lock"));
      if (!hasLock) {
        violations.push({
          code: "LOCKFILE_MISSING",
          message: `Package manifest requires a lockfile: ${normalizePathForId(rootDir, path.join(packageDir, "package.json"))}`,
          severity: "HIGH",
          sourceFile: normalizePathForId(rootDir, path.join(packageDir, "package.json")),
        });
      }
    }
  }

  for (const component of inventory.components) {
    if (policy.rejectUnpinnedDependencies && isUnpinned(component)) {
      violations.push({
        code: "UNPINNED_DEPENDENCY",
        message: `Dependency is not pinned: ${component.name}@${component.version ?? "<unknown>"}`,
        severity: "HIGH",
        sourceFile: component.sourceFile,
        componentId: component.id,
      });
    }
    if (policy.rejectMutableContainerTags && component.container?.mutableTag) {
      violations.push({
        code: "MUTABLE_CONTAINER_TAG",
        message: `Container base image must be digest-pinned in enterprise mode: ${component.container.baseImage}`,
        severity: "CRITICAL",
        sourceFile: component.sourceFile,
        componentId: component.id,
      });
    }
    if (
      policy.enterpriseMode &&
      policy.registryPolicy.denyPublicPackagePulls &&
      isPublicPull(component, policy)
    ) {
      violations.push({
        code: "PUBLIC_PACKAGE_PULL_DENIED",
        message: `Public package source is denied by enterprise policy: ${component.name}`,
        severity: "HIGH",
        sourceFile: component.sourceFile,
        componentId: component.id,
      });
    }
    if (policy.denyRuntimePackageInstallation && isRuntimeInstallerDependency(component)) {
      violations.push({
        code: "RUNTIME_PACKAGE_INSTALL_DENIED",
        message: `Runtime package installation path is denied by policy: ${component.name}`,
        severity: "HIGH",
        sourceFile: component.sourceFile,
        componentId: component.id,
      });
    }
  }
  return violations;
}

function parsePackageLock(rootDir: string, filePath: string): InventoryComponent[] {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as {
    packages?: Record<string, { name?: string; version?: string; dev?: boolean; integrity?: string }>;
    dependencies?: Record<string, { version?: string; dev?: boolean; integrity?: string }>;
  };
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  if (parsed.packages) {
    for (const [packagePath, pkg] of Object.entries(parsed.packages)) {
      if (!packagePath) continue;
      const name = pkg.name ?? nameFromNodeModulesPath(packagePath);
      if (!name) continue;
      components.push(
        component(rootDir, {
          name,
          version: pkg.version ?? null,
          ecosystem: "npm",
          packageManager: "npm-lock",
          sourceFile: rel,
          scope: pkg.dev ? "dev-only" : "runtime",
          affects: inferSurfaces(name, rel),
          runtimeLocation: inferRuntimeLocation(rel),
          hashes: [hash, ...(pkg.integrity ? [{ algorithm: "integrity" as const, value: pkg.integrity, source: rel }] : [])],
          purl: purl("npm", name, pkg.version),
          metadata: { lockfilePath: packagePath },
        }),
      );
    }
    return components;
  }
  for (const [name, dep] of Object.entries(parsed.dependencies ?? {})) {
    components.push(
      component(rootDir, {
        name,
        version: dep.version ?? null,
        ecosystem: "npm",
        packageManager: "npm-lock",
        sourceFile: rel,
        scope: dep.dev ? "dev-only" : "runtime",
        affects: inferSurfaces(name, rel),
        runtimeLocation: inferRuntimeLocation(rel),
        hashes: [hash, ...(dep.integrity ? [{ algorithm: "integrity" as const, value: dep.integrity, source: rel }] : [])],
        purl: purl("npm", name, dep.version),
      }),
    );
  }
  return components;
}

function parsePackageJson(rootDir: string, filePath: string): InventoryComponent[] {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as {
    name?: string;
    version?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
  };
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  if (typeof parsed.name === "string" && typeof parsed.version === "string") {
    components.push(
      component(rootDir, {
        name: parsed.name,
        version: parsed.version,
        ecosystem: "npm",
        packageManager: "package-json",
        sourceFile: rel,
        scope: "runtime",
        affects: inferSurfaces(parsed.name, rel),
        runtimeLocation: inferRuntimeLocation(rel),
        hashes: [hash],
        purl: purl("npm", parsed.name, parsed.version),
        metadata: { projectManifest: true },
      }),
    );
  }
  for (const [name, version] of Object.entries(parsed.dependencies ?? {})) {
    components.push(nodeManifestComponent(rootDir, rel, hash, name, version, "runtime"));
  }
  for (const [name, version] of Object.entries(parsed.optionalDependencies ?? {})) {
    components.push(nodeManifestComponent(rootDir, rel, hash, name, version, "runtime"));
  }
  for (const [name, version] of Object.entries(parsed.peerDependencies ?? {})) {
    components.push(nodeManifestComponent(rootDir, rel, hash, name, version, "unknown"));
  }
  for (const [name, version] of Object.entries(parsed.devDependencies ?? {})) {
    components.push(nodeManifestComponent(rootDir, rel, hash, name, version, "dev-only"));
  }
  return components;
}

function parsePnpmLock(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const parsed = parseYaml(fs.readFileSync(filePath, "utf8")) as unknown;
  const components: InventoryComponent[] = [];
  if (isRecord(parsed) && isRecord(parsed.packages)) {
    for (const key of Object.keys(parsed.packages)) {
      const parsedPackage = parsePnpmPackageKey(key);
      if (!parsedPackage) continue;
      components.push(
        component(rootDir, {
          name: parsedPackage.name,
          version: parsedPackage.version,
          ecosystem: "npm",
          packageManager: "pnpm-lock",
          sourceFile: rel,
          scope: "runtime",
          affects: inferSurfaces(parsedPackage.name, rel),
          runtimeLocation: inferRuntimeLocation(rel),
          hashes: [hash],
          purl: purl("npm", parsedPackage.name, parsedPackage.version),
          metadata: { lockfilePath: key },
        }),
      );
    }
  }
  return components;
}

function parseYarnLock(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const text = fs.readFileSync(filePath, "utf8");
  const components: InventoryComponent[] = [];
  const blocks = text.split(/\n(?=\S)/g);
  for (const block of blocks) {
    const header = block.match(/^("?[^:\n]+"?):/m)?.[1]?.replace(/^"|"$/g, "");
    const version = block.match(/^\s+version\s+"([^"]+)"/m)?.[1];
    const name = header ? yarnNameFromHeader(header) : null;
    if (!name || !version) continue;
    components.push(
      component(rootDir, {
        name,
        version,
        ecosystem: "npm",
        packageManager: "yarn-lock",
        sourceFile: rel,
        scope: "runtime",
        affects: inferSurfaces(name, rel),
        runtimeLocation: inferRuntimeLocation(rel),
        hashes: [hash],
        purl: purl("npm", name, version),
        metadata: { lockfileKey: header ?? name },
      }),
    );
  }
  return components;
}

function nodeManifestComponent(
  rootDir: string,
  sourceFile: string,
  hash: DependencyHash,
  name: string,
  version: string,
  scope: DependencyScope,
): InventoryComponent {
  return component(rootDir, {
    name,
    version,
    ecosystem: "npm",
    packageManager: "package-json",
    sourceFile,
    scope,
    affects: inferSurfaces(name, sourceFile),
    runtimeLocation: inferRuntimeLocation(sourceFile),
    hashes: [hash],
    purl: purl("npm", name, version),
    metadata: { versionSpec: version },
  });
}

function parsePyproject(rootDir: string, filePath: string): InventoryComponent[] {
  const text = fs.readFileSync(filePath, "utf8");
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const runtime = extractTomlArray(text, "dependencies");
  const optional = [...text.matchAll(/^\s*[\w-]+\s*=\s*\[([\s\S]*?)^\s*\]/gm)].flatMap((match) =>
    extractRequirementStrings(match[1] ?? ""),
  );
  return [...runtime.map((dep) => pythonComponent(rootDir, rel, hash, dep, "runtime")), ...optional.map((dep) => pythonComponent(rootDir, rel, hash, dep, "unknown"))];
}

function parseUvLock(rootDir: string, filePath: string): InventoryComponent[] {
  const text = fs.readFileSync(filePath, "utf8");
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  const packageBlocks = text.split(/\n(?=\[\[package\]\])/g);
  for (const block of packageBlocks) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name) {
      components.push(pythonResolvedComponent(rootDir, rel, hash, name, version ?? null, "uv-lock"));
    }
  }
  return components;
}

function parsePoetryLock(rootDir: string, filePath: string): InventoryComponent[] {
  const text = fs.readFileSync(filePath, "utf8");
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  const packageBlocks = text.split(/\n(?=\[\[package\]\])/g);
  for (const block of packageBlocks) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name) {
      components.push(pythonResolvedComponent(rootDir, rel, hash, name, version ?? null, "poetry-lock"));
    }
  }
  return components;
}

function parseRequirements(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  return lines
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("-"))
    .map((line) => pythonComponent(rootDir, rel, hash, line, "runtime"));
}

function parseDockerfile(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  const args = new Map<string, string>();
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    const arg = trimmed.match(/^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.+))?$/i);
    if (arg) args.set(arg[1], arg[2] ?? "");
    const from = trimmed.match(/^FROM\s+([^\s]+)(?:\s+AS\s+(.+))?/i);
    if (from) {
      const resolved = resolveDockerArgs(from[1], args);
      const parsed = parseContainerImage(resolved);
      components.push(
        component(rootDir, {
          name: parsed.name,
          version: parsed.version,
          ecosystem: "container",
          packageManager: "dockerfile",
          sourceFile: rel,
          sourceLine: index + 1,
          scope: "runtime",
          affects: { ...EMPTY_SURFACES, filesystem: true, process: true, network: true },
          runtimeLocation: "sandbox-runtime",
          hashes: [hash],
          purl: parsed.digest ? `pkg:docker/${encodeURIComponent(parsed.name)}@${parsed.digest}` : undefined,
          container: {
            image: resolved,
            baseImage: resolved,
            digest: parsed.digest,
            mutableTag: parsed.mutableTag,
            stage: from[2] ?? null,
          },
          metadata: { dockerfileIntent: "base-image" },
        }),
      );
    }
    components.push(...parseDockerInstallLine(rootDir, rel, hash, trimmed, index + 1));
  }
  return components;
}

function parseDockerInstallLine(
  rootDir: string,
  sourceFile: string,
  hash: DependencyHash,
  line: string,
  sourceLine: number,
): InventoryComponent[] {
  const components: InventoryComponent[] = [];
  const apt = line.match(/\bapt(?:-get)?\s+install\b([^;&|]+)/i);
  if (apt) {
    for (const token of apt[1].split(/\s+/).map(cleanPackageToken).filter(Boolean)) {
      if (token.startsWith("-")) continue;
      const [name, version = null] = token.split("=", 2);
      components.push(osPackageComponent(rootDir, sourceFile, sourceLine, hash, "apt", name, version));
    }
  }
  const apk = line.match(/\bapk\s+add\b([^;&|]+)/i);
  if (apk) {
    for (const token of apk[1].split(/\s+/).map(cleanPackageToken).filter(Boolean)) {
      if (token.startsWith("-")) continue;
      const [name, version = null] = token.split("=", 2);
      components.push(osPackageComponent(rootDir, sourceFile, sourceLine, hash, "apk", name, version));
    }
  }
  const rpm = line.match(/\b(?:dnf|yum|rpm)\s+(?:install|-i)\b([^;&|]+)/i);
  if (rpm) {
    for (const token of rpm[1].split(/\s+/).map(cleanPackageToken).filter(Boolean)) {
      if (token.startsWith("-")) continue;
      const [name, version = null] = token.split("=", 2);
      components.push(osPackageComponent(rootDir, sourceFile, sourceLine, hash, "rpm", name, version));
    }
  }
  return components;
}

function parseGitHubActions(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const parsed = parseYaml(fs.readFileSync(filePath, "utf8")) as unknown;
  const actions: string[] = [];
  collectWorkflowUses(parsed, actions);
  return actions.map((value) => {
    const [name, version = null] = value.split("@", 2);
    return component(rootDir, {
      name,
      version,
      ecosystem: "github-actions",
      packageManager: "github-actions",
      sourceFile: rel,
      scope: "build-time",
      affects: { ...EMPTY_SURFACES, secrets: true, filesystem: true, network: true },
      runtimeLocation: "ci",
      hashes: [hash],
      metadata: { uses: value },
    });
  });
}

function parseAgentManifest(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const parsed = parseYaml(fs.readFileSync(filePath, "utf8")) as unknown;
  const components: InventoryComponent[] = [];
  if (isRecord(parsed)) {
    for (const key of ["dependencies", "tools", "skills", "plugins"]) {
      const values = parsed[key];
      if (Array.isArray(values)) {
        for (const item of values) {
          const name = typeof item === "string" ? item : isRecord(item) && typeof item.name === "string" ? item.name : null;
          const version = isRecord(item) && typeof item.version === "string" ? item.version : null;
          if (name) {
            components.push(
              component(rootDir, {
                name,
                version,
                ecosystem: "agent-manifest",
                packageManager: "agent-manifest",
                sourceFile: rel,
                scope: "runtime",
                affects: { ...EMPTY_SURFACES, filesystem: true, process: true, network: true, policy: true },
                runtimeLocation: "plugin",
                hashes: [hash],
              }),
            );
          }
        }
      }
    }
  }
  return components;
}

function parseInstallerScript(rootDir: string, filePath: string): InventoryComponent[] {
  const rel = normalizePathForId(rootDir, filePath);
  const hash = lockHash(filePath);
  const components: InventoryComponent[] = [];
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    components.push(...parseDockerInstallLine(rootDir, rel, hash, lines[index].trim(), index + 1));
  }
  return components.map((item) => ({
    ...item,
    runtimeLocation: "installer",
  }));
}

function pythonComponent(
  rootDir: string,
  sourceFile: string,
  hash: DependencyHash,
  spec: string,
  scope: DependencyScope,
): InventoryComponent {
  const parsed = parsePythonRequirement(spec);
  return pythonResolvedComponent(rootDir, sourceFile, hash, parsed.name, parsed.version, "python", scope, {
    versionSpec: spec,
  });
}

function pythonResolvedComponent(
  rootDir: string,
  sourceFile: string,
  hash: DependencyHash,
  name: string,
  version: string | null,
  packageManager: string,
  scope: DependencyScope = "runtime",
  metadata?: Record<string, string>,
): InventoryComponent {
  return component(rootDir, {
    name,
    version,
    ecosystem: "PyPI",
    packageManager,
    sourceFile,
    scope,
    affects: inferSurfaces(name, sourceFile),
    runtimeLocation: inferRuntimeLocation(sourceFile),
    hashes: [hash],
    purl: purl("pypi", name, version),
    metadata,
  });
}

function osPackageComponent(
  rootDir: string,
  sourceFile: string,
  sourceLine: number,
  hash: DependencyHash,
  manager: "apt" | "apk" | "rpm",
  name: string,
  version: string | null,
): InventoryComponent {
  return component(rootDir, {
    name,
    version,
    ecosystem: manager,
    packageManager: manager,
    sourceFile,
    sourceLine,
    scope: "runtime",
    affects: { ...EMPTY_SURFACES, filesystem: true, process: true, network: true },
    runtimeLocation: sourceFile.toLowerCase().includes("dockerfile") ? "sandbox-runtime" : "installer",
    hashes: [hash],
    purl: purl(manager, name, version),
  });
}

function component(
  rootDir: string,
  input: Omit<InventoryComponent, "id">,
): InventoryComponent {
  const idText = `${input.packageManager}:${input.name}:${input.version ?? ""}:${input.sourceFile}:${input.sourceLine ?? ""}`;
  return {
    id: sha256Text(`${rootDir}:${idText}`).slice(0, 16),
    ...input,
  };
}

function walkFiles(rootDir: string): string[] {
  const results: string[] = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(path.join(current, entry.name));
      } else if (entry.isFile()) {
        results.push(path.join(current, entry.name));
      }
    }
  }
  return results.sort();
}

function summarizeSources(components: InventoryComponent[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const component of components) {
    summary[component.packageManager] = (summary[component.packageManager] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(summary).sort(([a], [b]) => a.localeCompare(b)));
}

function lockHash(filePath: string): DependencyHash {
  return {
    algorithm: "SHA-256",
    value: sha256File(filePath),
    source: path.basename(filePath),
  };
}

function purl(type: string, name: string, version?: string | null): string | undefined {
  if (!version) return undefined;
  return `pkg:${type}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function nameFromNodeModulesPath(packagePath: string): string | null {
  const marker = "node_modules/";
  const index = packagePath.lastIndexOf(marker);
  return index >= 0 ? packagePath.slice(index + marker.length) : null;
}

function extractTomlArray(text: string, key: string): string[] {
  const match = text.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)^\\s*\\]`, "m"));
  return match ? extractRequirementStrings(match[1] ?? "") : [];
}

function extractRequirementStrings(text: string): string[] {
  return [...text.matchAll(/"([^"]+)"/g)].map((match) => match[1]).filter(Boolean);
}

function parsePythonRequirement(spec: string): { name: string; version: string | null } {
  const cleaned = spec.split(";")[0].trim();
  const match = cleaned.match(/^([A-Za-z0-9_.-]+)\s*(?:\[.*\])?\s*(==|~=|>=|<=|>|<|=)\s*([^,\s]+)/);
  return { name: match?.[1] ?? cleaned.replace(/\[.*\]/, ""), version: match ? `${match[2]}${match[3]}` : null };
}

function parsePnpmPackageKey(value: string): { name: string; version: string } | null {
  const key = value.replace(/^\//, "");
  const parts = key.split("/");
  const last = parts[parts.length - 1] ?? "";
  if (key.startsWith("@") && parts.length >= 2) {
    const versionIndex = last.lastIndexOf("@");
    if (versionIndex <= 0) return null;
    return {
      name: `${parts[0]}/${last.slice(0, versionIndex)}`,
      version: last.slice(versionIndex + 1),
    };
  }
  const versionIndex = last.lastIndexOf("@");
  if (versionIndex <= 0) return null;
  return {
    name: last.slice(0, versionIndex),
    version: last.slice(versionIndex + 1),
  };
}

function yarnNameFromHeader(value: string): string | null {
  const first = value.split(",")[0]?.trim();
  if (!first) return null;
  const withoutProtocol = first.replace(/^npm:/, "");
  if (withoutProtocol.startsWith("@")) {
    const index = withoutProtocol.indexOf("@", 1);
    return index > 0 ? withoutProtocol.slice(0, index) : withoutProtocol;
  }
  const index = withoutProtocol.indexOf("@");
  return index > 0 ? withoutProtocol.slice(0, index) : withoutProtocol;
}

function resolveDockerArgs(value: string, args: Map<string, string>): string {
  return value.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_match, name: string) => args.get(name) ?? "");
}

function parseContainerImage(image: string): {
  name: string;
  version: string | null;
  digest: string | null;
  mutableTag: boolean;
} {
  const [withoutDigest, digestPart] = image.split("@", 2);
  const slashIndex = withoutDigest.lastIndexOf("/");
  const tagIndex = withoutDigest.lastIndexOf(":");
  const hasTag = tagIndex > slashIndex;
  const name = hasTag ? withoutDigest.slice(0, tagIndex) : withoutDigest;
  const tag = hasTag ? withoutDigest.slice(tagIndex + 1) : null;
  const digest = digestPart ?? null;
  return {
    name,
    version: digest ?? tag,
    digest,
    mutableTag: digest === null,
  };
}

function cleanPackageToken(token: string): string {
  return token.replace(/\\$/, "").replace(/^["']|["']$/g, "").trim();
}

function collectWorkflowUses(value: unknown, actions: string[]): void {
  if (Array.isArray(value)) {
    for (const item of value) collectWorkflowUses(item, actions);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (key === "uses" && typeof child === "string") actions.push(child);
    else collectWorkflowUses(child, actions);
  }
}

function inferSurfaces(name: string, sourceFile: string): SensitiveSurfaceFlags {
  const lower = `${name} ${sourceFile}`.toLowerCase();
  return {
    network: /(http|fetch|request|axios|cloudflare|docker|ssh|socket|tls|ssl|web|url)/.test(lower),
    filesystem: /(fs|file|path|tar|zip|docker|ssh|shell|script|install|uv|npm)/.test(lower),
    process: /(child|process|spawn|exec|shell|docker|tsx|typescript|node|bash|sh)/.test(lower),
    secrets: /(secret|credential|token|auth|key|oauth|env)/.test(lower),
    inference: /(openai|anthropic|nvidia|nim|model|inference|gateway)/.test(lower),
    policy: /(policy|permission|sandbox|shield|opa|seccomp|apparmor|openclaw|openshell)/.test(lower),
  };
}

function inferRuntimeLocation(sourceFile: string): InventoryComponent["runtimeLocation"] {
  const rel = sourceFile.toLowerCase();
  if (rel.startsWith(".github/")) return "ci";
  if (rel.includes("dockerfile")) return "sandbox-runtime";
  if (rel.startsWith("docs/")) return "docs";
  if (rel.includes("gateway")) return "inference-gateway";
  if (rel.includes("installer") || rel.endsWith("install.sh")) return "installer";
  if (rel.startsWith("agents/") || rel.includes("plugin")) return "plugin";
  if (rel.includes("build") || rel.includes("script")) return "build-pipeline";
  return "host-controller";
}

function isUnpinned(component: InventoryComponent): boolean {
  if (component.container) return component.container.mutableTag;
  if (component.ecosystem === "github-actions") {
    return !/^[a-f0-9]{40}$/i.test(component.version ?? "");
  }
  if (!component.version) return true;
  if (component.packageManager.endsWith("lock") || component.packageManager === "uv-lock") return false;
  return /^[~^*]|[<>=]|latest|workspace:|file:|git\+|https?:/i.test(component.version);
}

function isPublicPull(component: InventoryComponent, policy: VulnerabilityPolicy): boolean {
  if (component.packageManager === "package-json" || component.packageManager === "python") {
    return policy.registryPolicy.allowedPublicRegistries.length === 0;
  }
  if (component.container?.baseImage) {
    const registry = registryFromImage(component.container.baseImage);
    return !policy.registryPolicy.allowedContainerRegistries.includes(registry);
  }
  return false;
}

function isRuntimeInstallerDependency(component: InventoryComponent): boolean {
  return (
    component.runtimeLocation === "installer" &&
    ["apt", "apk", "rpm", "pip", "npm"].includes(component.packageManager)
  );
}

function registryFromImage(image: string): string {
  const first = image.split("/")[0] ?? "";
  if (first.includes(".") || first.includes(":") || first === "localhost") return first;
  return "docker.io";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
