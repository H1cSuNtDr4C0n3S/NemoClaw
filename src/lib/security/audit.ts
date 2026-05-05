// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import { ensureConfigDir } from "../config-io";
import { redactFull } from "../redact";
import type { SecurityAuditEntry, VulnerabilityPolicy } from "./types";

export function appendSecurityAuditEntry(
  policy: VulnerabilityPolicy,
  entry: SecurityAuditEntry,
): void {
  if (!policy.requireAudit || !policy.paths.auditLog) {
    throw new Error("Audit logging is required by policy but audit path is missing");
  }
  const auditPath = policy.paths.auditLog;
  ensureConfigDir(path.dirname(auditPath));
  rejectSymlinkAuditTarget(auditPath);
  const redacted = redactAuditValue(entry);
  fs.appendFileSync(auditPath, `${JSON.stringify(redacted)}\n`, { mode: 0o600 });
  fs.chmodSync(auditPath, 0o600);
}

function rejectSymlinkAuditTarget(auditPath: string): void {
  try {
    if (fs.lstatSync(auditPath).isSymbolicLink()) {
      throw new Error(`Refusing to append security audit log through a symbolic link: ${auditPath}`);
    }
  } catch (error) {
    if (error && typeof error === "object" && (error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
}

export function redactAuditValue(value: unknown): unknown {
  if (typeof value === "string") return redactPrivateUrls(redactFull(value));
  if (Array.isArray(value)) return value.map((item) => redactAuditValue(item));
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const redactedKey = redactFull(key);
      if (isSecretKey(key)) {
        result[redactedKey] = "<REDACTED>";
      } else {
        result[redactedKey] = redactAuditValue(child);
      }
    }
    return result;
  }
  return value;
}

function isSecretKey(key: string): boolean {
  return /(token|secret|password|credential|api[_-]?key|private[_-]?url|auth)/i.test(key);
}

function redactPrivateUrls(value: string): string {
  return value.replace(/https?:\/\/[^\s"']+/g, (candidate) => {
    try {
      const url = new URL(candidate);
      if (isPrivateHost(url.hostname)) return "<REDACTED_PRIVATE_URL>";
      return url.toString();
    } catch {
      return candidate;
    }
  });
}

function isPrivateHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (
    lower === "localhost" ||
    lower.startsWith("internal.") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal") ||
    lower.endsWith(".example")
  ) {
    return true;
  }
  if (/^10\./.test(lower)) return true;
  if (/^192\.168\./.test(lower)) return true;
  const private172 = lower.match(/^172\.(\d+)\./);
  return private172 ? Number(private172[1]) >= 16 && Number(private172[1]) <= 31 : false;
}
