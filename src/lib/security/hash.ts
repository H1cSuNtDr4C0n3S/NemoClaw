// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

type Jsonish =
  | string
  | number
  | boolean
  | null
  | Jsonish[]
  | {
      [key: string]: Jsonish | undefined;
    };

export function stableStringify(value: unknown): string {
  return JSON.stringify(sortForStableJson(value as Jsonish));
}

function sortForStableJson(value: Jsonish | undefined): Jsonish | undefined {
  if (Array.isArray(value)) {
    return value.map((item) => sortForStableJson(item) as Jsonish);
  }
  if (value && typeof value === "object") {
    const result: Record<string, Jsonish> = {};
    for (const key of Object.keys(value).sort()) {
      const sorted = sortForStableJson(value[key]);
      if (sorted !== undefined) {
        result[key] = sorted;
      }
    }
    return result;
  }
  return value;
}

export function sha256Text(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

export function sha256Object(value: unknown): string {
  return sha256Text(stableStringify(value));
}

export function sha256File(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

export function normalizePathForId(rootDir: string, filePath: string): string {
  return path.relative(rootDir, filePath).replace(/\\/g, "/");
}
