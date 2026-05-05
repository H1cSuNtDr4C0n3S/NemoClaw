// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { sha256Object } from "./hash";
import type { DependencyInventory, InventoryComponent } from "./types";

export interface CycloneDxSbom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: {
      components: Array<{
        type: "application";
        name: string;
        version: string;
      }>;
    };
    component: {
      type: "application";
      name: string;
      version: string;
      "bom-ref": string;
    };
    properties: Array<{ name: string; value: string }>;
  };
  components: CycloneDxComponent[];
}

interface CycloneDxComponent {
  type: "library" | "container" | "application";
  name: string;
  version?: string;
  "bom-ref": string;
  purl?: string;
  hashes?: Array<{ alg: string; content: string }>;
  properties: Array<{ name: string; value: string }>;
}

export function generateCycloneDxSbom(
  inventory: DependencyInventory,
  options: { gitCommit?: string | null } = {},
): CycloneDxSbom {
  const components = inventory.components
    .map(toCycloneDxComponent)
    .sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${uuidFromHash(sha256Object({ components, rootDir: inventory.rootDir }))}`,
    version: 1,
    metadata: {
      timestamp: inventory.generatedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "NemoClaw enterprise vulnerability management",
            version: "1",
          },
        ],
      },
      component: {
        type: "application",
        name: "NemoClaw/OpenShell reference stack",
        version: options.gitCommit ?? "unknown",
        "bom-ref": "nemoclaw-openshell",
      },
      properties: [
        { name: "nemoclaw:inventoryHash", value: sha256Object(inventory) },
        { name: "nemoclaw:sourceCount", value: String(inventory.components.length) },
      ],
    },
    components,
  };
}

function toCycloneDxComponent(component: InventoryComponent): CycloneDxComponent {
  const properties = [
    { name: "nemoclaw:componentId", value: component.id },
    { name: "nemoclaw:ecosystem", value: component.ecosystem },
    { name: "nemoclaw:packageManager", value: component.packageManager },
    { name: "nemoclaw:sourceFile", value: component.sourceFile },
    { name: "nemoclaw:scope", value: component.scope },
    { name: "nemoclaw:runtimeLocation", value: component.runtimeLocation },
    { name: "nemoclaw:affectsNetwork", value: String(component.affects.network) },
    { name: "nemoclaw:affectsFilesystem", value: String(component.affects.filesystem) },
    { name: "nemoclaw:affectsProcess", value: String(component.affects.process) },
    { name: "nemoclaw:affectsSecrets", value: String(component.affects.secrets) },
    { name: "nemoclaw:affectsInference", value: String(component.affects.inference) },
    { name: "nemoclaw:affectsPolicy", value: String(component.affects.policy) },
  ];
  if (component.container) {
    properties.push(
      { name: "nemoclaw:containerBaseImage", value: component.container.baseImage ?? "" },
      { name: "nemoclaw:containerDigest", value: component.container.digest ?? "" },
      { name: "nemoclaw:containerMutableTag", value: String(component.container.mutableTag) },
    );
  }
  return {
    type: component.ecosystem === "container" ? "container" : "library",
    name: component.name,
    ...(component.version ? { version: component.version } : {}),
    "bom-ref": component.id,
    ...(component.purl ? { purl: component.purl } : {}),
    hashes: component.hashes.map((hash) => ({
      alg: hash.algorithm,
      content: hash.value,
    })),
    properties,
  };
}

function uuidFromHash(hash: string): string {
  const hex = hash.slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
