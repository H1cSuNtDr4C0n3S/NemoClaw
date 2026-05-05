---
title:
  page: "Enterprise Hardening Roadmap"
  nav: "Enterprise Roadmap"
description:
  main: "Recommended next steps for operating NemoClaw/OpenShell in high-security enterprise environments."
keywords: ["nemoclaw enterprise hardening", "slsa", "signed containers", "immutable runtime", "siem"]
topics: ["generative_ai", "ai_agents", "security"]
tags: ["nemoclaw", "openshell", "enterprise", "supply_chain"]
content:
  type: concept
  difficulty: technical_advanced
  audience: ["security_engineer", "platform_engineer"]
status: published
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Enterprise Hardening Roadmap

This roadmap lists recommended controls for high-security enterprise deployments of NemoClaw/OpenShell.
It separates reference-stack functionality from controls that should be enforced by an organization’s release, identity, signing, network, and monitoring platforms.

:::{warning}
This subsystem can prepare and validate patches, but production rollout must be performed through the organization’s approved release pipeline.
:::

## Supply Chain

- Require internal package mirrors for npm, PyPI, OS packages, and container base images.
- Deny public package pulls by default and require explicit exceptions with expiration.
- Require lockfiles for every language ecosystem and block unpinned dependencies.
- Reject mutable container tags such as `latest`; require digest-pinned base images.
- Generate and retain SBOMs for every source commit, build candidate, and released artifact.
- Add image-level SBOM generation and compare Dockerfile intent with built image reality.
- Correlate OS packages against distro/vendor advisories in addition to OSV.

## Provenance And Signing

- Generate SLSA-style provenance for every patch candidate and release artifact.
- Store source commit, builder identity, build command, lockfile hashes, SBOM hash, policy hash, vulnerability report hash, test report hash, artifact digest, and approval reference.
- Sign container images and packages with an external signer.
- Keep signing keys outside NemoClaw; NemoClaw must not become the signing root.
- Enforce signature verification before sandbox image promotion.

## Immutable Runtime

- Keep agent and sandbox runtime environments immutable.
- Deny runtime package installation.
- Deny unsafe self-update.
- Rebuild and redeploy new signed artifacts rather than mutating running agents.
- Use canary deployment before broad rollout.
- Keep rollback metadata for every release and mitigation.

## Network And Execution Controls

- Use egress deny-by-default and explicitly allow required inference and enterprise services.
- Remove vulnerable binaries from OpenShell network allowlists during emergency mitigation.
- Tighten filesystem and process policies for vulnerable or untrusted components.
- Switch applicable controls from audit to enforce mode for high-risk components.
- Revoke temporary capabilities automatically when exception windows expire.

## Secrets And Data Protection

- Use an enterprise secret broker for provider credentials and tokens.
- Avoid storing secrets in agent-visible configuration unless the runtime explicitly requires it.
- Integrate DLP controls for logs, prompts, tool outputs, file transfers, and audit exports.
- Redact tokens, API keys, credentials, private URLs, and environment secrets before SIEM export.

## Vulnerability Intelligence

- Mirror OSV, CISA KEV, EPSS, GitHub Advisory Database, NVD, and vendor advisory feeds internally.
- Treat CVSS as theoretical severity, EPSS as exploit probability, and CISA KEV as confirmed exploitation in the wild.
- Prioritize KEV and high-EPSS vulnerabilities even when CVSS is incomplete.
- Fail closed for required provider failures in enterprise mode.
- Require privileged approval for KEV or CRITICAL waivers.

## Emergency Mitigation

- Support mitigation-only plans when no safe fixed version exists.
- Disable or quarantine vulnerable tools and plugins.
- Block runtime use until human review for components touching network, filesystem, process execution, secrets, inference, or policy enforcement.
- Require tests, audit records, approvals, and rollback metadata for mitigations.

## Monitoring And Audit

- Export append-only audit records to SIEM.
- Track scan schedules, provider failures, waiver expiration, approval references, candidate provenance, and rollout state.
- Alert on expired waivers, missing SBOMs, missing signatures, mutable container tags, and runtime install attempts.
- Retain SBOMs, vulnerability reports, test reports, provenance, and approvals for the enterprise retention period.

## Red-Team Validation

- Red-team prompt injection against tool/plugin installation paths.
- Test malicious package and plugin supply-chain scenarios.
- Validate that runtime self-update and runtime package installation remain blocked.
- Test policy bypass attempts for network, filesystem, process, secrets, and inference controls.
- Test rollback from failed patch and mitigation candidates.
