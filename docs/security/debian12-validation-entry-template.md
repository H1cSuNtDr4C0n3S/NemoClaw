---
title: Debian 12 Passed Validation Entry Template
description: Documentation-agent template for recording only passed Debian 12 NemoClaw validations.
status: draft
last_updated: 2026-05-06
---

# Debian 12 Passed Validation Entry Template

Use this template when updating
`docs/security/debian12-vulnerability-management-validation-log.md` after a Debian 12 validation step passes.

## Non-negotiable rules

- Add an entry only when the user-provided evidence contains the expected sentinel, such as `BOOTSTRAP_OK`, `NODE22_OK`, or `SECURITY_ARTIFACTS_OK`.
- Do not document failed, blocked, partial, retried, or inconclusive attempts.
- If a problem occurred and was later fixed, document only the final passing command and evidence.
- Do not infer missing data. If the evidence does not show the environment, command, sentinel, or log path, ask the coordinator for the missing passed-run evidence.
- Do not add GitHub Actions validation entries unless a passed workflow URL is provided.

## Required evidence fields

Every validation-log row needs:

- Date in UTC.
- Debian 12 VM environment summary.
- Validation name.
- How it passed, including command family and pass criterion.
- Evidence reference, including the timestamped `LOG=...` path and the observed sentinel.

## Row template

```markdown
| YYYY-MM-DD | Debian 12 VM, Node <version if relevant>, commit `<sha if relevant>` | <Validation name> | Ran `<command or script summary>` and verified <pass criteria>. Output ended with `<SENTINEL>`. | `<LOG path>`; sentinel `<SENTINEL>`; key evidence: `<short exact output facts>` |
```

## Examples with placeholders only

Do not copy these examples as real validations. Replace every placeholder with evidence from the actual passed run.

```markdown
| 2026-05-06 | Debian 12 VM | Debian baseline and bootstrap packages | Ran the Step 1 bootstrap block, installed required base packages, and verified tool versions. Output ended with `BOOTSTRAP_OK`. | `<LOG path from VM>`; sentinel `BOOTSTRAP_OK`; key evidence: Debian `<VERSION_ID>`, git `<version>`, Python `<version>`, GCC `<version>` |
| 2026-05-06 | Debian 12 VM, Node `<node version>` | Node.js 22 toolchain | Ran the Step 2 NodeSource install block and verified Node major version 22 or newer plus npm availability. Output ended with `NODE22_OK`. | `<LOG path from VM>`; sentinel `NODE22_OK`; key evidence: node `<version>`, npm `<version>` |
| 2026-05-06 | Debian 12 VM, commit `<sha>` | Security artifact smoke tests | Ran the Step 9 security CLI smoke block and verified policy, inventory, SBOM, report, plan, candidate, and audit artifacts with `jq` checks. Output ended with `SECURITY_ARTIFACTS_OK`. | `<LOG path from VM>`; sentinel `SECURITY_ARTIFACTS_OK`; artifacts under `.validation/security/artifacts/` |
```

## Coordinator handoff checklist

Before committing a validation-log update, confirm:

- [ ] The validation-log table contains only passed validations.
- [ ] `last_updated` was updated.
- [ ] The new row references the personal fork branch, if repository state was part of the validation.
- [ ] No troubleshooting narrative or failed attempt details were added.
- [ ] `git diff --check` passes.
- [ ] Commit and push go only to `personal/mspin/security-vulnerability-management-integration`.
