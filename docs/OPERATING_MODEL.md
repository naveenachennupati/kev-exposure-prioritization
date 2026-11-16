# Remediation workflow and exception policy

## Context and owner decisions
This is an independent security engineering implementation for demonstration and reuse, **not** a claimed corporate deployment. The operational owner must decide whether the tool is fit for a specific environment.

## Control gates
1. **Source review:** a PR author explains assumptions, affected controls, and changed evidence schemas.
2. **Automated validation:** `python -m unittest discover -s tests -v` must pass before merging; required Python standard library only.
3. **Evidence gate:** rerun the evidence command described in the README and inspect output rather than relying on screenshots.
4. **Access control:** no credentials, Azure tokens, user rosters, scanner inventories, or private incident material in git.
5. **Human approval:** access removals, patching and enabling new Sentinel alerts require explicit operator approval.
6. **Change rollback:** git revert to the preceding reviewed release; export a dated backup of local generated reports before rerunning.

## Abuse cases and mitigations
- **Untrusted input:** treat external JSON/CSV as untrusted; tests cover risk-relevant formats and missing information. Sanitized HTML output; no HTML or JS execution from user content.
- **Privilege escalation:** collection must use the minimum authorized read permissions; tools do not mutate identity, cloud or endpoint state.
- **Information disclosure:** sample identities use `example.test` and RFC 5737 documentation IP blocks; commit private inventory only to protected storage, never public CI artifacts.
- **False assurance:** client-side reports are evidence of code execution, **not** independent proof of live Microsoft service behavior.
- **Feed staleness:** public snapshots must disclose their retrieval date. Do not present old KEV entries as complete or current.

## Audit pack
| Item | Purpose |
|---|---|
| `reports/example-asset-workflow/remediation.json` | Locally generated, reproducible evidence |
| `tests/` | Regression coverage |
| `.github/workflows/tests.yml` | Remote CI recipe (becomes live after GitHub publication) |
| `README.md` | Operators' run commands and scope limitations |

## Readiness boundaries
**Validated locally:** source code and deterministic report generation.
**Requires authorized service access:** validation on the tenant's real schemas, real scan results, real entitlements and monitoring noise.
**Requires operating agreement:** approved thresholds, response SLA, notification routing, change control, emergency rollback, and identity/data-handling policy.
