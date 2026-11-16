# Exploitation-Aware Vulnerability Prioritization

## Measured outcome (public KEV positives + modeled scanner queue)

**Problem / baseline:** CVSS-only screening ignores documented exploitation and the potential importance of environmental context.

**Implementation:** official-source KEV ingestion, optional targeted FIRST EPSS, scanner importers, explainable priority tiers, remediation approvals and **fail-closed completeness validation**. A seven-entry KEV excerpt may confirm positive membership but cannot prove negative membership for other CVEs.

**Finding:** A controlled scenario with 240 hypothetical CVE-asset rows and seven publicly documented KEV-positive CVEs includes 80 modeled rows with CVSS below 7. All assets and CVSS/exposure scores are synthetic; they are NOT actual scanner findings or operational patching outcomes.

**Inspect:** `python -m src.operational_study` -> [`reports/operational-study.html`](reports/operational-study.html); optional `.github/workflows/public-intelligence.yml` refreshes the **complete public KEV feed** on GitHub Actions after publication. No successful scheduled run is claimed yet.


A vulnerability-operations pipeline that uses **official CISA KEV intelligence** and optional **FIRST EPSS scores**, joins them to scanner evidence from Qualys-style CSV or Trivy JSON, and produces an explainable remediation review queue (JSON, CSV, HTML).

## The operational problem

A high CVSS score alone does not tell a security team what to work on first. Known exploitation, threat likelihood, observed asset exposure and business criticality must be reviewed together—without inventing missing data.

## Data sources and method

- CISA's official KEV JSON catalog (canonical source; CISA-maintained GitHub mirror as fallback).
- FIRST EPSS API for **small targeted lists of CVEs** (not bulk crawling).
- Qualys-style CSV exports or Trivy JSON vulnerability scan output.
- Explicit priority decision factors; no unsupported CVSS, EPSS, asset importance or exposure values are fabricated.

**Important:** if scanner data is not provided, the output is a **public KEV intelligence watchlist**, not a statement about which systems are vulnerable.

## Verified outcome / reproducible public evidence

- Checked 7 selected **actual CISA KEV entries** from official 2026-11-13 catalog version, preserved with `source_url`, catalog version and date.
- Generated a 7-record watchlist with all 7 positively in KEV; no invented asset inventory and no invented EPSS values.
- 19 automated tests validate KEV matching, prioritization, importers, failure handling and report generation.
- `reports/brief.html` shows the evidence-based analyst view.

## Run

```bash
python -m unittest discover -s tests -v
python -m src.pipeline --kev-file data/official_kev_selected_2026-11-13.json --as-of 2026-11-16 --out reports
```

## Real feed and scanner integration

```bash
# Real up-to-date CISA feed plus actual Qualys-style export (private source data)
python -m src.pipeline --fetch-kev --qualys-csv private/qualys_findings.csv --fetch-epss --out private/review

# Or actual Trivy vulnerability result JSON
python -m src.pipeline --fetch-kev --trivy-json private/trivy_report.json --fetch-epss --out private/trivy_review
```

Use a CSV export with headings `Asset,CVE,CVSS,Exposure,Business Criticality`. Mappings support `Host`, `CVE ID`, `CVSS Base Score`, etc. If necessary, adapt `load_qualys_csv()` to the exact export schema; scanner configurations vary. Exported data can be confidential; never commit it.

The EPSS API supports targeted enrichment up to 80 unique CVEs in this implementation. For large-scale scoring, use the [FIRST daily bulk EPSS CSV](https://www.first.org/epss/data); avoid violating the service's intended API use. The example source only includes 7 selected catalog records and is **not** the full 1,781-entry snapshot.

## Prioritization rules

- **P0**: listed in CISA KEV **and** asset is reported as internet-exposed or business-critical.
- **P1**: in KEV, or EPSS >= 0.50, or internet-facing CVSS >= 8.0.
- **P2**: CVSS >= 7.0 or EPSS >= 0.10.
- **P3**: remainder / missing evidence; validate before action.

These are review tiers, not regulatory due dates or authoritative vulnerability exploitability claims. CISA dates relate to federal policy, not your organization's SLA.

## Sources

- [Official CISA-maintained KEV mirror](https://github.com/cisagov/kev-data)
- [Canonical CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS lookup API](https://api.first.org/epss/)
- [FIRST EPSS bulk data](https://www.first.org/epss/data)
- [Trivy JSON output](https://trivy.dev/latest/docs/configuration/reporting/)

# Security and source transparency

- No organization or employer data is included. **Never commit an actual tenant snapshot, scan export, credentials, access tokens, or incident records** to a public repository.
- Tested Python logic is not a substitute for service-side testing. Azure integration actions require the operator's authorized account and their approval.
- The tools generate review recommendations; they do not automatically disable accounts, remediate systems, or modify an Azure deployment.

## Operational maturity additions (release 3)

- **Release readiness:** source-controlled regression tests run on every pull request in GitHub Actions; no privileged Azure or scanner credentials required for CI.
- **Governance and auditability:** output evidence is deterministic for committed fixtures; the commands and boundaries are recorded in `docs/OPERATING_MODEL.md`.
- **Separation of duties:** output is advisory, never auto-applies changes to user accounts, analytics rules or patches. Deployment or remediation requires an authorized operator.
- **Traceability:** inspect `reports/example-asset-workflow/remediation.json` and rerun the documented steps before presenting results publicly.
- **Truthfulness:** an actual enterprise deployment is NOT claimed. Read-only cloud connectivity and cloud tenant validation require separate authorization.


## Example remediation lifecycle (separate from real CISA intelligence)

`fixtures_demo.csv` contains **fictional assets** in the reserved `example.test` domain. It exists solely to exercise the end-to-end remediation engine; it is NOT a scanner export from a real employer. CVEs in the fixture correspond to the preserved public KEV excerpt.

```bash
python -m src.pipeline --kev-file data/official_kev_selected_2026-11-13.json \
  --qualys-csv fixtures_demo.csv --as-of 2026-11-16 --out reports/example-asset-workflow
python -m src.remediation --input reports/example-asset-workflow/results.json \
  --as-of 2026-11-16 --out reports/example-asset-workflow/remediation.json
```

The remediation engine demonstrates **distinct asset/CVE tracking**, configurable example SLA targets, due-date evaluation, decision approval by two different people, and automatic re-opening of expired risk acceptances. It **refuses to generate asset remediation plans** from public watchlist-only data. The example SLA clock uses the report date as a stand-in for a verified first-seen timestamp: production use must supply actual scanner first-seen data and policy owners.
