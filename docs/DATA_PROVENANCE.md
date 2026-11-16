# Intelligence provenance and scope

**Input artifact**: `data/official_kev_selected_2026-11-13.json`

- 7 selected, actual entries transcribed from the CISA-operated KEV GitHub mirror, `catalogVersion=2026.11.13`, released 2026-11-13.
- Full official feed had `count=1781` at that date; the bundled excerpt has only 7 entries. The excerpt is not described as a complete catalog.
- Vendor, product, CVE ID, date added, remediation due date and forensic triage fields are recorded; CVSS and EPSS are *not* claimed for the excerpt.
- Live feed ingestion must be re-run when newer catalog entries matter; `catalogVersion` in output makes freshness auditable.
- CISA BOD remediation due dates are *not automatically* applicable to private entities.

The analyst demo uses verified public threat intelligence, not fictional enterprise asset discoveries. To calculate asset-specific exposure, supply an authorized vulnerability scanner export.
