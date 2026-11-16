# Vulnerability provenance and review: engineering decision record (V4)

**Status:** design and implementation documentation. These controls are implemented/tested locally where described; they are not evidence of a production security change or a completed external code review.

## Risk / failure mode

Selected KEV excerpts do not establish negative membership; EPSS is population likelihood, not asset risk; modeled scanner findings are not actual exposures.

## Safeguards

Require full current CISA catalog for scanner-wide findings; fail closed on partial excerpts with unlisted CVEs. Demand authorized scanner evidence, source dates, explicit asset criticality and independent exception approval.

## Acceptance before a public release

1. Confirm the change description and security threat model with the command/run output.
2. Run `python -m unittest discover -s tests -v` on an isolated branch.
3. Run the relevant reproducible outcome study and verify its source label and SHA-256 fingerprint.
4. Confirm `.gitignore` excludes private tenant snapshots, scan exports and secrets; review diff for personal data and API tokens.
5. In GitHub after publication, require a real green Actions build and artifact download before tagging a release; do not label an unreviewed commit as reviewed.
6. Record a tested rollback path and limitations in the release notes.

## Safe rollback

Withhold unverified priority downgrades; re-fetch official feed and rerun queued report; keep previous outputs and fingerprints. No customer patch actions have been performed.

## Remaining validation work

- Public Actions logs: **not yet available until the user publishes this repository**.
- Authorized Microsoft/Qualys/Trivy integration: **not claimed**.
- Real customer or employer outcome: **not claimed**.
