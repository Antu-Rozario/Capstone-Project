---
title: Evidence Handling Standard
applies_to:
---

# Evidence Handling Standard

## Preserving logs

When a case reaches High risk, the Analyst preserves the relevant metadata logs (file-access, removable-media and logon records for the affected days) in the case store. Preservation is allowed without approval, because it doesn't affect the person. It must cover only the dates and systems in the Findings.

## Chain of custody

Every case records who accessed or exported evidence, when, and why. Exported evidence is stored read-only with a checksum. Evidence is never changed. Analyst notes are added alongside it.

## What may and may not be examined

- **May examine:** metadata already collected for analytics (timestamps, file identifiers, file categories and sensitivity labels, device identifiers, actions).
- **Needs Reviewer approval:** re-identifying the subject, or requesting additional logs from system owners.
- **Not allowed under this standard:** opening file contents, reviewing personal email or web history, or accessing personal devices. Any such step needs Legal's involvement under a separate procedure.

## Documentation

Each case summary records: the Findings with observed and baseline values, the policy passages relied on, the possible benign explanations considered, the recommended actions with their approval status, and the Reviewer's decision with name, date and notes.
