---
title: Playbook — Mass Download
applies_to: MASS_DOWNLOAD
---

# Playbook — Mass Download (MASS_DOWNLOAD)

## What this Finding means

Far more files were downloaded or copied to removable media in a single day than the person's baseline, usually by an order of magnitude. Bulk transfer moves data outside the managed file share, where access controls and audit no longer apply.

## Common legitimate explanations

- Preparing a report, audit pack or board submission that needs many files at once.
- Migrating files to a new system, laptop or project share.
- Offline work before travel, with approval to work offline.
- A sync tool or script re-downloading a folder after a reset.

## Verification steps

1. Check whether the files belong to the person's own department and current projects (file categories in the Finding).
2. Check the sensitivity mix: a bulk transfer of public or internal files carries less risk than one of confidential or restricted files.
3. Look for known business events on that date (deadlines, quarter end, migrations).
4. Check whether the transfers came from the person's assigned device.

## Recommended actions

- Document the Finding and the triage outcome in the case record.
- Check the date against known business events and project schedules.
- **[approval required]** Confirm the business justification with the line manager through the Reviewer.
- **[approval required]** Temporarily restrict removable-media permissions while the review is ongoing.

## Escalation

One mass-download Finding of own-department files usually means Medium risk. Combined with confidential or restricted files, an unmanaged device or after-hours timing, apply the High-risk steps in the Escalation Matrix.
