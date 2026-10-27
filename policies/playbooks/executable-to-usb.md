---
title: Playbook — Executable Copied to Removable Media
applies_to: EXECUTABLE_TO_USB
---

# Playbook — Executable Copied to Removable Media (EXECUTABLE_TO_USB)

## What this Finding means

An executable file was copied to removable media. This is supporting evidence: software moved on USB drives can bypass software-installation controls and may introduce unapproved tools. On its own it isn't enough to raise a case above Low.

## Common legitimate explanations

- IT staff carrying installers or diagnostic tools.
- Developers transferring builds to test machines.
- Portable versions of approved software.
- Firmware updates for lab or field equipment.

## Verification steps

1. Check the person's role and whether software transfer is part of their duties.
2. Check the file name against the approved software catalogue.
3. Check which machine the drive was connected to next, if known.
4. Consider other Findings in the same window.

## Recommended actions

- Record as supporting evidence in the case record.
- Check the file against the approved software catalogue.
- **[approval required]** Ask IT security, through the Reviewer, to assess the executable for unapproved software.

## Escalation

On its own this stays Low. Combined with logons to other people's PCs or new USB use, review under the High-risk steps.
