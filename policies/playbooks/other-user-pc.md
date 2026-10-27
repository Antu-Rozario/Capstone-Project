---
title: Playbook — Logon to Another User's PC
applies_to: OTHER_USER_PC
---

# Playbook — Logon to Another User's PC (OTHER_USER_PC)

## What this Finding means

The person logged on to a PC assigned to someone else, which they don't normally do. This is supporting evidence: on its own it isn't enough to raise a case above Low, but together with other Findings it may suggest account sharing or misuse of credentials.

## Common legitimate explanations

- IT support or desk-side assistance.
- Hot-desking, or a colleague's PC used temporarily during hardware repair.
- Shared workstations not correctly labelled in the asset inventory.
- Training or pair-working sessions.

## Verification steps

1. Check the person's role (IT support logs on to other PCs routinely).
2. Check whether the PC owner was present or on leave.
3. Check what activity happened during the session: logon only, file access, or transfers.
4. Check the asset inventory for shared or reassigned machines.

## Recommended actions

- Record as supporting evidence in the case record.
- Check the asset inventory and the person's role.
- **[approval required]** If credential misuse is suspected, ask IT to review sign-in history for both accounts.

## Escalation

On its own this stays Low. Consider it with other Findings in the same window when deciding the overall risk level.
