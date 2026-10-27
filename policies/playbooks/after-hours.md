---
title: Playbook — After-Hours Activity
applies_to: AFTER_HOURS
---

# Playbook — After-Hours Activity (AFTER_HOURS)

## What this Finding means

File or logon activity happened outside company hours (07:00 to 19:00) at a level that is also unusual for this person. People who regularly work late or on call have that pattern in their own baseline, so it isn't flagged.

## Common legitimate explanations

- A deadline, release or incident needing late work.
- A temporary on-call rotation or a new shift pattern not yet in the baseline.
- Working from another time zone while travelling.
- A scheduled job or sync client running under the person's account.

## Verification steps

1. Compare with the person's usual hours shown in the baseline.
2. Check on-call rotas, change windows and incident tickets for the same nights.
3. Check what was accessed after hours: own-department working files or sensitive files.
4. Check whether the activity came from the assigned device or an unfamiliar one, which could suggest a compromised account.

## Recommended actions

- Document the Finding and the triage outcome.
- Check on-call rotas, change windows and incident records for the same dates.
- **[approval required]** Confirm with the line manager, through the Reviewer, whether late work was expected.
- **[approval required]** If the account may be compromised, ask IT to reset credentials and review sign-in history.

## Escalation

After-hours activity alone is usually Medium risk. Escalate to High when it comes with transfers, sensitive files or an unfamiliar device. Treat a possibly compromised account as a security incident under IT procedures.
