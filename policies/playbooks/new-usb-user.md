---
title: Playbook — New or Increased USB Use
applies_to: NEW_USB_USER
---

# Playbook — New or Increased USB Use (NEW_USB_USER)

## What this Finding means

USB storage devices were connected by a person who didn't use them during the baseline, or far more often than usual. Removable media is a common channel for moving data off managed systems.

## Common legitimate explanations

- A new task that needs removable media, such as a presentation at an offline venue or a lab instrument.
- A new device that needs USB setup.
- Approved transfers to an air-gapped system.
- Charging a phone or other device (some connections log as storage).

## Verification steps

1. Check whether file copies to removable media followed the connections, and their volume and type.
2. Check whether the department routinely uses removable media.
3. Check the timing: during business hours or after hours.
4. Check for approved exceptions to the removable-media policy.

## Recommended actions

- Document the Finding and the triage outcome.
- Check for an approved removable-media exception.
- **[approval required]** Remind the person of the removable-media policy, through the line manager and the Reviewer.
- **[approval required]** Temporarily restrict removable-media permissions while the review is ongoing.

## Escalation

Connections without file copies are usually Low or Medium. Connections followed by many file copies, especially after hours, call for the High-risk steps.
