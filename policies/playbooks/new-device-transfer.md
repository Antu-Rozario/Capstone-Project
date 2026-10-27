---
title: Playbook — Transfers From a New Device
applies_to: NEW_DEVICE_TRANSFER
---

# Playbook — Transfers From a New Device (NEW_DEVICE_TRANSFER)

## What this Finding means

Files were transferred (downloaded, copied to USB or uploaded externally) from a device that doesn't appear in the person's baseline and isn't their assigned PC. Unmanaged devices may not have encryption, data loss prevention or audit controls.

## Common legitimate explanations

- A replacement laptop or newly issued device not yet registered.
- Using a shared lab or meeting-room machine.
- An approved bring-your-own-device setup.
- A device renamed after reimaging.

## Verification steps

1. Check the device identifier against the asset inventory.
2. Check whether IT issued or reimaged a device for the person recently.
3. Check the volume and sensitivity of files transferred from the device.
4. Check whether uploads went to external destinations.

## Recommended actions

- Document the Finding and the triage outcome.
- Check the device identifier against the IT asset inventory.
- **[approval required]** Ask IT, through the Reviewer, to confirm whether the device is managed.
- **[approval required]** Temporarily block external sharing or removable media from the unmanaged device.

## Escalation

An inventoried device closes the case. An unknown device with confidential or restricted transfers or external uploads calls for the High-risk steps.
