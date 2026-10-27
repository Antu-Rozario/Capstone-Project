---
title: Privacy and Fairness Standard
applies_to:
---

# Privacy and Fairness Standard

Applies the NIST Privacy Framework functions (Identify, Govern, Control, Communicate, Protect) to insider-risk analytics.

## Data minimisation

Only file-access, removable-media and logon **metadata** is processed: who, when, which file or device, and which action. File contents, email, web history, personality or psychometric data, health data and protected characteristics are never collected or used.

## Pseudonymisation and re-identification

People are identified in analytics and case summaries only by pseudonymous IDs (for example `U0042`). The mapping to real identities is kept separately with restricted access. Re-identification needs Reviewer approval and is recorded in the case.

## Neutral language

Case summaries describe activity, not people.

- **Use** phrasing such as "activity deviated from the baseline", "transfers were higher than usual", "activity occurred outside usual hours", "this warrants review".
- **Never use** words that assert intent or guilt: malicious, criminal, guilty, theft, stealing, fraud, traitor, suspect, threat actor, "is an insider threat".
- Avoid naming people, and avoid speculating about motives, mood, finances, health or personal life.

## Benign explanations

Every case summary must list plausible legitimate explanations for the observed activity, such as project deadlines, quarter-end reporting, on-call duties, a new role, covering for a colleague, or tooling and migration work. The Reviewer weighs these before approving any action.

## Fairness monitoring

Baselines compare each person with their own history, or with their department when history is short. They never use demographic attributes. False-positive rates are monitored by department and role. A group with consistently higher rejected-case rates (for example night-shift or on-call staff) triggers a review of thresholds.

## Retention

Detections and case records are kept only as long as needed to resolve the case and to measure accuracy and fairness. Closed cases are kept in pseudonymous form.
