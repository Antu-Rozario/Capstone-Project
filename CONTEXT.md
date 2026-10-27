# Insider Threat File Access UEBA

Detects unusual file-access activity, explains it against baselines and policy, and prepares privacy-preserving cases that a human must review before any action is taken.

## Language

### Activity

**File-access Event**:
One recorded action by a User on a file, such as a view, edit, download or copy to USB.
_Avoid_: Log line, record, hit

**User**:
An account holder whose File-access Events are monitored, identified only by a pseudonymous ID.
_Avoid_: Employee, suspect, insider, actor

**Owning Department**:
The department a file belongs to, which may differ from the accessing User's department.
_Avoid_: File owner, source department

**Sensitivity**:
The classification of a file: public, internal, confidential or restricted. Confidential and restricted count as sensitive.
_Avoid_: Classification level, secrecy

**Transfer Action**:
An action that moves data off the managed file share: download, copy to USB or upload to an external location.
_Avoid_: Exfiltration (that word asserts intent), export

### Detection

**Baseline Window**:
The leading period of activity used to learn what is normal; nothing in it is scored.
_Avoid_: Training period, history

**Detection Window**:
The period after the Baseline Window in which activity is scored against the Baseline.
_Avoid_: Test period, live window

**Baseline**:
The learned typical activity of one User, or of their Peer Group when the User's own history is thin.
_Avoid_: Profile, norm

**Peer Group**:
The Users who share a department and are compared with one another.
_Avoid_: Cohort, team

**Finding**:
One named deviation from the Baseline, carrying observed-versus-expected evidence, for example a mass download on a given date.
_Avoid_: Alert, incident, violation

**Risk Score**:
A 0–100 measure of how far a User's Detection-Window activity deviates from their Baseline. It describes activity, not the person.
_Avoid_: Threat score, guilt score, suspicion level

**Scenario**:
A labelled pattern of anomalous activity, either injected by the synthetic generator or labelled in the CERT benchmark, such as a mass download or after-hours access.
_Avoid_: Attack, case type

**Intensity**:
How strongly a Scenario departs from normal, such as a mass download at 10× a User's usual transfers.
_Avoid_: Strength, severity (Severity describes Findings, not injected data)

**Ground-truth Label**:
The recorded answer for whether a User's activity contains an injected or benchmark-labelled Scenario, kept apart from the events. CERT calls these users "insiders"; we keep the label and drop the word.
_Avoid_: Answer key, insider flag

**Hard Negative**:
A Scenario that looks unusual but has a legitimate reason, such as on-call night work, and should not be flagged.
_Avoid_: Benign anomaly, false alarm

### Case handling

**Case Summary**:
The structured, pseudonymous write-up of one User's Findings, with policy citations and recommended actions, awaiting review.
_Avoid_: Report, verdict, investigation result

**Policy Passage**:
A cited section of the insider-risk policy corpus that grounds an explanation or recommendation.
_Avoid_: Source, reference doc

**Control Mapping**:
The reviewed link from a Finding type to the MITRE ATT&CK techniques its activity is consistent with and the NIST controls that address it; a reference, never a conclusion about the User.
_Avoid_: TTP attribution, classification

**Privacy Lint**:
The check that a Case Summary uses neutral, activity-focused language and contains no real names.
_Avoid_: Filter, censor

**Sensitive Recommendation**:
A recommended action that affects a User's access, employment or legal standing, such as restricting access or an HR referral. It stays unauthorised until approved.
_Avoid_: Response action, enforcement

**Reviewer**:
The human who approves, rejects or requests more information on a Case Summary.
_Avoid_: Approver, admin, investigator

**Review Decision**:
A Reviewer's recorded outcome on a Case Summary: approved, rejected or needs more information.
_Avoid_: Sign-off, verdict
