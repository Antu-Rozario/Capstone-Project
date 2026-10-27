# Requirements — Insider Threat File Access UEBA Agent (Group 8A)

Laurentian University · Applied AI Agents for Cybersecurity Operations · Fall 2026 · Master's capstone
**Defensive use only**

**Sources:**
- `Group 8A.pdf` (the project brief);
- `notes/1. Capstone Project - General Notes.pdf` (course-wide expectations);
- `notes/2. Grading Rubric.pdf`;
- `notes/3. Additional Free Resources.pdf`.

Domain terms in **bold** are defined in [CONTEXT.md](CONTEXT.md).

---

## 1. Why we are building this

**Problem.** Sensitive file access can signal negligence, a compromised account or insider risk. Raw file-access logs alone are hard to act on. An analyst sees thousands of rows and cannot easily tell:

- whether a spike is unusual *for that person and their department*;
- which policy applies;
- how to describe what they see without accusing anyone.

**Target user.** An insider-risk or SOC analyst at a mid-sized organisation. Behind them sits a **Reviewer** (a senior analyst, HR or privacy officer) who approves any action.

**Goal.** A user-behaviour analytics (UEBA) agent that:

1. learns what normal file access looks like;
2. flags deviations;
3. explains each one with evidence, policy citations and a **Control Mapping**;
4. drafts an investigation summary in privacy-preserving language that a human must review before anything happens.

**MVP outcome (from the brief).** A dashboard that:

- ranks **Users** by **Risk Score**;
- explains the anomalous file behaviour;
- produces an analyst **Case Summary** in privacy-preserving language.

**Business and industry value.** The tool cuts the time from raw log to an explained, policy-grounded case, and lowers the risk of unfair or accusatory investigations. It is decision support, not an autonomous system. Both points go on presentation slide 7.

**What makes it a master's-level project.** Beyond building the tool, we answer research questions with evidence (§7). We evaluate on a recognised public benchmark (CERT) and run controlled experiments on our own synthetic data (§5).

**Scope discipline.** The rubric says *"a polished MVP with clear scope is better than a large unfinished platform."* So every requirement has a priority:

| Priority | Meaning |
|---|---|
| **Must** | Needed for the MVP and the rubric. Build first. |
| **Should** | Adds master's-level depth. Build once every Must works end to end. |
| **Could** | Only if time remains. Otherwise list it as future work. |

| Who uses it | Needs |
|---|---|
| Insider-risk / SOC analyst | A short ranked list, the reason each user is on it, and evidence to verify |
| Reviewer | To approve or reject recommendations before any action is taken |
| Course evaluators | Everything in the rubric (§2): a working pipeline, correct security framing, metrics, a human approval step, a clean demo |

---

## 2. How we will be graded

From the grading rubric. Use this table to check marks are covered before each milestone.

| Rubric component | Weight | What markers look for | Where we satisfy it |
|---|---|---|---|
| Problem definition and cybersecurity relevance | 10% | Clear use case, target user, safety boundary, practical value | §1, §3, one-page proposal (D-1) |
| Data pipeline | 15% | Public or synthetic data, schema, preprocessing, data card, reproducibility | FR-1, FR-2, FR-9, data card (D-4), NFR-5 |
| AI/RAG/agent architecture | 20% | Working pipeline, clear tool use, structured outputs, reasonable prompts | FR-3, FR-4, FR-5 (3 named tools, JSON output, versioned prompts) |
| Cybersecurity correctness | 15% | MITRE/control mapping, safe recommendations, defensive framing | **FR-11 Control Mapping**, FR-5 Sensitive Recommendations, §3 |
| Evaluation | 15% | Metrics, test cases, error analysis, limitations | FR-8, §7 research questions, error analysis, limitations section |
| Deployment/demo | 10% | Working Streamlit/Gradio/FastAPI demo with a clean UI | FR-7, Docker, D-6 demo checklist |
| Human-in-the-loop and ethics | 10% | Approval checkpoints, privacy and safety controls | FR-6, Privacy Lint (FR-5), NFR-1, NFR-2 |
| Report and presentation | 5% | Clear report, architecture diagram, demo narrative | D-7, D-8, §8 |

**Portfolio expectations, also from the rubric:**

- **Explain your own module.** Each student must be able to explain their individual module in an interview. Each module has one named owner (§8).
- **Document every assumption,** especially CERT field mappings and synthetic generator settings, in the data card.
- **Show the full flow in the demo:** the input, the AI/agent pipeline, the decision, the evidence and the human approval step.

---

## 3. Scope and safety boundaries

**In scope:**

- three data sources:
  - **Must:** a synthetic generator;
  - **Should:** the CERT Insider Threat Dataset;
  - **Could:** an application audit-log importer;
- per-user and per-department baselines;
- rule-based, statistical and unsupervised ML anomaly detection;
- RAG over insider-risk policy;
- MITRE ATT&CK and NIST control mapping;
- an LLM or template agent with 3 tools that writes Case Summaries;
- a human approval step;
- a Streamlit dashboard;
- an evaluation harness and research studies.

**Out of scope:**

- real employee, student, university or customer data in any form;
- automated enforcement such as suspending accounts or blocking access;
- monitoring outside file and device activity (email, web, keystrokes);
- psychometric or personality data. CERT's `psychometric.csv` is deliberately excluded;
- file contents. We use metadata only;
- any judgement of intent or guilt;
- a production-grade platform.

**Safety boundaries.** These combine the course-wide rules with our own, and apply to every component.

1. **Public or synthetic data only.**
   - CERT is itself synthetic, so it qualifies.
   - The app-log importer ships with a synthetic sample. It is never pointed at a real application's logs.
2. **Describe activity, never character or intent.** The system never says that a person is an insider threat. ATT&CK techniques are cited as "activity consistent with", never as a conclusion.
3. **Pseudonymous IDs only.** Event logs and Case Summaries identify people only by IDs such as `U0042`. Real (fake, Faker-generated) names live only in a separate directory.
4. **Human approval for anything that affects a user or account.** Every Case Summary starts in `pending_review`. **Sensitive Recommendations** are not authorised until a Reviewer approves them.
5. **Local and defensive only.** The LLM runs locally through Ollama or LM Studio, and no log data leaves the machine. There is no scanning, no offensive capability and no live malware.
6. **Licences verified.** Dataset and model licences and terms of use are checked and recorded before use (NFR-7).

---

## 4. Functional requirements

Each requirement lists **What**, **Why**, **How** and **Done when**. Owners follow the course's standard 5-person roles:

1. Data Lead
2. AI/RAG Lead
3. Agent Lead
4. App/Deployment Lead
5. Evaluation/Security Lead

### FR-1 File-access schema — Must (Data Lead)

- **What.** One event schema shared by every data source. The fields are:
  - `event_id`, `source`, `event_type` (`file`, `device` or `logon`), `user_id`, `department`, `role`;
  - `file_id`, `file_type`, `file_category`, `file_department`, `sensitivity`;
  - `timestamp`, `action`, `device_id`, `bytes`.

  **Ground-truth Labels** are kept in a separate table (`user_id`, `scenario`, `is_anomalous`, `window_start`, `window_end`), never inside the events.
- **Why.** Every downstream component needs one shared contract. The brief requires user, department, file category, sensitivity, timestamp, action and device. We add:
  - `file_department`, so we can detect access to sensitive departments;
  - `source`, so results can be reported per dataset;
  - `event_type` and `file_type`, because CERT's insider evidence is mostly USB-connect and logon events, and its files carry only a type (from the extension), not a business category (see FR-9);
  - separate labels, so the detector can never see the answers.
- **How.**
  - Constants live in `src/ueba/schema.py`.
  - Six departments, each owning three file categories.
  - Four **Sensitivity** levels: public, internal, confidential, restricted. A source that doesn't record a field uses `unknown` rather than a guess.
  - Seven file actions. Three of them (download, copy_to_usb, upload_external) are **Transfer Actions**.
  - Four context actions: `usb_connect`, `usb_disconnect`, `logon`, `logoff`.
- **Done when.** Every loader's output validates against the schema.
- **Status.** ✅ Schema implemented. The CERT loader's output validates against it.

### FR-2 Synthetic testbed with controlled anomalies — Must (Data Lead)

- **What.** A documented, seeded generator that produces normal behaviour plus labelled anomalous **Scenarios**. Each Scenario's **Intensity** is set by a parameter.
- **Why.**
  - The course requires "a public or synthetic dataset, or a documented synthetic data generator".
  - It gives exact labels.
  - It supports the controlled experiments (RQ2, RQ3) that CERT's few, fixed scenarios can't.
- **How.**
  - The structure is modelled on CERT (action types, departments, roles).
  - Faker supplies names for the directory only. NumPy supplies the behaviour.
  - The period is split into a **Baseline Window** followed by a **Detection Window**. Anomalies are injected only into the Detection Window.
  - Anomalous Scenarios:

    | Scenario | What is injected | Intensity parameter |
    |---|---|---|
    | `mass_download` | Many transfers in one day | Multiple of the user's normal daily transfers (5×, 10×, 50×, 100×) |
    | `after_hours` | Activity between 22:00 and 04:00 on several nights | Number of nights and events per night |
    | `cross_department_sensitive` | Confidential or restricted files owned by other departments | Accesses per day |
    | `new_device_transfer` | Transfers from an unmanaged device | Transfers per day |
    | `slow_drip` (Should) | A small daily increase in transfers sustained over two weeks | Extra transfers per day |

  - **Hard Negatives:**

    | Hard Negative | Priority | What it simulates |
    |---|---|---|
    | `benign_on_call` | Must | IT staff working at night |
    | `benign_quarter_end` | Should | A legitimate Finance download surge at quarter end |
    | `benign_new_hire` | Should | A user with little Baseline history |

  - The Data Lead owns the injection settings. The AI/RAG Lead tunes detectors without seeing them.
- **Done when.**
  - The same seed reproduces the same data.
  - Every Scenario and Hard Negative appears in the labels.
  - No injected event falls in the Baseline Window.
  - Intensity can be swept from a config.
  - The generator is documented in the data card.
- **Status.** ✅ Done. All 5 Scenarios (including `slow_drip`) and all 3 Hard Negatives are implemented, with 22 passing tests.
  - **Run:** `.venv/bin/python -m ueba.generator --out data/processed/synthetic`. Intensity sweeps go through `--config`.
  - **Default output:** 82,686 events and 120 users (15 anomalous) over 42 days. The Detection Window ends on the 2026-09-30 quarter end.
  - **Normal behaviour includes USB copies and external uploads**, so they aren't free giveaways.
  - See [docs/data-card.md](docs/data-card.md) Part B.

### FR-3 Baselines, detectors and Risk Score — Must (AI/RAG Lead)

- **What.** Per-user and per-**Peer Group** baselines, several detectors, and a combined Risk Score.
- **Why.** "200 downloads" is normal for one role and alarming for another. Baselines turn raw counts into explainable deviations. Comparing detectors is RQ1.
- **How.**
  - Build daily feature rows for each user:
    - event count;
    - transfer count;
    - after-hours count;
    - sensitive accesses to other departments' files;
    - transfers from new devices;
    - distinct files;
    - a rolling 14-day transfer total.
  - Learn each user's mean and standard deviation from the Baseline Window. Use the Peer Group when the user's history is thin.
  - Deterministic rules each emit a **Finding** with observed-vs-baseline evidence:

    | Rule | Priority | Triggered by |
    |---|---|---|
    | `MASS_DOWNLOAD` | Must | A one-day transfer spike |
    | `AFTER_HOURS` | Must | Activity outside company hours *and* outside the user's own usual hours |
    | `CROSS_DEPT_SENSITIVE` | Must | Sensitive files owned by other departments |
    | `NEW_DEVICE_TRANSFER` | Must | Transfers from a device not seen in the Baseline Window |
    | `SUSTAINED_INCREASE` | Should | The rolling transfer total well above the user's baseline |
    | `NEW_USB_USER` | Should (CERT) | USB connects by a user with no USB use in the Baseline Window, or a sharp rise over their usual rate. CERT scenarios 1 and 2 |
    | `OTHER_USER_PC` | Should (CERT) | A logon to another user's assigned PC, for a user who doesn't normally do this. CERT scenario 3. **Supporting evidence only** (low severity, can't flag a user alone; see experiment E2) |
    | `EXECUTABLE_TO_USB` | Should (CERT) | An executable file copied to removable media. CERT scenario 3. **Supporting evidence only** (low severity; see experiment E2) |

  - **Which rules apply to which data.** CERT has no sensitivity or owning department, so `CROSS_DEPT_SENSITIVE` can only be evaluated on synthetic data. Results are reported per dataset, and a rule that can't run is marked "n/a", not scored as a miss.
  - **`left_organisation` is never a detection feature.** All 70 CERT insiders left the organisation, against 155 of 1,000 users overall, so using it leaks the label (see the data card).
  - **CERT Baseline Window:** 2010-01 to 2010-05. The first labelled insider activity is on 2010-06-10.
  - Detectors behind one interface:
    - **Must:** peer-group z-score and `IsolationForest`;
    - **Should:** `LocalOutlierFactor` and `OneClassSVM`.
  - The Risk Score is 0–100 and combines rule Findings with the chosen ML detector, giving a Low, Medium or High level. Users are ranked by it.
- **Done when.**
  - Every injected Scenario user at the default Intensity gets a Finding from the matching rule.
  - Ranked results come with evidence.
  - Every detector runs on every loaded dataset.
- **Status.** ✅ Done. 39 tests across features, baselines, rules, detectors and metrics.
  - **Run:** `.venv/bin/python -m ueba.detection <processed-data-dir> [--baseline-end YYYY-MM-DD] [--detector isolation_forest|baseline_zscore|lof|ocsvm]`. It writes `ranking.csv`, `findings.json` and `metrics.json` to `data/results/<dataset>/`.
  - **Synthetic, default Intensity:** precision, recall and F1 all 1.00, with 0 of 25 hard negatives flagged. This proves the pipeline works, not real-world accuracy.
  - **CERT r4.2 (v2):** precision 0.58, recall 0.97, F1 0.73, normal-user false-positive rate 5.3%.
  - The v1 → v2 change was label-informed. It's recorded in [docs/experiment-log.md](docs/experiment-log.md).

### FR-4 Policy RAG — Must (AI/RAG Lead)

- **What.** Retrieval over a local corpus of insider-risk handling policy: the escalation matrix, privacy and fairness guidelines, evidence handling, and per-scenario playbooks.
- **Why.** Explanations and recommendations must be grounded in policy rather than invented by the LLM. Citations let the Reviewer check them, and their accuracy is measured in RQ4.
- **How.**
  - Markdown policies live in `policies/`, chunked by heading. They are written by the team and informed by the NIST Privacy Framework and public insider-risk guidance.
  - Embeddings come from **embeddinggemma through the local Ollama server**, searched with a **FAISS** index. This replaces sentence-transformers: Ollama is already part of the stack, and it avoids a multi-GB PyTorch install. TF-IDF is the offline fallback.
  - **Hybrid search** merges keyword (TF-IDF) and semantic (embeddinggemma) rankings with reciprocal rank fusion. Each one alone missed questions the other answered.
  - Results are **Policy Passages** with citation IDs of the form `doc#section`.
- **Done when.** A query for each Finding type returns the matching playbook passage within the top 3 results.
- **Status.** ✅ Done. 30 tests.
  - **Corpus:** 12 documents split into 63 passages: insider-risk handling policy, escalation matrix, privacy and fairness standard, evidence handling standard, and 8 playbooks (one per rule).
  - **Retrieval:** every Finding type returns its playbook in the top 3, with TF-IDF, embeddinggemma and hybrid alike. The free-text questions are answered by hybrid search.
  - **Run:** `.venv/bin/python -m ueba.rag "query" [--backend auto|hybrid|ollama|tfidf] [--finding-type RULE]`.

### FR-5 Explanation agent and Case Summary — Must (Agent Lead)

- **What.** An agent loop that uses **3 tools** to turn a flagged user's Findings into a structured JSON **Case Summary**.
- **Why.** The brief asks for an agent that explains *why* a user was flagged. The course requires an agent workflow with 1–4 tools (1–3 in the week-4 milestone) and structured output.
- **How.**
  - The agent is a simple custom Python tool-calling loop, as the course recommends. LangGraph is optional.
  - **As built: planner-executor.** Code decides which tools to call (context once, then policy search and control lookup for each Finding) and assembles every exact fact. The LLM writes only the narrative (summary and innocent explanations). This keeps an 8B local model from choosing or inventing evidence. The narrative must also pass a hallucination guard: every number in it must appear in the facts.
  - **Tools:**

    | Tool | Returns |
    |---|---|
    | `get_user_context(user_id)` | Department, role, Baseline, Findings and an event sample |
    | `search_policy(query)` | Policy Passages from FR-4 |
    | `lookup_control_mapping(finding_type)` | ATT&CK techniques and NIST controls from FR-11 |

  - **Steps:**
    1. Call the three tools to gather context.
    2. Draft the summary with a local LLM through Ollama. Use a deterministic template if no LLM is running.
    3. Run the **Privacy Lint**, which rejects accusatory terms and real names. Fall back to the template if the LLM draft fails.
  - The LLM only writes text from facts it is given. It never decides who is risky.
  - Prompts are versioned in the repo and documented in the report.
  - The output fields are:
    - `case_id` and the pseudonymous subject;
    - `risk_score` and `risk_level`;
    - `summary`;
    - `observations[]`, each with evidence;
    - `possible_benign_explanations[]`;
    - `policy_citations[]`;
    - `control_mapping[]`;
    - `recommended_actions[]`, each with `requires_approval`;
    - `privacy_note`;
    - `human_review_required: true`;
    - `status: pending_review`;
    - `generated_by` (model name or `template`).
- **Done when.**
  - The output validates against the schema.
  - Every observation cites evidence.
  - Every Sensitive Recommendation has `requires_approval: true`.
  - The Privacy Lint passes.
  - **Should:** the pipeline runs with at least two local models for RQ4.
- **Status.** ✅ Done. 17 agent tests, plus 7 for the Privacy Lint.
  - **Run:** `.venv/bin/python -m ueba.agent <processed-data-dir> [--top N | --user U0042] [--llm auto|none|<model>]`. Cases are written to `data/cases/<dataset>/<case_id>.json`.
  - **Fallbacks:** if the LLM is unavailable, errors, fails the Privacy Lint or writes an unsupported number, a grounded template writes the narrative and `generated_by` records why.
  - **First live run (gemma4, 8B):** 5 of 5 synthetic and 2 of 2 CERT narratives used, all lint-clean, about 6 seconds each.
  - **Observed limitation:** the guard checks numbers, not claims. One summary said transfers happened "on separate occasions", which the facts don't support. This feeds the FR-8 hallucination analysis.

### FR-6 Human-in-the-loop checkpoint — Must (Agent Lead)

- **What.** A Reviewer records a **Review Decision** (approve, reject or needs_more_info) with their name, notes and a timestamp.
- **Why.** The course requires a human-in-the-loop checkpoint before any sensitive recommendation, and that all recommendations affecting users or accounts need human approval. This is 10% of the grade, together with ethics.
- **How.**
  - A persistent JSON review store.
  - Sensitive Recommendations stay unauthorised until the case is approved.
  - Rejected cases are kept, so the false-positive rate can be measured.
- **Done when.** Without an approval, a case's authorised-actions list contains no Sensitive Recommendation.
- **Status.** ✅ Done (`src/ueba/review.py`, 6 tests). The append-only JSON store keeps every decision. `authorised_actions()` releases approval-required actions only when the latest decision is `approved`. The dashboard (FR-7) will provide the UI.

### FR-7 Risk dashboard — Must (App/Deployment Lead)

- **What.** A Streamlit app with five parts:
  - a data source selector;
  - the ranked risk table;
  - a per-user drill-down: daily activity against the baseline, Findings, detector scores and the Control Mapping;
  - Case Summary generation;
  - the review panel and an evaluation tab.
- **Why.** The MVP outcome is a dashboard. "Deployment/demo" is 10% of the grade, and it asks for a clean UI.
- **How.**
  - Pseudonymous IDs by default.
  - A privacy and fairness banner on every page.
  - Approval controls next to each Case Summary.
  - Packaged with Docker.
- **Done when.** The D-6 demo checklist runs end to end from the UI.
- **Status.** ✅ Done (`src/ueba/app.py`, with testable helpers in `dashboard.py`). 8 helper tests plus 3 headless Streamlit AppTest tests: load, generate a case, approve, and refusal without a Reviewer name.
  - **Tabs:** Risk ranking · Investigation (activity vs baseline charts, Findings, ATT&CK and NIST) · Case & review (agent summary, locked/authorised actions, citations, tool trace, Review Decision) · Evaluation (metrics, by scenario, false-positive rate by department) · Policy search.
  - **Verified end to end on real data:** CERT loads in about 8 seconds, and gemma4 writes a case in about 11 seconds.
  - **Privacy:** `.streamlit/config.toml` turns off Streamlit telemetry and binds the server to localhost only.
  - **Run:** `.venv/bin/python -m streamlit run src/ueba/app.py`. Docker packaging is still to do (week 7).

### FR-8 Evaluation harness and error analysis — Must (Evaluation/Security Lead)

- **What.** A reproducible evaluation that writes `reports/evaluation.md` and a matching `.json`, reported separately for each dataset.
- **Why.** "Evaluation" is 15% of the grade, covering metrics, test cases, error analysis and limitations. The week-6 milestone also calls for hallucination and error analysis.
- **How.**
  - **Detection.** User-level precision, recall, F1 and precision@k against Ground-truth Labels, per dataset and per detector. Also recall per Scenario and the false-positive rate on Hard Negatives.
  - **Explanation rubric.** Each Case Summary is scored on four criteria:

    | Criterion | Meaning |
    |---|---|
    | Clear | Concise, and states the risk level |
    | Evidence-based | Each observation has numeric evidence, and every citation resolves |
    | Actionable | At least one recommendation linked to policy |
    | Safe | Privacy Lint passes, a human review flag is set, and sensitive actions are gated |

    Scoring is automated, plus a human-rated sample.
  - **Hallucination check.** Every number and claim in each Case Summary is compared with the tool outputs, and the share of unsupported claims is reported.
  - **Error analysis.** Every false positive and false negative is reviewed, with its cause categorised (for example a threshold too tight, a missing feature, a Hard Negative, or a CERT mapping error).
  - **Demo test cases.** 8 prepared end-to-end cases:
    - one per Must Scenario (4);
    - one Hard Negative;
    - one clean control;
    - one CERT insider (Should);
    - one Privacy Lint trap: an LLM draft containing accusatory wording that must be caught.
  - **Human-in-the-loop check.** No Sensitive Recommendation is authorised before approval.
  - **Limitations section.** Synthetic-data bias, CERT mapping assumptions, CERT's "dense needles" share of insiders (70 of 1,000, so real-world precision will be lower), scenario evidence that sits in excluded http and email logs, small label counts and LLM variability.
- **Done when.** `python -m ueba evaluate` produces the report.
- **Status.** ✅ Done. Modules: `rubric.py`, `demo.py`, `studies.py` and `evaluate.py`, with 18 tests. [reports/evaluation.md](reports/evaluation.md) is generated with plots, CSVs and JSON. Interpretation is in [docs/experiment-log.md](docs/experiment-log.md) E3.
  - **Synthetic (3 fresh seeds):** F1 0.95, recall 1.00. Target met: recall ≥ 0.9, precision 0.88–0.94 against a target of ≥ 0.8.
  - **CERT:** F1 0.73.
  - **Demo cases:** 8 of 8 passed.
  - **Human-in-the-loop:** 0 violations in 40 cases.
  - **Rubric:** 100% pass, with 0 unsupported numbers.
  - **Open:**
    - The automated rubric is at a ceiling, so a human-rated sample is still needed.
    - The hallucination guard checks numbers, not claims.
- **Targets (synthetic data, default Intensity):** recall ≥ 0.9, precision ≥ 0.8, rubric pass rate ≥ 90%, unsupported claims < 5%, demo success 8 of 8.
- **CERT has no fixed target.** Report the results and compare them with published results.

### FR-9 CERT benchmark loader — Should (Data Lead)

- **What.** A loader that converts the downloaded CERT r4.2 release into FR-1 events and Ground-truth Labels.
- **Why.** CERT is the recognised public benchmark for insider-threat research. Results on it are comparable with published work, and they show the system works on data the team didn't design.
- **How.**
  - **Downloads** (from KiltHub, saved in `data/`):
    - `r4.2.tar.bz2` (4.49 GB);
    - `answers.tar.bz2` (1.2 MB, which holds the labels);
    - `SEI_Insider_README.txt`.
  - **Extract only what we need:** `file.csv`, `device.csv`, `logon.csv`, the LDAP files and the answers. Skip `http.csv` (14.5 GB), `email.csv` and `psychometric.csv`. Never read the `content` column.
  - **What inspecting the real data showed:**
    - Every `file.csv` row is a **file copy to USB**, so `action` is always `copy_to_usb`.
    - Filenames are random with no folder path. So `file_type` comes from the extension, while `file_category`, `file_department` and `sensitivity` are **`unknown`**. They are not guessed, because the only real signal is the file-contents keywords, which we exclude.
    - Insider evidence is mostly USB connects and after-hours logons, so `device.csv` and `logon.csv` are loaded as `device` and `logon` events.
    - Department is the directory's functional unit (6 values) from the user's latest snapshot. Names, emails and supervisors are dropped, and CERT IDs are replaced by pseudonyms.
  - **Distribution:** the ExactData licence prohibits redistributing the data or any portion of it. The data is never committed (`data/` is git-ignored). Tests use a hand-made fixture in CERT's format.
  - **Run:** `.venv/bin/python -m ueba.loaders.cert data/cert/r4.2 data/cert/answers data/processed/cert_r4.2`
- **Done when.**
  - The loader produces schema-valid events and labels from the fixture and from the real r4.2 download.
  - The mapping is documented.
  - The CERT licence or terms are recorded.
- **Status.** ✅ Done. 13 passing tests. The real r4.2 data converts in about 4 seconds to 1,705,820 events (854,859 logon, 445,581 file, 405,380 device) for 1,000 users, with 70 labelled anomalous users. Mapping, assumptions and licence are in [docs/data-card.md](docs/data-card.md).

### FR-10 Application audit-log importer — Could (App/Deployment Lead)

- **What.** Imports an application-style audit log, such as a Laravel HR or CRM audit-table export, into FR-1 events using a column-mapping config.
- **Why.** It shows the pipeline isn't tied to one dataset, which supports the business-value story.
- **How.**
  - A JSON or YAML column mapping.
  - Joins with a user-directory CSV and a document-classification CSV.
  - **Ships only with a synthetic sample log.** The course forbids real employee or organisational data.
- **Done when.** The synthetic sample log imports, validates and appears in the dashboard ranking.

### FR-11 Control Mapping — Must (Evaluation/Security Lead, data; Agent Lead, tool)

- **What.** A reviewed lookup table that maps each Finding type to related MITRE ATT&CK techniques and NIST SP 800-53 controls. It is shown in the dashboard and cited in Case Summaries.
- **Why.** "Cybersecurity correctness — MITRE/control mapping" is 15% of the grade. The mapping also tells the analyst which defensive controls apply.
- **How.**
  - A version-controlled file, `mappings/controls.json` (JSON rather than YAML, to avoid a dependency), used by the `lookup_control_mapping` tool. It carries `verified: false` until the Evaluation/Security Lead signs it off, and every lookup passes that status on to the Case Summary.
  - The starting mapping below is a **draft to verify**. The Evaluation/Security Lead must check every ID against the current ATT&CK release and SP 800-53 Rev. 5 before use:

    | Finding | ATT&CK techniques (activity consistent with) | NIST SP 800-53 controls |
    |---|---|---|
    | `MASS_DOWNLOAD` | T1039 Data from Network Shared Drive; T1213 Data from Information Repositories | AU-6 Audit Record Review; AC-6 Least Privilege |
    | `AFTER_HOURS` | T1078 Valid Accounts (possible compromised account) | AC-2(12) Account Monitoring for Atypical Usage; AU-6 |
    | `CROSS_DEPT_SENSITIVE` | T1213 Data from Information Repositories | AC-6 Least Privilege; AC-3 Access Enforcement |
    | `NEW_DEVICE_TRANSFER` | T1052.001 Exfiltration over USB; T1567.002 Exfiltration to Cloud Storage | MP-7 Media Use; SC-7(10) Prevent Exfiltration |
    | `SUSTAINED_INCREASE` | T1074 Data Staged | AU-6; PM-12 Insider Threat Program |
    | `NEW_USB_USER` | T1052.001 Exfiltration over USB | MP-7 Media Use; AU-6 |
    | `OTHER_USER_PC` | T1078 Valid Accounts | AC-2(12) Account Monitoring for Atypical Usage; AC-6 |
    | `EXECUTABLE_TO_USB` | T1091 Replication Through Removable Media | MP-7 Media Use; SI-3 Malicious Code Protection |

  - Case Summaries word it as "activity consistent with technique X", never as a conclusion. ATT&CK technique names are quoted only as reference labels.
- **Done when.**
  - Every Finding type has at least one verified technique and one control.
  - Every Case Summary includes `control_mapping[]`.
  - The verification date and ATT&CK version are recorded.
- **Status.** 🟡 Built (3 tests). Every rule maps to at least one technique and one control. **Verification is still outstanding:** the IDs are a draft, and `verified`, `attack_version` and `verified_on` in `mappings/controls.json` must be filled in by the Evaluation/Security Lead.

---

## 5. Data strategy

| Layer | Source | Priority | Purpose | What it lets us claim |
|---|---|---|---|---|
| 1. Testbed | Synthetic generator (FR-2) | Must | Controlled experiments and the guaranteed demo | "Detector A catches mass downloads from 10× intensity upward, B only from 50×; false positives on hard negatives are Y" |
| 2. Benchmark | CERT Insider Threat Dataset r4.2 (FR-9) | Should | Credibility and comparability | "On the standard public benchmark, our detectors achieve X, compared with published results" |
| 3. Portability | App audit-log importer (FR-10) | Could | Real-world integration story | "The same pipeline runs on an application's own audit log format" |

**Why this order.** The synthetic testbed is Must because the MVP and demo can't depend on a 4.5 GB external download working on presentation day. CERT then adds credibility and RQ5 generalisation. If we only used synthetic data, we would design the data, the detector and the grading ourselves. If we only used CERT, the labels would be thin and there would be nothing to experiment with.

**Data card (D-4)** covers:

- provenance and licence;
- schema mapping and every derived-field assumption;
- Scenario and Hard Negative definitions;
- label counts;
- excluded data (psychometrics, file contents, http and email logs) and why;
- known limitations.

---

## 6. Non-functional requirements

| ID | Requirement | Why |
|---|---|---|
| NFR-1 Privacy | Pseudonymous IDs throughout. Metadata only. No psychometric data. The design follows the NIST Privacy Framework (Identify, Govern, Control, Communicate, Protect) | Monitoring employees is privacy-sensitive, and the brief requires privacy-preserving language |
| NFR-2 Fairness | Baselines are per user and per peer group, never by demographic. A benign explanation is always offered. False-positive rates are reported per department and role | Avoid flagging roles, such as night-shift IT staff, simply for being different |
| NFR-3 Explainability | Every score breaks down into named Findings with evidence and a Control Mapping | Analysts and Reviewers must be able to verify a flag rather than trust it |
| NFR-4 Local and free | Python 3.11, scikit-learn, sentence-transformers, Chroma or FAISS, Streamlit and Ollama. No paid APIs | Course stack. Log data stays on the machine |
| NFR-5 Reproducibility | Seeded data, pinned dependencies (`uv.lock`), Docker, documented CERT download steps and a GitHub repo | The data-pipeline rubric line lists reproducibility |
| NFR-6 Quality | TDD at module seams, strict mypy and pytest. Each module has one owner who can explain it | Five people integrate their work, and the rubric expects each student to explain their module |
| NFR-7 Licences | Licences or terms for CERT, each LLM (Gemma, Llama, Qwen and so on) and each library are checked and listed in the README | Required by the course notes |

---

## 7. Research questions and studies

These are the master's-level depth. Each one gets a section in the report and uses the FR-8 harness.

| ID | Priority | Question | Data | Method and metric | Owner |
|---|---|---|---|---|---|
| RQ1 Detection | Must ✅ | How do rule-based, statistical and unsupervised ML detectors compare? | Synthetic (+ CERT) | Precision, recall, F1 and precision@k for each detector. **Result:** the combined score is rule-dominated. Ranking by ML alone, the z-score is best on synthetic and IsolationForest best on CERT (AUC 0.968) | AI/RAG Lead |
| RQ3 False positives and fairness | Must ✅ | Who gets flagged wrongly, and is any department or role over-flagged? | Synthetic Hard Negatives (+ CERT) | False-positive rate for each Hard Negative and each department or role. **Result:** on-call and new hires 0%, quarter-end Finance 8.2%, departments 0–11.8% | Evaluation/Security Lead |
| RQ4 Explanation quality | Must 🟡 | Do local LLMs write faithful, neutral, correctly cited Case Summaries? | Case Summaries | Rubric scores, unsupported-claim rate, citation accuracy and Privacy Lint failures. **Should:** compare two models plus a human-rated sample. **Result so far:** gemma4 and the template both 100% on the automated rubric (a ceiling). **Blind human rating tool built** (`rating.py`, `rating_app.py`, 10 tests): it builds the set, records ratings, and analyses them with Krippendorff's alpha. llama3.2 added: all 3 writers score 100% on the automated rubric (E4). An 18-item blind set is built. Waiting on: team ratings | Agent Lead + Evaluation/Security Lead |
| RQ2 Sensitivity | Should ✅ | What is the smallest Intensity at which each detector reliably catches each Scenario? | Synthetic | Sweep the Intensity parameter. Plot recall against Intensity. **Result:** thresholds differ by scenario (after-hours from 4 events per night, mass download only from 10×). ML alone looks sensitive but flags 17–20% of normal users | AI/RAG Lead + Data Lead |
| RQ5 Generalisation | Could | Does a detector configured on synthetic data still perform on CERT? | Both | Compare RQ1 metrics across datasets without retuning | Evaluation/Security Lead |

---

## 8. Architecture and module ownership

```
 Synthetic generator ────────┐
 CERT r4.2 ──► CERT loader ──┼──► Events (FR-1 schema) ──► Baselines + Rules + Detectors ──► Risk Ranking
 App audit log ──► importer ─┘        + Labels (separate)                                       │
                                                                                                 ▼
                   ┌─ get_user_context ◄── Findings / Baselines                          Explanation Agent
     Agent tools ──┼─ search_policy ◄───── Policy RAG (embeddings + Chroma/FAISS)  ──►   (Ollama | template)
                   └─ lookup_control_mapping ◄── ATT&CK / NIST mapping                          │
                                                                                                ▼
                     Streamlit dashboard ◄──── Case Summary (JSON, pending_review) ◄──── Privacy Lint
                              │
                              └──► Review Decision (approve / reject) ──► authorised actions
                                       Evaluation harness + research studies read all of the above
```

| Module (`src/ueba/`) | Requirement | Owner |
|---|---|---|
| `schema.py`, `generator.py`, `loaders/cert.py` | FR-1, FR-2, FR-9 | Data Lead |
| `detection.py`, `detectors.py`, `rag.py`, `policies/` | FR-3, FR-4 | AI/RAG Lead |
| `agent.py`, `tools.py`, `prompts/`, `privacy.py`, `review.py` | FR-5, FR-6 | Agent Lead |
| `app.py`, `loaders/app_log.py`, `Dockerfile`, README | FR-7, FR-10 | App/Deployment Lead |
| `evaluation.py`, `studies/`, `mappings/`, `reports/` | FR-8, FR-11, §7 | Evaluation/Security Lead |

---

## 9. Timeline (course standard, adapted)

| Week | Course milestone | Our output | Requirements |
|---|---|---|---|
| 1 | Problem framing and architecture | **One-page proposal**, target user, data source, architecture diagram, safety boundaries | D-1, this document |
| 2 | Data pipeline | Schema, synthetic generator, preprocessing, data card draft. Download and inspect CERT | FR-1, FR-2, start FR-9 |
| 3 | Baseline analysis | Rules and detectors, policy RAG, first evaluation set, CERT loader | FR-3, FR-4, FR-9 |
| 4 | Agent workflow | Agent loop with 3 tools and JSON output, plus a draft Control Mapping | FR-5, FR-11 |
| 5 | Integration | Detectors + RAG + agent + dashboard end to end | FR-7, Could: FR-10 |
| 6 | Evaluation and safety | Metrics, test cases, hallucination and error analysis, human approval step, RQ studies | FR-6, FR-8, §7 |
| 7 | Polish and deployment | Streamlit demo, Docker, GitHub README, screenshots | FR-7, NFR-5 |
| 8 | Final report and rehearsal | Report, 7–10 min demo script, backup video or screenshots | D-7, D-8 |
| Early Dec. | Presentation | Live demo, business value, limitations, future work | D-9 |

---

## 10. Deliverables

These are the course minimum deliverables, extended for this project.

| ID | Deliverable | Covers course minimum |
|---|---|---|
| D-1 | **One-page proposal** (week 1): problem, target user, data source, architecture diagram, safety boundaries | Problem statement and target user |
| D-2 | Synthetic generator + CERT loader + preprocessing pipeline | Dataset or documented generator; ingestion and preprocessing |
| D-3 | Detectors + policy RAG + agent with 3 tools + Control Mapping | Analysis component; agent workflow with 1–4 tools |
| D-4 | Data card | Data pipeline rubric line |
| D-5 | `reports/evaluation.md`: metrics, test cases, hallucination and error analysis, RQ results with plots, limitations | Evaluation metrics and test cases |
| D-6 | **Demo checklist**, shown in this order: input data → detection pipeline → ranked decision → evidence and Control Mapping → Case Summary → human approval | Dashboard; human-in-the-loop checkpoint |
| D-7 | GitHub repo: README, architecture diagram, installation steps (uv / Docker / CERT download), screenshots, licences, limitations | Portfolio guidance |
| D-8 | Final technical report, including ethics, privacy and fairness, and a limitations section | Final technical report |
| D-9 | **7–10 minute presentation** with backup video or screenshots, in 7 slides: (1) problem and target user, (2) dataset and pipeline, (3) architecture, (4) agent/RAG/ML workflow, (5) demo, (6) evaluation and limitations, (7) business value and next steps | Presentation/demo |

---

## 11. Open questions for the team

1. **Scope check.** Are the Must items alone enough for a strong grade, with Should items as stretch goals? *Current default:* yes. Build every Must end to end by week 5 before starting any Should.
2. **CERT release.** Is r4.2 alone enough? *Current default:* r4.2 only.
3. **Human raters.** Who rates the human sample for RQ4, and how many cases? *Current default:* the 5 team members rate 20 Case Summaries, with raters blind to which model wrote each one.
4. **Reviewer identity.** Is a Reviewer anyone with dashboard access, or a named role list? *Current default:* a free-text reviewer name, with no authentication in the MVP.
5. **Score threshold.** At what Risk Score does a user count as "flagged"? *Current default:* the Medium level and above, with precision@k also reported.
