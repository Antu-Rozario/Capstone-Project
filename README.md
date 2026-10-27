# Insider Threat File Access UEBA Agent

**Group 8A** · Applied AI Agents for Cybersecurity Operations · Laurentian University · Fall 2026 · Defensive use only

A user and entity behaviour analytics (UEBA) agent that learns what normal file activity looks like for each person and department. It flags unusual activity such as mass downloads, after-hours access, sensitive files from other departments and transfers from unmanaged devices. For each flag it shows the evidence, cites the organisation's policy and drafts a privacy-preserving case summary. **A human must review every summary before any action is taken.**

> The system describes *activity*, never people's intent. A high Risk Score means "this activity deviates from this person's usual pattern and is worth a human look", not "this person is a threat".

---

## Contents

- [Why](#why)
- [Features](#features)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Data setup](#data-setup)
- [Usage](#usage)
- [Results so far](#results-so-far)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Privacy, safety and licences](#privacy-safety-and-licences)
- [Team roles](#team-roles)
- [Documentation](#documentation)
- [Limitations](#limitations)

---

## Why

Sensitive file access can signal negligence, a compromised account or insider risk. Raw logs alone don't tell an analyst whether a spike is unusual *for that person*, which policy applies, or how to write it up without accusing anyone. This project turns raw file-access logs into a ranked, explained, policy-grounded list for a human analyst to review.

**Target user:** an insider-risk or SOC analyst, with a Reviewer (senior analyst, HR or privacy officer) who approves any action.

## Features

Status: ✅ done · 🚧 in progress · ⏳ planned. Full requirements are in [REQUIREMENTS.md](REQUIREMENTS.md).

| Feature | Requirement | Status |
|---|---|---|
| One event schema shared by every data source | FR-1 | ✅ |
| Synthetic data generator: 5 anomalous scenarios with adjustable strength, plus 3 innocent-but-unusual groups | FR-2 | ✅ |
| CERT Insider Threat r4.2 loader (public benchmark) | FR-9 | ✅ |
| Per-user baselines with department fallback | FR-3 | ✅ |
| 8 explainable rules that each produce a Finding with observed-vs-baseline evidence | FR-3 | ✅ |
| 4 ML detectors: z-score, IsolationForest, LOF, One-Class SVM | FR-3 | ✅ |
| 0–100 Risk Score (Low, Medium, High) and user ranking | FR-3 | ✅ |
| Detection metrics: precision, recall, F1, precision@k, false-positive rates by scenario and department | FR-8 | ✅ |
| Policy RAG: 12-document policy corpus, hybrid search (TF-IDF + embeddinggemma, FAISS), citations you can resolve | FR-4 | ✅ |
| Explanation agent: 3 tools, gemma4 narrative, structured JSON Case Summary, Privacy Lint, hallucination guard, template fallback | FR-5 | ✅ |
| MITRE ATT&CK and NIST SP 800-53 Control Mapping | FR-11 | 🟡 built; IDs awaiting verification |
| Human-in-the-loop approval step (review store; UI comes with the dashboard) | FR-6 | ✅ |
| Streamlit dashboard: ranking, investigation charts, Case Summary, review and approval, evaluation, policy search | FR-7 | ✅ |
| Full evaluation report: explanation rubric, hallucination check, 8 demo cases, RQ1–RQ4 studies with plots | FR-8 | ✅ |
| Application audit-log importer (optional) | FR-10 | ⏳ |

## How it works

```
 Synthetic generator ────────┐
 CERT r4.2 ──► CERT loader ──┼──► Events (shared schema) ──► Daily features ──► Baselines
 App audit log ──► importer ─┘        + Labels (separate)                            │
                                                                                     ▼
                                                     Rules → Findings (evidence)  +  ML detector
                                                                       │
                                                                       ▼
                                                          Risk Score + ranked users
                                                                       │
              ┌─ get_user_context ◄── Findings / Baselines              ▼
 Agent tools ─┼─ search_policy ◄───── Policy RAG (embeddinggemma + FAISS)   Explanation Agent (Ollama gemma4)
              └─ lookup_control_mapping ◄── ATT&CK / NIST                            │
                                                                                     ▼
                                Streamlit dashboard ◄── Case Summary (JSON, pending_review) ◄── Privacy Lint
                                         └──► Human Review Decision ──► authorised actions
```

**Detection in brief:**

1. **Daily features for each user:** file events, transfers, after-hours activity, sensitive files from other departments, transfers from new devices, USB connects, logons to other users' PCs, `.exe` copies to USB, and a rolling 14-day transfer total.
2. **Baselines** come from a normal-only Baseline Window: the first 4 weeks for the synthetic data, and January to May 2010 for CERT.
3. **Rules** compare each day with the user's own baseline and produce Findings in neutral language. Example: *"312 file transfers in one day on 2026-09-22, against a baseline of 2.1 (threshold 25.0)."*
4. **The Risk Score** is 75% rule Findings and 25% ML detector. ML can raise a score but never create one, so every flagged user has explainable evidence.

## Installation

### Prerequisites

| Tool | Version | Install |
|---|---|---|
| Python | 3.11 | Installed automatically by uv |
| [uv](https://docs.astral.sh/uv/) | ≥ 0.9 | `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| [Ollama](https://ollama.com) | recent | Download from ollama.com. Needed for embeddings and the agent |
| Disk | about 6 GB | For the CERT download (optional) |

### Steps

```bash
# 1. Clone
git clone <repo-url> ueba-insider-threat && cd ueba-insider-threat

# 2. Install dependencies into .venv (Python 3.11 is installed automatically)
uv sync

# 3. Make the src/ package importable (one-time)
echo "$PWD/src" > "$(.venv/bin/python -c 'import site; print(site.getsitepackages()[0])')/ueba_src.pth"

# 4. Local models for RAG and the agent
ollama pull embeddinggemma     # embeddings for policy search (~620 MB)
ollama pull gemma4             # LLM for Case Summaries (~9.6 GB)
ollama pull llama3.2           # second LLM for the RQ4 comparison (~2 GB, optional)

# 5. Check everything works
.venv/bin/python -m pytest -q
```

> **Folder names containing `:`** (for example `Ai:Ml in Cybersecurity`) break `uv run`, because `:` is the PATH separator. That's why the commands here call `.venv/bin/python` directly. In a folder without `:`, `uv run python -m ...` works too.

## Data setup

Both sources are optional to download. The synthetic data is generated locally in seconds.

### Synthetic testbed (no download)

```bash
.venv/bin/python -m ueba.generator --out data/processed/synthetic
# variations: --seed 7 --users 200, or --config my_intensity.json for strength sweeps
```

### CERT Insider Threat r4.2 (public benchmark)

1. **Download** from Carnegie Mellon's KiltHub ([SEI dataset page](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)) into `data/`:
   - `r4.2.tar.bz2` (4.49 GB)
   - `answers.tar.bz2` (1.2 MB, the labels)
   - `SEI_Insider_README.txt`

   **Each team member downloads it themselves.** The licence forbids redistribution, so don't share the files and don't commit them.
2. **Extract only the files we use.** This skips the 14.5 GB web log, the email log and the personality-score file:
   ```bash
   mkdir -p data/cert
   tar -xjf data/answers.tar.bz2 -C data/cert
   tar -xjf data/r4.2.tar.bz2 -C data/cert r4.2/file.csv r4.2/logon.csv r4.2/device.csv r4.2/LDAP r4.2/readme.txt r4.2/license.txt
   ```
3. **Convert** to the shared schema (about 4 seconds):
   ```bash
   .venv/bin/python -m ueba.loaders.cert data/cert/r4.2 data/cert/answers data/processed/cert_r4.2
   ```

## Usage

### Run detection

```bash
# Synthetic: the Baseline Window is read from config.json
.venv/bin/python -m ueba.detection data/processed/synthetic

# CERT: the Baseline Window ends 2010-06-01 (first insider activity is 2010-06-10)
.venv/bin/python -m ueba.detection data/processed/cert_r4.2 --baseline-end 2010-06-01

# Choose a detector: isolation_forest (default) | baseline_zscore | lof | ocsvm
.venv/bin/python -m ueba.detection data/processed/synthetic --detector lof
```

Output goes to `data/results/<dataset>/`:

- `ranking.csv`: every user with Risk Score, level, rules and top Finding;
- `findings.json`: every Finding with its evidence;
- `metrics.json`: precision, recall, F1, precision@k and false-positive rates, when labels exist;
- `detection_meta.json`: detector, Baseline Window and which rules apply to this data.

### Search the policy corpus (RAG)

```bash
.venv/bin/python -m ueba.rag "an employee copied hundreds of files to a thumb drive"
.venv/bin/python -m ueba.rag "recommended actions" --finding-type NEW_USB_USER --k 5
.venv/bin/python -m ueba.rag "who approves restricting access" --backend tfidf   # offline, no Ollama
```

| Backend | How it searches | When it's used |
|---|---|---|
| `hybrid` | Keyword + semantic rankings, merged with reciprocal rank fusion | Default when Ollama is running |
| `ollama` | embeddinggemma embeddings in a FAISS index | Semantic only |
| `tfidf` | Keyword search | Offline fallback, and in tests |

Every result has a citation ID such as `playbook-mass-download#recommended-actions`, which the agent cites and the evaluation checks.

### Generate Case Summaries (agent)

```bash
.venv/bin/python -m ueba.agent data/processed/synthetic --top 3            # 3 highest-risk users
.venv/bin/python -m ueba.agent data/processed/synthetic --user U0027       # one user
.venv/bin/python -m ueba.agent data/processed/cert_r4.2 --baseline-end 2010-06-01 --top 2
.venv/bin/python -m ueba.agent data/processed/synthetic --llm none         # template only, no Ollama
```

Cases are saved as JSON in `data/cases/<dataset>/`.

**How a case is built:**

1. **Tools gather facts.** `get_user_context` runs once. Then, for each Finding, `search_policy` (RAG) and `lookup_control_mapping` (ATT&CK and NIST).
2. **Code assembles the exact parts:** observations with evidence, policy citations, control mapping, and recommended actions with `requires_approval` flags taken from the playbooks.
3. **gemma4 writes only the narrative** (the summary and innocent explanations), using the versioned prompt in `src/ueba/prompts/`.
4. **Checks.** The Privacy Lint rejects accusatory words and real names, and a hallucination guard rejects numbers not in the facts. If a check fails, or Ollama is down, a grounded template writes the narrative and `generated_by` says why.
5. **The case starts as `pending_review`.** Sensitive actions stay locked until a Reviewer approves the case (`src/ueba/review.py`).

### Open the dashboard

```bash
.venv/bin/python -m streamlit run src/ueba/app.py
# then open http://localhost:8501
```

| Tab | What you can do |
|---|---|
| 📊 **Risk ranking** | See every user ranked by Risk Score. Filter by level and department, and read each user's top Finding |
| 🔎 **Investigation** | Daily activity charts against the user's baseline (Detection Window shaded), each Finding with its evidence, ATT&CK and NIST mapping |
| 📝 **Case & review** | Generate a Case Summary (gemma4). See locked 🔒 and authorised ✅ actions, citations and the agent's tool trace. Record a Review Decision as Reviewer |
| 📈 **Evaluation** | Precision, recall, F1, precision@k, results by scenario, false-positive rate by department (fairness) |
| 📚 **Policy search** | Ask the policy corpus questions |

**Sidebar:** choose the dataset, ML detector and user, and enter your Reviewer name.

**Privacy settings:** `.streamlit/config.toml` turns off Streamlit telemetry and serves on `localhost` only.

**Optional environment variables:**

| Variable | Values | Purpose |
|---|---|---|
| `UEBA_LLM` | `auto`, `none`, or a model name | Which LLM writes the narrative |
| `UEBA_RAG` | `auto`, `hybrid`, `ollama`, `tfidf` | Which search backend to use |
| `UEBA_DATA_ROOT` | a folder path | Where the processed datasets are |
| `UEBA_REVIEWS` | a file path | Where Review Decisions are stored |
| `UEBA_CASES_DIR` | a folder path | Where Case Summaries are saved |

**The demo story,** following the rubric's input → pipeline → decision → evidence → approval order:

1. Pick the synthetic dataset.
2. Open the top-ranked user.
3. Show the activity spike against the baseline in the Investigation tab.
4. Generate the Case Summary.
5. Point out the 🔒 locked actions.
6. Enter a Reviewer name and approve the case.
7. Show the actions turn ✅ authorised.

## Results so far

Full report: [reports/evaluation.md](reports/evaluation.md). Interpretation and caveats: [docs/experiment-log.md](docs/experiment-log.md) (E1–E3). A user counts as flagged at risk level Medium or above.

| Measure | Result |
|---|---|
| Synthetic, 3 fresh seeds not used in development | precision 0.88–0.94 · recall 1.00 · **F1 0.95** |
| CERT r4.2 (public benchmark) | precision 0.58 · recall 0.97 · **F1 0.73** · normal-user false-positive rate 5.3% |
| Demo cases (end to end) | **8 of 8** passed, including a CERT insider and a Privacy Lint trap |
| Human-in-the-loop | **0** sensitive actions authorised without approval, in 40 cases |
| Explanation rubric (clear, evidence-based, actionable, safe) | 100% for gemma4 and the template, with 0 unsupported numbers |

**Research findings:**

- **RQ1, detectors:** the Risk Score is rule-dominated. Ranking by the ML score alone, IsolationForest is best on CERT (AUC 0.968), and a simple z-score is best on synthetic data.
- **RQ2, how faint an anomaly can be:** after-hours activity is caught from 4 events per night, but mass downloads only from about 10× normal. The ML detector alone looks more sensitive, but it flags 17–20% of normal users, which justifies "ML raises a score, never creates one".
- **RQ3, fairness:** on-call staff and new hires are never flagged. Quarter-end Finance users are flagged 8.2% of the time, because a department-wide rush resembles a personal increase. That's future work.
- **RQ4, narratives:** the template, gemma4 (8B) and llama3.2 (3B) all score 100% on the automated rubric, even though llama3.2's summaries are visibly weaker (rule names instead of evidence, repetitive). The automated rubric measures safety, not quality. A blind human rating set of 18 items is ready for the team to rate.

**Read these with care:**

- **Synthetic results reflect the generator's assumptions.**
- **The CERT v2 rule change was label-informed** (E2).

**Run the evaluation:**

```bash
.venv/bin/python -m ueba.evaluate            # full: 3 seeds + CERT + gemma4 (~5 min)
.venv/bin/python -m ueba.evaluate --quick    # smoke run (~30 s)
```

## Human rating of Case Summaries (RQ4)

The automated rubric can't tell the narrative writers apart, so RQ4 also uses a **blind human rating**. Each rater sees the evidence and one summary, but not which writer produced it (the template, gemma4 or llama3.2).

```bash
# 1. Build the blind rating set: the same users, written by every available writer, shuffled
.venv/bin/python -m ueba.rating build                     # skips models that aren't pulled

# 2. Each team member rates in the browser (progress is saved, so you can resume)
.venv/bin/python -m streamlit run src/ueba/rating_app.py

# 3. Un-blind and summarise: mean scores per writer, unsupported-claim rate, Krippendorff's alpha
.venv/bin/python -m ueba.rating analyse                   # writes reports/human_rating.md
```

**Criteria (1–5):**

| Criterion | What the rater judges |
|---|---|
| Clarity | Easy to understand, and states the risk level and what happened |
| Faithfulness | Every statement is supported by the evidence shown |
| Usefulness | Helps the analyst decide what to check next |
| Neutrality | Describes activity, not the person |

Raters also tick a box when the summary contains a claim the evidence doesn't support.

**Limitation:** the template's fixed wording is recognisable, so blinding fully separates the LLMs from each other but only partly separates them from the template.

## Project structure

```
├── README.md               ← you are here
├── REQUIREMENTS.md         ← what we build, why and how (FR/NFR, rubric mapping, timeline)
├── CONTEXT.md              ← domain glossary (Finding, Risk Score, Hard Negative, ...)
├── Group 8A.pdf            ← project brief (local only; course handout, not published)
├── notes/                  ← course notes, grading rubric, resources (local only, not published)
├── docs/
│   ├── data-card.md        ← both data sources: provenance, licence, mapping, limitations
│   └── experiment-log.md   ← every result-changing experiment (E1–E3), before/after numbers
├── policies/               ← policy corpus for RAG: 4 general documents + playbooks/ (one per rule)
├── mappings/controls.json  ← ATT&CK / NIST mapping (draft, awaiting verification)
├── .streamlit/config.toml  ← dashboard privacy settings (no telemetry, localhost only)
├── src/ueba/
│   ├── schema.py           ← shared event schema
│   ├── generator.py        ← synthetic testbed (FR-2)
│   ├── loaders/cert.py     ← CERT r4.2 loader (FR-9)
│   ├── features.py         ← daily per-user features
│   ├── baselines.py        ← per-user baselines with department fallback
│   ├── detectors.py        ← z-score, IsolationForest, LOF, OC-SVM
│   ├── detection.py        ← rules, Findings, Risk Score, ranking, CLI (FR-3)
│   ├── rag.py              ← policy corpus loader, TF-IDF/embeddinggemma/hybrid search (FR-4)
│   ├── controls.py         ← ATT&CK / NIST Control Mapping lookup (FR-11)
│   ├── privacy.py          ← Privacy Lint (FR-5)
│   ├── agent.py            ← tools, Case Summary builder, Ollama LLM, validation, CLI (FR-5)
│   ├── prompts/            ← versioned LLM prompts
│   ├── review.py           ← Review Decisions and approval gating (FR-6)
│   ├── dashboard.py        ← testable helpers for the dashboard
│   ├── app.py              ← Streamlit dashboard (FR-7)
│   ├── evaluation.py       ← detection metrics (FR-8)
│   ├── rubric.py           ← explanation rubric + hallucination checks
│   ├── demo.py             ← 8 prepared end-to-end demo cases
│   ├── studies.py          ← RQ1–RQ4 studies
│   ├── evaluate.py         ← runs everything, writes reports/
│   ├── rating.py           ← blind human rating: build set, store ratings, analyse (RQ4)
│   └── rating_app.py       ← Streamlit rating page for raters
├── reports/                ← evaluation.md, plots, CSVs, JSON
├── tests/                  ← pytest suite; fixtures are hand-made, never real CERT rows
└── data/                   ← git-ignored: downloads, processed data, results
```

## Testing

```bash
.venv/bin/python -m pytest -q          # full suite
.venv/bin/python -m pytest tests/test_detection.py -q
.venv/bin/python -m mypy               # strict type checking
```

Each module boundary is developed test-first. CERT tests use a small hand-made fixture in CERT's format, because the licence forbids copying real rows.

## Privacy, safety and licences

- **Synthetic or public data only.** CERT is itself fully synthetic. No real employee data is used.
- **Pseudonymous IDs** (`U0042`) everywhere. Names exist only in a separate directory, and CERT names and emails are dropped.
- **Metadata only.** File contents are never read. CERT's web, email and personality files are excluded.
- **No people profiling.** "Left the organisation" is never a detection feature, because it would leak CERT's labels.
- **Human approval** is required before any recommendation that affects a user's access or employment (FR-6).
- **Everything runs locally.** Ollama models run on your machine and no log data leaves it.

**Licences:**

| Component | Licence |
|---|---|
| CERT r4.2 | ExactData End User Agreement. **No redistribution**, and reports may describe results only |
| Synthetic data | Our own |
| Python libraries | pandas, NumPy, scikit-learn and FAISS are BSD/MIT. Faker is MIT |
| Models | gemma4 and embeddinggemma: check the Gemma terms on [ollama.com/library](https://ollama.com/library) before use |

## Team roles

The course's standard 5-person split. Each person owns and can explain their modules.

| Role | Owns |
|---|---|
| Data Lead | `schema.py`, `generator.py`, `loaders/`, data card |
| AI/RAG Lead | `features.py`, `baselines.py`, `detectors.py`, `detection.py`, `rag.py`, `policies/` |
| Agent Lead | Agent, tools, prompts, Privacy Lint, review step |
| App/Deployment Lead | Streamlit app, Docker, README |
| Evaluation/Security Lead | `evaluation.py`, experiments, Control Mapping, report |

## Documentation

| Document | What's in it |
|---|---|
| [REQUIREMENTS.md](REQUIREMENTS.md) | Requirements FR-1 to FR-11, rubric mapping, research questions, timeline, deliverables |
| [CONTEXT.md](CONTEXT.md) | Glossary of domain terms |
| [docs/data-card.md](docs/data-card.md) | Data provenance, schema mapping, assumptions, profiles, limitations |
| [docs/experiment-log.md](docs/experiment-log.md) | Every result-changing experiment |

## Limitations

- **The synthetic data reflects our assumptions.** Its results show relative detector behaviour, not real-world accuracy.
- **CERT r4.2 has only USB file copies,** with no views, downloads, sensitivity or owning department. So the "sensitive files from other departments" rule can only be evaluated on synthetic data.
- **Both datasets are "dense"** (12.5% and 7% anomalous users). Real-world prevalence is far lower, so real precision would be lower.
- **Some CERT scenario evidence sits in logs we deliberately exclude** (web and email).
- **This is an MVP for decision support,** not a production or autonomous system.
