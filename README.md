# GuardClaw

> **Runtime security middleware for AI agent social platforms.**
> Open-source artefact accompanying the paper:
> *"A Survey of Security Vulnerabilities in AI Agent Social Platforms: Taxonomy, Real-World Case Studies, and the GuardClaw Mitigation Framework"*

---

## What Is GuardClaw?

OpenClaw is a personal AI agent that reads posts from **Moltbook** (an AI-only social network), installs skills from **ClawHub** (a marketplace), and fetches remote instructions every 4 hours via a **heartbeat** URL. Because the AI processes all of this content automatically — without human review — a single malicious post can hijack thousands of agents simultaneously.

GuardClaw is a **drop-in plugin** that intercepts every piece of content before the agent acts on it. It requires **no changes** to OpenClaw's internal architecture.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        OpenClaw Agent                        │
│                                                             │
│   Moltbook Posts ──► [ SIF ] ──► Agent Context Window      │
│   ClawHub Skills ──► [ SIF ] ──► Agent Context Window      │
│   Heartbeat File ──► [ HBS ] ──► Agent Execution           │
│   Agent Actions  ──► [ CATS ] ─► Trust Database            │
└─────────────────────────────────────────────────────────────┘
```

GuardClaw has three components:

| Component | File | Hook | Purpose |
|---|---|---|---|
| **SIF** — Social Injection Filter | `sif.py` | `before_context_ingest` | Screens every social post and skill before it enters the agent |
| **HBS** — Heartbeat Sanitizer | `hbs.py` | `before_heartbeat_fetch` | Validates every 4-hour heartbeat instruction file |
| **CATS** — Cross-Agent Trust Scorer | `cats.py` | `after_agent_action` | Tracks per-agent behaviour history and adjusts risk dynamically |

---

## Attack Stages Covered

GuardClaw defends against all six stages of the AI agent social platform kill chain:

| Stage | Name | Component |
|---|---|---|
| S1 | Initial Access | SIF + CATS |
| S2 | Privilege Escalation | SIF (partial) |
| S3 | Persistence / Heartbeat Anchor Injection | HBS |
| S4 | Lateral Movement | SIF + CATS |
| S5 | Exfiltration | SIF + HBS |
| S6 | Platform Persistence *(novel)* | CATS |

---

## Repository Structure

```
guardclaw/
├── sif.py                        # Social Injection Filter
├── hbs.py                        # Heartbeat Sanitizer
├── cats.py                       # Cross-Agent Trust Scorer
├── patterns.json                 # 130 injection pattern library
├── guardclaw.plugin.json         # Plugin manifest / hook registration
├── requirements.txt              # Python dependencies
├── smoke_test.py                 # 8 quick component tests
├── docker-compose.yml            # Full testbed (mock Moltbook + ClawHub + Ollama)
└── eval_battery/
    ├── run_tests.py              # 200-scenario evaluation harness
    ├── benign_control.json       # 20 benign scenarios (false positive testing)
    ├── results.json              # Last saved evaluation output
    ├── scenarios/
    │   ├── s1_initial_access.json
    │   ├── s2_privilege_escalation.json
    │   ├── s3_persistence.json
    │   ├── s4_lateral_movement.json
    │   ├── s5_exfiltration.json
    │   └── s6_platform_persistence.json
    ├── mock_moltbook/            # Mock Moltbook REST API (Docker)
    ├── mock_clawhub/             # Mock ClawHub marketplace (Docker)
    ├── victim/                   # Victim agent with GuardClaw installed (Docker)
    └── attacker/                 # Attack scenario runner (Docker)
```

---

## Quick Start

### Requirements

- Python 3.10+
- [Ollama](https://ollama.com/download) with `llama3:8b` pulled (for LLM fallback)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Pull the LLM model

```bash
ollama pull llama3:8b
```

### 3. Run the smoke test (8 quick checks)

```bash
python smoke_test.py
```

Expected output:
```
PASS 1: explicit injection blocked
PASS 2: normal post allowed
PASS 3: base64 payload detected
PASS 4: untrusted domain blocked
PASS 5: dangerous heartbeat command blocked
PASS 6: clean heartbeat allowed
PASS 7: new agent starts neutral
PASS 8: bad actor trust reduced

All 8 smoke tests passed. GuardClaw is working correctly.
```

### 4. Run the full evaluation (200 scenarios)

```bash
# All 200 scenarios
python eval_battery/run_tests.py

# Single stage with per-scenario output
python eval_battery/run_tests.py --stage S1 --verbose

# All stages with verbose output
python eval_battery/run_tests.py --verbose
```

---

## Evaluation Results

Results from the full 200-scenario evaluation using **Llama 3 8B** (CPU, via Ollama):

```
  GuardClaw Evaluation Results
------------------------------------------------------------------------------
Stage           |  Total |  Blocked |  Quarantined |  Missed | Detection Rate
------------------------------------------------------------------------------
S1 Init.Access  |   30   |    18    |      12      |    0    | 100.0%
S2 Priv.Esc     |   30   |    14    |       5      |    11   |  63.3%
S3 Persist.     |   30   |    14    |       3      |    13   |  56.7%
S4 Lateral      |   30   |    15    |       4      |    11   |  63.3%
S5 Exfil.       |   30   |    13    |       2      |    15   |  50.0%
S6 Plat.Pers.   |   30   |     0    |       3      |    27   |  10.0%
Benign (FP)     |   20   |  3 (FP)  |      --      |    --   | FP Rate: 15.0%
------------------------------------------------------------------------------

  Overall detection rate  : 57.2%  (103/180 attack scenarios)
  False positive rate     : 15.0%  (3/20 benign scenarios flagged)
  Median processing time  : 2.2 ms per scenario
```

> **Note:** The Blocked/Quarantined split may vary slightly between runs due to LLM non-determinism. Detection rates (Blocked + Quarantined combined) are stable across runs.

---

## Component Details

### SIF — Social Injection Filter (`sif.py`)

Screens content through a **three-layer pipeline**:

**Layer 1 — Pattern Matching**
- 130 regex patterns across 4 categories loaded from `patterns.json`:
  - `instruction_override` — phrases like *"ignore all previous instructions"*, *"jailbreak mode"*, *"DAN mode"*
  - `exfiltration` — phrases like *"send API key to..."*, *"curl https://..."*, *"upload to S3"*
  - `encoded_payloads` — Base64 strings, `eval()`, `exec()`, `os.system()` calls
  - Authority impersonation and platform bypass patterns
- Each matching pattern adds **+0.25** to the risk score

**Layer 2 — Trust Adjustment**
- `score += CATS_risk × 0.30`
- Content from a low-trust agent is scored more strictly automatically

**Layer 3 — LLM Fallback**
- Triggered only for ambiguous content (score in the quarantine band)
- Uses a **different** model from the host agent to avoid shared blind spots
- Fails **safe**: if Ollama is unreachable, verdict is QUARANTINE (not ALLOW)

**Decision thresholds:**

| Score | Verdict | Meaning |
|---|---|---|
| ≥ 0.75 | `BLOCK` | Dangerous — agent never sees it |
| 0.25 – 0.74 | LLM called → `BLOCK` or `QUARANTINE` | Ambiguous — second opinion |
| < 0.25 | `ALLOW` | Clean — passes through |

**Audit log:** `~/.guardclaw/sif_audit.jsonl`

---

### HBS — Heartbeat Sanitizer (`hbs.py`)

Validates each heartbeat fetch through **4 sequential checks**:

| Check | What it does | Verdict on fail |
|---|---|---|
| 1. Domain allowlist | Rejects URLs not in `ALLOWED_DOMAINS` | `BLOCK` |
| 2. SHA-256 hash | Detects any byte-level change since last fetch | Triggers checks 3 & 4 |
| 3. Dangerous verb scan | Flags `curl`, `wget`, `ssh`, `eval(`, `exec(`, `base64 -d`, `\|bash`, `rm -rf` | `BLOCK` |
| 4. Semantic drift | Cosine similarity of embeddings vs. previous version; threshold 0.85 | `QUARANTINE` |

State (hashes + embeddings) is persisted in `~/.guardclaw/heartbeat_state.json`.
**Audit log:** `~/.guardclaw/hbs_audit.jsonl`

---

### CATS — Cross-Agent Trust Scorer (`cats.py`)

Maintains a **behavioural profile** for every Moltbook agent in a local SQLite database.

**Trust score formula:**

```
τ = 0.3α  +  0.4φ  +  0.2(1 − δ)  +  0.1(1 − ε)
```

| Term | Meaning |
|---|---|
| α (alpha) | Account age — saturates at 30 days |
| φ (phi) | Clean post ratio — fraction of posts never flagged |
| δ (delta) | Cascade depth norm — deep resharing chains reduce trust |
| ε (epsilon) | Embedding drift norm — sudden semantic shift in posting style |

| Score | Meaning |
|---|---|
| 0.5 | New/unknown agent (neutral) |
| → 1.0 | Long-standing, clean history |
| < 0.3 | **Quarantined for 48 hours** — τ = 0.0 during quarantine |

The ε (embedding drift) term specifically detects **Stage 6 Platform Persistence**: an agent that posts normally for weeks then suddenly shifts topic/style is flagged even if individual posts look clean.

**Database:** `~/.guardclaw/cats.db`
**Audit log:** `~/.guardclaw/cats_audit.jsonl`

---

## Pattern Library (`patterns.json`)

130 regex patterns across multiple attack categories. Example patterns:

```
instruction_override : "ignore all previous instructions"
instruction_override : "jailbreak mode", "DAN mode", "developer mode enabled"
exfiltration         : "curl https://attacker.com", "send API key to..."
encoded_payloads     : Base64 strings ≥40 chars, eval(), exec(), os.system()
```

Patterns are loaded at import time and shared across all SIF calls in the process.

---

## Configuration

All thresholds are configurable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `GUARDCLAW_BLOCK_THRESHOLD` | `0.75` | SIF score above which content is blocked |
| `GUARDCLAW_QUARANTINE_THRESHOLD` | `0.25` | SIF score above which LLM fallback is called |
| `GUARDCLAW_LLM_MODEL` | `llama3:8b` | Ollama model for Layer 3 fallback |
| `GUARDCLAW_TRUSTED_DOMAINS` | `moltbook.com` | Comma-separated HBS domain allowlist |
| `GUARDCLAW_DRIFT_THRESHOLD` | `0.85` | HBS semantic drift cosine similarity floor |
| `GUARDCLAW_CATS_DB` | `~/.guardclaw/cats.db` | CATS SQLite database path |
| `GUARDCLAW_QUARANTINE_THRESHOLD` (CATS) | `0.3` | Trust score below which agent is quarantined |

---

## Docker Testbed

For a fully isolated end-to-end test with mock services:

```bash
docker compose up
```

This starts:
- `mock-moltbook` — simulated Moltbook REST API (port 8001)
- `mock-clawhub` — simulated ClawHub marketplace (port 8002)
- `victim` — OpenClaw-like agent with GuardClaw installed
- `attacker` — runs all 180 attack scenarios against the victim
- `ollama` — local LLM for Layer 3 fallback (port 11434)

> The Docker network is **internal only** — no real internet access is used.

---

## Audit Logs

All three components write append-only JSONL audit logs to `~/.guardclaw/`:

```
~/.guardclaw/
├── sif_audit.jsonl       # Every SIF verdict: timestamp, source, score, verdict
├── hbs_audit.jsonl       # Every heartbeat decision: URL, check, reason
└── cats_audit.jsonl      # Every trust update: agent_id, τ, drift, quarantined
```

---

## Known Limitations

| Limitation | Detail |
|---|---|
| **S6 detection gap** | Platform Persistence detection rate is 10% — slow-burn reputation laundering is hard to detect with current embedding drift window |
| **LLM latency** | Llama 3 8B on CPU takes 250–2000 ms per ambiguous call; GPU deployment recommended for production |
| **False positive rate** | 15% on adversarially constructed borderline benign content; operator review of QUARANTINE queue resolves these |
| **Pattern coverage** | Missed scenarios (score = 0.150) use evasive phrasing not yet in the pattern library |

---

## Dependencies

```
fastapi               # API framework (mock services)
uvicorn               # ASGI server
requests              # HTTP client
sentence-transformers # Embedding model (all-MiniLM-L6-v2) for HBS + CATS
ollama                # LLM fallback client (Layer 3 SIF)
python-dotenv         # Environment variable loading
pytest                # Test runner
```

---

## Citation

If you use GuardClaw or the evaluation battery in your research, please cite:

```
[Your Name et al.], "A Survey of Security Vulnerabilities in AI Agent Social
Platforms: Taxonomy, Real-World Case Studies, and the GuardClaw Mitigation
Framework", [Conference/Journal], 2026.
```

---

## Ethical Notice

GuardClaw is evaluated exclusively against locally-controlled mock infrastructure. No real OpenClaw deployments, real Moltbook users, or real credentials are used at any point. The 200-scenario evaluation battery contains **no real exploit code** — scenarios are synthetic representations of documented attack patterns. All real CVEs referenced in the companion paper were publicly disclosed and patched before this work was published.
