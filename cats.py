"""
cats.py — Cross-Agent Trust Scorer (CATS)
GuardClaw OpenClaw plugin | after_agent_action hook

Maintains a behavioural profile for every Moltbook agent and computes
a trust score τ ∈ [0, 1] that gates how strictly SIF screens that agent's
future content.

τ = 0.3α + 0.4φ + 0.2(1 − δ) + 0.1(1 − ε)

  α — account age term       (older agents are more trusted)
  φ — clean-post ratio       (fraction of posts never flagged)
  δ — cascade depth norm     (deep resharing chains reduce trust)
  ε — embedding drift norm   (sudden semantic shift → Stage 6 detection)

The embedding drift term specifically detects Stage 6 Platform Persistence:
an agent that has been posting normally for weeks but whose content
suddenly shifts semantic profile is a strong signal of compromise.
"""

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# ---------------------------------------------------------------------------
# Model — loaded once at import time
# ---------------------------------------------------------------------------

_MODEL = SentenceTransformer("all-MiniLM-L6-v2")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DB_PATH: str = os.path.expanduser(
    os.getenv("GUARDCLAW_CATS_DB", "~/.guardclaw/cats.db")
)

QUARANTINE_HOURS: int = 48
QUARANTINE_THRESHOLD: float = float(
    os.getenv("GUARDCLAW_QUARANTINE_THRESHOLD", "0.3")
)

# Trust-score weight vector: τ = Wα·α + Wφ·φ + Wδ·(1−δ) + Wε·(1−ε)
# Defaults are the paper's engineering-judgment values; overridable at runtime
# by the weight-sensitivity ablation (eval_battery/ablation.py). Must sum to 1.0.
W_ALPHA: float = float(os.getenv("GUARDCLAW_W_ALPHA", "0.3"))
W_PHI: float = float(os.getenv("GUARDCLAW_W_PHI", "0.4"))
W_DELTA: float = float(os.getenv("GUARDCLAW_W_DELTA", "0.2"))
W_EPSILON: float = float(os.getenv("GUARDCLAW_W_EPSILON", "0.1"))


def set_weights(alpha: float, phi: float, delta: float, epsilon: float) -> None:
    """
    Override the trust-score weight vector at runtime.

    Weights should sum to 1.0; a warning is logged otherwise (the formula
    still runs, but τ may fall outside [0, 1]). Used by the ablation study
    to test how sensitive detection/FP rates are to these specific values.
    """
    global W_ALPHA, W_PHI, W_DELTA, W_EPSILON
    W_ALPHA, W_PHI, W_DELTA, W_EPSILON = alpha, phi, delta, epsilon
    total = alpha + phi + delta + epsilon
    if abs(total - 1.0) > 1e-6:
        logging.getLogger("guardclaw.cats").warning(
            "CATS weights sum to %.4f, not 1.0 — tau may leave [0, 1]", total
        )

# ---------------------------------------------------------------------------
# Paths and audit logger
# ---------------------------------------------------------------------------

_GUARDCLAW_DIR = Path.home() / ".guardclaw"
_AUDIT_PATH = _GUARDCLAW_DIR / "cats_audit.jsonl"

_GUARDCLAW_DIR.mkdir(parents=True, exist_ok=True)

_audit_logger = logging.getLogger("guardclaw.cats.audit")
_audit_handler = logging.FileHandler(_AUDIT_PATH, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False


def _log_audit(agent_id: str, tau: float, drift: float,
               flagged: bool, quarantined: bool) -> None:
    """Append one trust-update line to cats_audit.jsonl."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "trust_score": tau,
        "embedding_drift": round(drift, 4),
        "was_flagged": flagged,
        "quarantined": quarantined,
    }
    _audit_logger.info(json.dumps(record, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id             TEXT PRIMARY KEY,
    created_at           REAL,
    total_posts          INTEGER DEFAULT 0,
    flagged_posts        INTEGER DEFAULT 0,
    cascade_depth_norm   REAL    DEFAULT 0.0,
    embedding_drift_norm REAL    DEFAULT 0.0,
    embedding_centroid   TEXT,
    quarantine_until     REAL    DEFAULT 0,
    last_updated         TEXT
)
"""


def _connect() -> sqlite3.Connection:
    """Open a connection with row_factory set to dict-like Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Ensure ~/.guardclaw/ exists and the agents table is present.
    Safe to call multiple times (CREATE TABLE IF NOT EXISTS).
    """
    _GUARDCLAW_DIR.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute(_CREATE_TABLE)
        conn.commit()


# Run at import time so every subsequent call can assume the schema exists.
init_db()


# ---------------------------------------------------------------------------
# Trust scoring
# ---------------------------------------------------------------------------

def get_trust_score(agent_id: str) -> float:
    """
    Compute τ for agent_id from its current database row.

    Returns 0.5 (neutral) for unknown agents — they have not earned
    trust but should not be pre-emptively penalised.
    Returns 0.0 for agents currently under quarantine.

    τ = 0.3α + 0.4φ + 0.2(1 − δ) + 0.1(1 − ε)
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

    if row is None:
        return 0.5

    # Active quarantine overrides formula entirely
    if time.time() < row["quarantine_until"]:
        return 0.0

    # α — account age, saturates at 30 days
    alpha = min(1.0, (time.time() - row["created_at"]) / (30 * 86400))

    # φ — fraction of posts that were never flagged
    phi = 1.0 - (row["flagged_posts"] / max(1, row["total_posts"]))

    # δ — normalised cascade depth (higher depth → lower trust contribution)
    delta = row["cascade_depth_norm"]

    # ε — embedding drift (higher drift → lower trust contribution)
    epsilon = row["embedding_drift_norm"]

    tau = (
        W_ALPHA * alpha
        + W_PHI * phi
        + W_DELTA * (1.0 - delta)
        + W_EPSILON * (1.0 - epsilon)
    )
    return round(tau, 3)


# ---------------------------------------------------------------------------
# Hook entry point
# ---------------------------------------------------------------------------

def update_trust(
    agent_id: str,
    content: str,
    was_flagged: bool = False,
    cascade_depth: int = 0,
) -> Dict:
    """
    Process one agent action and update the behavioural profile.

    Called by OpenClaw after every agent action via the after_agent_action
    hook. Updates post counts, cascade depth, and the rolling embedding
    centroid, then recomputes τ and triggers quarantine if τ drops below
    QUARANTINE_THRESHOLD.

    Parameters
    ----------
    agent_id      : Stable identifier for the Moltbook agent.
    content       : The text content of the agent's action/post.
    was_flagged   : True if SIF or another component flagged this action.
    cascade_depth : How many hops this content has been reshared.

    Returns
    -------
    Dict with trust_score, drift, quarantine status, and post counts.
    """
    now_ts = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

        is_new = row is None

        if is_new:
            # Bootstrap a fresh profile
            conn.execute(
                """
                INSERT INTO agents
                    (agent_id, created_at, total_posts, flagged_posts,
                     cascade_depth_norm, embedding_drift_norm,
                     embedding_centroid, quarantine_until, last_updated)
                VALUES (?, ?, 0, 0, 0.0, 0.0, NULL, 0, ?)
                """,
                (agent_id, now_ts, now_iso),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()

        # ------------------------------------------------------------------
        # Increment post counts
        # ------------------------------------------------------------------
        new_total = row["total_posts"] + 1
        new_flagged = row["flagged_posts"] + (1 if was_flagged else 0)

        # ------------------------------------------------------------------
        # Cascade depth — normalised to [0, 1] with ceiling at 100 hops
        # ------------------------------------------------------------------
        new_cascade_norm = min(1.0, cascade_depth / 100)

        # ------------------------------------------------------------------
        # Embedding centroid update and drift computation
        #
        # The centroid is the running mean of all post embeddings for this
        # agent. Cosine distance from the centroid to the new embedding
        # measures how much today's content diverges from historical baseline.
        #
        # Key property: a gradual drift barely moves the centroid, so a
        # sudden large shift (Stage 6 compromise) produces a high ε even
        # if prior posts looked normal.
        # ------------------------------------------------------------------
        new_emb: np.ndarray = _MODEL.encode([content])[0]

        if row["embedding_centroid"] is not None:
            centroid = np.array(json.loads(row["embedding_centroid"]))
            similarity = float(cosine_similarity([centroid], [new_emb])[0][0])
            drift = float(1.0 - similarity)
            # Online mean update: new_centroid = ((n-1)·old + new_emb) / n
            n = new_total
            new_centroid = ((centroid * (n - 1)) + new_emb) / n
        else:
            drift = 0.0
            new_centroid = new_emb

        new_centroid_json = json.dumps(new_centroid.tolist())

        # ------------------------------------------------------------------
        # Persist updated profile
        # ------------------------------------------------------------------
        quarantine_until = row["quarantine_until"]

        conn.execute(
            """
            UPDATE agents SET
                total_posts          = ?,
                flagged_posts        = ?,
                cascade_depth_norm   = ?,
                embedding_drift_norm = ?,
                embedding_centroid   = ?,
                quarantine_until     = ?,
                last_updated         = ?
            WHERE agent_id = ?
            """,
            (
                new_total,
                new_flagged,
                new_cascade_norm,
                drift,
                new_centroid_json,
                quarantine_until,
                now_iso,
                agent_id,
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Recompute τ from the freshly written row
    # ------------------------------------------------------------------
    tau = get_trust_score(agent_id)

    # ------------------------------------------------------------------
    # Quarantine if τ has fallen below the threshold
    # ------------------------------------------------------------------
    quarantined = False
    if tau < QUARANTINE_THRESHOLD:
        quarantine_until = now_ts + QUARANTINE_HOURS * 3600
        with _connect() as conn:
            conn.execute(
                "UPDATE agents SET quarantine_until = ? WHERE agent_id = ?",
                (quarantine_until, agent_id),
            )
            conn.commit()
        quarantined = True

    _log_audit(agent_id, tau, drift, was_flagged, quarantined)

    return {
        "agent_id": agent_id,
        "trust_score": tau,
        "flagged_posts": new_flagged,
        "total_posts": new_total,
        "embedding_drift": round(drift, 4),
        "quarantined": quarantined,
    }


# ---------------------------------------------------------------------------
# SIF integration helper
# ---------------------------------------------------------------------------

def get_risk(agent_id: str) -> float:
    """
    Return 1.0 − τ as the risk score fed into SIF's cats_risk parameter.

    A fully trusted agent (τ = 1.0) contributes 0.0 additional risk.
    A quarantined agent (τ = 0.0) contributes the maximum 1.0.
    """
    return round(1.0 - get_trust_score(agent_id), 3)


# ---------------------------------------------------------------------------
# Debugging / audit
# ---------------------------------------------------------------------------

def get_agent_profile(agent_id: str) -> Optional[Dict]:
    """
    Return the full stored profile for agent_id as a plain dict.
    Returns None if the agent has never been seen.
    Excludes the raw embedding centroid vector (too large for display).
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

    if row is None:
        return None

    profile = dict(row)
    # Omit the raw centroid JSON — it's a 384-float vector, not human-readable
    profile.pop("embedding_centroid", None)
    profile["trust_score"] = get_trust_score(agent_id)
    profile["risk_score"] = get_risk(agent_id)
    profile["quarantined"] = time.time() < profile.get("quarantine_until", 0)
    return profile
