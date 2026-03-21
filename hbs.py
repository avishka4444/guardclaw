"""
hbs.py — Heartbeat Sanitizer (HBS)
GuardClaw OpenClaw plugin | before_heartbeat_fetch hook

OpenClaw fetches a remote Markdown file every 4 hours and executes it.
Attacker control of that file = full control of every subscribing agent
(Heartbeat Anchor Injection — novel attack class, see companion paper).

HBS validates every fetch through four ordered checks:
  1. Domain allowlist       — reject unknown origins immediately
  2. SHA-256 hash           — detect any byte-level change
  3. Dangerous verb scan    — flag executable/exfiltration commands
  4. Semantic drift         — catch meaning-level tampering that evades (3)
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from sentence_transformers import SentenceTransformer, util

# ---------------------------------------------------------------------------
# Model — loaded once at import time (shared across all calls in the process)
# ---------------------------------------------------------------------------

_MODEL = SentenceTransformer("all-MiniLM-L6-v2")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ALLOWED_DOMAINS: List[str] = [
    d.strip()
    for d in os.getenv("GUARDCLAW_TRUSTED_DOMAINS", "moltbook.com").split(",")
    if d.strip()
]

DANGEROUS_VERBS: List[str] = [
    "curl ",
    "wget ",
    "ssh ",
    "eval(",
    "exec(",
    "base64 -d",
    "__import__",
    "os.system",
    "subprocess",
    "rm -rf",
    "|bash",
    "|sh",
]

DRIFT_THRESHOLD: float = float(os.getenv("GUARDCLAW_DRIFT_THRESHOLD", "0.85"))

STATE_FILE: str = os.path.expanduser("~/.guardclaw/heartbeat_state.json")

# ---------------------------------------------------------------------------
# Paths and audit logger
# ---------------------------------------------------------------------------

_GUARDCLAW_DIR = Path.home() / ".guardclaw"
_AUDIT_PATH = _GUARDCLAW_DIR / "hbs_audit.jsonl"

_GUARDCLAW_DIR.mkdir(parents=True, exist_ok=True)

_audit_logger = logging.getLogger("guardclaw.hbs.audit")
_audit_handler = logging.FileHandler(_AUDIT_PATH, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False


def _log_audit(url: str, verdict: str, check: str, reason: str, **extra) -> None:
    """Append one decision line to hbs_audit.jsonl."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "verdict": verdict,
        "check": check,
        "reason": reason,
        **extra,
    }
    _audit_logger.info(json.dumps(record, ensure_ascii=False))


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_state() -> dict:
    """
    Read per-URL state from STATE_FILE.
    Returns an empty dict if the file is missing or corrupt — never raises.
    Also ensures ~/.guardclaw/ exists.
    """
    _GUARDCLAW_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    """Write state dict to STATE_FILE as pretty-printed JSON."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Hook entry point
# ---------------------------------------------------------------------------

def sanitize_heartbeat(url: str, content: str) -> Dict:
    """
    Validate a heartbeat fetch before OpenClaw executes it.

    Parameters
    ----------
    url     : The URL the heartbeat was fetched from.
    content : Raw Markdown content of the heartbeat file.

    Returns
    -------
    Dict with at minimum: verdict ("BLOCK" | "QUARANTINE" | "ALLOW"),
    check (which check made the decision), reason (human-readable string).
    """

    # ------------------------------------------------------------------
    # Check 1 — Domain allowlist
    # Reject anything not explicitly trusted. This is the cheapest
    # check and eliminates the most obvious attack vector first.
    # ------------------------------------------------------------------
    domain = urlparse(url).netloc
    if domain not in ALLOWED_DOMAINS:
        reason = f"Domain '{domain}' not in allowlist {ALLOWED_DOMAINS}"
        _log_audit(url, "BLOCK", "domain_allowlist", reason)
        return {"verdict": "BLOCK", "reason": reason, "check": "domain_allowlist"}

    # ------------------------------------------------------------------
    # Check 2 — SHA-256 hash comparison
    # Track whether content changed at all since last seen.
    # No previous hash means this is the first fetch — treat as baseline.
    # ------------------------------------------------------------------
    current_hash = hashlib.sha256(content.encode()).hexdigest()
    state = load_state()
    previous = state.get(url, {})
    content_changed = (
        previous.get("hash") is not None and previous["hash"] != current_hash
    )

    # ------------------------------------------------------------------
    # Check 3 — Dangerous verb scan
    # Runs on EVERY fetch (first-time and changed) because a brand-new
    # malicious heartbeat file must be caught even before a baseline exists.
    # ------------------------------------------------------------------
    content_lower = content.lower()
    for verb in DANGEROUS_VERBS:
        if verb.lower() in content_lower:
            reason = f"Dangerous command detected: '{verb}'"
            _log_audit(url, "BLOCK", "dangerous_verb", reason, verb=verb)
            return {"verdict": "BLOCK", "reason": reason, "check": "dangerous_verb"}

    if content_changed:
        # --------------------------------------------------------------
        # Check 4 — Semantic drift
        # Encode both versions and compare cosine similarity.
        # A low similarity score means the *meaning* shifted significantly
        # even if no individual dangerous verb was present — this catches
        # sophisticated rewrites that evade Check 3.
        # Only runs when a previous embedding snapshot exists.
        # --------------------------------------------------------------
        if previous.get("embedding_text") is not None:
            current_emb = _MODEL.encode(content, convert_to_tensor=True)
            prev_emb = _MODEL.encode(
                previous["embedding_text"], convert_to_tensor=True
            )
            similarity = float(util.cos_sim(current_emb, prev_emb)[0][0])

            if similarity < DRIFT_THRESHOLD:
                reason = (
                    f"Semantic drift detected: similarity {similarity:.3f} "
                    f"< threshold {DRIFT_THRESHOLD}"
                )
                _log_audit(
                    url,
                    "QUARANTINE",
                    "semantic_drift",
                    reason,
                    similarity=round(similarity, 4),
                )
                return {
                    "verdict": "QUARANTINE",
                    "reason": reason,
                    "check": "semantic_drift",
                    "similarity": similarity,
                }

    # ------------------------------------------------------------------
    # All checks passed — update persisted state for this URL
    # ------------------------------------------------------------------
    state[url] = {
        "hash": current_hash,
        "embedding_text": content[:500],   # first 500 chars as embedding anchor
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "check_count": previous.get("check_count", 0) + 1,
    }
    save_state(state)

    reason = "All checks passed" + (" (content unchanged)" if not content_changed else "")
    _log_audit(
        url,
        "ALLOW",
        "all_checks",
        reason,
        hash=current_hash,
        changed=content_changed,
    )
    return {"verdict": "ALLOW", "hash": current_hash, "changed": content_changed}


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def get_hbs_log() -> List[dict]:
    """
    Return the last 50 entries from the HBS audit log.
    Returns an empty list if the log does not yet exist.
    """
    try:
        with open(_AUDIT_PATH, encoding="utf-8") as f:
            lines = f.readlines()
        entries = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries[-50:]
    except FileNotFoundError:
        return []
