# GuardClaw Evaluation Testbed — For research purposes only.
# No real user data, credentials, or production systems used.
#
# victim/server.py
# Minimal OpenClaw-like agent with GuardClaw plugin installed.
# Polls Moltbook for new posts and processes them through the SIF hook.

import importlib.util
import json
import os
import sys
import time

import requests

MOLTBOOK_URL = os.getenv("MOLTBOOK_URL", "http://mock-moltbook:8001")
CLAWHUB_URL = os.getenv("CLAWHUB_URL", "http://mock-clawhub:8002")
GUARDCLAW_ENABLED = os.getenv("GUARDCLAW_ENABLED", "true").lower() == "true"

# Load GuardClaw plugin from mounted volume
_plugin_path = "/extensions/guardclaw"
if GUARDCLAW_ENABLED and _plugin_path not in sys.path:
    sys.path.insert(0, _plugin_path)

if GUARDCLAW_ENABLED:
    import sif
    import cats

POLL_INTERVAL = 5  # seconds between feed polls
_seen_post_ids = set()


def ingest_post(post: dict) -> dict:
    """Run a post through the before_context_ingest hook pipeline."""
    content = post.get("content", "")
    agent_id = post.get("agent_id", "unknown")

    if not GUARDCLAW_ENABLED:
        return {"verdict": "ALLOW", "score": 0.0, "method": "disabled"}

    cats_risk = cats.get_risk(agent_id)
    result = sif.screen_content(content, cats_risk=cats_risk, source=agent_id)

    # Feed the verdict back into CATS
    cats.update_trust(
        agent_id=agent_id,
        content=content,
        was_flagged=result["verdict"] != "ALLOW",
    )

    return result


def run():
    print("[victim] Starting. GuardClaw enabled:", GUARDCLAW_ENABLED)
    while True:
        try:
            resp = requests.get(f"{MOLTBOOK_URL}/feed", timeout=5)
            posts = resp.json().get("posts", [])
            for i, post in enumerate(posts):
                if i in _seen_post_ids:
                    continue
                _seen_post_ids.add(i)
                result = ingest_post(post)
                print(f"[victim] post {i} → {result['verdict']} "
                      f"(score={result.get('score', 'n/a')})")
        except Exception as exc:
            print(f"[victim] feed poll error: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
