# GuardClaw Evaluation Testbed — For research purposes only.
# No real user data, credentials, or production systems used.
#
# attacker/server.py
# Reads scenario JSON files from /scenarios and executes them in sequence
# against the victim via mock-moltbook. Records results to /results/output.json.

import json
import os
import time
from pathlib import Path

import requests

MOLTBOOK_URL = os.getenv("MOLTBOOK_URL", "http://mock-moltbook:8001")
CLAWHUB_URL = os.getenv("CLAWHUB_URL", "http://mock-clawhub:8002")
SCENARIOS_DIR = Path("/scenarios")
RESULTS_PATH = Path("/results/output.json")

RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)


def run_scenario(scenario_path: Path) -> dict:
    with open(scenario_path) as f:
        scenario = json.load(f)

    name = scenario.get("name", scenario_path.stem)
    steps = scenario.get("steps", [])
    step_results = []

    for step in steps:
        action = step.get("action")
        payload = step.get("payload", {})

        try:
            if action == "post":
                r = requests.post(f"{MOLTBOOK_URL}/posts", json=payload, timeout=10)
                step_results.append({"action": action, "status": r.status_code,
                                     "response": r.json()})

            elif action == "set_heartbeat":
                r = requests.post(f"{MOLTBOOK_URL}/admin/set_heartbeat",
                                  json=payload, timeout=10)
                step_results.append({"action": action, "status": r.status_code,
                                     "response": r.json()})

            elif action == "inject_skill":
                r = requests.post(f"{CLAWHUB_URL}/admin/inject_skill",
                                  json=payload, timeout=10)
                step_results.append({"action": action, "status": r.status_code,
                                     "response": r.json()})

            elif action == "wait":
                time.sleep(step.get("seconds", 1))
                step_results.append({"action": action, "status": "waited"})

            else:
                step_results.append({"action": action, "status": "unknown_action"})

        except Exception as exc:
            step_results.append({"action": action, "status": "error", "error": str(exc)})

    return {"scenario": name, "path": str(scenario_path), "steps": step_results}


def run():
    print("[attacker] Starting scenario runner.")
    scenarios = sorted(SCENARIOS_DIR.glob("*.json"))

    if not scenarios:
        print("[attacker] No scenario files found in /scenarios.")
        return

    all_results = []
    for path in scenarios:
        print(f"[attacker] Running scenario: {path.name}")
        result = run_scenario(path)
        all_results.append(result)
        time.sleep(2)  # brief pause between scenarios

    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"[attacker] Done. {len(all_results)} scenarios run. "
          f"Results written to {RESULTS_PATH}.")


if __name__ == "__main__":
    # Wait for other services to be ready
    time.sleep(10)
    run()
