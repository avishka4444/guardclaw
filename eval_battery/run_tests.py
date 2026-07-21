import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
eval_battery/run_tests.py
GuardClaw evaluation harness — runs all 200 scenarios against live components.

Usage:
    python run_tests.py                  # all 200 scenarios
    python run_tests.py --stage S1       # single stage
    python run_tests.py --verbose        # per-scenario output
    python run_tests.py --stage S3 --verbose
"""

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Path setup — allow running from any working directory
# ---------------------------------------------------------------------------

_EVAL_DIR = Path(__file__).parent
_REPO_ROOT = _EVAL_DIR.parent
sys.path.insert(0, str(_REPO_ROOT))

import sif
import hbs
import cats

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCENARIOS_DIR = _EVAL_DIR / "scenarios"
BENIGN_FILE = _EVAL_DIR / "benign_control.json"
RESULTS_FILE = _EVAL_DIR / "results.json"

HEARTBEAT_URL = "https://moltbook.com/heartbeat.md"

STAGE_FILES = {
    "S1": SCENARIOS_DIR / "s1_initial_access.json",
    "S2": SCENARIOS_DIR / "s2_privilege_escalation.json",
    "S3": SCENARIOS_DIR / "s3_persistence.json",
    "S4": SCENARIOS_DIR / "s4_lateral_movement.json",
    "S5": SCENARIOS_DIR / "s5_exfiltration.json",
    "S6": SCENARIOS_DIR / "s6_platform_persistence.json",
    "BENIGN": BENIGN_FILE,
}

STAGE_LABELS = {
    "S1": "S1 Init.Access",
    "S2": "S2 Priv.Esc   ",
    "S3": "S3 Persist.   ",
    "S4": "S4 Lateral    ",
    "S5": "S5 Exfil.     ",
    "S6": "S6 Plat.Pers. ",
    "BENIGN": "Benign (FP)   ",
}

# Verdicts that count as "detected" for attack scenarios
DETECTED_VERDICTS = {"BLOCK", "QUARANTINE"}


# ---------------------------------------------------------------------------
# Scenario loading
# ---------------------------------------------------------------------------

def load_scenarios(stage_filter: Optional[str] = None) -> List[Dict]:
    """Load and return all scenarios, optionally filtered to one stage."""
    scenarios = []

    if stage_filter:
        stage_upper = stage_filter.upper()
        path = STAGE_FILES.get(stage_upper)
        if path is None:
            print(f"[error] Unknown stage '{stage_filter}'. "
                  f"Valid stages: {', '.join(STAGE_FILES)}", file=sys.stderr)
            sys.exit(1)
        with open(path, encoding="utf-8") as f:
            batch = json.load(f)
        for s in batch:
            s.setdefault("stage", stage_upper)
        scenarios.extend(batch)
    else:
        for stage, path in STAGE_FILES.items():
            if not path.exists():
                print(f"[warn] Missing scenario file: {path}", file=sys.stderr)
                continue
            with open(path, encoding="utf-8") as f:
                batch = json.load(f)
            for s in batch:
                s.setdefault("stage", stage)
            scenarios.extend(batch)

    return scenarios


# ---------------------------------------------------------------------------
# Single scenario runner
# ---------------------------------------------------------------------------

def run_scenario(scenario: Dict) -> Dict:
    """
    Execute one scenario against the live GuardClaw components.
    Returns an outcome dict with verdict, pass/fail, timing, etc.
    """
    content = scenario["content"]
    source = scenario.get("source", "unknown")
    expected = scenario["expected_verdict"]
    stage = scenario.get("stage", "?")

    t0 = time.perf_counter()

    if source == "heartbeat":
        result = hbs.sanitize_heartbeat(HEARTBEAT_URL, content)
        actual_verdict = result.get("verdict", "ALLOW")
        score = result.get("similarity", None)
        triggers = []
        method = result.get("check", "hbs")
    else:
        cats_risk = cats.get_risk(scenario.get("id", "unknown"))
        result = sif.screen_content(content, cats_risk=cats_risk, source=source)
        actual_verdict = result.get("verdict", "ALLOW")
        score = result.get("score", 0.0)
        triggers = result.get("triggers", [])
        method = result.get("method", "regex")

    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Determine pass/fail
    is_benign = (stage == "BENIGN")
    if is_benign:
        # For benign scenarios a false positive = non-ALLOW verdict
        passed = (actual_verdict == "ALLOW")
    else:
        # For attack scenarios a miss = ALLOW verdict
        passed = (actual_verdict == expected) or (actual_verdict in DETECTED_VERDICTS)

    return {
        "id": scenario.get("id"),
        "stage": stage,
        "name": scenario.get("name"),
        "attack_class": scenario.get("attack_class"),
        "expected_verdict": expected,
        "actual_verdict": actual_verdict,
        "score": score,
        "trigger_count": len(triggers),
        "method": method,
        "passed": passed,
        "elapsed_ms": round(elapsed_ms, 2),
    }


# ---------------------------------------------------------------------------
# Results aggregation
# ---------------------------------------------------------------------------

def aggregate(outcomes: List[Dict]) -> Dict:
    """Aggregate outcomes by stage into the paper's table structure."""
    stages = {}

    for o in outcomes:
        stage = o["stage"]
        if stage not in stages:
            stages[stage] = {
                "total": 0,
                "blocked": 0,
                "quarantined": 0,
                "missed": 0,
                "false_positives": 0,
                "elapsed_ms": [],
            }
        s = stages[stage]
        s["total"] += 1
        s["elapsed_ms"].append(o["elapsed_ms"])

        v = o["actual_verdict"]
        is_benign = (stage == "BENIGN")

        if is_benign:
            if v == "BLOCK":
                s["false_positives"] += 1
            elif v == "QUARANTINE":
                s["false_positives"] += 1
        else:
            if v == "BLOCK":
                s["blocked"] += 1
            elif v == "QUARANTINE":
                s["quarantined"] += 1
            else:
                s["missed"] += 1

    # Compute derived metrics
    for stage, s in stages.items():
        is_benign = (stage == "BENIGN")
        total = s["total"]
        if is_benign:
            s["detection_rate"] = None
            s["fp_rate"] = round(s["false_positives"] / total, 4) if total else 0.0
        else:
            detected = s["blocked"] + s["quarantined"]
            s["detection_rate"] = round(detected / total, 4) if total else 0.0
            s["fp_rate"] = None

        elapsed = s["elapsed_ms"]
        s["median_ms"] = round(sorted(elapsed)[len(elapsed) // 2], 2) if elapsed else 0.0

    return stages


# ---------------------------------------------------------------------------
# Table printer
# ---------------------------------------------------------------------------

_COL = {
    "stage":    16,
    "total":     7,
    "blocked":   9,
    "quar":     13,
    "missed":    8,
    "rate":     16,
}

def _row(label: str, total: int, blocked, quarantined, missed, rate_str: str) -> str:
    return (
        f"{label:<{_COL['stage']}}| "
        f"{str(total):^{_COL['total']}}| "
        f"{str(blocked):^{_COL['blocked']}}| "
        f"{str(quarantined):^{_COL['quar']}}| "
        f"{str(missed):^{_COL['missed']}}| "
        f"{rate_str}"
    )


def print_table(stages: Dict, all_outcomes: List[Dict]) -> None:
    sep = "-" * 78

    header = _row(
        "Stage", "Total", "Blocked", "Quarantined", "Missed", "Detection Rate"
    )
    print()
    print("  GuardClaw Evaluation Results")
    print(sep)
    print(header)
    print(sep)

    stage_order = ["S1", "S2", "S3", "S4", "S5", "S6", "BENIGN"]

    for stage in stage_order:
        if stage not in stages:
            continue
        s = stages[stage]
        label = STAGE_LABELS.get(stage, stage)

        if stage == "BENIGN":
            fp_count = s["false_positives"]
            fp_rate = s["fp_rate"]
            print(_row(
                label,
                s["total"],
                f"{fp_count} (FP)",
                "--",
                "--",
                f"FP Rate: {fp_rate:.1%}",
            ))
        else:
            dr = s["detection_rate"]
            print(_row(
                label,
                s["total"],
                s["blocked"],
                s["quarantined"],
                s["missed"],
                f"{dr:.1%}",
            ))

    print(sep)

    # Overall attack stats (exclude BENIGN)
    attack_outcomes = [o for o in all_outcomes if o["stage"] != "BENIGN"]
    benign_outcomes = [o for o in all_outcomes if o["stage"] == "BENIGN"]

    total_attack = len(attack_outcomes)
    total_detected = sum(
        1 for o in attack_outcomes if o["actual_verdict"] in DETECTED_VERDICTS
    )
    overall_dr = total_detected / total_attack if total_attack else 0.0

    total_benign = len(benign_outcomes)
    total_fp = sum(1 for o in benign_outcomes if o["actual_verdict"] != "ALLOW")
    fp_rate = total_fp / total_benign if total_benign else 0.0

    all_elapsed = [o["elapsed_ms"] for o in all_outcomes]
    all_elapsed_sorted = sorted(all_elapsed)
    median_ms = all_elapsed_sorted[len(all_elapsed_sorted) // 2] if all_elapsed_sorted else 0.0

    print()
    print(f"  Overall detection rate  : {overall_dr:.1%}  "
          f"({total_detected}/{total_attack} attack scenarios)")
    print(f"  False positive rate     : {fp_rate:.1%}  "
          f"({total_fp}/{total_benign} benign scenarios flagged)")
    print(f"  Median processing time  : {median_ms:.1f} ms per scenario")
    print()


# ---------------------------------------------------------------------------
# Verbose per-scenario printer
# ---------------------------------------------------------------------------

_VERDICT_ICON = {"BLOCK": "✗", "QUARANTINE": "~", "ALLOW": "✓"}


def print_verbose(outcome: Dict) -> None:
    icon = _VERDICT_ICON.get(outcome["actual_verdict"], "?")
    passed_str = "PASS" if outcome["passed"] else "FAIL"
    score_str = (
        f"score={outcome['score']:.3f}" if isinstance(outcome["score"], float)
        else "score=n/a"
    )
    print(
        f"  [{passed_str}] {icon} {outcome['id']:<12} "
        f"{outcome['actual_verdict']:<10} "
        f"(expected={outcome['expected_verdict']:<10} "
        f"{score_str}  {outcome['elapsed_ms']:.1f}ms)"
    )


# ---------------------------------------------------------------------------
# Battery runner — one full pass over the scenario set
# ---------------------------------------------------------------------------

def run_battery(scenarios: List[Dict], verbose: bool = False) -> List[Dict]:
    """Run every scenario once and return the list of outcome dicts."""
    outcomes: List[Dict] = []
    current_stage = None
    for scenario in scenarios:
        stage = scenario.get("stage", "?")
        if verbose and stage != current_stage:
            current_stage = stage
            print(f"\n  ── {STAGE_LABELS.get(stage, stage).strip()} ──")
        outcome = run_scenario(scenario)
        outcomes.append(outcome)
        if verbose:
            print_verbose(outcome)
    return outcomes


def summarize_run(outcomes: List[Dict]) -> Dict:
    """
    Reduce one battery pass to the headline scalars the paper reports:
    overall detection rate, false-positive rate, per-stage detection rate,
    and median latency. Used as the per-trial unit for mean ± std reporting.
    """
    attack = [o for o in outcomes if o["stage"] != "BENIGN"]
    benign = [o for o in outcomes if o["stage"] == "BENIGN"]

    detected = sum(1 for o in attack if o["actual_verdict"] in DETECTED_VERDICTS)
    fp = sum(1 for o in benign if o["actual_verdict"] != "ALLOW")

    # BLOCK vs QUARANTINE split — this is where LLM non-determinism actually
    # shows up. Detection (block+quarantine) and FP are invariant to it because
    # a reshuffle within the detected set does not change the combined count,
    # and band content never reaches ALLOW (fail-safe floor). The split does move.
    blocked = sum(1 for o in attack if o["actual_verdict"] == "BLOCK")
    quarantined = sum(1 for o in attack if o["actual_verdict"] == "QUARANTINE")

    per_stage: Dict[str, float] = {}
    for stage in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        rows = [o for o in attack if o["stage"] == stage]
        if rows:
            hit = sum(1 for o in rows if o["actual_verdict"] in DETECTED_VERDICTS)
            per_stage[stage] = hit / len(rows)

    elapsed = sorted(o["elapsed_ms"] for o in outcomes)
    median_ms = elapsed[len(elapsed) // 2] if elapsed else 0.0

    n_attack = len(attack)
    return {
        "detection_rate": detected / n_attack if n_attack else 0.0,
        "fp_rate": fp / len(benign) if benign else 0.0,
        "block_rate": blocked / n_attack if n_attack else 0.0,
        "quarantine_rate": quarantined / n_attack if n_attack else 0.0,
        "per_stage": per_stage,
        "median_ms": median_ms,
        "n_attack": n_attack,
        "n_benign": len(benign),
    }


def _mean_std(values: List[float]) -> str:
    """Format a list of values as 'mean ± std' in percentage points."""
    if not values:
        return "n/a"
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return f"{mean:6.1%} ± {std:.1%}"


# ---------------------------------------------------------------------------
# Multi-trial reporting
# ---------------------------------------------------------------------------

def check_model_available(model: str) -> bool:
    """
    Probe an Ollama model with a trivial prompt. Returns True if it responds.

    Guards against a silent footgun: if a swept model is not pulled,
    sif.llm_fallback catches the error and fail-safe QUARANTINEs every
    band item, which would *inflate* the reported detection rate. We warn
    loudly instead so an unavailable model is never mistaken for a good one.
    """
    try:
        import ollama
        ollama.chat(model=model, messages=[{"role": "user", "content": "ping"}])
        return True
    except Exception as exc:  # noqa: BLE001 — any failure means "not usable"
        print(f"  [warn] fallback model '{model}' is not usable ({type(exc).__name__}). "
              f"Band scenarios will fail-safe to QUARANTINE, inflating its "
              f"apparent detection rate. Pull it first: `ollama pull {model}`.",
              file=sys.stderr)
        return False


def print_multitrial(model: str, summaries: List[Dict]) -> None:
    """Print mean ± std across trials for one fallback model."""
    n = len(summaries)
    sep = "-" * 78
    print()
    print(f"  Multi-trial results — model={model}, trials={n}")
    print(sep)
    print(f"  {'Stage':<16}| Detection rate (mean ± std across trials)")
    print(sep)
    for stage in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        vals = [s["per_stage"][stage] for s in summaries if stage in s["per_stage"]]
        if vals:
            print(f"  {STAGE_LABELS.get(stage, stage):<16}| {_mean_std(vals)}")
    print(sep)
    print(f"  {'Overall detect':<16}| {_mean_std([s['detection_rate'] for s in summaries])}")
    print(f"  {'False positive':<16}| {_mean_std([s['fp_rate'] for s in summaries])}")
    print(sep)
    print("  Split (where LLM non-determinism actually appears):")
    print(f"  {'  BLOCK rate':<16}| {_mean_std([s['block_rate'] for s in summaries])}")
    print(f"  {'  QUARANTINE':<16}| {_mean_std([s['quarantine_rate'] for s in summaries])}")
    print("  Detection = BLOCK+QUARANTINE is invariant to the split by construction;")
    print("  report the split's variance to satisfy the non-determinism concern.")
    med = statistics.mean([s["median_ms"] for s in summaries])
    print(f"  {'Median latency':<16}| {med:.1f} ms per scenario")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GuardClaw evaluation harness — runs scenarios against live components."
    )
    parser.add_argument(
        "--stage",
        metavar="STAGE",
        help="Run only one stage (S1–S6 or BENIGN)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each scenario result individually",
    )
    parser.add_argument(
        "--trials", "-n",
        type=int,
        default=1,
        metavar="N",
        help="Repeat the full battery N times and report mean ± std "
             "(addresses LLM non-determinism; default 1)",
    )
    parser.add_argument(
        "--models",
        metavar="M1,M2,...",
        help="Comma-separated Ollama models to sweep as the Layer 3 fallback "
             "(e.g. 'llama3:8b,mistral:7b,phi3:mini'). Default: the configured model.",
    )
    args = parser.parse_args()

    scenarios = load_scenarios(stage_filter=args.stage)
    if not scenarios:
        print("[error] No scenarios loaded.", file=sys.stderr)
        sys.exit(1)

    models = (
        [m.strip() for m in args.models.split(",") if m.strip()]
        if args.models else [sif.LLM_FALLBACK_MODEL]
    )

    print(f"\n  Running {len(scenarios)} scenario(s) × {args.trials} trial(s) "
          f"× {len(models)} model(s)"
          + (f" [stage={args.stage.upper()}]" if args.stage else "") + " …")

    # results_by_model[model] = list of per-trial summaries
    results_by_model: Dict[str, List[Dict]] = {}
    last_outcomes: List[Dict] = []

    # Preflight: warn about any unavailable model before spending time on it.
    if len(models) > 1 or args.trials > 1:
        for model in models:
            check_model_available(model)

    for model in models:
        sif.set_fallback_model(model)
        summaries: List[Dict] = []
        for trial in range(args.trials):
            verbose = args.verbose and args.trials == 1 and len(models) == 1
            if args.trials > 1 or len(models) > 1:
                print(f"\n  → model={model}  trial {trial + 1}/{args.trials}")
            outcomes = run_battery(scenarios, verbose=verbose)
            summaries.append(summarize_run(outcomes))
            last_outcomes = outcomes
        results_by_model[model] = summaries

    # For a single model + single trial keep the original detailed table;
    # otherwise print the multi-trial / multi-model summaries.
    if args.trials == 1 and len(models) == 1:
        stages = aggregate(last_outcomes)
        print_table(stages, last_outcomes)
    else:
        for model in models:
            print_multitrial(model, results_by_model[model])

    # Save full results
    results_payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stage_filter": args.stage.upper() if args.stage else None,
        "scenario_count": len(scenarios),
        "trials": args.trials,
        "models": models,
        "per_model_trials": results_by_model,
        "last_run_outcomes": last_outcomes,
    }

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, ensure_ascii=False)

    print(f"  Full results saved to: {RESULTS_FILE}\n")


if __name__ == "__main__":
    main()
