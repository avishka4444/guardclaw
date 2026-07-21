import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

"""
eval_battery/ablation.py
GuardClaw sensitivity ablation for the two sets of hand-tuned constants the
companion paper describes as "engineering judgment":

  1. SIF decision thresholds   (QUARANTINE=0.25, BLOCK=0.75 in Algorithm 1)
  2. CATS trust weight vector  (0.3 / 0.4 / 0.2 / 0.1 in Equation 1)

Reviewer note this answers: the paper claimed these values were "validated
through the controlled evaluation" but ran no ablation isolating whether the
*specific* values matter. This script sweeps each set and reports how the
detection rate, false-positive rate, and per-archetype quarantine decisions
move — turning an assertion into a measured finding.

The SIF sweep pins the Layer 3 LLM to a deterministic fail-safe stub so the
threshold geometry is isolated from LLM non-determinism (and no Ollama is
required). Run run_tests.py --trials N for the LLM-in-the-loop numbers.

Usage:
    python eval_battery/ablation.py            # both ablations
    python eval_battery/ablation.py --sif       # SIF thresholds only
    python eval_battery/ablation.py --cats      # CATS weights only
"""

import argparse
import json
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

_EVAL_DIR = Path(__file__).parent
_REPO_ROOT = _EVAL_DIR.parent
sys.path.insert(0, str(_REPO_ROOT))

import sif
import cats
from run_tests import load_scenarios, DETECTED_VERDICTS

DEFAULT_QUARANTINE = 0.25
DEFAULT_BLOCK = 0.75
DEFAULT_WEIGHTS = (0.3, 0.4, 0.2, 0.1)  # (alpha, phi, delta, epsilon)


# ===========================================================================
# Part 1 — SIF threshold sweep
# ===========================================================================

def _deterministic_fallback(content: str) -> Dict:
    """
    Stand-in for the Layer 3 LLM: always returns the fail-safe QUARANTINE
    verdict (exactly what sif.llm_fallback yields when Ollama is unreachable).
    Holding the LLM decision constant isolates the effect of the thresholds.
    """
    return {"verdict": "QUARANTINE", "reason": "ablation stub (deterministic)"}


def _score_only(content: str, cats_risk: float) -> float:
    """Recompute SIF's raw score without a verdict (mirrors sif.screen_content)."""
    import re
    triggers = [p for p in sif.PATTERNS if re.search(p, content, re.IGNORECASE)]
    return round(len(triggers) * 0.25 + cats_risk * 0.3, 3)


def sweep_sif_thresholds(scenarios: List[Dict]) -> None:
    """Grid-sweep (quarantine, block) thresholds; report detection & FP rate."""
    # Precompute the raw score for every scenario once — scores don't depend
    # on the thresholds, so we can re-derive verdicts for each grid point
    # without re-running regex 30×/grid-cell.
    scored: List[Tuple[str, str, float]] = []  # (stage, expected, score)
    for s in scenarios:
        if s.get("source") == "heartbeat":
            continue  # HBS path has no SIF thresholds
        risk = 0.5  # unknown agent → neutral risk, as in the live battery
        scored.append((s.get("stage", "?"), s["expected_verdict"],
                       _score_only(s["content"], risk)))

    attack = [x for x in scored if x[0] != "BENIGN"]
    benign = [x for x in scored if x[0] == "BENIGN"]

    def verdict(score: float, q: float, b: float) -> str:
        if score >= b:
            return "BLOCK"
        if score >= q:
            return "QUARANTINE"  # deterministic stub keeps it quarantined
        return "ALLOW"

    quarantine_grid = [0.15, 0.20, 0.25, 0.30, 0.40, 0.50]
    block_grid = [0.60, 0.75, 0.90]

    print("\n  SIF THRESHOLD ABLATION")
    print("  (deterministic LLM stub — isolates threshold geometry)")
    print("  " + "-" * 72)
    print(f"  {'quarantine':>11} {'block':>7} {'detection':>11} {'false_pos':>11}"
          f"   {'note':<20}")
    print("  " + "-" * 72)

    for b in block_grid:
        for q in quarantine_grid:
            if q >= b:
                continue
            det = sum(1 for _, _, sc in attack
                      if verdict(sc, q, b) in DETECTED_VERDICTS)
            fp = sum(1 for _, _, sc in benign if verdict(sc, q, b) != "ALLOW")
            det_rate = det / len(attack) if attack else 0.0
            fp_rate = fp / len(benign) if benign else 0.0
            note = ""
            if abs(q - DEFAULT_QUARANTINE) < 1e-9 and abs(b - DEFAULT_BLOCK) < 1e-9:
                note = "← paper default"
            print(f"  {q:>11.2f} {b:>7.2f} {det_rate:>10.1%} {fp_rate:>11.1%}"
                  f"   {note:<20}")
    print("  " + "-" * 72)
    print("  Reading: the quarantine threshold trades detection against false")
    print("  positives; the block threshold barely moves either on this battery")
    print("  because few scenarios score >= 0.60. This is the sensitivity the")
    print("  paper should report rather than asserting the values were validated.\n")


# ===========================================================================
# Part 2 — CATS weight sensitivity
# ===========================================================================

# Archetypes expressed directly as normalised signals (alpha, phi, delta, eps).
# alpha=account-age, phi=clean-post-ratio, delta=cascade-depth, eps=embedding-drift
_ARCHETYPES: Dict[str, Tuple[float, float, float, float]] = {
    "veteran_clean":     (1.00, 1.00, 0.00, 0.00),  # should stay trusted
    "new_sybil":         (0.03, 1.00, 0.00, 0.00),  # young → age term should gate
    "reputation_launder": (1.00, 1.00, 0.00, 0.70),  # S6: only eps betrays it
    "cascade_amplified": (1.00, 0.90, 0.90, 0.20),  # deep reshare chain
    "flagged_spammer":   (1.00, 0.20, 0.50, 0.30),  # phi should sink it
}


def _seed_archetypes(db_path: str) -> None:
    """Insert one row per archetype into a fresh temp DB with backdated age."""
    conn = sqlite3.connect(db_path)
    conn.execute(cats._CREATE_TABLE)
    now = time.time()
    for name, (alpha, phi, delta, eps) in _ARCHETYPES.items():
        created_at = now - alpha * 30 * 86400          # invert alpha → age
        total, flagged = 100, round((1.0 - phi) * 100)  # invert phi → flags
        conn.execute(
            """INSERT OR REPLACE INTO agents
               (agent_id, created_at, total_posts, flagged_posts,
                cascade_depth_norm, embedding_drift_norm,
                embedding_centroid, quarantine_until, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)""",
            (name, created_at, total, flagged, delta, eps, ""),
        )
    conn.commit()
    conn.close()


def sweep_cats_weights(default_thresh: float = 0.3) -> None:
    """Recompute τ per archetype under the default vs. perturbed weight vectors."""
    tmp = tempfile.mkdtemp(prefix="guardclaw_ablation_")
    db_path = str(Path(tmp) / "cats_ablation.db")
    cats.DB_PATH = db_path            # redirect all cats DB access to temp
    _seed_archetypes(db_path)

    # The vectors to compare: paper default + one "lesion" per term (weight
    # zeroed, redistributed to phi) + a uniform baseline.
    variants: Dict[str, Tuple[float, float, float, float]] = {
        "paper default (.3/.4/.2/.1)": DEFAULT_WEIGHTS,
        "no age term  (0/.7/.2/.1)":   (0.0, 0.7, 0.2, 0.1),
        "no phi term  (.3/0/.4/.3)":   (0.3, 0.0, 0.4, 0.3),
        "no drift term(.35/.45/.2/0)": (0.35, 0.45, 0.20, 0.0),
        "uniform      (.25×4)":        (0.25, 0.25, 0.25, 0.25),
    }

    print("\n  CATS WEIGHT ABLATION")
    print(f"  τ per archetype; values < {default_thresh} → QUARANTINE (marked *)")
    print("  " + "-" * 78)
    header = f"  {'weight vector':<30}" + "".join(
        f"{name[:11]:>13}" for name in _ARCHETYPES
    )
    print(header)
    print("  " + "-" * 78)

    # tau_by_variant[label][archetype] = tau
    tau_by_variant: Dict[str, Dict[str, float]] = {}
    for label, (wa, wp, wd, we) in variants.items():
        cats.set_weights(wa, wp, wd, we)
        row = {name: cats.get_trust_score(name) for name in _ARCHETYPES}
        tau_by_variant[label] = row
        cells = "".join(
            f"{row[name]:>11.2f}{'*' if row[name] < default_thresh else ' '}"
            for name in _ARCHETYPES
        )
        print(f"  {label:<30}{cells}")

    cats.set_weights(*DEFAULT_WEIGHTS)  # restore

    # --- Data-derived reading (no hand-written claims) ---------------------
    default_label = "paper default (.3/.4/.2/.1)"
    default_row = tau_by_variant[default_label]
    quarantined = [n for n, t in default_row.items() if t < default_thresh]

    # Largest τ swing each lesion causes vs. the default, per archetype.
    swings: List[Tuple[str, str, float]] = []
    for label, row in tau_by_variant.items():
        if label == default_label:
            continue
        for name in _ARCHETYPES:
            swings.append((label, name, row[name] - default_row[name]))
    swings.sort(key=lambda x: abs(x[2]), reverse=True)

    print("  " + "-" * 78)
    print("  Reading (derived from the table above):")
    if quarantined:
        print(f"   • Under the paper's default weights, {len(quarantined)} archetype(s) "
              f"cross the {default_thresh} quarantine line: {', '.join(quarantined)}.")
    else:
        print(f"   • Under the paper's default weights, NO archetype crosses the "
              f"{default_thresh} quarantine line — not even 'reputation_launder' "
              f"(τ={default_row['reputation_launder']:.2f}) or 'flagged_spammer' "
              f"(τ={default_row['flagged_spammer']:.2f}).")
        print("     This is consistent with — and helps explain — the paper's 10%")
        print("     S6 detection rate: at weight 0.1 the drift (ε) term cannot pull")
        print("     a clean-looking launderer below the threshold on its own.")
    top = swings[0]
    print(f"   • Weights are not inert: the largest single-lesion swing is "
          f"{top[2]:+.2f} τ")
    print(f"     ('{top[0]}' on '{top[1]}'), so the choice of vector does move τ —")
    print("     the open question the paper should state is whether 0.3 is the right")
    print("     quarantine line for these weights, not whether the weights matter.\n")


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="GuardClaw constant-sensitivity ablation.")
    parser.add_argument("--sif", action="store_true", help="Run only the SIF threshold sweep")
    parser.add_argument("--cats", action="store_true", help="Run only the CATS weight sweep")
    args = parser.parse_args()

    run_sif = args.sif or not args.cats
    run_cats = args.cats or not args.sif

    if run_sif:
        # Pin the LLM to the deterministic stub for a reproducible sweep.
        sif.llm_fallback = _deterministic_fallback
        scenarios = load_scenarios()
        sweep_sif_thresholds(scenarios)

    if run_cats:
        sweep_cats_weights()


if __name__ == "__main__":
    main()
