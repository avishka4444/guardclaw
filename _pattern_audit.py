"""Audit which S1 scenarios score 0.150 (zero regex matches) and why."""
import sys, io, json, re, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sif import PATTERNS

TARGET_IDS = {"s1_013","s1_014","s1_016","s1_017","s1_022","s1_023",
              "s1_027","s1_028","s1_029","s1_030"}

path = os.path.join(os.path.dirname(__file__),
                    "eval_battery", "scenarios", "s1_initial_access.json")
with open(path, encoding="utf-8") as f:
    scenarios = json.load(f)

for s in scenarios:
    if s["id"] not in TARGET_IDS:
        continue
    content = s["content"]
    hits = [p for p in PATTERNS if re.search(p, content, re.IGNORECASE)]
    print(f"\n{'='*60}")
    print(f"{s['id']} ({s['attack_class']})")
    print(f"  Content: {content[:120]!r}")
    print(f"  Hits   : {len(hits)} pattern(s)")
    for h in hits:
        print(f"    - {h[:80]}")
