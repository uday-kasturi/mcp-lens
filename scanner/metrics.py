"""
Evaluation metrics: detection rate, FPR, and baseline comparison table.
Read this file before interpreting any numbers.
"""

import json
from pathlib import Path
from typing import Any, Optional

CHECKPOINT_PATH = Path(__file__).parent.parent / "eval_results" / "checkpoint.json"


# ---------- Checkpoint I/O ----------

def load_checkpoint() -> list[dict[str, Any]]:
    if CHECKPOINT_PATH.exists():
        return json.loads(CHECKPOINT_PATH.read_text())
    return []


def save_checkpoint(results: list[dict[str, Any]]) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_PATH.write_text(json.dumps(results, indent=2))


# ---------- Core metrics ----------

def compute_metrics(
    semantic_results: list[dict[str, Any]],
    baseline_results: Optional[list] = None,
) -> dict[str, Any]:
    """
    semantic_results: list of dicts with keys:
        tool_id, ground_truth, attack_category, verdict, confidence
    baseline_results: optional parallel list from baseline.py
    """
    malicious = [r for r in semantic_results if r["ground_truth"] == "malicious"]
    legitimate = [r for r in semantic_results if r["ground_truth"] == "legitimate"]
    novel = [r for r in semantic_results if r.get("novel", False)]
    known_mal = [r for r in malicious if not r.get("novel", False)]

    def _flagged(r: dict[str, Any]) -> bool:
        return r.get("verdict") in ("MALICIOUS", "SUSPICIOUS")

    tp = sum(1 for r in malicious if _flagged(r))
    fn = len(malicious) - tp
    fp = sum(1 for r in legitimate if _flagged(r))
    tn = len(legitimate) - fp

    novel_tp = sum(1 for r in novel if _flagged(r))
    known_tp = sum(1 for r in known_mal if _flagged(r))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Per-category breakdown
    categories: dict[str, dict[str, int]] = {}
    for r in malicious:
        cat = r.get("attack_category") or "unknown"
        if cat not in categories:
            categories[cat] = {"detected": 0, "missed": 0}
        if _flagged(r):
            categories[cat]["detected"] += 1
        else:
            categories[cat]["missed"] += 1

    result = {
        "total": len(semantic_results),
        "malicious": len(malicious),
        "legitimate": len(legitimate),
        "novel_variants": len(novel),
        "known_malicious": len(known_mal),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_rate": round(tp / len(malicious), 4) if malicious else 0.0,
        "false_positive_rate": round(fp / len(legitimate), 4) if legitimate else 0.0,
        "novel_detection_rate": round(novel_tp / len(novel), 4) if novel else 0.0,
        "known_detection_rate": round(known_tp / len(known_mal), 4) if known_mal else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "per_category": categories,
    }

    if baseline_results:
        result["comparison"] = _comparison_table(semantic_results, baseline_results)

    return result


# ---------- Comparison table ----------

def _comparison_table(
    semantic: list[dict[str, Any]],
    baseline: list[dict[str, Any]],
) -> dict[str, Any]:
    """Returns per-category and aggregate comparison between semantic and baseline."""
    sem_by_id = {r["tool_id"]: r for r in semantic}
    base_by_id = {r["tool_id"]: r for r in baseline}

    # Aggregate
    cats: dict[str, dict[str, dict[str, int]]] = {}
    for tool_id, sem_r in sem_by_id.items():
        base_r = base_by_id.get(tool_id, {})
        gt = sem_r.get("ground_truth")
        cat = sem_r.get("attack_category") or "legitimate"

        if cat not in cats:
            cats[cat] = {"semantic": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}, "baseline": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}}

        sem_flagged = sem_r.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
        base_flagged = base_r.get("baseline_verdict") == "FLAGGED"

        for key, flagged in [("semantic", sem_flagged), ("baseline", base_flagged)]:
            if gt == "malicious":
                cats[cat][key]["tp" if flagged else "fn"] += 1
            else:
                cats[cat][key]["fp" if flagged else "tn"] += 1

    comparison: dict[str, Any] = {}
    for cat, data in cats.items():
        row: dict[str, Any] = {}
        for scanner in ("semantic", "baseline"):
            d = data[scanner]
            total_mal = d["tp"] + d["fn"]
            total_leg = d["fp"] + d["tn"]
            dr = d["tp"] / total_mal if total_mal else 0.0
            fpr = d["fp"] / total_leg if total_leg else 0.0
            row[scanner] = {**d, "detection_rate": round(dr, 3), "fpr": round(fpr, 3)}
        comparison[cat] = row

    return comparison


# ---------- Formatted output ----------

def print_metrics(metrics: dict[str, Any]) -> None:
    print("\n=== Semantic Scanner Results ===\n")
    print(f"Total:               {metrics['total']}")
    print(f"Malicious:           {metrics['malicious']} ({metrics['known_malicious']} known + {metrics['novel_variants']} novel)")
    print(f"Legitimate:          {metrics['legitimate']}")
    print(f"\nDetection rate:      {metrics['detection_rate']:.1%}  (TP={metrics['tp']}, FN={metrics['fn']})")
    print(f"  Known malicious:   {metrics['known_detection_rate']:.1%}")
    print(f"  Novel variants:    {metrics['novel_detection_rate']:.1%}")
    print(f"False positive rate: {metrics['false_positive_rate']:.1%}  (FP={metrics['fp']}, TN={metrics['tn']})")
    print(f"Precision:           {metrics['precision']:.1%}")
    print(f"Recall:              {metrics['recall']:.1%}")
    print(f"F1:                  {metrics['f1']:.3f}")

    print("\nPer-category detection:")
    for cat, counts in sorted(metrics["per_category"].items()):
        total = counts["detected"] + counts["missed"]
        rate = counts["detected"] / total if total else 0
        print(f"  {cat:<25} {counts['detected']}/{total} ({rate:.0%})")

    if "comparison" in metrics:
        print("\n=== Comparison Table (Semantic vs qsag-core Baseline) ===\n")
        header = f"{'Category':<26} {'Semantic DR':>11} {'Semantic FPR':>12} {'Baseline DR':>11} {'Baseline FPR':>12}"
        print(header)
        print("-" * len(header))
        for cat, row in sorted(metrics["comparison"].items()):
            sem = row["semantic"]
            base = row["baseline"]
            print(
                f"  {cat:<24} {sem['detection_rate']:>10.1%} {sem['fpr']:>11.1%}"
                f" {base['detection_rate']:>10.1%} {base['fpr']:>11.1%}"
            )
