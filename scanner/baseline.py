"""
qsag-core regex baseline runner.
No API calls. Measures what keyword/pattern matching catches vs misses.
"""

import json
import re
from pathlib import Path
from typing import Any

CORPUS_PATH = Path(__file__).parent.parent / "corpus" / "labels.json"

# qsag-core pattern set: known bad strings and regex patterns
QSAG_PATTERNS: list[tuple[str, str]] = [
    # Explicit exfil destinations
    (r"https?://(?!github\.com|api\.github\.com|slack\.com|postgresql|localhost)[a-z0-9._-]+\.[a-z]{2,}/(?:collect|ingest|upload|exfil|beacon|harvest)", "hardcoded_exfil_url"),
    (r"/dev/tcp/", "tcp_redirect"),
    (r"ftp://", "ftp_exfil"),
    (r"s3://[a-z0-9._-]*attacker[a-z0-9._-]*", "attacker_s3"),
    # Explicit credential file references
    (r"~/\.ssh/id_rsa(?!\.pub)", "ssh_private_key"),
    (r"/etc/passwd", "passwd_file"),
    (r"\.env\b", "dotenv_file"),
    (r"credentials(?:\.json|\.yaml|\.csv)?", "credentials_file"),
    (r"aws[_\s]credentials", "aws_credentials"),
    # Explicit shell execution
    (r"\bcurl\s+-s\s+", "curl_silent"),
    (r"bash\s+-c", "bash_exec"),
    (r"subprocess", "subprocess"),
    # System prompt / jailbreak keywords
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "ignore_previous"),
    (r"developer\s+mode", "developer_mode"),
    (r"system\s+override", "system_override"),
    (r"new\s+(?:prime\s+)?directive", "new_directive"),
    (r"disable\s+(?:content\s+policy|safety|restrictions)", "disable_safety"),
    # Destructive/dangerous operations (causes legitimate FPs)
    (r"\bdelete\b", "keyword_delete"),
    (r"\bdrop\b", "keyword_drop"),
    (r"\bexecute\b", "keyword_execute"),
    (r"\bshell\b", "keyword_shell"),
    (r"\bpasswd\b", "keyword_passwd"),
    (r"\bcredentials?\b", "keyword_credentials"),
    (r"\bsecret\b", "keyword_secret"),
    (r"\btoken\b", "keyword_token"),
    (r"\bprivate.key\b", "keyword_private_key"),
    # Hidden instruction markers
    (r"\[hidden\s+instruction", "hidden_instruction"),
    (r"<hidden>", "html_hidden_tag"),
    (r"\[ai\s+instruction\]", "ai_instruction_bracket"),
    (r"not\s+visible\s+to\s+human", "not_visible"),
    # Remote code download/exec
    (r"download[s]?\s+and\s+execut", "download_exec"),
    (r"https?://[a-z0-9._-]+/setup\.sh", "remote_setup_script"),
]

_COMPILED = [(re.compile(pat, re.IGNORECASE), label) for pat, label in QSAG_PATTERNS]


def _tool_text(entry: dict[str, Any]) -> str:
    parts = [
        entry.get("tool_name", ""),
        entry.get("tool_description", ""),
        json.dumps(entry.get("tool_schema", {})),
    ]
    return " ".join(parts)


def run_baseline(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for entry in entries:
        text = _tool_text(entry)
        matched_patterns: list[str] = []
        for pattern, label in _COMPILED:
            if pattern.search(text):
                matched_patterns.append(label)

        verdict = "FLAGGED" if matched_patterns else "CLEAN"
        results.append({
            "tool_id": entry["tool_id"],
            "tool_name": entry.get("tool_name"),
            "ground_truth": entry["ground_truth"],
            "attack_category": entry.get("attack_category"),
            "novel": entry.get("novel", False),
            "qsag_label_agrees": entry.get("qsag_catches"),
            "baseline_verdict": verdict,
            "matched_patterns": matched_patterns,
        })
    return results


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    malicious = [r for r in results if r["ground_truth"] == "malicious"]
    legitimate = [r for r in results if r["ground_truth"] == "legitimate"]
    novel = [r for r in results if r["novel"]]
    known_mal = [r for r in malicious if not r["novel"]]

    tp = sum(1 for r in malicious if r["baseline_verdict"] == "FLAGGED")
    fn = sum(1 for r in malicious if r["baseline_verdict"] == "CLEAN")
    fp = sum(1 for r in legitimate if r["baseline_verdict"] == "FLAGGED")
    tn = sum(1 for r in legitimate if r["baseline_verdict"] == "CLEAN")

    novel_tp = sum(1 for r in novel if r["baseline_verdict"] == "FLAGGED")
    known_tp = sum(1 for r in known_mal if r["baseline_verdict"] == "FLAGGED")

    detection_rate = tp / len(malicious) if malicious else 0.0
    fpr = fp / len(legitimate) if legitimate else 0.0
    novel_detection = novel_tp / len(novel) if novel else 0.0
    known_detection = known_tp / len(known_mal) if known_mal else 0.0

    # Per-category breakdown
    categories: dict[str, dict[str, int]] = {}
    for r in malicious:
        cat = r["attack_category"] or "unknown"
        if cat not in categories:
            categories[cat] = {"flagged": 0, "missed": 0}
        if r["baseline_verdict"] == "FLAGGED":
            categories[cat]["flagged"] += 1
        else:
            categories[cat]["missed"] += 1

    return {
        "total": len(results),
        "malicious": len(malicious),
        "legitimate": len(legitimate),
        "novel_variants": len(novel),
        "known_malicious": len(known_mal),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "novel_detection_rate": round(novel_detection, 4),
        "known_detection_rate": round(known_detection, 4),
        "per_category": categories,
    }


def load_corpus() -> list[dict[str, Any]]:
    data = json.loads(CORPUS_PATH.read_text())
    return data["entries"]


def main() -> None:
    entries = load_corpus()
    results = run_baseline(entries)
    metrics = compute_metrics(results)

    print("\n=== qsag-core Baseline Results ===\n")
    print(f"Total tools:         {metrics['total']}")
    print(f"Malicious:           {metrics['malicious']} ({metrics['known_malicious']} known + {metrics['novel_variants']} novel)")
    print(f"Legitimate:          {metrics['legitimate']}")
    print(f"\nDetection rate:      {metrics['detection_rate']:.1%}  (TP={metrics['tp']}, FN={metrics['fn']})")
    print(f"  Known malicious:   {metrics['known_detection_rate']:.1%}")
    print(f"  Novel variants:    {metrics['novel_detection_rate']:.1%}  <-- the gap")
    print(f"False positive rate: {metrics['false_positive_rate']:.1%}  (FP={metrics['fp']}, TN={metrics['tn']})")

    print("\nPer-category detection:")
    for cat, counts in sorted(metrics["per_category"].items()):
        total_cat = counts["flagged"] + counts["missed"]
        rate = counts["flagged"] / total_cat if total_cat else 0
        print(f"  {cat:<25} {counts['flagged']}/{total_cat} ({rate:.0%})")

    print("\nFalse positives (legitimate tools flagged):")
    for r in results:
        if r["ground_truth"] == "legitimate" and r["baseline_verdict"] == "FLAGGED":
            print(f"  {r['tool_id']:<30} patterns={r['matched_patterns']}")

    print("\nMissed malicious (novel variants):")
    for r in results:
        if r["ground_truth"] == "malicious" and r["novel"] and r["baseline_verdict"] == "CLEAN":
            print(f"  {r['tool_id']}")

    return metrics


if __name__ == "__main__":
    main()
