"""Corpus evaluation runner. Resumes from checkpoint automatically."""
import json, diskcache, sys
from pathlib import Path
from scanner.analyzer import analyze_tool, LABELING_MODEL
from scanner.extractor import load_corpus_profiles
from scanner.baseline import load_corpus
from scanner.metrics import save_checkpoint, load_checkpoint

CACHE_DIR = Path("cache/api_responses")
BATCH_SIZE = 25
MODEL = LABELING_MODEL  # haiku

profiles = load_corpus_profiles(Path("corpus/labels.json"))
entries = load_corpus()

cache = diskcache.Cache(str(CACHE_DIR))
results = load_checkpoint()
done_ids = {r["tool_id"] for r in results}
remaining = [p for p in profiles if p["tool_id"] not in done_ids]
print(f"RESUMING: {len(results)} done, {len(remaining)} remaining", flush=True)

errors = []
for i in range(0, len(remaining), BATCH_SIZE):
    batch = remaining[i:i+BATCH_SIZE]
    batch_results = []
    for profile in batch:
        entry = next((e for e in entries if e["tool_id"] == profile["tool_id"]), {})
        try:
            raw = analyze_tool(profile, model=MODEL, cache=cache)
            batch_results.append({
                "tool_id": profile["tool_id"],
                "tool_name": profile.get("tool_name"),
                "ground_truth": entry.get("ground_truth"),
                "attack_category": entry.get("attack_category"),
                "novel": entry.get("novel", False),
                "verdict": raw.get("verdict"),
                "confidence": raw.get("confidence"),
                "evidence": raw.get("evidence"),
                "reasoning": raw.get("reasoning"),
                "cache_hit": raw.get("cache_hit"),
            })
        except Exception as e:
            errors.append(profile["tool_id"])
            print(f"ERROR {profile['tool_id']}: {e}", flush=True)
    results.extend(batch_results)
    save_checkpoint(results)
    n_cached = sum(1 for r in batch_results if r.get("cache_hit"))
    print(f"BATCH {i//BATCH_SIZE+1}: {len(results)}/{len(profiles)} done  cached={n_cached}/{len(batch)}", flush=True)

print(f"DONE total={len(results)} errors={len(errors)}", flush=True)
if errors:
    print(f"ERRORS: {errors}", flush=True)
