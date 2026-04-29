"""
mcp-scan CLI entry point.

Usage:
  mcp-scan --server ./path/to/server.json
  mcp-scan --server ./server.py
  mcp-scan --corpus ./corpus/ --eval --model sonnet
  mcp-scan --compare-baseline
"""

import argparse
import json
import os
import sys
from pathlib import Path

import diskcache
from rich.console import Console
from rich.table import Table
from rich import box

from scanner.analyzer import LABELING_MODEL, EVAL_MODEL, analyze_server, analyze_tool
from scanner.baseline import load_corpus, run_baseline, compute_metrics as baseline_metrics
from scanner.extractor import from_json_manifest, from_python_source, load_corpus_profiles
from scanner.metrics import (
    compute_metrics as sem_metrics,
    print_metrics,
    save_checkpoint,
    load_checkpoint,
    CHECKPOINT_PATH,
)

console = Console()

CACHE_DIR = Path(__file__).parent / "cache" / "api_responses"
BATCH_SIZE = 25


def _model_for(name: str) -> str:
    if name == "sonnet":
        return EVAL_MODEL
    if name == "haiku":
        return LABELING_MODEL
    # Allow full model ID passthrough
    return name


def cmd_scan_server(args: argparse.Namespace) -> None:
    path = Path(args.server)
    if not path.exists():
        console.print(f"[red]Error:[/red] {path} does not exist.")
        sys.exit(1)

    console.print(f"\n[bold]Scanning:[/bold] {path}")

    if path.suffix == ".py":
        profiles = from_python_source(path)
    else:
        profiles = from_json_manifest(path)

    if not profiles:
        console.print("[yellow]No tools found in server definition.[/yellow]")
        return

    model = _model_for(args.model)
    cache = diskcache.Cache(str(CACHE_DIR))

    console.print(f"  Tools found: {len(profiles)}")
    console.print(f"  Model: {model}\n")

    result = analyze_server(profiles, model=model, cache=cache)
    _print_server_result(result)

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
        console.print(f"\n[dim]Saved to {args.output}[/dim]")


def _print_server_result(result: dict) -> None:
    verdict = result["server_verdict"]
    color = {"HIGH_RISK": "red", "MEDIUM_RISK": "yellow", "LOW_RISK": "green"}.get(verdict, "white")

    console.print(f"[bold {color}]Server verdict: {verdict}[/bold {color}]")
    console.print(f"Risk score:     {result['risk_score']:.2f}")
    console.print(f"Flagged tools:  {result['flagged_count']} / {result['total_tools']}\n")

    if result["flagged_tools"]:
        table = Table(title="Flagged Tools", box=box.SIMPLE)
        table.add_column("Tool", style="cyan")
        table.add_column("Verdict", style="bold")
        table.add_column("Confidence")
        table.add_column("Category")
        table.add_column("Evidence")

        for t in result["flagged_tools"]:
            vcolor = "red" if t.get("verdict") == "MALICIOUS" else "yellow"
            table.add_row(
                t.get("tool_name", ""),
                f"[{vcolor}]{t.get('verdict', '')}[/{vcolor}]",
                t.get("confidence", ""),
                t.get("attack_category") or "",
                (t.get("evidence") or "")[:80],
            )
        console.print(table)
    else:
        console.print("[green]No tools flagged.[/green]")


def cmd_eval_corpus(args: argparse.Namespace) -> None:
    model = _model_for(args.model)
    cache = diskcache.Cache(str(CACHE_DIR))

    corpus_path = Path(args.corpus) / "labels.json" if Path(args.corpus).is_dir() else Path(args.corpus)
    profiles = load_corpus_profiles(corpus_path)
    entries = load_corpus()

    console.print(f"\n[bold]Corpus evaluation[/bold]")
    console.print(f"  Corpus:  {corpus_path} ({len(profiles)} tools)")
    console.print(f"  Model:   {model}")
    console.print(f"  Batch:   {BATCH_SIZE}\n")

    results = load_checkpoint()
    done_ids = {r["tool_id"] for r in results}
    remaining = [p for p in profiles if p["tool_id"] not in done_ids]

    if not remaining:
        console.print("[yellow]Checkpoint complete — all tools already evaluated.[/yellow]")
    else:
        for i in range(0, len(remaining), BATCH_SIZE):
            batch = remaining[i:i + BATCH_SIZE]
            batch_results = []
            for profile in batch:
                entry = next((e for e in entries if e["tool_id"] == profile["tool_id"]), {})
                raw = analyze_tool(profile, model=model, cache=cache)
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
            results.extend(batch_results)
            save_checkpoint(results)
            n_done = len(results)
            n_total = len(profiles)
            console.print(f"  Batch {i // BATCH_SIZE + 1} done — {n_done}/{n_total} tools evaluated")

    if args.compare_baseline:
        base_results = run_baseline(entries)
        metrics = sem_metrics(results, base_results)
    else:
        metrics = sem_metrics(results)

    print_metrics(metrics)

    if args.output:
        Path(args.output).write_text(json.dumps({"metrics": metrics, "results": results}, indent=2))
        console.print(f"\n[dim]Saved to {args.output}[/dim]")


def cmd_compare_baseline(args: argparse.Namespace) -> None:
    entries = load_corpus()
    results = run_baseline(entries)
    metrics = baseline_metrics(results)

    console.print("\n[bold]qsag-core Baseline Results[/bold]\n")
    _print_baseline_table(metrics)


def _print_baseline_table(metrics: dict) -> None:
    console.print(f"Detection rate:      [bold]{metrics['detection_rate']:.1%}[/bold]  (TP={metrics['tp']}, FN={metrics['fn']})")
    console.print(f"  Known malicious:   {metrics['known_detection_rate']:.1%}")
    console.print(f"  Novel variants:    [red]{metrics['novel_detection_rate']:.1%}[/red]  <-- the gap")
    console.print(f"False positive rate: {metrics['false_positive_rate']:.1%}  (FP={metrics['fp']}, TN={metrics['tn']})\n")

    table = Table(title="Per-Category Detection", box=box.SIMPLE)
    table.add_column("Category", style="cyan")
    table.add_column("Detected", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Rate", justify="right")

    for cat, counts in sorted(metrics["per_category"].items()):
        total = counts["flagged"] + counts["missed"]
        rate = counts["flagged"] / total if total else 0
        table.add_row(cat, str(counts["flagged"]), str(total), f"{rate:.0%}")
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Semantic MCP tool poisoning detector",
    )
    subparsers = parser.add_subparsers(dest="command")

    # mcp-scan server <path>
    p_server = subparsers.add_parser("server", help="Scan a single MCP server definition")
    p_server.add_argument("--server", required=True, help="Path to server JSON or Python file")
    p_server.add_argument("--model", default="haiku", help="Model to use (haiku|sonnet|<model-id>)")
    p_server.add_argument("--output", help="Save JSON report to file")

    # mcp-scan eval
    p_eval = subparsers.add_parser("eval", help="Run evaluation against corpus")
    p_eval.add_argument("--corpus", default="./corpus", help="Path to corpus directory or labels.json")
    p_eval.add_argument("--model", default="haiku", help="Model to use (haiku|sonnet)")
    p_eval.add_argument("--compare-baseline", action="store_true", help="Include qsag-core comparison")
    p_eval.add_argument("--output", help="Save results JSON to file")

    # mcp-scan baseline
    p_base = subparsers.add_parser("baseline", help="Run qsag-core baseline only (no API calls)")

    # Legacy flat arg support: mcp-scan --server <path>
    parser.add_argument("--server", help=argparse.SUPPRESS)
    parser.add_argument("--corpus", help=argparse.SUPPRESS)
    parser.add_argument("--eval", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--compare-baseline", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--model", default="haiku", help=argparse.SUPPRESS)
    parser.add_argument("--output", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Route subcommands
    if args.command == "server":
        cmd_scan_server(args)
    elif args.command == "eval":
        cmd_eval_corpus(args)
    elif args.command == "baseline":
        cmd_compare_baseline(args)
    # Legacy flat-arg routing
    elif args.server:
        cmd_scan_server(args)
    elif args.eval or args.corpus:
        cmd_eval_corpus(args)
    elif args.compare_baseline:
        cmd_compare_baseline(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
