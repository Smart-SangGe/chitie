#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TOKEN_RE = re.compile(r"[a-z0-9_./:+-]+")
SEVERITY_PREFIX_RE = re.compile(r"^\[(critical|high|medium|low|info)\]\s*")

STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "are",
    "was",
    "will",
    "all",
    "not",
    "into",
    "true",
    "false",
    "user",
    "users",
    "group",
    "groups",
    "linux",
    "information",
    "check",
    "checks",
}


def read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="ignore")


def normalize_line(line: str) -> str:
    line = ANSI_RE.sub("", line)
    line = line.strip().lower()
    line = SEVERITY_PREFIX_RE.sub("", line)
    line = re.sub(r"\s+", " ", line)

    if not line:
        return ""
    if set(line) <= set("-=*_~[](){}|:;.,'\"` "):
        return ""
    # Ignore very noisy banner/art lines.
    if len(re.findall(r"[a-z0-9]", line)) < 3:
        return ""

    line = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "<date>", line)
    line = re.sub(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b", "<time>", line)
    line = re.sub(r"\b(pid|uid|gid)=\d+\b", r"\1=<num>", line)
    line = re.sub(r"0x[0-9a-f]+", "<hex>", line)
    return line


def line_to_signal(line: str) -> str:
    tokens = []
    for token in TOKEN_RE.findall(line):
        if token.isdigit():
            continue
        if token in STOPWORDS:
            continue
        if len(token) < 3:
            continue
        if not re.search(r"[a-z]", token):
            continue
        tokens.append(token)

    if len(tokens) < 2:
        return ""
    return " ".join(sorted(set(tokens)))


def extract_signals(text: str) -> tuple[set[str], list[str]]:
    normalized_lines = []
    signals = set()

    for raw in text.splitlines():
        normalized = normalize_line(raw)
        if not normalized:
            continue
        normalized_lines.append(normalized)
        signal = line_to_signal(normalized)
        if signal:
            signals.add(signal)

    return signals, normalized_lines


def compute_metrics(chitie_signals: set[str], linpeas_signals: set[str]) -> dict:
    shared = chitie_signals & linpeas_signals
    only_chitie = chitie_signals - linpeas_signals
    only_linpeas = linpeas_signals - chitie_signals

    tp = len(shared)
    fp = len(only_chitie)
    fn = len(only_linpeas)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "sample_tp": sorted(list(shared))[:10],
        "sample_fp": sorted(list(only_chitie))[:10],
        "sample_fn": sorted(list(only_linpeas))[:10],
    }


def missing_required_patterns(required_patterns: list[str], chitie_lines: list[str], linpeas_lines: list[str]) -> list[str]:
    missing = []
    for pattern in required_patterns:
        p = pattern.strip().lower()
        if not p:
            continue
        expected = any(p in line for line in linpeas_lines)
        present = any(p in line for line in chitie_lines)
        if expected and not present:
            missing.append(p)
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare chitie output parity against linpeas output.")
    parser.add_argument("--chitie", required=True, type=Path)
    parser.add_argument("--linpeas", required=True, type=Path)
    parser.add_argument("--min-precision", type=float, default=0.95)
    parser.add_argument("--min-recall", type=float, default=0.98)
    parser.add_argument("--required-patterns", default="")
    parser.add_argument("--report-json", type=Path)
    args = parser.parse_args()

    chitie_text = read_text(args.chitie)
    linpeas_text = read_text(args.linpeas)
    chitie_signals, chitie_lines = extract_signals(chitie_text)
    linpeas_signals, linpeas_lines = extract_signals(linpeas_text)

    metrics = compute_metrics(chitie_signals, linpeas_signals)
    required_patterns = [p.strip() for p in args.required_patterns.split(",") if p.strip()]
    missing_patterns = missing_required_patterns(required_patterns, chitie_lines, linpeas_lines)

    result = {
        "chitie_file": str(args.chitie),
        "linpeas_file": str(args.linpeas),
        "signals": {
            "chitie": len(chitie_signals),
            "linpeas": len(linpeas_signals),
        },
        "metrics": metrics,
        "thresholds": {
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
        },
        "required_patterns": required_patterns,
        "missing_required_patterns": missing_patterns,
    }

    if args.report_json:
        args.report_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} "
        f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f}"
    )
    if missing_patterns:
        print(f"Missing required patterns: {', '.join(missing_patterns)}")

    passed = (
        metrics["precision"] >= args.min_precision
        and metrics["recall"] >= args.min_recall
        and not missing_patterns
    )
    print("Result: PASS" if passed else "Result: FAIL")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
