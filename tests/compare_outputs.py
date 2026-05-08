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

NOISE_TOKENS = {
    "available",
    "check",
    "checks",
    "common",
    "detected",
    "details",
    "done",
    "enumeration",
    "escalation",
    "file",
    "files",
    "found",
    "high",
    "info",
    "interesting",
    "linpeas",
    "medium",
    "mode",
    "not",
    "output",
    "potential",
    "present",
    "root",
    "run",
    "searching",
    "system",
    "warning",
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
    shared, only_chitie, only_linpeas = match_signals(chitie_signals, linpeas_signals)

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


def signal_tokens(signal: str) -> set[str]:
    return {token for token in signal.split() if token not in NOISE_TOKENS}


def has_anchor(tokens: set[str]) -> bool:
    return any(
        token.startswith("/")
        or token.startswith("cve-")
        or token.startswith("cap_")
        or token.endswith(".service")
        or token.endswith(".timer")
        or token in {"suid", "sgid", "sudo", "passwd", "shadow", "cron"}
        for token in tokens
    )


def fuzzy_score(chitie_signal: str, linpeas_signal: str) -> float:
    chitie_tokens = signal_tokens(chitie_signal)
    linpeas_tokens = signal_tokens(linpeas_signal)
    if len(chitie_tokens) < 2 or len(linpeas_tokens) < 2:
        return 0.0

    intersection = chitie_tokens & linpeas_tokens
    if len(intersection) < 2:
        return 0.0

    shared_paths = {token for token in intersection if token.startswith("/")}
    if shared_paths:
        return 2.0 + (len(intersection) / max(len(chitie_tokens), len(linpeas_tokens)))

    smaller = min(len(chitie_tokens), len(linpeas_tokens))
    larger = max(len(chitie_tokens), len(linpeas_tokens))
    containment = len(intersection) / smaller
    coverage = len(intersection) / larger

    # Path/CVE/capability anchored lines often differ only by explanatory text.
    if has_anchor(chitie_tokens | linpeas_tokens):
        if containment >= 0.60 and coverage >= 0.24:
            return containment + coverage
        return 0.0

    # Non-anchored lines need a stronger overlap to avoid accidental matches.
    if len(intersection) >= 3 and containment >= 0.65 and coverage >= 0.32:
        return containment + coverage
    return 0.0


def match_signals(chitie_signals: set[str], linpeas_signals: set[str]) -> tuple[set[str], set[str], set[str]]:
    exact_shared = chitie_signals & linpeas_signals
    unmatched_chitie = set(chitie_signals - exact_shared)
    unmatched_linpeas = set(linpeas_signals - exact_shared)
    fuzzy_shared = set(exact_shared)

    candidates = []
    for linpeas_signal in unmatched_linpeas:
        for chitie_signal in unmatched_chitie:
            score = fuzzy_score(chitie_signal, linpeas_signal)
            if score:
                candidates.append((score, chitie_signal, linpeas_signal))

    used_chitie = set()
    used_linpeas = set()
    for _, chitie_signal, linpeas_signal in sorted(candidates, reverse=True):
        if chitie_signal in used_chitie or linpeas_signal in used_linpeas:
            continue
        used_chitie.add(chitie_signal)
        used_linpeas.add(linpeas_signal)
        fuzzy_shared.add(linpeas_signal)

    only_chitie = unmatched_chitie - used_chitie
    only_linpeas = unmatched_linpeas - used_linpeas
    return fuzzy_shared, only_chitie, only_linpeas


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
