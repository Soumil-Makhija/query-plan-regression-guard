"""Command-line capture, comparison, and request-trace analysis."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from .analysis import analyze_snapshot, analyze_trace
from .report import to_markdown


class _DatabaseFailure(Exception):
    """The cause is intentionally withheld because drivers may include secrets."""


def load_manifest(path: str) -> dict:
    from .manifest import load_manifest as loader
    return loader(path)


def select_queries(manifest: dict, base: str | None) -> tuple[list[str], dict]:
    from .manifest import select_queries as selector
    return selector(manifest, base)


def capture_snapshot(manifest: dict, query_ids: list[str], dsn: str, **kwargs: Any) -> dict:
    # psycopg is optional for offline comparison/trace use and imported lazily.
    try:
        from .db import capture
        return capture(manifest, query_ids, dsn, **kwargs)
    except Exception as exc:
        raise _DatabaseFailure(type(exc).__name__) from None


def _reject_constant(value: str) -> None:
    raise ValueError("JSON must contain finite numbers")


def _read_json(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, parse_constant=_reject_constant)


def _atomic_write(path: str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=f".{target.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_result(args: argparse.Namespace, report: dict) -> None:
    markdown_path = getattr(args, "markdown", None)
    if markdown_path and Path(args.output).resolve() == Path(markdown_path).resolve():
        raise ValueError("JSON and Markdown outputs must have different paths")
    # Serialize both first; invalid values cannot leave a partial JSON artifact.
    serialized = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    markdown = to_markdown(report) if markdown_path else None
    _atomic_write(args.output, serialized)
    if markdown_path:
        _atomic_write(markdown_path, markdown)


def _add_finding(report: dict, code: str, severity: str, query_id: str | None, message: str, **evidence: Any) -> None:
    report["findings"].append({"code": code, "severity": severity, "query_id": query_id,
                               "message": message, "evidence": evidence})
    key = {"error": "errors", "warning": "warnings", "info": "infos"}[severity]
    report["summary"][key] += 1


def _exit_for_report(report: dict, fail_on: str) -> int:
    summary = report["summary"]
    if fail_on == "none":
        return 0
    if summary["errors"] or (fail_on == "warning" and summary["warnings"]):
        return 1
    return 0


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plan-guard", description="Check PostgreSQL estimated plans and explicit request traces.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "check"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--base", help="Git revision to use for changed-query selection")
        command.add_argument("--dsn-env", default="PLAN_GUARD_DSN", help="Environment variable containing the PostgreSQL DSN")
        command.add_argument("--statement-timeout-ms", type=_positive_int, default=3000)
        command.add_argument("--lock-timeout-ms", type=_positive_int, default=500)
        if name == "check":
            command.add_argument("--baseline", required=True)
            _add_report_arguments(command)
    compare = commands.add_parser("compare")
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--policy", help="JSON file containing policy thresholds")
    compare.add_argument("--output", required=True)
    _add_report_arguments(compare)
    trace = commands.add_parser("trace")
    trace.add_argument("--input", required=True, help="JSON array of explicit trace events")
    trace.add_argument("--output", required=True)
    trace.add_argument("--min-repeats", type=_positive_int, default=5)
    _add_report_arguments(trace)
    return parser


def _add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--markdown", help="Also write a Markdown report")
    parser.add_argument("--fail-on", choices=("error", "warning", "none"), default="warning")


def _run(args: argparse.Namespace) -> int:
    if args.command == "compare":
        policy = _read_json(args.policy) if args.policy else None
        report = analyze_snapshot(_read_json(args.candidate), _read_json(args.baseline), policy)
        for query_id in report["new_query_ids"]:
            _add_finding(report, "BASELINE_MISSING", "warning", query_id,
                         "Candidate query has no baseline. Regression coverage is incomplete; static analysis still applies.")
    elif args.command == "trace":
        report = analyze_trace(_read_json(args.input), args.min_repeats)
    else:
        manifest = load_manifest(args.manifest)
        selected_ids, selection = select_queries(manifest, args.base)
        baseline = None
        if args.command == "check":
            baseline = _read_json(args.baseline)
            if not isinstance(baseline, dict) or not isinstance(baseline.get("queries"), dict):
                raise ValueError("Baseline must be a snapshot with a queries object")
        if not selected_ids:
            if args.command == "capture":
                raise ValueError("No queries selected; capture requires at least one selected query")
            # A docs-only change needs no connection. Use the baseline context
            # solely to validate the empty-scope report, never as a fresh capture.
            snapshot = {"schema_version": 1, "context": baseline.get("context"), "queries": {}}
        else:
            dsn = os.environ.get(args.dsn_env)
            if not dsn:
                raise ValueError("PostgreSQL DSN environment variable is unset or empty")
            snapshot = capture_snapshot(manifest, selected_ids, dsn,
                                        statement_timeout_ms=args.statement_timeout_ms,
                                        lock_timeout_ms=args.lock_timeout_ms)
        snapshot["selection"] = selection
        if args.command == "capture":
            _write_result(args, snapshot)
            print(f"Captured {len(snapshot['queries'])} selected queries.")
            return 0
        # Unselected baseline entries are outside the check's scope, not removed.
        selected_set = set(selected_ids)
        filtered_baseline = dict(baseline)
        filtered_baseline["queries"] = {query_id: query for query_id, query in baseline["queries"].items()
                                         if query_id in selected_set}
        report = analyze_snapshot(snapshot, filtered_baseline, manifest.get("policy"))
        report["selection"] = selection
        for query_id in sorted(selected_set - set(filtered_baseline["queries"])):
            _add_finding(report, "BASELINE_MISSING", "warning", query_id,
                         "Selected query has no baseline. Regression coverage is incomplete; static analysis still applies.")
        if not selected_ids:
            _add_finding(report, "NO_QUERIES_SELECTED", "info", None,
                         "No queries selected. This check provides no plan-regression coverage.")
    _write_result(args, report)
    summary = report["summary"]
    print(f"{summary['errors']} errors, {summary['warnings']} warnings, {summary['infos']} infos.")
    return _exit_for_report(report, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except _DatabaseFailure as exc:
        print(f"plan-guard: database capture failed ({exc}). Check connection, read-only access, and timeouts.", file=sys.stderr)
    except (ValueError, OSError) as exc:
        print(f"plan-guard: {exc}", file=sys.stderr)
    except Exception as exc:
        # Unexpected driver/Git errors must never print connection details or SQL.
        print(f"plan-guard: command failed ({type(exc).__name__}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
