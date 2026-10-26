"""Safe, deterministic Markdown rendering for analysis reports."""

from __future__ import annotations

import html
import json
import re


def _escape(value: object) -> str:
    text = html.escape(str(value), quote=True).replace("\\", "\\\\")
    for character in "`*_{}[]()#+-.!|~":
        text = text.replace(character, "\\" + character)
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _json_block(value: object) -> str:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}json\n{text}\n{fence}"


def to_markdown(report: dict) -> str:
    """Render values as escaped text and evidence as dynamically fenced JSON."""
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    lines = ["# Query Plan Guard report", "",
             f"Errors: {summary.get('errors', 0)} · Warnings: {summary.get('warnings', 0)} · Infos: {summary.get('infos', 0)}", ""]
    selection = report.get("selection")
    if selection is not None:
        lines.extend(["## Query selection", "", _json_block(selection), ""])
    if "analyzed_query_ids" in report:
        lines.extend([f"Analyzed queries: {len(report['analyzed_query_ids'])}. "
                      f"Compared queries: {len(report.get('compared_query_ids', []))}.", ""])
    if "requests_analyzed" in report:
        lines.extend([f"Analyzed requests: {report['requests_analyzed']}. "
                      f"Trace events: {report.get('events_analyzed', 0)}.", ""])
    if not findings:
        lines.extend(["No findings at the configured thresholds. This does not prove performance or complete query coverage.", ""])
    else:
        lines.extend(["| Severity | Code | Query | Finding |", "| --- | --- | --- | --- |"])
        for finding in findings:
            lines.append("| " + " | ".join(_escape(finding.get(key) if finding.get(key) is not None else "—")
                                            for key in ("severity", "code", "query_id", "message")) + " |")
        lines.extend(["", "## Evidence", ""])
        for index, finding in enumerate(findings, start=1):
            lines.extend([f"### {index}. {_escape(finding.get('code', 'Finding'))}", "",
                          _json_block(finding.get("evidence", {})), ""])
    lines.extend(["Estimated plan costs are planner units, not milliseconds. Scan advisories require workload review. "
                  "Potential N+1 findings are candidates from explicit trace evidence, not proof of a causal loop.", ""])
    return "\n".join(lines)
