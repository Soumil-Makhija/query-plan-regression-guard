"""Deterministic analysis of PostgreSQL estimated plans and explicit query traces.

Planner costs are relative units, not milliseconds. An advisory identifies a
candidate for investigation; it neither executes SQL nor proposes executable DDL.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any


DEFAULT_POLICY = {
    "min_table_rows": 1000,
    "max_selectivity": 0.2,
    "cost_ratio": 2.0,
    "cost_delta": 50.0,
}
_INDEX_SCANS = {"Index Scan", "Index Only Scan", "Bitmap Heap Scan"}
_SEQ_SCANS = {"Seq Scan", "Parallel Seq Scan"}


def _number(value: Any, where: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} must be a finite, nonnegative number")
    try:
        valid = math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f"{where} must be a finite, nonnegative number")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where} must be a nonempty string")
    return value


def _mapping(value: Any, where: str) -> dict:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ValueError(f"{where} must be an object with string keys")
    return value


def _json_value(value: Any, where: str) -> None:
    """Reject non-JSON and non-finite context values without coercing them."""
    pending = [(value, where, frozenset())]
    while pending:
        current, path, ancestors = pending.pop()
        if current is None or isinstance(current, (str, bool)):
            continue
        if isinstance(current, (int, float)):
            try:
                finite = math.isfinite(current)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"{path} must contain finite numbers")
        elif isinstance(current, (dict, list)):
            if id(current) in ancestors:
                raise ValueError(f"{path} contains a cycle")
            ancestors = ancestors | {id(current)}
            if isinstance(current, dict):
                _mapping(current, path)
                pending.extend((v, f"{path}.{k}", ancestors) for k, v in current.items())
            else:
                pending.extend((v, f"{path}[{i}]", ancestors) for i, v in enumerate(current))
        else:
            raise ValueError(f"{path} contains a non-JSON value")


def _nodes(plan: dict, where: str) -> list[tuple[str, dict]]:
    wrapper = _mapping(plan, where)
    if "Plan" not in wrapper:
        raise ValueError(f"{where}.Plan is required")
    # Validate all numeric plan values, including optional EXPLAIN statistics.
    _json_value(wrapper, where)
    numbers = [(wrapper, where)]
    while numbers:
        current, path = numbers.pop()
        if isinstance(current, dict):
            numbers.extend((v, f"{path}.{k}") for k, v in current.items())
        elif isinstance(current, list):
            numbers.extend((v, f"{path}[{i}]") for i, v in enumerate(current))
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            _number(current, path)
    result = []
    pending = [(wrapper["Plan"], "Plan")]
    while pending:
        node, path = pending.pop()
        _mapping(node, f"{where}.{path}")
        _string(node.get("Node Type"), f"{where}.{path}.Node Type")
        for key in ("Total Cost", "Plan Rows"):
            _number(node.get(key), f"{where}.{path}.{key}")
        for key in ("Startup Cost", "Plan Width", "Actual Startup Time", "Actual Total Time",
                    "Actual Rows", "Actual Loops", "Workers Planned", "Workers Launched"):
            if key in node:
                _number(node[key], f"{where}.{path}.{key}")
        for key in ("Schema", "Relation Name", "Alias", "Filter", "Index Name"):
            if key in node:
                _string(node[key], f"{where}.{path}.{key}")
        children = node.get("Plans", [])
        if not isinstance(children, list):
            raise ValueError(f"{where}.{path}.Plans must be an array")
        result.append((path, node))
        pending.extend(
            (child, f"{path}.Plans[{i}]")
            for i, child in reversed(list(enumerate(children)))
        )
    return result


def _snapshot(value: Any, label: str) -> dict[str, list[tuple[str, dict]]]:
    snapshot = _mapping(value, label)
    if type(snapshot.get("schema_version")) is not int or snapshot["schema_version"] != 1:
        raise ValueError(f"{label}.schema_version must be 1")
    context = _mapping(snapshot.get("context"), f"{label}.context")
    version = context.get("server_version_num")
    if type(version) is not int or version < 90000:
        raise ValueError(f"{label}.context.server_version_num must be a PostgreSQL version number")
    _mapping(context.get("settings"), f"{label}.context.settings")
    _json_value(context["settings"], f"{label}.context.settings")
    queries = _mapping(snapshot.get("queries"), f"{label}.queries")
    plans = {}
    for query_id, raw in queries.items():
        _string(query_id, f"{label}.queries key")
        where = f"{label}.queries.{query_id}"
        query = _mapping(raw, where)
        for field in ("sql_sha256", "params_sha256"):
            _string(query.get(field), f"{where}.{field}")
        relations = _mapping(query.get("relations"), f"{where}.relations")
        for name, raw_relation in relations.items():
            _string(name, f"{where}.relations key")
            relation = _mapping(raw_relation, f"{where}.relations.{name}")
            _number(relation.get("rows"), f"{where}.relations.{name}.rows")
            indexes = relation.get("indexes")
            if not isinstance(indexes, list):
                raise ValueError(f"{where}.relations.{name}.indexes must be an array")
            for index in indexes:
                _string(index, f"{where}.relations.{name}.indexes entry")
        plans[query_id] = _nodes(query.get("plan"), f"{where}.plan")
    return plans


def _policy(value: dict | None) -> dict:
    result = dict(DEFAULT_POLICY)
    if value is not None:
        _mapping(value, "policy")
        unknown = set(value) - set(result)
        if unknown:
            raise ValueError(f"Unknown policy fields: {', '.join(sorted(unknown))}")
        result.update(value)
    for key, val in result.items():
        _number(val, f"policy.{key}")
    if not 0 <= result["max_selectivity"] <= 1:
        raise ValueError("policy.max_selectivity must be between 0 and 1")
    if result["cost_ratio"] <= 1:
        raise ValueError("policy.cost_ratio must be greater than 1")
    return result


def _finding(code: str, severity: str, query_id: str | None, message: str, **evidence: Any) -> dict:
    return {"code": code, "severity": severity, "query_id": query_id,
            "message": message, "evidence": evidence}


def _summary(findings: list[dict]) -> dict:
    counts = Counter(finding["severity"] for finding in findings)
    return {"errors": counts["error"], "warnings": counts["warning"], "infos": counts["info"]}


def _relation(node: dict) -> str | None:
    if "Schema" in node and "Relation Name" in node:
        return f"{node['Schema']}.{node['Relation Name']}"
    return None


def _scans(nodes: list[tuple[str, dict]]) -> dict[tuple[str, str], Counter]:
    result = defaultdict(Counter)
    for _, node in nodes:
        relation = _relation(node)
        kind = node["Node Type"]
        if relation and kind in _INDEX_SCANS | _SEQ_SCANS:
            alias = node.get("Alias", node["Relation Name"])
            result[(relation, alias)]["indexed" if kind in _INDEX_SCANS else "sequential"] += 1
    return result


def analyze_snapshot(candidate: dict, baseline: dict | None = None, policy: dict | None = None) -> dict:
    """Analyze estimated plans; invalid or incomparable inputs raise ValueError.

    Settings and per-query relation-statistics drift suppress regression claims.
    Static sequential-scan advisories still run. PostgreSQL major-version or
    parameter mismatches are invalid comparisons and fail before any report.
    """
    thresholds = _policy(policy)
    candidate_nodes = _snapshot(candidate, "candidate")
    baseline_nodes = _snapshot(baseline, "baseline") if baseline is not None else {}
    overlap = sorted(set(candidate_nodes) & set(baseline_nodes))
    if baseline is not None:
        old_version = baseline["context"]["server_version_num"]
        new_version = candidate["context"]["server_version_num"]
        if old_version // 10000 != new_version // 10000:
            raise ValueError("Baseline and candidate PostgreSQL major versions differ")
        for query_id in overlap:
            if candidate["queries"][query_id]["params_sha256"] != baseline["queries"][query_id]["params_sha256"]:
                raise ValueError(f"Query {query_id!r} parameter hashes differ; use identical parameters")

    findings = []
    compared = []
    suppressed = []
    new_ids = sorted(set(candidate_nodes) - set(baseline_nodes)) if baseline is not None else []
    removed_ids = sorted(set(baseline_nodes) - set(candidate_nodes))
    settings_differ = baseline is not None and candidate["context"]["settings"] != baseline["context"]["settings"]
    for query_id in sorted(candidate_nodes):
        query = candidate["queries"][query_id]
        for path, node in candidate_nodes[query_id]:
            relation = _relation(node)
            stats = query["relations"].get(relation)
            # Parallel scan rows are per-worker estimates. Do not mistake those
            # for the scan's full selectivity without a worker model.
            if (node["Node Type"] not in _SEQ_SCANS or not node.get("Filter")
                    or node.get("Parallel Aware", False) or node["Node Type"] == "Parallel Seq Scan"
                    or stats is None or stats["rows"] < thresholds["min_table_rows"]
                    or stats["rows"] == 0):
                continue
            selectivity = node["Plan Rows"] / stats["rows"]
            if selectivity <= thresholds["max_selectivity"]:
                indexes = sorted(stats["indexes"])
                advice = ("Existing indexes may be unusable for this predicate; inspect their definitions and planner estimates."
                          if indexes else "A suitable index may be missing; inspect the predicate and workload before adding one.")
                findings.append(_finding(
                    "SELECTIVE_SEQ_SCAN", "warning", query_id,
                    f"Estimated selective sequential scan on {relation}. {advice}",
                    relation=relation, node_path=path, table_rows=stats["rows"],
                    estimated_rows=node["Plan Rows"], estimated_selectivity=selectivity,
                    existing_indexes=indexes, filter=node["Filter"],
                    advisory="possibly_unusable_index" if indexes else "possibly_missing_index",
                ))
        if query_id not in overlap:
            continue
        old_query = baseline["queries"][query_id]
        reasons = []
        if settings_differ:
            reasons.append("planner settings differ")
        changed_relations = []
        referenced_relations = {
            relation for _, node in candidate_nodes[query_id] + baseline_nodes[query_id]
            if (relation := _relation(node)) is not None
        }
        relation_names = set(query["relations"]) | set(old_query["relations"]) | referenced_relations
        for relation in sorted(relation_names):
            old = old_query["relations"].get(relation)
            new = query["relations"].get(relation)
            if old is None or new is None:
                changed_relations.append({"relation": relation, "reason": "relation context missing in one snapshot"})
            elif (old["rows"] == 0 and new["rows"] != 0) or (
                old["rows"] != 0 and abs(new["rows"] - old["rows"]) / old["rows"] > 0.25
            ):
                changed_relations.append({"relation": relation, "baseline_rows": old["rows"], "candidate_rows": new["rows"]})
        if changed_relations:
            reasons.append("relation row estimates differ by more than 25% or relation context is missing")
        if reasons:
            suppressed.append(query_id)
            findings.append(_finding(
                "CONTEXT_MISMATCH", "warning", query_id,
                "Regression comparison suppressed: " + "; ".join(reasons) + ". Static advisories still apply.",
                reasons=reasons, changed_relations=changed_relations,
                settings_differ=settings_differ,
            ))
            continue
        compared.append(query_id)
        old_scans = _scans(baseline_nodes[query_id])
        new_scans = _scans(candidate_nodes[query_id])
        for relation, alias in sorted(set(old_scans) & set(new_scans)):
            before, after = old_scans[(relation, alias)], new_scans[(relation, alias)]
            if after["sequential"] > before["sequential"] and after["indexed"] < before["indexed"]:
                findings.append(_finding(
                    "INDEX_TO_SEQ_SCAN", "error", query_id,
                    f"Indexed access changed to sequential access for {relation} (alias {alias}).",
                    relation=relation, alias=alias, baseline_scans=dict(sorted(before.items())),
                    candidate_scans=dict(sorted(after.items())),
                ))
        old_cost = old_query["plan"]["Plan"]["Total Cost"]
        new_cost = query["plan"]["Plan"]["Total Cost"]
        delta = new_cost - old_cost
        ratio = new_cost / old_cost if old_cost else None
        ratio_exceeded = ratio >= thresholds["cost_ratio"] if ratio is not None else new_cost > 0
        ratio_overflow = ratio is not None and not math.isfinite(ratio)
        if ratio_overflow:
            ratio = None
        if delta > 0 and delta >= thresholds["cost_delta"] and ratio_exceeded:
            findings.append(_finding(
                "COST_REGRESSION", "error", query_id,
                "Estimated root plan cost increased beyond both configured ratio and absolute thresholds; costs are planner units, not runtime.",
                baseline_cost=old_cost, candidate_cost=new_cost, cost_delta=delta,
                cost_ratio=ratio, zero_baseline_cost=old_cost == 0,
                cost_ratio_exceeds_finite_range=ratio_overflow,
                minimum_ratio=thresholds["cost_ratio"], minimum_delta=thresholds["cost_delta"],
            ))
    for query_id in new_ids:
        findings.append(_finding("NEW_QUERY", "info", query_id, "New query has static analysis but no baseline comparison."))
    for query_id in removed_ids:
        findings.append(_finding("REMOVED_QUERY", "info", query_id, "Baseline query is absent from the candidate snapshot."))
    return {
        "schema_version": 1, "findings": findings, "summary": _summary(findings),
        "policy": thresholds, "analyzed_query_ids": sorted(candidate_nodes),
        "compared_query_ids": compared, "context_suppressed_query_ids": suppressed,
        "new_query_ids": new_ids, "removed_query_ids": removed_ids,
    }


def analyze_trace(events: list[dict], min_repeats: int = 5) -> dict:
    """Identify potential N+1 patterns from explicit request-level trace evidence.

    A candidate requires a preceding parent event, repeated child-query identity,
    and distinct parameter hashes in one request. This cannot prove a causal
    loop; plans alone cannot establish N+1 behavior.
    """
    if type(min_repeats) is not int or min_repeats < 2:
        raise ValueError("min_repeats must be an integer of at least 2")
    if not isinstance(events, list):
        raise ValueError("events must be an array")
    parents = defaultdict(list)
    children = defaultdict(list)
    requests = set()
    for i, event in enumerate(events):
        where = f"events[{i}]"
        _mapping(event, where)
        request_id = _string(event.get("request_id"), f"{where}.request_id")
        query_id = _string(event.get("query_id"), f"{where}.query_id")
        _string(event.get("params_hash"), f"{where}.params_hash")
        role = event.get("role")
        if role not in ("parent", "child", "other"):
            raise ValueError(f"{where}.role must be parent, child, or other")
        if "duration_ms" in event:
            _number(event["duration_ms"], f"{where}.duration_ms")
        requests.add(request_id)
        if role == "parent":
            if query_id not in parents[request_id]:
                parents[request_id].append(query_id)
        elif role == "child" and parents[request_id]:
            children[(request_id, query_id)].append((event, tuple(parents[request_id])))
    findings = []
    for (request_id, query_id), repeated in sorted(children.items()):
        distinct = len({event["params_hash"] for event, _ in repeated})
        if len(repeated) >= min_repeats and distinct >= min_repeats:
            durations = [event["duration_ms"] for event, _ in repeated if "duration_ms" in event]
            duration_sum = sum(durations)
            _number(duration_sum, "aggregate trace duration")
            preceding_parents = sorted({parent for _, seen in repeated for parent in seen})
            findings.append(_finding(
                "POTENTIAL_N_PLUS_ONE", "warning", query_id,
                "Potential N+1 candidate: repeated child query with distinct parameters follows a parent in one request. This is trace evidence, not proof of a causal N+1 loop.",
                request_id=request_id, parent_query_ids=preceding_parents,
                child_count=len(repeated), distinct_parameter_count=distinct,
                min_repeats=min_repeats, measured_duration_count=len(durations),
                total_measured_duration_ms=duration_sum,
            ))
    return {"schema_version": 1, "findings": findings, "summary": _summary(findings),
            "requests_analyzed": len(requests), "events_analyzed": len(events),
            "min_repeats": min_repeats}
