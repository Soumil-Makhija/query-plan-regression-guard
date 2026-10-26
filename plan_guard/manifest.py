"""Validated query manifests and committed, merge-base Git selection.

Paths are relative to the manifest directory. Globs use shell-style matching
within each path segment; a standalone ** matches zero or more directories.
Git selection compares committed HEAD with its merge base with the supplied
revision. Uncommitted and untracked changes are outside that selection scope.
"""
from __future__ import annotations

import fnmatch
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess

from plan_guard.analysis import DEFAULT_POLICY


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _fields(value, allowed, where):
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValueError(f"Unknown {where} fields: {', '.join(sorted(unknown))}")


def _relative(value, where):
    if (not isinstance(value, str) or not value.strip() or "\x00" in value
            or "\\" in value):
        raise ValueError(f"{where} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or ".." in path.parts or not path.parts:
        raise ValueError(f"{where} must stay within the manifest directory")
    return path.as_posix()


def _globs(value, where):
    if not isinstance(value, list):
        raise ValueError(f"{where} must be an array")
    return [_relative(pattern, f"{where}[{i}]") for i, pattern in enumerate(value)]


def load_manifest(path: Path | str) -> dict:
    """Load a strict version-1 JSON manifest; reject paths escaping its root."""
    manifest_path = Path(path).resolve()
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Nonfinite JSON value: {value}")))
    except (OSError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Cannot read manifest {manifest_path}: {exc}") from exc
    _fields(data, {"schema_version", "queries", "migrations", "policy"}, "manifest")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("manifest.schema_version must be 1")
    raw_queries = data.get("queries")
    if not isinstance(raw_queries, list) or not raw_queries:
        raise ValueError("manifest.queries must be a nonempty array")
    root = manifest_path.parent
    queries = {}
    for i, raw in enumerate(raw_queries):
        where = f"queries[{i}]"
        _fields(raw, {"id", "sql", "params", "sources"}, where)
        query_id = raw.get("id")
        if not isinstance(query_id, str) or not query_id.strip():
            raise ValueError(f"{where}.id must be a nonempty string")
        if query_id in queries:
            raise ValueError(f"Duplicate query id: {query_id}")
        sql_path = _relative(raw.get("sql"), f"{where}.sql")
        try:
            resolved_sql = (root / sql_path).resolve(strict=True)
            if not resolved_sql.is_relative_to(root):
                raise ValueError(f"{where}.sql escapes the manifest directory")
            sql = resolved_sql.read_text(encoding="utf-8")
        except (OSError, UnicodeError, RuntimeError) as exc:
            raise ValueError(f"Cannot read {where}.sql: {exc}") from exc
        if not sql.strip():
            raise ValueError(f"{where}.sql must not be empty")
        params = raw.get("params", [])
        if not isinstance(params, (list, dict)):
            raise ValueError(f"{where}.params must be an array or object")
        pending = [params]
        while pending:
            current = pending.pop()
            if isinstance(current, float) and not math.isfinite(current):
                raise ValueError(f"{where}.params must contain finite JSON values")
            if isinstance(current, list):
                pending.extend(current)
            elif isinstance(current, dict):
                pending.extend(current.values())
        queries[query_id] = {"sql": sql, "sql_path": sql_path,
                             "resolved_sql_path": resolved_sql.relative_to(root).as_posix(), "params": params,
                             "sources": _globs(raw.get("sources", []), f"{where}.sources")}
    migrations = _globs(data.get("migrations", []), "migrations")
    policy = data.get("policy", {})
    _fields(policy, DEFAULT_POLICY, "policy")
    for key, value in policy.items():
        try:
            valid = not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError(f"policy.{key} must be a finite nonnegative number")
    if "max_selectivity" in policy and policy["max_selectivity"] > 1:
        raise ValueError("policy.max_selectivity must be between 0 and 1")
    if "cost_ratio" in policy and policy["cost_ratio"] <= 1:
        raise ValueError("policy.cost_ratio must be greater than 1")
    return {"root": root, "path": manifest_path, "queries": queries,
            "migrations": migrations, "policy": policy}


def _git(root, *args):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Git command failed: {exc}") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"Git command failed: {detail}")
    return result.stdout


def _match(path, pattern):
    """Match path segments; ** also matches zero intervening directories."""
    parts, globs = PurePosixPath(path).parts, PurePosixPath(pattern).parts
    pending, seen = [(0, 0)], set()
    while pending:
        pi, gi = pending.pop()
        if (pi, gi) in seen:
            continue
        seen.add((pi, gi))
        if gi == len(globs):
            if pi == len(parts):
                return True
        elif globs[gi] == "**":
            pending.append((pi, gi + 1))
            if pi < len(parts):
                pending.append((pi + 1, gi))
        elif pi < len(parts) and fnmatch.fnmatchcase(parts[pi], globs[gi]):
            pending.append((pi + 1, gi + 1))
    return False


def select_queries(manifest: dict, base: str | None = None) -> tuple[list[str], dict]:
    """Select stable IDs from changed SQL, sources, manifest, or migrations.

    A base must resolve to a commit; shallow/missing bases and Git failures raise
    ValueError instead of silently skipping checks. Renames are delete+add.
    """
    all_ids = sorted(manifest["queries"])
    if base is None:
        return all_ids, {"mode": "all", "base": None, "head": None, "changed_paths": [],
                         "reason": "No base revision supplied; all registered queries selected",
                         "scope": "working_tree"}
    if not isinstance(base, str) or not base.strip() or "\x00" in base:
        raise ValueError("base must be a nonempty Git revision")
    root = manifest["root"]
    repo_raw = _git(root, "rev-parse", "--show-toplevel")
    repo = Path(os.fsdecode(repo_raw[:-1] if repo_raw.endswith(b"\n") else repo_raw)).resolve()
    try:
        prefix = root.relative_to(repo)
        manifest_rel = manifest["path"].relative_to(repo).as_posix()
    except ValueError as exc:
        raise ValueError("Manifest must be inside the Git worktree") from exc
    resolved = _git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").decode("ascii").strip()
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    changed = sorted(os.fsdecode(path) for path in _git(
        repo, "diff", "--no-ext-diff", "--name-only", "-z", "--no-renames", f"{resolved}...{head}", "--"
    ).split(b"\x00") if path)
    relative = []
    for path in changed:
        try:
            relative.append(PurePosixPath(path).relative_to(PurePosixPath(prefix.as_posix())).as_posix())
        except ValueError:
            continue
    metadata = {"mode": "git", "base": resolved, "head": head, "changed_paths": changed,
                "root_prefix": prefix.as_posix(), "scope": "committed_HEAD"}
    if manifest_rel in changed:
        metadata["reason"] = "Manifest changed; all registered queries selected"
        return all_ids, metadata
    if any(_match(path, glob) for path in relative for glob in manifest["migrations"]):
        metadata["reason"] = "Migration changed; all registered queries selected"
        return all_ids, metadata
    selected = sorted(query_id for query_id, query in manifest["queries"].items()
                      if query["sql_path"] in relative or query["resolved_sql_path"] in relative or any(
                          _match(path, glob) for path in relative for glob in query["sources"]))
    metadata["reason"] = "Changed registered SQL or source dependencies" if selected else "No registered query dependencies changed"
    return selected, metadata
