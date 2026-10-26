# Query plan regression guard

Check PostgreSQL plans for queries affected by a pull request. Capture a baseline
against a representative CI database, apply the candidate changes to an equivalent
CI database, then gate on estimated cost regressions and lost indexed access.
JSON and Markdown reports explain the evidence. No model API or telemetry.

## Install and run

Python 3.11+ and PostgreSQL 16–18 are the target platforms (see CI for verified
versions). Use a disposable CI database and a limited database role. SQL is trusted
project input. Planning is not a security sandbox: PostgreSQL may evaluate
functions while planning. The tool never requests `EXPLAIN ANALYZE` or applies DDL.

```sh
python -m venv .venv
. .venv/bin/activate
pip install .
# Set PLAN_GUARD_DSN in your environment; do not put passwords in git or reports.
# First load examples/setup.sql into a fresh disposable database using psql.
psql "$PLAN_GUARD_DSN" -v ON_ERROR_STOP=1 -f examples/setup.sql
plan-guard capture --manifest examples/manifest.json --output artifacts/baseline.json
# Apply candidate migrations yourself to the CI database, e.g. DROP the customer index.
plan-guard check --manifest examples/manifest.json --baseline artifacts/baseline.json \
  --output artifacts/check.json --markdown artifacts/check.md
# Offline analysis of already captured plans:
plan-guard compare --baseline artifacts/baseline.json --candidate artifacts/baseline.json \
  --output artifacts/control.json
# Explicitly synthetic request trace, produces a warning (exit 1):
plan-guard trace --input examples/trace.json --output artifacts/trace.json
```

Exit codes: **0** no findings at the selected threshold, **1** findings meet the
threshold, **2** invalid input, capture, or Git failure. Default `--fail-on warning`
also blocks missing baseline coverage and suppressed comparisons. `--fail-on error`
or `none` is an explicit relaxation; inspect warnings before choosing it.

## Register queries and PR dependencies

A versioned JSON manifest maps stable query/case IDs to SQL files and application
source globs, relative to the manifest directory. Give each representative
parameter set its own stable ID. A changed parameter hash cannot be compared to
its previous baseline; establish a reviewed new baseline instead.

```json
{
  "schema_version": 1,
  "queries": [{
    "id": "orders/typical-customer",
    "sql": "queries/orders.sql",
    "params": [42],
    "sources": ["app/*.py"]
  }],
  "migrations": ["migrations/*"],
  "policy": {"cost_ratio": 2, "cost_delta": 50}
}
```

Use psycopg `%s` / `%(name)s` placeholders and positional arrays or named objects.
Values are bound separately. In parameterized SQL write literal percent signs as
`%%`; no-parameter SQL uses ordinary `%`. One PostgreSQL EXPLAINable statement per
file, including nonexecuting DML plans. Multiple statements are rejected by the
server's prepared-query protocol. Empty params are optional.

`check --base <commit-or-ref>` selects queries affected by the **committed**
`base...HEAD` merge-base diff, including declared source dependencies. SQL changes
select their query; manifest or configured migration changes select all queries.
Globs match path segments: `*` stays within one directory; `**` matches zero or more directories. Unknown base refs
fail; fetch enough history (CI `fetch-depth: 0`). Without `--base`, all registered
queries run. Uncommitted changes are not part of PR selection; commit them or run
all queries. Selection is explicit in each report. An empty selection means no
mapped query was affected; it does not establish application-wide coverage.

Dependencies are declared, not inferred from arbitrary ORM/application code. Map
schema migrations, functions, views, and shared SQL builders conservatively.
Deletion of a query is reported as baseline coverage removal in offline compare;
a selected capture requires each registered SQL file to exist.

## What the findings mean

- **COST_REGRESSION:** root total estimated cost grows by at least both 2× and 50
  planner units by default. Child costs are already included; they are not summed.
- **INDEX_TO_SEQ_SCAN:** the same relation/alias loses indexed scans while gaining
  sequential scans. This is a plan change, not proof of worse runtime.
- **SELECTIVE_SEQ_SCAN:** a nonparallel filtered sequential scan estimates at most
  20% of a relation of at least 1,000 estimated rows. Review possibly missing or
  unusable indexes. No automatic index advice/DDL or certainty of a missing index.
  Small tables, broad/unfiltered scans, and per-worker parallel selectivity are
  deliberately excluded from this advisory.
- **CONTEXT_MISMATCH:** settings differ, relation metadata is missing, or relation
  row estimates drift by over 25%. Regression conclusions are suppressed for the
  affected query; static scan advisories still apply. Major PostgreSQL version or
  parameter mismatches are invalid input.
- **POTENTIAL_N_PLUS_ONE:** trace-only candidate, described below. A plan, including
  Nested Loop, cannot establish N+1 request behavior.

Policy fields: `min_table_rows`, `max_selectivity`, `cost_ratio`, `cost_delta`.
Offline `compare --policy policy.json` accepts the same object. Baseline SQL text
may change for a stable query ID; its hashes are recorded for review.

## Trace evidence for N+1 candidates

Supply a JSON array in event order, with `request_id`, stable `query_id`,
`params_hash`, and explicit `role` (`parent`, `child`, `other`). Optional
`duration_ms` records observed time. Hash parameter identities locally; do not
submit private SQL or values. See [examples/trace.json](examples/trace.json).

A candidate requires a parent event followed by at least five repetitions of one
child query with at least five distinct parameter hashes **within one request**.
`--min-repeats` changes that threshold. This suggests a possible per-row fetch
loop; batched queries or legitimate workflows may produce the same pattern.
Instrumentation roles and hashes are user supplied, not inferred. There is no
automatic tracing agent, CI-log ingestion, or statistical/causal guarantee.

## Capture and baseline limits

The adapter uses JSON `EXPLAIN (VERBOSE, COSTS, ANALYZE FALSE, SETTINGS)`, bound
parameters, a repeatable-read/read-only transaction, and an unconditional rollback.
Statement timeout defaults to 3,000 ms; lock timeout to 500 ms; connect timeout to
5 seconds. Unknown relation statistics fail capture: load representative data and
run `ANALYZE` before capturing. Errors omit connection and SQL details.

Snapshots record PostgreSQL version, planner settings (including memory/parallel
settings), role/search path, SQL/parameter hashes, plans, row estimates, and valid
index names. **Plans themselves can contain literal values, predicates, names and
paths.** Inspect artifacts and use synthetic data before sharing. Hashing metadata
is not plan redaction or anonymization.

Equal row counts/settings cannot guarantee comparable distributions, cache state,
hardware, extensions, role policies, index definitions, collation versions, or
statistics. Use equivalent schema/data, PostgreSQL major version and configuration
for baseline/candidate. Cost units are not milliseconds; no runtime latency,
missing-index proof, or production performance guarantee is claimed. A stored
baseline is a reviewed reference, not a correctness oracle. Multiple parameter
cases help with skew, but do not cover all workloads or generic prepared plans.

## Development and architecture

```sh
python -m unittest discover -v
# Required for real integration tests (otherwise they explicitly skip):
PLAN_GUARD_TEST_DSN="$PLAN_GUARD_DSN" python -m unittest discover -v
python -m compileall -q plan_guard
python -m build
```

`analysis.py` is pure validation/comparison; `manifest.py` loads strict manifests
and maps Git changes; `db.py` captures consistent bounded plans; `cli.py` composes
commands; `report.py` writes shareable evidence. Tests cover root-cost invariants,
context suppression, scan aliases, trace qualification, Git mappings and actual
PostgreSQL behavior. CI and a reproducible installed CLI example are being added
in the final integration milestone.

Reference semantics: [PostgreSQL EXPLAIN](https://www.postgresql.org/docs/current/sql-explain.html),
[planner costs](https://www.postgresql.org/docs/current/using-explain.html),
[read-only transactions](https://www.postgresql.org/docs/current/sql-set-transaction.html),
[psycopg bound parameters](https://www.psycopg.org/psycopg3/docs/basic/params.html),
[Git diff](https://git-scm.com/docs/git-diff).

MIT licensed.
