# Query plan regression guard

A Python tool for PostgreSQL query-plan regression checks. The first milestone
provides pure JSON plan analysis and request-scoped repeated-query evidence.
Database capture and the installed CLI are in development; this milestone is a
library, not a completed command-line workflow.

## Core scope

Compare root estimated costs and indexed access changing to a sequential scan.
Flag selective sequential scans on large relations, with a qualified advisory to
review predicate/index compatibility. A sequential scan does not prove a missing
index; planner costs are estimates, not latency measurements. Different planner
settings or substantially different table sizes suppress regression conclusions.

N+1 evidence is analyzed separately from explicitly request-scoped trace events.
Repeated child queries with varying parameters after a parent event are candidates
for application review, not proof of an ORM defect. Individual plans never claim N+1.

## Development

Python 3.11+. Run `python -m unittest discover -v`. No database is required for the
pure core tests. See `plan_guard/analysis.py` for the snapshot and trace API.

MIT licensed. No telemetry or automatic index/schema changes.
