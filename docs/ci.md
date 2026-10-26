# CI integration

The [repository workflow](../.github/workflows/ci.yml) runs the full test suite on
Python 3.11/3.14 against PostgreSQL 16/18. It requires a live service before tests,
builds and reinstalls the wheel, exercises the installed CLI outside the checkout,
and uploads logs, environment evidence, the wheel, and the end-to-end report even
when a later step fails. Credentials in that workflow belong only to its disposable
synthetic database.

## Checking application pull requests

A useful baseline is a capture of the base revision's SQL against its schema and
representative data. Capture the candidate against the migrated schema with the
same data distribution, parameter cases, PostgreSQL major version, role, and
planner settings. Run `ANALYZE` after loading or changing data. A plan captured
against an empty database is not a representative baseline.

Use stable query/case IDs and identical parameters across revisions. Map SQL
builders, application callers, views, functions, and migrations in the manifest;
`--base` uses committed Git changes and declared mappings, not inferred application
dependencies. Put the manifest at a directory containing its SQL and dependency
paths. `*` matches one path segment; `**` can span directories. Manifest or mapped
migration changes select every registered query. Fetch complete Git history.

The following is an **adaptation example**, not a drop-in workflow. Before using
it, add a reviewed `ci/prepare_plan_db.sh` to your application that creates or
resets a disposable schema, applies that worktree's migrations, loads the same
deterministic fixtures, and runs `ANALYZE`. Make it read `PLAN_GUARD_DSN`; never
point it at a shared or production database. Change `plan-guard.json` to your
manifest path and install a reviewed release or pinned revision of this tool.
Provision a PostgreSQL service as in the repository workflow, and set both DSN
variables only to that service with synthetic credentials.

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  plans:
    runs-on: ubuntu-latest
    # Add the disposable PostgreSQL service and PLAN_GUARD_DSN env here.
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: actions/setup-python@v6
        with:
          python-version: '3.14'
      # Install your reviewed/pinned plan-guard release in this environment.
      - name: Capture base plans, then check candidate
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          mkdir -p artifacts
          git worktree add --detach ../plan-base "$BASE_SHA"
          (
            cd ../plan-base
            sh ci/prepare_plan_db.sh
            plan-guard capture --manifest plan-guard.json \
              --output "$GITHUB_WORKSPACE/artifacts/baseline.json"
          )
          sh ci/prepare_plan_db.sh
          plan-guard check --manifest plan-guard.json --base "$BASE_SHA" \
            --baseline artifacts/baseline.json \
            --output artifacts/check.json --markdown artifacts/check.md
      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: query-plan-evidence
          path: artifacts/
```

The two setup calls intentionally reset and reconstruct each revision's database
from the same deterministic fixture recipe. Alternatively, restore the same base
snapshot into two disposable databases and migrate only the candidate copy. Do
not capture base SQL against an already migrated candidate schema. New query IDs
have no baseline and trigger `BASELINE_MISSING`; review their plans and establish
an accepted baseline before treating regression coverage as complete.

Keep the workflow on ordinary `pull_request` with read-only repository permissions
and no private credentials. Do not run candidate SQL/code in `pull_request_target`
or attach production/network secrets to the job. Review the workflow and setup
scripts through your usual repository controls. PostgreSQL planning can evaluate
functions; read-only capture is not isolation for untrusted SQL.

## Interpreting the gate

The default `--fail-on warning` exits 1 for regressions, selective-scan advisories,
missing baseline coverage, or suppressed comparisons. Exit 2 means invalid input,
Git, or capture failure. Inspect the JSON/Markdown evidence before changing a
baseline or relaxing policy. Settings drift and relation-row drift over 25%
suppress regression conclusions; equal counts still do not prove equivalent
distributions or configurations.

An empty changed-query selection exits 0 with `NO_QUERIES_SELECTED` and explicit
selection metadata. It means no declared dependency matched; it is not proof of
application-wide coverage. Run without `--base` periodically to check all
registered query cases. N+1 candidates require a separate explicit request trace;
query plans alone cannot establish repeated application fetches.

Artifacts can contain predicate literals and database names despite hashed SQL
and parameters. Use synthetic fixtures and review artifacts before sharing them.
The workflow uses the official [checkout](https://github.com/actions/checkout),
[setup-python](https://github.com/actions/setup-python), and
[upload-artifact](https://github.com/actions/upload-artifact) actions; pin reviewed
action revisions when your repository requires immutable dependencies.
