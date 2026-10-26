#!/usr/bin/env python3
"""Exercise the installed CLI with a real PostgreSQL fixture and real Git PR.

Uses PLAN_GUARD_DSN, creates/removes one randomly named schema, and keeps reports
under the requested output directory. Run after installing the built wheel.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

import psycopg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='artifacts/e2e.json')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    evidence = output.parent / 'e2e-artifacts'
    evidence.mkdir(parents=True, exist_ok=True)
    dsn = os.environ.get('PLAN_GUARD_DSN')
    if not dsn:
        raise SystemExit('PLAN_GUARD_DSN is required (disposable test database)')
    schema = 'e2e_' + uuid.uuid4().hex
    environment = os.environ.copy()
    environment.pop('PYTHONPATH', None)
    environment.pop('PLAN_GUARD_UNSET_SYNTHETIC_DSN', None)
    repository = Path(__file__).resolve().parents[1]
    checks = []
    with tempfile.TemporaryDirectory(prefix='plan-guard-installed-') as directory:
        root = Path(directory)

        def run(*command, expected=0):
            completed = subprocess.run(command, cwd=root, env=environment,
                                       text=True, capture_output=True, timeout=60)
            if completed.returncode != expected:
                # Tool output deliberately has no DSN; retain it on failure.
                raise AssertionError(f'{command[0]} exit {completed.returncode}, expected {expected}: '
                                     f'{completed.stdout}\n{completed.stderr}')
            return completed.stdout.strip()

        def cli(*arguments, expected=0):
            return run(sys.executable, '-m', 'plan_guard', *arguments, expected=expected)

        module = Path(run(sys.executable, '-c', 'import plan_guard; print(plan_guard.__file__)')).resolve()
        if module.parent == repository / 'plan_guard':
            raise AssertionError('CLI resolved source checkout rather than installed package')
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(f'CREATE SCHEMA {schema}')
            try:
                conn.execute(f'CREATE TABLE {schema}.orders '
                             '(id integer PRIMARY KEY, customer_id integer, padding text)')
                conn.execute(f"INSERT INTO {schema}.orders SELECT i, i % 10000, repeat('x',80) "
                             'FROM generate_series(1,50000) i')
                conn.execute(f'CREATE INDEX customer_idx ON {schema}.orders(customer_id)')
                conn.execute(f'ANALYZE {schema}.orders')
                (root / 'queries').mkdir()
                (root / 'app').mkdir()
                (root / 'queries/lookup.sql').write_text(
                    f'SELECT id FROM {schema}.orders WHERE customer_id=%s\n')
                (root / 'queries/count.sql').write_text(f'SELECT count(*) FROM {schema}.orders\n')
                (root / 'app/list.py').write_text('# base application dependency\n')
                manifest = {'schema_version': 1, 'queries': [
                    {'id': 'lookup/typical', 'sql': 'queries/lookup.sql', 'params': [42],
                     'sources': ['app/list.py']},
                    {'id': 'count', 'sql': 'queries/count.sql', 'sources': ['app/count.py']},
                ], 'migrations': ['migrations/**']}
                (root / 'manifest.json').write_text(json.dumps(manifest))
                run('git', 'init', '-q', '-b', 'main')
                run('git', 'config', 'user.name', 'Synthetic Fixture')
                run('git', 'config', 'user.email', 'fixture@example.invalid')
                run('git', 'add', '.')
                run('git', 'commit', '-qm', 'Synthetic base')
                base = run('git', 'rev-parse', 'HEAD')
                baseline = evidence / 'baseline.json'
                cli('capture', '--manifest', 'manifest.json', '--output', str(baseline))
                cli('check', '--manifest', 'manifest.json', '--baseline', str(baseline),
                    '--output', str(evidence / 'control.json'))
                checks.append('indexed full baseline control: exit 0')
                (root / 'app/list.py').write_text('# changed application dependency\n')
                run('git', 'add', '.')
                run('git', 'commit', '-qm', 'Synthetic PR source change')
                conn.execute(f'DROP INDEX {schema}.customer_idx')
                regression = evidence / 'regression.json'
                cli('check', '--manifest', 'manifest.json', '--baseline', str(baseline),
                    '--base', base, '--output', str(regression),
                    '--markdown', str(evidence / 'regression.md'), expected=1)
                report = json.loads(regression.read_text())
                assert report['analyzed_query_ids'] == ['lookup/typical'], report
                assert report['removed_query_ids'] == [], report
                required = {'INDEX_TO_SEQ_SCAN', 'COST_REGRESSION', 'SELECTIVE_SEQ_SCAN'}
                assert required <= {finding['code'] for finding in report['findings']}, report
                cost = next(f['evidence'] for f in report['findings'] if f['code'] == 'COST_REGRESSION')
                checks.append('committed source PR selected only lookup; real index loss: exit 1')
                conn.execute(f'CREATE INDEX customer_idx ON {schema}.orders(customer_id)')
                cli('check', '--manifest', 'manifest.json', '--baseline', str(baseline),
                    '--base', base, '--output', str(evidence / 'restored.json'))
                checks.append('index restored control: exit 0')
                current = run('git', 'rev-parse', 'HEAD')
                (root / 'README.md').write_text('Synthetic documentation-only PR\n')
                run('git', 'add', '.')
                run('git', 'commit', '-qm', 'Synthetic docs-only PR')
                cli('check', '--manifest', 'manifest.json', '--baseline', str(baseline),
                    '--base', current, '--output', str(evidence / 'empty.json'))
                empty = json.loads((evidence / 'empty.json').read_text())
                assert empty['analyzed_query_ids'] == [], empty
                assert empty['findings'][0]['code'] == 'NO_QUERIES_SELECTED', empty
                checks.append('documentation-only PR: explicit empty scope, exit 0')
                events = [{'request_id': 'synthetic', 'query_id': 'parent',
                           'params_hash': 'root', 'role': 'parent'}]
                events.extend({'request_id': 'synthetic', 'query_id': 'lookup',
                               'params_hash': f'customer-{i}', 'role': 'child'} for i in range(8))
                (root / 'trace.json').write_text(json.dumps(events))
                cli('trace', '--input', 'trace.json', '--output', str(evidence / 'trace.json'), expected=1)
                checks.append('synthetic trace N+1 candidate: exit 1')
                cli('compare', '--baseline', str(baseline), '--candidate', str(baseline),
                    '--output', str(evidence / 'offline.json'))
                checks.append('offline identical-plan comparison: exit 0')
                cli('capture', '--manifest', 'manifest.json', '--output', str(evidence / 'error.json'),
                    '--dsn-env', 'PLAN_GUARD_UNSET_SYNTHETIC_DSN', expected=2)
                checks.append('missing connection environment: exit 2')
                result = {'schema_version': 1, 'checks': checks,
                          'postgres_version_num': conn.info.server_version,
                          'installed_module': str(module), 'fixture_rows': 50000,
                          'estimated_cost_evidence': cost, 'artifacts': str(evidence)}
                output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
                print(json.dumps(result, indent=2, sort_keys=True))
            finally:
                conn.execute(f'DROP SCHEMA {schema} CASCADE')


if __name__ == '__main__':
    main()
