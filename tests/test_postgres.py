"""Real PostgreSQL tests. Opt in with PLAN_GUARD_TEST_DSN (disposable DB).

Each class creates and removes only its own randomly named schema.
"""
import os
import unittest
import uuid

from plan_guard.analysis import analyze_snapshot
from plan_guard.db import CaptureError, capture


@unittest.skipUnless(os.environ.get('PLAN_GUARD_TEST_DSN'), 'PLAN_GUARD_TEST_DSN not configured')
class PostgresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        cls.dsn = os.environ['PLAN_GUARD_TEST_DSN']
        cls.schema = 'guard_' + uuid.uuid4().hex
        cls.conn = psycopg.connect(cls.dsn, autocommit=True)
        cls.conn.execute(f'CREATE SCHEMA {cls.schema}')
        cls.conn.execute(f'''CREATE TABLE {cls.schema}.orders
            (id integer PRIMARY KEY, customer_id integer, padding text)''')
        cls.conn.execute(f'''INSERT INTO {cls.schema}.orders
            SELECT i, i % 10000, repeat('x', 80) FROM generate_series(1,50000) i''')
        cls.conn.execute(f'CREATE INDEX customer_idx ON {cls.schema}.orders(customer_id)')
        cls.conn.execute(f'ANALYZE {cls.schema}.orders')

    @classmethod
    def tearDownClass(cls):
        cls.conn.execute(f'DROP SCHEMA {cls.schema} CASCADE')
        cls.conn.close()

    def manifest(self, sql=None, params=None):
        return {'queries': {'orders': {
            'sql': sql or f'SELECT id FROM {self.schema}.orders WHERE customer_id=%s',
            'params': [42] if params is None else params, 'sql_path': 'queries/orders.sql',
        }}}

    def collect(self, manifest=None, **kwargs):
        return capture(manifest or self.manifest(), ['orders'], self.dsn, **kwargs)

    def test_real_index_loss_and_restoration(self):
        baseline = self.collect()
        try:
            self.conn.execute(f'DROP INDEX {self.schema}.customer_idx')
            candidate = self.collect()
            report = analyze_snapshot(candidate, baseline)
            codes = {f['code'] for f in report['findings']}
            self.assertTrue({'SELECTIVE_SEQ_SCAN', 'INDEX_TO_SEQ_SCAN', 'COST_REGRESSION'} <= codes, report)
            self.assertGreater(candidate['queries']['orders']['plan']['Plan']['Total Cost'],
                               baseline['queries']['orders']['plan']['Plan']['Total Cost'])
        finally:
            self.conn.execute(f'CREATE INDEX IF NOT EXISTS customer_idx ON {self.schema}.orders(customer_id)')
        restored = analyze_snapshot(self.collect(), baseline)
        self.assertEqual(restored['summary']['errors'], 0, restored)

    def test_explain_does_not_execute_sleep_or_dml(self):
        snap = self.collect(self.manifest('SELECT pg_sleep(5)', []), statement_timeout_ms=250)
        self.assertNotIn('Execution Time', snap['queries']['orders']['plan'])
        self.assertNotIn('Actual Rows', snap['queries']['orders']['plan']['Plan'])
        self.collect(self.manifest(f'INSERT INTO {self.schema}.orders VALUES (999999, 1, %s)', ['new']))
        self.assertEqual(self.conn.execute(f'SELECT count(*) FROM {self.schema}.orders WHERE id=999999').fetchone()[0], 0)
        self.assertTrue(snap['context']['read_only'])

    def test_bound_parameter_is_not_executed_as_sql(self):
        text = f"x'; DROP TABLE {self.schema}.orders; --"
        snap = self.collect(self.manifest(f'SELECT id FROM {self.schema}.orders WHERE padding=%s', [text]))
        self.assertEqual(len(snap['queries']), 1)
        self.assertEqual(self.conn.execute(f'SELECT count(*) FROM {self.schema}.orders').fetchone()[0], 50000)
        self.assertNotIn('params', snap['queries']['orders'])

    def test_multiple_statements_rejected_and_connection_recovers(self):
        with self.assertRaises(CaptureError):
            self.collect(self.manifest(f'SELECT 1; DROP TABLE {self.schema}.orders', []))
        self.assertIn('orders', self.collect()['queries'])

    def test_lock_timeout_and_rollback_recovery(self):
        import psycopg
        with psycopg.connect(self.dsn) as blocker:
            blocker.execute(f'LOCK TABLE {self.schema}.orders IN ACCESS EXCLUSIVE MODE')
            with self.assertRaises(CaptureError):
                self.collect(statement_timeout_ms=500, lock_timeout_ms=25)
            blocker.rollback()
        self.assertIn('orders', self.collect()['queries'])

    def test_statistics_required_for_relation_analysis(self):
        name = f'{self.schema}.unanalyzed'
        self.conn.execute(f'CREATE TABLE {name} (id integer)')
        try:
            with self.assertRaisesRegex(CaptureError, 'statistics'):
                self.collect(self.manifest(f'SELECT * FROM {name}', []))
        finally:
            self.conn.execute(f'DROP TABLE {name}')

    def test_statement_timeout_bounds_planner_function_evaluation(self):
        name = f'{self.schema}.slow_plan'
        self.conn.execute(f"""CREATE FUNCTION {name}(integer) RETURNS integer
            LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM pg_sleep(1); RETURN $1; END $$""")
        try:
            with self.assertRaises(CaptureError):
                self.collect(self.manifest(f'SELECT {name}(42)', []), statement_timeout_ms=25)
        finally:
            self.conn.execute(f'DROP FUNCTION {name}(integer)')
        self.assertIn('orders', self.collect()['queries'])

    def test_work_mem_change_suppresses_regression_conclusions(self):
        from psycopg.conninfo import make_conninfo
        baseline = self.collect()
        dsn = make_conninfo(self.dsn, options='-c work_mem=64MB')
        candidate = capture(self.manifest(), ['orders'], dsn)
        report = analyze_snapshot(candidate, baseline)
        self.assertEqual(report['context_suppressed_query_ids'], ['orders'])
        self.assertIn('CONTEXT_MISMATCH', {f['code'] for f in report['findings']})

    def test_static_percent_sql_without_parameters(self):
        snap = self.collect(self.manifest("SELECT 10 % 3, 'hello' LIKE 'hell%'", []))
        self.assertIn('orders', snap['queries'])

    def test_planner_resource_settings_are_recorded(self):
        snap = self.collect()
        for key in ('work_mem', 'plan_cache_mode', 'max_parallel_workers_per_gather',
                    'row_security', '__current_user', '__current_schemas'):
            self.assertIn(key, snap['context']['settings'])

    def test_invalid_limits_and_queries_rejected(self):
        for value in (0, -1, True, 600001):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collect(statement_timeout_ms=value)
        with self.assertRaises(ValueError):
            capture(self.manifest(), ['missing'], self.dsn)


if __name__ == '__main__':
    unittest.main()
