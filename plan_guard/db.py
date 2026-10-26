"""Bounded, non-ANALYZE PostgreSQL plan capture for trusted CI databases.

This is not a SQL security sandbox: the planner may evaluate functions. Use a
restricted database role and disposable representative data. Plans may contain
literal values even though SQL text and parameters are hashed in our metadata.
"""
from __future__ import annotations

import hashlib
import json


class CaptureError(RuntimeError):
    """Capture failed; details are intentionally not rendered by the CLI."""


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False,
                                     separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _walk(node):
    yield node
    for child in node.get('Plans', []):
        yield from _walk(child)


def capture(manifest, query_ids, dsn, statement_timeout_ms=3000, lock_timeout_ms=500):
    """Capture one consistent read-only transaction, rolling it back on exit.

    Extended-protocol preparation rejects multiple SQL statements. SQL is a
    single PostgreSQL EXPLAINable statement, including DML (planned only).
    Connection/planning errors deliberately omit DSNs, SQL and parameter values.
    """
    import psycopg

    for name, value in [('statement timeout', statement_timeout_ms), ('lock timeout', lock_timeout_ms)]:
        if type(value) is not int or value <= 0 or value > 600000:
            raise ValueError(f'{name} must be an integer between 1 and 600000 ms')
    if not isinstance(dsn, str) or not dsn.strip():
        raise ValueError('Connection environment variable must be nonempty')
    if len(query_ids) != len(set(query_ids)) or any(q not in manifest['queries'] for q in query_ids):
        raise ValueError('Unknown or duplicate selected query ID')
    result = {'schema_version': 1, 'context': {}, 'queries': {}}
    if not query_ids:
        raise ValueError('No queries selected for capture')
    try:
        with psycopg.connect(dsn, connect_timeout=5, autocommit=False) as conn:
            try:
                conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                conn.execute("SELECT set_config('statement_timeout', %s, true)", [str(statement_timeout_ms)])
                conn.execute("SELECT set_config('lock_timeout', %s, true)", [str(lock_timeout_ms)])
                settings = dict(conn.execute("""
                    SELECT name, setting FROM pg_settings
                    WHERE category LIKE 'Query Tuning%'
                       OR name IN ('search_path', 'default_statistics_target',
                          'block_size', 'server_encoding', 'lc_collate', 'lc_ctype',
                          'work_mem', 'hash_mem_multiplier', 'shared_buffers',
                          'max_parallel_workers_per_gather', 'max_parallel_workers',
                          'max_worker_processes', 'plan_cache_mode', 'row_security')
                    ORDER BY name
                """).fetchall())
                settings['__current_user'] = conn.execute('SELECT current_user').fetchone()[0]
                settings['__current_schemas'] = conn.execute('SELECT current_schemas(true)').fetchone()[0]
                result['context'] = {
                    'server_version_num': conn.info.server_version,
                    'settings': settings,
                    'isolation': 'repeatable read', 'read_only': True,
                    'explain_analyze': False,
                }
                for query_id in sorted(query_ids):
                    query = manifest['queries'][query_id]
                    row = conn.execute(
                        'EXPLAIN (FORMAT JSON, VERBOSE TRUE, COSTS TRUE, ANALYZE FALSE, SETTINGS TRUE) '
                        + query['sql'], query['params'] or None, prepare=True,
                    ).fetchone()
                    if row is None or not isinstance(row[0], list) or len(row[0]) != 1:
                        raise CaptureError('Unexpected EXPLAIN response')
                    plan = row[0][0]
                    relations = {}
                    for node in _walk(plan['Plan']):
                        if 'Schema' not in node or 'Relation Name' not in node:
                            continue
                        schema, table = node['Schema'], node['Relation Name']
                        key = f'{schema}.{table}'
                        if key in relations:
                            continue
                        metadata = conn.execute("""
                            SELECT c.reltuples::float8,
                              ARRAY(SELECT ic.relname FROM pg_index i
                                    JOIN pg_class ic ON ic.oid=i.indexrelid
                                    WHERE i.indrelid=c.oid AND i.indisvalid
                                    ORDER BY ic.relname)
                            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                            WHERE n.nspname=%s AND c.relname=%s
                        """, [schema, table]).fetchone()
                        if metadata is None or metadata[0] < 0:
                            raise CaptureError('Missing relation statistics; ANALYZE the CI fixture database')
                        relations[key] = {'rows': metadata[0], 'indexes': metadata[1]}
                    result['queries'][query_id] = {
                        'sql_sha256': hashlib.sha256(query['sql'].encode()).hexdigest(),
                        'params_sha256': digest(query['params']),
                        'sql_path': query['sql_path'], 'plan': plan, 'relations': relations,
                    }
            finally:
                conn.rollback()
    except CaptureError:
        raise
    except (psycopg.Error, OSError, KeyError, TypeError) as exc:
        raise CaptureError('PostgreSQL capture failed; check connection, statement, statistics and timeouts') from exc
    return result
