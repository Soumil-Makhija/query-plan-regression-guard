"""Behavioral examples for estimated-plan analysis and request trace evidence."""

import copy
import json
import math
import unittest

from plan_guard.analysis import analyze_snapshot, analyze_trace


def scan(kind="Seq Scan", cost=200, rows=10, **extra):
    node = {"Node Type": kind, "Total Cost": cost, "Plan Rows": rows,
            "Schema": "public", "Relation Name": "orders", "Alias": "orders"}
    if kind == "Seq Scan":
        node["Filter"] = "(customer_id = 42)"
    node.update(extra)
    return node


def snapshot(node=None, table_rows=10000, indexes=None, query_id="orders"):
    return {"schema_version": 1,
            "context": {"server_version_num": 160003, "settings": {"random_page_cost": "4"}},
            "queries": {query_id: {"sql_sha256": "a" * 64, "params_sha256": "b" * 64,
                "plan": {"Plan": node if node is not None else scan()},
                "relations": {"public.orders": {"rows": table_rows, "indexes": indexes or []}}}}}


def codes(report):
    return [finding["code"] for finding in report["findings"]]


def trace(count=5, *, params=None, request="req-1", role="child"):
    result = [{"request_id": request, "query_id": "list-orders", "params_hash": "parent", "role": "parent"}]
    for i in range(count):
        result.append({"request_id": request, "query_id": "order-detail", "params_hash": str(i) if params is None else params,
                       "role": role, "duration_ms": 2.5})
    return result


class StaticPlanTests(unittest.TestCase):
    def test_large_selective_scan_advises_possible_missing_index(self):
        report = analyze_snapshot(snapshot())
        finding = report["findings"][0]
        self.assertEqual("SELECTIVE_SEQ_SCAN", finding["code"])
        self.assertEqual("warning", finding["severity"])
        self.assertEqual("possibly_missing_index", finding["evidence"]["advisory"])
        self.assertAlmostEqual(0.001, finding["evidence"]["estimated_selectivity"])
        self.assertEqual({"errors": 0, "warnings": 1, "infos": 0}, report["summary"])

    def test_existing_index_does_not_mean_it_can_satisfy_the_predicate(self):
        finding = analyze_snapshot(snapshot(indexes=["orders_created_at_idx"]))["findings"][0]
        self.assertEqual("possibly_unusable_index", finding["evidence"]["advisory"])
        self.assertIn("may be unusable", finding["message"])

    def test_small_table_and_broad_scan_and_unfiltered_scan_are_allowed(self):
        self.assertEqual([], analyze_snapshot(snapshot(table_rows=99))["findings"])
        self.assertEqual([], analyze_snapshot(snapshot(scan(rows=9000)))["findings"])
        node = scan()
        del node["Filter"]
        self.assertEqual([], analyze_snapshot(snapshot(node))["findings"])

    def test_thresholds_are_inclusive_and_can_be_configured(self):
        data = snapshot(scan(rows=200), table_rows=1000)
        self.assertIn("SELECTIVE_SEQ_SCAN", codes(analyze_snapshot(data)))
        self.assertNotIn("SELECTIVE_SEQ_SCAN", codes(analyze_snapshot(data, policy={"min_table_rows": 1001})))
        self.assertNotIn("SELECTIVE_SEQ_SCAN", codes(analyze_snapshot(data, policy={"max_selectivity": 0.19})))

    def test_nested_plan_scan_has_precise_node_path(self):
        node = {"Node Type": "Nested Loop", "Total Cost": 250, "Plan Rows": 10,
                "Plans": [scan("Index Scan", cost=20), scan()]}
        report = analyze_snapshot(snapshot(node))
        self.assertEqual("Plan.Plans[1]", report["findings"][0]["evidence"]["node_path"])
        self.assertNotIn("POTENTIAL_N_PLUS_ONE", codes(report))

    def test_parallel_per_worker_rows_do_not_generate_selectivity_claim(self):
        self.assertEqual([], analyze_snapshot(snapshot(scan(**{"Parallel Aware": True})))["findings"])
        self.assertEqual([], analyze_snapshot(snapshot(scan("Parallel Seq Scan", Filter="x = 1")))["findings"])

    def test_missing_relation_context_does_not_invent_table_size(self):
        data = snapshot()
        data["queries"]["orders"]["relations"] = {}
        self.assertEqual([], analyze_snapshot(data)["findings"])

    def test_input_is_immutable_and_report_is_deterministic_json(self):
        data = snapshot()
        before = copy.deepcopy(data)
        one, two = analyze_snapshot(data), analyze_snapshot(data)
        self.assertEqual(before, data)
        self.assertEqual(one, two)
        json.dumps(one, allow_nan=False)


class RegressionTests(unittest.TestCase):
    def test_index_to_seq_and_root_cost_regression(self):
        baseline = snapshot(scan("Index Scan", cost=50))
        candidate = snapshot(scan(cost=200))
        report = analyze_snapshot(candidate, baseline)
        self.assertEqual(["SELECTIVE_SEQ_SCAN", "INDEX_TO_SEQ_SCAN", "COST_REGRESSION"], codes(report))
        self.assertEqual(["orders"], report["compared_query_ids"])
        self.assertEqual(2, report["summary"]["errors"])

    def test_bitmap_heap_and_index_only_are_indexed_access(self):
        for kind in ("Bitmap Heap Scan", "Index Only Scan"):
            with self.subTest(kind=kind):
                self.assertIn("INDEX_TO_SEQ_SCAN", codes(analyze_snapshot(snapshot(), snapshot(scan(kind)))))

    def test_cost_requires_ratio_and_absolute_threshold(self):
        for old, new in ((10, 30), (1000, 1100), (200, 100)):
            with self.subTest(old=old, new=new):
                self.assertNotIn("COST_REGRESSION", codes(analyze_snapshot(snapshot(scan(cost=new)), snapshot(scan(cost=old)))))
        self.assertIn("COST_REGRESSION", codes(analyze_snapshot(snapshot(scan(cost=100)), snapshot(scan(cost=50)))))

    def test_only_root_cost_is_compared_without_summing_subtree_costs(self):
        old = {"Node Type": "Nested Loop", "Total Cost": 100, "Plan Rows": 1,
               "Plans": [scan(cost=20), scan(cost=20)]}
        new = {"Node Type": "Nested Loop", "Total Cost": 110, "Plan Rows": 1,
               "Plans": [scan(cost=100), scan(cost=100)]}
        self.assertNotIn("COST_REGRESSION", codes(analyze_snapshot(snapshot(new), snapshot(old))))

    def test_zero_cost_baseline_report_remains_finite_json(self):
        report = analyze_snapshot(snapshot(scan(cost=100)), snapshot(scan(cost=0)))
        finding = next(item for item in report["findings"] if item["code"] == "COST_REGRESSION")
        self.assertIsNone(finding["evidence"]["cost_ratio"])
        self.assertTrue(finding["evidence"]["zero_baseline_cost"])
        json.dumps(report, allow_nan=False)

    def test_row_drift_suppresses_regression_but_not_static_advisory(self):
        baseline = snapshot(scan("Index Scan", cost=20), table_rows=10000)
        candidate = snapshot(scan(cost=200), table_rows=12501)
        report = analyze_snapshot(candidate, baseline)
        self.assertEqual(["SELECTIVE_SEQ_SCAN", "CONTEXT_MISMATCH"], codes(report))
        self.assertEqual([], report["compared_query_ids"])
        self.assertEqual(["orders"], report["context_suppressed_query_ids"])
        candidate["queries"]["orders"]["relations"]["public.orders"]["rows"] = 12500
        self.assertIn("COST_REGRESSION", codes(analyze_snapshot(candidate, baseline)))

    def test_row_drift_suppression_is_per_query(self):
        baseline = snapshot(scan("Index Scan", cost=20))
        baseline["queries"]["steady"] = copy.deepcopy(baseline["queries"]["orders"])
        candidate = snapshot(scan(cost=200), table_rows=15000)
        candidate["queries"]["steady"] = copy.deepcopy(snapshot()["queries"]["orders"])
        report = analyze_snapshot(candidate, baseline)
        self.assertEqual(["steady"], report["compared_query_ids"])
        self.assertEqual(["orders"], report["context_suppressed_query_ids"])
        self.assertEqual(["steady"], [f["query_id"] for f in report["findings"] if f["code"] == "COST_REGRESSION"])

    def test_settings_change_suppresses_regressions(self):
        baseline = snapshot(scan("Index Scan", cost=20))
        candidate = snapshot()
        candidate["context"]["settings"]["random_page_cost"] = "1.1"
        self.assertEqual(["SELECTIVE_SEQ_SCAN", "CONTEXT_MISMATCH"], codes(analyze_snapshot(candidate, baseline)))

    def test_missing_relation_context_suppresses_regressions(self):
        baseline = snapshot(scan("Index Scan", cost=20))
        candidate = snapshot()
        candidate["queries"]["orders"]["relations"] = {}
        self.assertEqual(["CONTEXT_MISMATCH"], codes(analyze_snapshot(candidate, baseline)))

    def test_major_version_and_parameter_mismatch_fail_closed(self):
        baseline = snapshot()
        for change in ("major", "params"):
            candidate = copy.deepcopy(baseline)
            if change == "major":
                candidate["context"]["server_version_num"] = 170001
            else:
                candidate["queries"]["orders"]["params_sha256"] = "c" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                analyze_snapshot(candidate, baseline)
        candidate = copy.deepcopy(baseline)
        candidate["context"]["server_version_num"] = 160099
        self.assertEqual(["orders"], analyze_snapshot(candidate, baseline)["compared_query_ids"])

    def test_self_join_aliases_prevent_mismatched_scan_claim(self):
        old = {"Node Type": "Nested Loop", "Total Cost": 100, "Plan Rows": 1,
               "Plans": [scan("Index Scan", Alias="a"), scan(Alias="b")]}
        new = copy.deepcopy(old)
        new["Plans"] = [scan("Index Scan", Alias="a"), scan(Alias="c")]
        self.assertNotIn("INDEX_TO_SEQ_SCAN", codes(analyze_snapshot(snapshot(new), snapshot(old))))

    def test_new_removed_and_sql_changed_queries_are_distinguished(self):
        baseline = snapshot(query_id="gone")
        candidate = snapshot(query_id="new")
        report = analyze_snapshot(candidate, baseline)
        self.assertEqual(["new"], report["new_query_ids"])
        self.assertEqual(["gone"], report["removed_query_ids"])
        self.assertEqual([], report["compared_query_ids"])
        same_id = snapshot()
        changed = snapshot()
        changed["queries"]["orders"]["sql_sha256"] = "c" * 64
        self.assertEqual(["orders"], analyze_snapshot(changed, same_id)["compared_query_ids"])


class InvalidSnapshotTests(unittest.TestCase):
    def test_invalid_numbers_are_rejected(self):
        for value in (-1, math.nan, math.inf, -math.inf, True, "100", None, 10 ** 1000):
            for field in ("Total Cost", "Plan Rows", "Startup Cost"):
                with self.subTest(value=str(value)[:20], field=field), self.assertRaises(ValueError):
                    analyze_snapshot(snapshot(scan(**{field: value})))
        data = snapshot(table_rows=-1)
        with self.assertRaises(ValueError):
            analyze_snapshot(data)

    def test_signed_postgres_query_identifier_is_valid(self):
        data = snapshot()
        data['queries']['orders']['plan']['Query Identifier'] = -58789857489123456
        analyze_snapshot(data)

    def test_invalid_tree_shape_is_rejected(self):
        invalid = [None, [], {}, {"Node Type": "Seq Scan", "Total Cost": 2}, scan(Plans={}), scan(Plans=[None])]
        for node in invalid:
            data = snapshot()
            data["queries"]["orders"]["plan"]["Plan"] = node
            with self.subTest(node=node), self.assertRaises(ValueError):
                analyze_snapshot(data)
        cyclic = scan()
        cyclic["Plans"] = [cyclic]
        with self.assertRaisesRegex(ValueError, "cycle"):
            analyze_snapshot(snapshot(cyclic))

    def test_invalid_snapshot_context_and_policy_are_rejected(self):
        for mutation in (lambda s: s.update(schema_version=True),
                         lambda s: s["context"].update(server_version_num="160003"),
                         lambda s: s["context"].update(settings={"cost": math.nan}),
                         lambda s: s["queries"]["orders"].update(relations=[])):
            data = snapshot()
            mutation(data)
            with self.assertRaises(ValueError):
                analyze_snapshot(data)
        for policy in ({"surprise": 1}, {"cost_ratio": 1}, {"max_selectivity": 2}, {"cost_delta": -1}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                analyze_snapshot(snapshot(), policy=policy)

    def test_empty_snapshot_is_valid(self):
        data = snapshot()
        data["queries"] = {}
        self.assertEqual([], analyze_snapshot(data)["findings"])


class TraceTests(unittest.TestCase):
    def test_repeated_distinct_children_after_parent_are_only_a_candidate(self):
        report = analyze_trace(trace())
        finding = report["findings"][0]
        self.assertEqual("POTENTIAL_N_PLUS_ONE", finding["code"])
        self.assertEqual(5, finding["evidence"]["child_count"])
        self.assertEqual(5, finding["evidence"]["distinct_parameter_count"])
        self.assertEqual(12.5, finding["evidence"]["total_measured_duration_ms"])
        self.assertIn("not proof", finding["message"])

    def test_repeats_same_parameter_hash_are_not_n_plus_one(self):
        self.assertEqual([], analyze_trace(trace(20, params="same"))["findings"])

    def test_children_without_preceding_parent_are_not_candidates(self):
        events = trace()
        self.assertEqual([], analyze_trace(events[1:])["findings"])
        self.assertEqual([], analyze_trace(events[1:] + events[:1])["findings"])
        self.assertEqual([], analyze_trace(trace(role="other"))["findings"])

    def test_threshold_applies_within_request_and_query_identity(self):
        self.assertEqual([], analyze_trace(trace(4))["findings"])
        self.assertEqual([], analyze_trace(trace(3) + trace(3, request="req-2"))["findings"])
        events = trace(6)
        for event in events[4:]:
            event["query_id"] = "another-child"
        self.assertEqual([], analyze_trace(events)["findings"])
        self.assertEqual(1, len(analyze_trace(trace(3), min_repeats=3)["findings"]))

    def test_missing_durations_are_not_invented(self):
        events = trace()
        del events[1]["duration_ms"]
        evidence = analyze_trace(events)["findings"][0]["evidence"]
        self.assertEqual(4, evidence["measured_duration_count"])
        self.assertEqual(10, evidence["total_measured_duration_ms"])

    def test_invalid_trace_fails_before_returning_findings(self):
        for changed in ({"duration_ms": math.inf}, {"role": "unknown"}, {"params_hash": ""}, {"request_id": None}):
            events = trace()
            events[-1].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                analyze_trace(events)
        for repeats in (1, 0, True, 2.5):
            with self.subTest(repeats=repeats), self.assertRaises(ValueError):
                analyze_trace([], min_repeats=repeats)


if __name__ == "__main__":
    unittest.main()
