import unittest

from analyze_runtime import paired_deltas


class RuntimeAnalysisTests(unittest.TestCase):
    def test_pairs_by_repeat_before_summarizing(self):
        rows = [
            {"repeat": "3", "mode": "count", "bpf_ns_per_run": "32"},
            {"repeat": "1", "mode": "count", "bpf_ns_per_run": "10"},
            {"repeat": "2", "mode": "pass", "bpf_ns_per_run": "20"},
            {"repeat": "3", "mode": "pass", "bpf_ns_per_run": "30"},
            {"repeat": "1", "mode": "pass", "bpf_ns_per_run": "1"},
            {"repeat": "2", "mode": "count", "bpf_ns_per_run": "21"},
        ]
        self.assertEqual(paired_deltas(rows, "count", "pass"), [9, 1, 2])

    def test_rejects_missing_pass_trial(self):
        rows = [{"repeat": "1", "mode": "count", "bpf_ns_per_run": "10"}]
        with self.assertRaisesRegex(ValueError, "missing pass"):
            paired_deltas(rows, "count", "pass")
