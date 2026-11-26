import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bench


class AttachmentLookupTests(unittest.TestCase):
    def test_reads_generic_xdp_from_receiver_namespace(self):
        output = [{"xdp": {"attached": [
            {"mode": 1, "prog": {"id": 12}},
            {"mode": 2, "prog": {"id": 21}},
        ]}}]
        with patch.object(bench, "run", return_value=SimpleNamespace(stdout=json.dumps(output))) as run:
            self.assertEqual(bench.attached_program_id("receiver", "xdp-pass"), "21")
        run.assert_called_once_with("ip", "-j", "-n", "receiver", "link",
                                    "show", "dev", "rx0", capture_output=True)

    def test_reads_tc_ingress_and_ignores_header_row(self):
        output = [{"kind": "bpf"}, {"kind": "bpf", "options": {"prog": {"id": 42}}}]
        with patch.object(bench, "run", return_value=SimpleNamespace(stdout=json.dumps(output))) as run:
            self.assertEqual(bench.attached_program_id("receiver", "tc"), "42")
        run.assert_called_once_with("ip", "netns", "exec", "receiver", "tc", "-j",
                                    "filter", "show", "dev", "rx0", "ingress",
                                    capture_output=True)
