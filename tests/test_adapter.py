import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from runtime import snapshot
from test_snapshot import fixture

spec = importlib.util.spec_from_file_location("adapt", Path(__file__).resolve().parents[1] / "scripts/adapt_generator.py")
adapt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapt)

SOURCE = """from pathlib import Path
BASE = Path(STATE)
def load_rules():
    return {'rule-providers': {}, 'rules': []}
def make_config(config, states):
    snippet = load_rules()
    return {
        'proxies': config['nodes'], 'traffic': states,
        'proxy-groups': [{'name': '节点选择', 'type': 'select', 'proxies': ['test-node']}],
        'rule-providers': snippet['rule-providers'], 'rules': snippet['rules'],
    }
"""

class AdapterTests(unittest.TestCase):
    def test_preserves_nodes_stats_and_legacy_then_accepts_preview_override(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(sys.modules, {"snapshot": snapshot}):
            scope = {"STATE": directory}
            exec(compile(adapt.adapt(SOURCE), "<adapter>", "exec"), scope)
            nodes, stats = [{"name": "test-node", "server": "example.invalid"}], [{"used_bytes": 123}]
            doc = scope["make_config"]({"nodes": nodes}, stats)
            self.assertEqual(doc["proxies"], nodes)
            self.assertEqual(doc["traffic"], stats)
            self.assertEqual(doc["rules"], [])
            m, inline, _ = fixture()
            new = scope["make_config"]({"nodes": nodes}, stats, snapshot_override=(m, inline))
            self.assertEqual(new["proxies"], nodes)
            self.assertEqual(new["traffic"], stats)
            self.assertEqual(len(new["proxy-groups"]), 1)
            self.assertEqual({p["format"] for p in new["rule-providers"].values()}, {"mrs"})

    def test_unknown_production_structure_and_double_patch_are_rejected(self):
        with self.assertRaises(ValueError):
            adapt.adapt(SOURCE.replace("snippet = load_rules()", "snippet = {}"))
        with self.assertRaises(ValueError):
            adapt.adapt(adapt.adapt(SOURCE))
