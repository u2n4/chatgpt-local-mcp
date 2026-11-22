"""Stage 1-2 Contract Tests: verifies all 33 original v0.2.0 tool names and V0.4.0 JSON Schemas."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]


class TestV040Contracts(unittest.TestCase):
    def test_v020_catalog_has_all_33_tools(self):
        cat_path = REPO / "schemas" / "v0.2.0-catalog.json"
        self.assertTrue(cat_path.is_file(), "v0.2.0-catalog.json missing")
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))
        self.assertEqual(len(catalog), 33)
        for required in ("bridge_info", "bridge_health", "project_list", "file_read", "git_status", "artifact_read"):
            self.assertIn(required, catalog)

    def test_v040_exported_schemas_exist_and_are_valid_json(self):
        expected = [
            "v0.4.0-task-grant.schema.json",
            "v0.4.0-durable-job.schema.json",
            "v0.4.0-patch-plan.schema.json",
            "v0.4.0-evidence-manifest.schema.json",
            "v0.4.0-structured-error.schema.json",
            "v0.4.0-device-identity.schema.json",
            "v0.4.0-telemetry-header.schema.json",
        ]
        for fname in expected:
            p = REPO / "schemas" / fname
            self.assertTrue(p.is_file(), f"Missing exported schema {fname}")
            obj = json.loads(p.read_text(encoding="utf-8"))
            self.assertIsInstance(obj, dict)


if __name__ == "__main__":
    unittest.main()
