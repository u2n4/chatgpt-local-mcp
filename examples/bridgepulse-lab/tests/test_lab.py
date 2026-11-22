from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from bridgepulse_lab.baseline import compare_baselines, export_comparison_report
from bridgepulse_lab.measurements import ValidationLimits, analyze_csv_dataset, convert_to_si

FIXTURE_CSV = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_airspeed_dataset.csv"


class TestBridgePulseLab(unittest.TestCase):
    def test_knots_to_mps_exact_international_factor(self):
        val, unit = convert_to_si(20.0, "kt")
        self.assertEqual(unit, "m/s")
        # Exact international knot = 1852/3600 = 0.5144444444 m/s -> 20 kt = 10.2888888889 m/s
        self.assertAlmostEqual(val, 10.288889, places=5)

    def test_feet_and_celsius_conversions(self):
        m, u_m = convert_to_si(100.0, "ft")
        self.assertEqual(u_m, "m")
        self.assertAlmostEqual(m, 30.48, places=4)
        k, u_k = convert_to_si(25.0, "C")
        self.assertEqual(u_k, "K")
        self.assertAlmostEqual(k, 298.15, places=4)

    def test_unknown_unit_raises_value_error(self):
        with self.assertRaises(ValueError):
            convert_to_si(10.0, "furlongs/fortnight")

    def test_synthetic_csv_filters_stale_missing_and_out_of_range(self):
        ref = datetime(2026, 11, 19, 0, 0, 20, tzinfo=timezone.utc)
        rep = analyze_csv_dataset(
            FIXTURE_CSV,
            limits=ValidationLimits(min_value=0.0, max_value=100.0, max_stale_seconds=60.0),
            reference_time_utc=ref,
            dataset_label="synthetic_airspeed_fixture",
            evidence_class="software_unit",
        )
        self.assertTrue(rep["synthetic_data"])
        self.assertEqual(rep["counts"]["total_rows"], 6)
        self.assertEqual(rep["counts"]["valid_rows"], 3)
        self.assertEqual(rep["counts"]["stale_rows"], 1)
        self.assertEqual(rep["counts"]["out_of_range_rows"], 1)
        self.assertEqual(rep["counts"]["missing_rows"], 1)
        # Mean of (20*0.5144444444, 30*0.5144444444, 15.433333) = 13.718518 m/s
        self.assertAlmostEqual(rep["metrics"]["mean"], 13.718518, places=4)

    def test_baseline_comparison_and_export(self):
        before = {
            "identity": {"manifest_id": "evid_before"},
            "environment": {"host_name": "HOST-A"},
            "source": {"source_hash_after": "aaa"},
            "time": {"monotonic_duration_ms": 120},
            "tests": {"executed": 5, "passed": 4, "failed": 1},
            "conclusions": {"overall_verdict": "FAIL"},
        }
        after = {
            "identity": {"manifest_id": "evid_after"},
            "environment": {"host_name": "HOST-A"},
            "source": {"source_hash_after": "bbb"},
            "time": {"monotonic_duration_ms": 115},
            "tests": {"executed": 5, "passed": 5, "failed": 0},
            "conclusions": {"overall_verdict": "PASS"},
        }
        cmp_res = compare_baselines(before, after)
        self.assertEqual(cmp_res["verdict_transition"], "FAIL -> PASS")
        self.assertTrue(cmp_res["source_hash_changed"])
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_comparison_report(cmp_res, None, Path(tmp))
            self.assertTrue(Path(paths["json_path"]).is_file())
            self.assertTrue(Path(paths["markdown_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
