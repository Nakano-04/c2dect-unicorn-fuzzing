"""Tests del prototipo extendido de triaje (datos sinteticos)."""

import unittest
from pathlib import Path

from crash_triage import (
    campaign_summary,
    coverage_summary,
    dedupe,
    fingerprint,
    load_json,
    minimize,
    reproducibility,
)

HERE = Path(__file__).resolve().parent
CRASHES = load_json(HERE / "fixtures" / "crashes.json")


class TestTriaje(unittest.TestCase):
    def test_dedupe(self):
        result = dedupe(CRASHES)
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["unique"], 3)
        self.assertEqual(result["groups"][0]["count"], 3)

    def test_fingerprint_ignora_metadata(self):
        a = {"signal": "SIGSEGV", "rip": "0x1000", "stack": "[ret]", "t": 1}
        b = {"signal": "SIGSEGV", "rip": "0x1000", "stack": "[ret]", "t": 999}
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_minimize(self):
        seed = b"xxxCRASHyyy"
        result = minimize(seed, lambda b: b"CRASH" in b)
        self.assertEqual(result, b"CRASH")

    def test_minimize_sin_disparador(self):
        result = minimize(b"abc", lambda b: False)
        self.assertNotIn(b"CRASH", result)


class TestCoberturaYReproducibilidad(unittest.TestCase):
    def test_cobertura_acumulada(self):
        cov = coverage_summary(CRASHES)
        self.assertEqual(cov["runs"], 5)
        self.assertEqual(cov["total_edges"], 5)
        self.assertEqual(sum(r["new_edges"] for r in cov["per_run"]), 5)

    def test_reproducibilidad(self):
        r = reproducibility(CRASHES)
        self.assertEqual(r["total"], 5)
        self.assertEqual(r["reproduced"], 3)
        self.assertEqual(r["rate"], 0.6)

    def test_reproducibilidad_vacia(self):
        self.assertIsNone(reproducibility([])["rate"])

    def test_resumen_campana(self):
        s = campaign_summary(CRASHES)
        self.assertIn("crashes", s)
        self.assertIn("coverage", s)
        self.assertIn("reproducibility", s)
        self.assertEqual(s["exec_per_unique_crash"], round(5 / 3, 4))


if __name__ == "__main__":
    unittest.main()
