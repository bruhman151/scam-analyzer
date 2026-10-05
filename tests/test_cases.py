"""Check the documented synthetic examples without treating them as an accuracy study."""

import json
from pathlib import Path
import unittest

from analyzer import analyze_text


CASES = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))


class DocumentedTextCasesTests(unittest.TestCase):
    def test_text_examples_match_the_documented_expectations(self):
        for case in CASES:
            if case["kind"] != "text":
                continue
            with self.subTest(case=case["id"]):
                result = analyze_text(case["content"])
                self.assertEqual(result["status"], case.get("expected_status", "analyzed"))
                self.assertEqual(result["risk"], case["expected_risk"])
                found = {signal["id"] for signal in result["signals"]}
                self.assertTrue(set(case["expected_signals"]).issubset(found))


if __name__ == "__main__":
    unittest.main()

