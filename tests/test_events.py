import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from driver_policy_auditor.events import classify, load_events
from driver_policy_auditor.report import write_html

class EventTests(unittest.TestCase):
    def test_fixture_is_classified(self):
        findings = load_events(Path(__file__).parent / "fixtures" / "codeintegrity.xml")
        self.assertEqual([f.event_id for f in findings], [3077, 3033]); self.assertEqual(findings[0].category, "app-control-policy"); self.assertEqual(findings[1].category, "revoked-or-expired-signature")
    def test_signature_classification(self): self.assertEqual(classify(3004, "invalid signature"), "signature-requirement")
    def test_html_is_self_contained(self):
        target = Path(__file__).parent / "_report.html"
        try: write_html(target, {"status": {"read_only": True}, "findings": []}); self.assertIn("read-only", target.read_text(encoding="utf-8"))
        finally: target.unlink(missing_ok=True)

if __name__ == "__main__": unittest.main()
