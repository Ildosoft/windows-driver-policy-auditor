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
    def test_unrelated_event_is_ignored(self):
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System></Event>'
        from driver_policy_auditor.events import parse_events_xml
        self.assertEqual(parse_events_xml(xml), [])
    def test_html_is_self_contained(self):
        target = Path(__file__).parent / "_report.html"
        try:
            write_html(target, {"status": {"read_only": True}, "findings": [{"timestamp":"now","event_id":3077,"category":"test","file_path":"<script>","policy_name":"fixture"}]})
            output = target.read_text(encoding="utf-8"); self.assertIn("read-only", output); self.assertNotIn("<script>", output)
        finally: target.unlink(missing_ok=True)

if __name__ == "__main__": unittest.main()
