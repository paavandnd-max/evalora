"""Focused behavioral and dispatch tests for Phase 2 DocGuard handlers."""

import io
import unittest
import zipfile

import server
from genuine_handlers import GENUINE_HANDLERS


def archive(*members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in members:
            zf.writestr(name, content)
    return out.getvalue()


class Phase2HandlerTests(unittest.TestCase):
    phase2_ids = [f"DG-{index:03d}" for index in range(1, 21)]

    def invoke(self, identifier, files, **extra):
        result = GENUINE_HANDLERS[identifier]({"files": files, **extra})
        self.assertEqual(result["id"], identifier)
        self.assertIn(result["state"], {"pass", "fail", "not_testable"})
        self.assertIn("detail", result)
        self.assertIsInstance(result["detail"], str)
        self.assertEqual(result["passed"], result["state"] == "pass")
        return result

    def test_all_phase2_ids_are_registered_and_dispatched(self):
        self.assertTrue(set(self.phase2_ids) <= set(GENUINE_HANDLERS))
        results = server.run_selected_catalogue_checks(
            self.phase2_ids,
            [{"name": "sample.pdf", "content": "%PDF-1.7\n%%EOF"}],
        )
        self.assertEqual([result["id"] for result in results], self.phase2_ids)
        for result in results:
            self.assertIn("state", result)
            self.assertIn("detail", result)

    def test_pdf_and_office_structure_checks(self):
        clean_pdf = {"name": "clean.pdf", "content_bytes": b"%PDF-1.7\n%%EOF"}
        clean_docx = {"name": "clean.docx", "content_bytes": archive(("[Content_Types].xml", "<Types/>"), ("word/document.xml", "<document/>"))}
        macro_docm = {"name": "macro.docm", "content_bytes": archive(("[Content_Types].xml", "macroEnabledMain"), ("word/document.xml", "<document/>"), ("word/vbaProject.bin", "metadata"))}
        self.assertEqual(self.invoke("DG-001", [clean_pdf])["state"], "pass")
        self.assertEqual(self.invoke("DG-002", [clean_docx])["state"], "pass")
        self.assertEqual(self.invoke("DG-003", [macro_docm])["state"], "pass")
        self.assertEqual(self.invoke("DG-004", [macro_docm])["state"], "pass")
        self.assertEqual(self.invoke("DG-005", [clean_docx])["state"], "pass")
        self.assertEqual(self.invoke("DG-007", [clean_pdf, clean_docx])["state"], "pass")

    def test_archive_safety_checks_reject_specific_bad_evidence(self):
        nested = {"name": "outer.zip", "content_bytes": archive(("inner.zip", "nested"))}
        traversal = {"name": "unsafe.zip", "content_bytes": archive(("../escape.txt", "bad"))}
        renamed = {"name": "notes.txt", "content_bytes": b"MZ" + b"\x00" * 10}
        duplicate_a = {"name": "a.txt", "content": "same"}
        duplicate_b = {"name": "a.txt", "content": "same"}
        self.assertEqual(self.invoke("DG-010", [nested])["state"], "fail")
        self.assertEqual(self.invoke("DG-011", [traversal])["state"], "fail")
        self.assertEqual(self.invoke("DG-009", [renamed])["state"], "fail")
        self.assertEqual(self.invoke("DG-019", [duplicate_a, duplicate_b])["state"], "fail")

    def test_submission_boundaries_and_missing_evidence(self):
        self.assertEqual(self.invoke("DG-017", [{"name": "empty.txt", "content": ""}])["state"], "fail")
        self.assertEqual(self.invoke("DG-018", [{"name": "a.txt", "content": "a"}, {"name": "b.txt", "content": "b"}])["state"], "pass")
        self.assertEqual(self.invoke("DG-016", [{"name": "large.txt", "content": "x" * 20}], max_file_bytes=10)["state"], "fail")
        for identifier in self.phase2_ids:
            result = self.invoke(identifier, [])
            self.assertNotEqual(result["state"], "pass")


if __name__ == "__main__":
    unittest.main()
