import unittest
import server
from genuine_handlers import GENUINE_HANDLERS


PASS = {
    "REL-001": [{"name":"main.py","content":"if __name__ == '__main__':\n    run()"}],
    "REL-002": [{"name":".env.example","content":"TOKEN=placeholder"},{"name":"app.py","content":"import os\nos.getenv('TOKEN')"}],
    "REL-004": [{"name":"app.py","content":"try:\n    run()\nexcept Exception:\n    recover()"}],
    "REL-005": [{"name":"app.py","content":"subprocess.run(cmd, timeout=5)"}],
    "DEP-001": [{"name":"requirements.txt","content":"requests>=2"}],
    "DEP-002": [{"name":"README.md","content":"deployment"}],
    "DEP-003": [{"name":"index.html","content":"<script>fetch('/api')</script>"},{"name":"api.py","content":"@app.get('/api')\ndef api(): pass"}],
    "DEP-004": [{"name":"config.py","content":"DEBUG = False\nENV='production'"}],
    "UX-001": [{"name":"index.html","content":"<a href='/'>Home</a><a href='/about'>About</a>"}],
    "UX-002": [{"name":"index.html","content":"<input required aria-invalid='false'>"}],
    "UX-003": [{"name":"app.js","content":"const isLoading = true;"}],
    "UX-004": [{"name":"app.js","content":"return 'No results';"}],
    "UX-005": [{"name":"app.js","content":"return 'Try again';"}],
    "UX-006": [{"name":"style.css","content":"@media (max-width:600px) {}"}],
    "UX-007": [{"name":"app.js","content":"onKeyDown={handleKey}"}],
    "UX-008": [{"name":"index.html","content":"<label for='x'>Name</label>"}],
    "UX-009": [{"name":"style.css","content":".text { color: #111; }"}],
    "UX-010": [{"name":"app.js","content":"localStorage.setItem('x','1');"}],
    "UX-011": [{"name":"app.js","content":"if (expired) redirect('/login');"}],
    "UX-012": [{"name":"app.js","content":"console.log('ok');"}],
}

NEGATIVE = {
    "REL-001": [{"name":"README.md","content":"docs"}], "REL-002": [{"name":"app.py","content":"os.getenv('TOKEN')"}],
    "REL-004": [{"name":"app.py","content":"run()"}], "REL-005": [{"name":"app.py","content":"run()"}],
    "DEP-001": [{"name":"README.md","content":"run"}], "DEP-002": [{"name":"README.md","content":"run"}],
    "DEP-003": [{"name":"index.html","content":"<main>static</main>"}], "DEP-004": [{"name":"config.py","content":"DEBUG=True"}],
    "UX-001": [{"name":"index.html","content":"<a href='/'>Home</a>"}], "UX-002": [{"name":"index.html","content":"<input>"}],
    "UX-003": [{"name":"app.js","content":"submit();"}], "UX-004": [{"name":"app.js","content":"render(items);"}],
    "UX-005": [{"name":"app.js","content":"fetch(url);"}], "UX-006": [{"name":"style.css","content":".x{}"}],
    "UX-007": [{"name":"index.html","content":"<div>Go</div>"}], "UX-008": [{"name":"index.html","content":"<button>Go</button>"}],
    "UX-009": [{"name":"style.css","content":".x{margin:1px}"}], "UX-010": [{"name":"app.js","content":"render();"}],
    "UX-011": [{"name":"app.js","content":"login();"}], "UX-012": [{"name":"app.js","content":"console.error('bad');"}],
}


class Phase1HandlerTests(unittest.TestCase):
    def test_each_handler_has_independent_positive_negative_missing_malformed_and_pipeline_paths(self):
        ids = sorted(PASS)
        self.assertEqual(len(ids), 20)
        for cid in ids:
            with self.subTest(cid=cid):
                self.assertEqual(GENUINE_HANDLERS[cid]({"files": PASS[cid], "repository_url": "https://github.com/o/r"})["state"], "pass")
                self.assertEqual(GENUINE_HANDLERS[cid]({"files": NEGATIVE[cid], "repository_url": "http://example.com/r"})["state"], "fail")
                self.assertEqual(GENUINE_HANDLERS[cid]({})["state"], "not_testable")
                malformed = GENUINE_HANDLERS[cid]({"files": ["not-a-file"]})
                self.assertIn(malformed["state"], {"fail", "not_testable"})
                dispatched = server.run_selected_catalogue_checks([cid], PASS[cid], "https://github.com/o/r")
                self.assertEqual(dispatched[0]["id"], cid)
                self.assertEqual(dispatched[0]["state"], "pass")

    def test_unimplemented_nearby_catalogue_id_remains_not_selectable(self):
        with self.assertRaises(ValueError):
            server.run_selected_catalogue_checks(["REL-003"], PASS["REL-001"])


if __name__ == "__main__":
    unittest.main()
