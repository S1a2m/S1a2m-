from email.message import Message
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from site_review import review


class SiteReviewTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.scope = Path(temp.name) / "scope.json"
        self.url = "https://example.test/"
        self.scope.write_text(json.dumps({
            "activity": "https-header-review", "approved": True,
            "rules_reference": "test approval", "urls": [self.url],
        }), encoding="utf-8")

    @patch("site_review.build_opener")
    def test_get_reads_headers_and_leaves_body_unread(self, build):
        opener = build.return_value
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "text/html"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        result = review(self.url, self.scope)
        self.assertEqual([entry["header"] for entry in result["observations"]],
                         ["Content-Security-Policy", "X-Content-Type-Options"])
        self.assertEqual(result["cve_status"], "not_assessed")
        response.read.assert_not_called()
        opener.open.assert_called_once()
        self.assertEqual(opener.open.call_args.args[0].full_url, self.url)

    @patch("site_review.build_opener")
    def test_out_of_scope_url_is_rejected_before_network(self, build):
        with self.assertRaisesRegex(ValueError, "exact URL"):
            review(self.url + "other", self.scope)
        build.assert_not_called()

    @patch("site_review.build_opener")
    def test_redirect_is_an_incomplete_review(self, build):
        opener = build.return_value
        opener.open.side_effect = HTTPError(self.url, 301, "Moved", {
            "Location": "https://other.example.test/",
        }, None)
        result = review(self.url, self.scope)
        self.assertEqual(result["status"], "review_incomplete")
        opener.open.assert_called_once()
        self.assertIsNone(build.call_args.args[0].redirect_request(None, None, 301, "", {}, ""))
