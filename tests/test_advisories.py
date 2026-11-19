import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

from advisories import assess_version, report


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.scope = self.write_json("scope.json", {
            "activity": "offline-advisory-review", "approved": True,
            "rules_reference": "synthetic approval", "assets": ["test-service"],
        })
        self.inventory = self.write_json("inventory.json", {
            "components": [
                {"asset": "test-service", "ecosystem": "PyPI",
                 "name": "Demo_Lib", "version": version}
                for version in ["1.9", "2.0", None]
            ],
        })
        self.archive = self.root / "osv.zip"

    def write_json(self, filename, content):
        path = self.root / filename
        path.write_text(json.dumps(content), encoding="utf-8")
        return path

    def test_bulk_cli_maps_and_prioritizes_inventory(self):
        advisory = {
            "id": "TEST-2026-A", "aliases": ["CVE-2026-999001"],
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T12:00:00+02:00",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "0"}, {"fixed": "2.0"}]}]}],
        }
        second = dict(advisory, id="TEST-2026-B", aliases=["CVE-2026-999002"])
        with ZipFile(self.archive, "w") as archive:
            for index, row in enumerate([
                advisory, advisory, second,
                dict(advisory, published="2025-12-31T23:59:59Z"),
                dict(advisory, withdrawn="2026-03-01T00:00:00Z"),
                dict(advisory, published=None),
            ]):
                archive.writestr(f"{index}.json", json.dumps(row))
        kev = self.write_json("kev.json", {"vulnerabilities": [{"cveID": "CVE-2026-999002"}]})
        epss = self.root / "epss.csv.gz"
        with gzip.open(epss, "wt", encoding="utf-8") as stream:
            stream.write("#score_date:2026-03-02\ncve,epss\nCVE-2026-999001,0.5\n")
        entry = Path(__file__).resolve().parents[1] / "hunter.py"
        run = subprocess.run([
            sys.executable, str(entry), "advisories", "--scope", str(self.scope),
            "--inventory", str(self.inventory), "--osv", str(self.archive),
            "--kev", str(kev), "--epss", str(epss),
        ], check=True, capture_output=True, text=True)
        result = json.loads(run.stdout)
        self.assertEqual(result["coverage"], {
            "records_read": 6, "published_in_year": 3, "missing_publication": 1, "withdrawn": 1,
        })
        rows = result["findings"]
        self.assertEqual([(row["advisory"], row["status"]) for row in rows], [
            ("TEST-2026-B", "version_match"), ("TEST-2026-A", "version_match"),
            ("TEST-2026-B", "review_required"), ("TEST-2026-A", "review_required"),
        ])
        self.assertEqual(rows[0]["kev"], ["CVE-2026-999002"])
        self.assertEqual(rows[1]["epss"], 0.5)
        self.assertEqual(rows[1]["version"], "1.9")
        self.assertEqual(result["sources"]["epss_score_date"], "2026-03-02")
        self.assertEqual(result["sources"]["osv"][0]["latest_record_modified_utc"],
                         "2026-01-02T10:00:00+00:00")
        self.assertEqual(result["component_coverage"], {
            "no_advisory_data": 0, "no_version_match": 1, "version_match": 1, "review_required": 1,
        })

    def test_php_vendor_advisories_across_all_four_release_lines(self):
        versions = ["8.2.34", "8.3.35", "8.4.26", "8.5.11",
                    "8.2.35", "8.3.36", "8.4.27", "8.5.12", None]
        inventory = self.write_json("php.json", {"components": [
            {"asset": "test-service", "ecosystem": "PHP", "name": "php-src", "version": version}
            for version in versions
        ] + [{"asset": "test-service", "ecosystem": "PHP", "name": "unmapped", "version": "1.0.0"}]})
        data = Path(__file__).resolve().parents[1] / "data" / "php"
        result = report(self.scope, inventory, sorted(data.glob("*.json")))
        self.assertEqual(result["component_coverage"], {
            "no_advisory_data": 1, "no_version_match": 4, "version_match": 4, "review_required": 1,
        })
        for cve in ["CVE-2026-109618", "CVE-2026-109619"]:
            rows = [row for row in result["findings"] if cve in row["cves"]]
            self.assertEqual({row["version"] for row in rows}, set(versions[:4] + [None]))
            self.assertTrue(all(row["references"] for row in rows))

    def test_rejects_unapproved_asset_before_opening_feed(self):
        inventory = self.write_json("other.json", {
            "components": [{"asset": "test-service-other", "ecosystem": "PyPI",
                            "name": "demo-lib", "version": "1.9"}],
        })
        with self.assertRaisesRegex(ValueError, "outside approved scope"):
            report(self.scope, inventory, [self.archive])

    def test_semver_boundaries_and_unsupported_ordering(self):
        affected = {"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0.0-beta.2"}, {"last_affected": "1.0.0"},
        ]}]}
        self.assertEqual(assess_version("1.0.0-beta.10", "npm", affected)[0], "version_match")
        self.assertEqual(assess_version("1.0.0+local", "npm", affected)[0], "version_match")
        self.assertIsNone(assess_version("1.0.1", "npm", affected))
        self.assertEqual(assess_version("latest", "npm", affected)[0], "review_required")
        affected["ranges"][0]["type"] = "ECOSYSTEM"
        self.assertEqual(assess_version("1.0.1", "npm", affected)[0], "review_required")
