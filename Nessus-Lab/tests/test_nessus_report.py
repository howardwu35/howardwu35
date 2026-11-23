import csv
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import nessus_report as nr  # noqa: E402

FX = os.path.join(HERE, "fixtures")
BASE = os.path.join(FX, "synthetic_baseline.nessus")
RESCAN = os.path.join(FX, "synthetic_rescan.nessus")
KEV = os.path.join(FX, "synthetic_kev.csv")
ASSETS = os.path.join(ROOT, "assets.example.csv")


class ParseTests(unittest.TestCase):
    def test_info_filtered_by_default(self):
        findings, hosts = nr.parse_nessus(BASE)
        self.assertEqual(len(hosts), 2)
        self.assertTrue(all(f.severity >= 1 for f in findings))
        self.assertEqual(len(findings), 14)

    def test_info_included_on_request(self):
        findings, _ = nr.parse_nessus(BASE, include_info=True)
        self.assertEqual(len(findings), 16)

    def test_fields(self):
        findings, _ = nr.parse_nessus(BASE)
        ms17 = next(f for f in findings if f.plugin_id == "97833")
        self.assertEqual(ms17.severity_name, "Critical")
        self.assertEqual(ms17.vpr, 9.7)
        self.assertIn("CVE-2017-0144", ms17.cves)
        self.assertTrue(ms17.exploit_available)
        self.assertEqual(ms17.exploit_frameworks, ["Metasploit"])


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.findings, _ = nr.parse_nessus(BASE)
        nr.enrich(self.findings, nr.load_assets(ASSETS), nr.load_kev(KEV))

    def test_kev_flag(self):
        self.assertTrue(next(f for f in self.findings if f.plugin_id == "97833").in_kev)
        self.assertFalse(next(f for f in self.findings if f.plugin_id == "57608").in_kev)

    def test_criticality_raises_risk(self):
        # Same CVSS on a high-criticality asset scores above medium criticality
        f = nr.Finding("h", "1.1.1.1", "", "", "80", "tcp", "www", "1", "x", "fam", 2, "Medium",
                       5.0, None, None)
        f.asset_criticality = "medium"; nr.score_finding(f); medium = f.risk_score
        f.asset_criticality = "high"; nr.score_finding(f)
        self.assertGreater(f.risk_score, medium)

    def test_cap(self):
        self.assertTrue(all(f.risk_score <= 10.0 for f in self.findings))


class OutputTests(unittest.TestCase):
    def test_report_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            rc = nr.main(["report", BASE, "-o", d, "--assets", ASSETS, "--kev", KEV])
            self.assertEqual(rc, 0)
            for name in ("findings.csv", "poam.csv", "report.md"):
                self.assertTrue(os.path.getsize(os.path.join(d, name)) > 0)
            with open(os.path.join(d, "poam.csv"), newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 14)  # one POA&M item per unique plugin
            crit = [r for r in rows if r["Original Risk Rating"] == "Critical"]
            self.assertTrue(all(r["Scheduled Completion Date"] == "2026-12-01" for r in crit))

    def test_diff(self):
        base, _ = nr.parse_nessus(BASE)
        new, _ = nr.parse_nessus(RESCAN)
        rem, per, intro = nr.diff_scans(base, new)
        self.assertEqual((len(rem), len(per), len(intro)), (7, 7, 1))


if __name__ == "__main__":
    unittest.main()
