#!/usr/bin/env python3
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_export42 as se

class SigmaExport(unittest.TestCase):
    def test_sigma_fires_and_silent(self):
        finding = {"rule":"java-sql-injection","snippet":"executeQuery","path":"src/Dao.java","line":1}
        pos = ["foo executeQuery bar"]
        neg = ["safe placeholder"]
        r = se.export_sigma(finding, pos, neg)
        self.assertTrue(r["exported"])
        self.assertTrue(r["positive_test"]["all_fired"])
        self.assertTrue(r["negative_test"]["silent"])

    def test_gate_blocks_negative(self):
        finding = {"rule":"java-sql-injection","snippet":"executeQuery","path":"src/Dao.java","line":1}
        pos = ["executeQuery"]
        neg = ["executeQuery in negative"]
        with self.assertRaises(se.SigmaExportError):
            se.export_sigma(finding, pos, neg)

    def test_gate_blocks_positive_miss(self):
        finding = {"rule":"java-sql-injection","snippet":"executeQuery","path":"src/Dao.java","line":1}
        with self.assertRaises(se.SigmaExportError):
            se.export_sigma(finding, ["no match"], ["safe"])

    def test_yara_fires_and_silent(self):
        finding = {"rule":"java-xss-reflected","snippet":"innerHTML","path":"a.js","line":2}
        pos = ["elem.innerHTML = x"]
        neg = ["textContent"]
        r = se.export_yara(finding, pos, neg)
        self.assertTrue(r["exported"])

    def test_conversion(self):
        finding = {"rule":"py-sql-injection","snippet":"SELECT","path":"app.py","line":5}
        sigma = se.finding_to_sigma(finding)
        self.assertIn("selection", sigma["detection"])
        yara = se.finding_to_yara(finding)
        self.assertIn("rule Attestor", yara)

if __name__ == "__main__":
    unittest.main()
