import tempfile
import unittest
from pathlib import Path
from src.pipeline import kev_records,evaluate,priority,load_qualys_csv,load_trivy_json,epss_scores,write_outputs

TEST_KEV={'catalogVersion':'test','dateReleased':'2026-11-10','vulnerabilities':[{'cveID':'CVE-2026-111560','vendorProject':'Barracuda Networks','product':'Multiple Products','dateAdded':'2026-11-10','dueDate':'2026-11-13'}]}

class PrioritizationTests(unittest.TestCase):
    def test_kev_parse(self):self.assertIn('CVE-2026-111560',kev_records(TEST_KEV))
    def test_kev_plus_external_is_p0(self):
        rows=[{'cve':'CVE-2026-111560','asset':'edge01','exposure':'internet','criticality':'medium','cvss':'8.3'}]
        r=evaluate(TEST_KEV,rows,as_of='2026-11-16')
        self.assertEqual('P0',r['items'][0]['priority'])
        self.assertIn('due date has passed',' '.join(r['items'][0]['priority_factors']))
    def test_kev_without_asset_only_p1_not_false_p0(self):
        r=evaluate(TEST_KEV,as_of='2026-11-16')
        self.assertEqual('public_kev_watchlist',r['mode'])
        self.assertEqual('P1',r['items'][0]['priority'])
        self.assertEqual('',r['items'][0]['asset'])
    def test_non_kev_high_epss_is_p1(self):
        rows=[{'cve':'CVE-2020-9999','asset':'vm1','cvss':'4.2'}]
        r=evaluate(TEST_KEV,rows,{'CVE-2020-9999':{'epss':0.62,'percentile':0.94}})
        self.assertEqual('P1',r['items'][0]['priority'])
    def test_cvss_critical_without_exposure_is_p2(self):
        rows=[{'cve':'CVE-2020-9999','asset':'vm1','cvss':'9.7'}]
        self.assertEqual('P2',evaluate(TEST_KEV,rows)['items'][0]['priority'])
    def test_unsupported_missing_cvss_not_manufactured(self):
        r=evaluate(TEST_KEV,[{'cve':'CVE-2020-9999','cvss':'unknown'}])
        self.assertIsNone(r['items'][0]['cvss'])
    def test_qualys_import(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'q.csv';p.write_text('Asset,CVE,CVSS,Exposure,Business Criticality\nedge01,CVE-2026-111560,9.1,Internet,High\n')
            x=load_qualys_csv(p)
            self.assertEqual('edge01',x[0]['asset'])
    def test_trivy_import(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'trivy.json';p.write_text('{"Results":[{"Target":"app:latest","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-111560","CVSS":{"nvd":{"V3Score":8.3}}}]}]}')
            self.assertEqual(8.3,load_trivy_json(p)[0]['cvss'])
    def test_epss_parses_values(self):
        def fake_fetch(url):return {'data':[{'cve':'CVE-2026-111560','epss':'0.871','percentile':'0.98','date':'2026-11-15'}]}
        self.assertAlmostEqual(0.871,epss_scores(['CVE-2026-111560'],fake_fetch)['CVE-2026-111560']['epss'])
    def test_epss_invalid_score_ignored(self):
        def fake_fetch(url):return {'data':[{'cve':'CVE-2026-111560','epss':'3.0','percentile':'0.98'}]}
        self.assertEqual({},epss_scores(['CVE-2026-111560'],fake_fetch))
    def test_outputs_created(self):
        with tempfile.TemporaryDirectory() as td:
            write_outputs(evaluate(TEST_KEV),Path(td))
            self.assertTrue((Path(td)/'brief.html').exists())
    def test_no_kev_equals_no_known_exploitation(self):
        r=evaluate(TEST_KEV,[{'cve':'CVE-2000-1111','asset':'anything'}])
        self.assertFalse(r['items'][0]['known_exploited'])

if __name__=='__main__':unittest.main()
