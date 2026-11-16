import unittest
import json
from src.operational_study import build_fixture, evaluate_study,CATALOG
from src.pipeline import evaluate

class ExposureStudyTests(unittest.TestCase):
    def test_known_positive_sample(self):
        d=json.loads(CATALOG.read_text());self.assertTrue(d['excerpt'])
        r=evaluate_study()
        self.assertEqual(r['known_exploited_positive_records'],r['hypothetical_observations'])
    def test_partial_catalog_rejects_unlisted(self):
        d=json.loads(CATALOG.read_text())
        with self.assertRaisesRegex(ValueError,'Partial KEV excerpt'):
            evaluate(d,[{'cve':'CVE-1999-9999','asset':'example.test'}])
    def test_partial_catalog_can_check_positive_only(self):
        d=json.loads(CATALOG.read_text());row=build_fixture(d)[0]
        self.assertTrue(evaluate(d,[row])['items'][0]['known_exploited'])
    def test_reproducible_hash(self):
        a=evaluate_study();b=evaluate_study();self.assertEqual(a['model_fixture_sha256'],b['model_fixture_sha256'])

if __name__=='__main__':unittest.main()
