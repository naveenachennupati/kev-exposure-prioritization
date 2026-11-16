import unittest
from src.remediation import analyze,item_id

def sample():
    return {'mode':'asset_exposure_queue','as_of':'2026-11-01',
            'items':[{'asset':'host.example.test','cve':'CVE-2021-0001','priority':'P1','known_exploited':True}]}

class RemediationTests(unittest.TestCase):
    def test_watchlist_must_not_create_fake_asset_remediation_plan(self):
        with self.assertRaisesRegex(ValueError,'watchlist'):
            analyze({'mode':'public_kev_watchlist','items':[],'as_of':'2026-11-01'})
    def test_open_item_becomes_overdue_by_configured_sla(self):
        r=analyze(sample(),as_of='2026-11-20')
        self.assertEqual(1,r['overdue_open_items']);self.assertEqual('2026-11-15',r['records'][0]['policy_due_date'])
    def test_independent_approval_required_for_closure(self):
        d={item_id(sample()['items'][0]):{'status':'resolved','owner':'alice','approver':'alice','ticket':'CHG-1'}}
        with self.assertRaises(ValueError):analyze(sample(),d)
    def test_approved_fix_not_overdue(self):
        d={item_id(sample()['items'][0]):{'status':'resolved','owner':'alice','approver':'bob','ticket':'CHG-1'}}
        r=analyze(sample(),d,as_of='2026-11-20');self.assertEqual(0,r['overdue_open_items'])
    def test_risk_acceptance_needs_expiry(self):
        d={item_id(sample()['items'][0]):{'status':'accepted_risk','owner':'alice','approver':'bob','ticket':'RISK-2'}}
        with self.assertRaises(ValueError):analyze(sample(),d)
    def test_expired_exception_reopens_remediation(self):
        d={item_id(sample()['items'][0]):{'status':'accepted_risk','owner':'alice','approver':'bob','ticket':'RISK-2','exception_expires':'2026-11-08'}}
        r=analyze(sample(),d,as_of='2026-11-20')
        self.assertEqual('expired_exception',r['records'][0]['status']);self.assertEqual(1,r['overdue_open_items'])
    def test_no_duplicates(self):
        s=sample();s['items'].append(dict(s['items'][0]))
        with self.assertRaises(ValueError):analyze(s)

if __name__=='__main__':unittest.main()
