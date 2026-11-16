"""Policy-governed vulnerability remediation tracking for asset-backed scanner findings.

Fails closed for CISA public intelligence-only mode. No vulnerability changes are made.
SLAs are *example organization policy*, not CISA or regulatory requirements.
"""
import argparse
from collections import Counter
from datetime import date,timedelta
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SLA_DAYS={'P0':7,'P1':14,'P2':30,'P3':90}
STATES={'open','in_progress','resolved','accepted_risk','false_positive'}


def item_id(item):
    if not item.get('asset'): raise ValueError('Asset is required for remediation')
    return hashlib.sha256(f"{item['asset']}|{item['cve']}".encode()).hexdigest()[:16]


def analyze(report,decisions=None,as_of=None,policy=None):
    if report.get('mode') != 'asset_exposure_queue':
        raise ValueError('Public KEV watchlist cannot become an asset remediation plan')
    today=date.fromisoformat(as_of or report['as_of'])
    baseline=date.fromisoformat(report['as_of'])
    policy=dict(SLA_DAYS if policy is None else policy)
    if set(policy)!=set(SLA_DAYS) or not all(isinstance(x,int) and 0<x<=365 for x in policy.values()):
        raise ValueError('Invalid organization SLA policy')
    decisions=decisions or {}
    records=[]; seen=set()
    for item in report['items']:
        key=item_id(item)
        if key in seen: raise ValueError('Duplicate asset/CVE finding must be merged upstream')
        seen.add(key)
        status=decisions.get(key,{}).get('status','open')
        if status not in STATES: raise ValueError('Invalid remediation state')
        action=decisions.get(key,{})
        owner=action.get('owner','');ticket=action.get('ticket','');approver=action.get('approver','')
        if status in {'resolved','accepted_risk','false_positive'}:
            if not owner or not approver or owner.casefold()==approver.casefold() or not ticket:
                raise ValueError('Closed decisions require ticket, independent owner and approver')
        expiry=action.get('exception_expires')
        if status=='accepted_risk':
            if not expiry: raise ValueError('Accepted risk requires expiry')
            if date.fromisoformat(expiry)<today: status='expired_exception'
        deadline=baseline+timedelta(days=policy[item['priority']])
        open_state=status in ('open','in_progress','expired_exception')
        records.append({'item_id':key,'asset':item['asset'],'cve':item['cve'],'priority':item['priority'],
                        'known_exploited':item['known_exploited'],'owner':owner,'ticket':ticket,'status':status,
                        'policy_due_date':deadline.isoformat(),'days_to_due':(deadline-today).days,
                        'overdue':open_state and today>deadline,
                        'policy_note':'Example customizable internal SLA; not a CISA mandated deadline'})
    records.sort(key=lambda r:(SLA_DAYS[r['priority']],r['days_to_due'],r['asset'],r['cve']))
    counts=Counter(x['status'] for x in records)
    return {'as_of':today.isoformat(),'mode':'asset_remediation_review','policy_days':policy,
            'input_sha256':hashlib.sha256(json.dumps(report,sort_keys=True).encode()).hexdigest(),
            'records':records,'counts':dict(counts),'overdue_open_items':sum(x['overdue'] for x in records),
            'distinct_assets':len({x['asset'] for x in records}),
            'interpretation':'SLA clock uses report as-of date as illustrative first-seen; replace with verified scanner first-seen for real use. No assets or patches are modified.'}


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--out',type=Path,default=ROOT/'reports'/'remediation.json')
    p.add_argument('--as-of',default=None)
    a=p.parse_args();result=analyze(json.loads(a.input.read_text()),as_of=a.as_of)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(f"{len(result['records'])} asset-backed findings; {result['overdue_open_items']} overdue by example policy")
if __name__=='__main__':main()
