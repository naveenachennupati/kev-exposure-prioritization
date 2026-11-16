"""Modeled scanner prioritization study using documented CISA KEV-positive CVEs.

The asset inventory, exposures and CVSS values are generated hypothetical inputs.
The KEV-positive CVE IDs are taken only from the included selected CISA excerpt.
This exercise MUST NOT be represented as a real scan or patching result.
"""
from collections import Counter
from pathlib import Path
from html import escape
import argparse
import csv
import hashlib
import json
from .pipeline import evaluate,kev_records

BASE=Path(__file__).resolve().parents[1]
CATALOG=BASE/'data'/'official_kev_selected_2026-11-13.json'

def build_fixture(catalog):
    """240 evidence-tagged synthetic asset-CVE observations across 120 fictitious assets."""
    cves=sorted(kev_records(catalog))
    rows=[]
    for i in range(240):
        asset=f'example-node-{(i%120)+1:03d}.example.test'
        exposed='Internet' if i%4==0 else 'Internal'
        critical='High' if i%9==0 else 'Medium'
        # CVSS values below are hypotheses within a scenario, NOT NVD or scanner scores.
        hypothetical_cvss=(6.3 if i%3==0 else 7.2 if i%3==1 else 9.1)
        rows.append({'cve':cves[(i*5)%len(cves)],'asset':asset,'cvss':str(hypothetical_cvss),
                     'exposure':exposed,'criticality':critical,'scanner':'MODELED source rows: no actual scan'})
    return rows

def evaluate_study():
    catalog=json.loads(CATALOG.read_text())
    if not catalog.get('excerpt'):raise ValueError('Expected a flagged selected official excerpt')
    findings=build_fixture(catalog)
    out=evaluate(catalog,findings=__import__('copy').deepcopy(findings),as_of='2026-11-16')
    baseline=sum(float(x['cvss'])>=7 for x in findings)
    p0=sum(x['priority']=='P0' for x in out['items'])
    p1=sum(x['priority']=='P1' for x in out['items'])
    below=sum(float(x['cvss'])<7 for x in findings)
    source=json.dumps(findings,sort_keys=True,separators=(',',':')).encode()
    return {'study':'Exploitation-aware scanner queue (hypothetical asset exposure exercise)',
            'evidence_level':'Seven official KEV-positive CVE IDs; all scanner/asset/CVSS/exposure attributes MODELED',
            'official_selected_kev_cves':len(kev_records(catalog)),
            'hypothetical_observations':len(findings),'hypothetical_assets':len({x['asset'] for x in findings}),
            'baseline_cvss_threshold':7.0,
            'cvss_only_review_candidates':baseline,
            'known_exploited_positive_records':out['kev_matches'],
            'kev_positive_records_below_cvss_threshold':below,
            'risk_queue_p0':p0,'risk_queue_p1':p1,
            'first_response_share_pct':round(100*p0/len(findings),1),
            'model_fixture_sha256':hashlib.sha256(source).hexdigest(),
            'verified_public_source':'CISA KEV catalog curated excerpt, release 2026-11-13',
            'source_scope':'All modeled CVE IDs are within known-positive selected excerpt; no negatives inferred from excerpt.',
            'limitations':['This is NOT an actual Qualys/Trivy scan or real asset exposure; hostnames use example.test and CVSS values are hypothetical.',
                  'The 7-entry official KEV excerpt establishes known positives ONLY; it cannot establish which unlisted CVEs are not KEV.',
                  'The share of CVSS-below-7 cases is a scenario design property, not a measured prevalence.',
                  'No EPSS probability, actual remediation cost, operational SLA performance, or patching outcome is claimed.'],
            'sample_rows':out['items'][:20]}

def write(report,out):
    out.mkdir(parents=True,exist_ok=True)
    (out/'operational-study.json').write_text(json.dumps(report,indent=2)+'\n')
    limitations=''.join('<li>'+escape(x)+'</li>' for x in report['limitations'])
    html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Vulnerability queue outcome exercise</title><style>body{{background:#0c1728;color:#edf6fa;font:15px/1.65 Arial,sans-serif;margin:0}}main{{max-width:940px;margin:50px auto;padding:0 24px}}h1{{font-size:36px}}.over{{color:#65ddc3;text-transform:uppercase;letter-spacing:2px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin:22px 0}}.card{{background:#1a2c41;padding:18px;border-radius:10px}}.card b{{display:block;font-size:32px;color:#85e7d3}}.card span{{font-size:13px;color:#c2d0da}}p,li{{color:#c3d1dc}}</style></head><body><main><p class="over">Vulnerability operations / controlled model</p><h1>Why KEV changes the remediation conversation</h1><p>We applied a seven-entry publicly sourced KEV-positive reference list to {report['hypothetical_observations']} hypothetical scanner observations across {report['hypothetical_assets']} fictional systems. This measures a scenario, not an enterprise scan.</p><div class="cards"><div class="card"><b>{report['hypothetical_observations']}</b><span>modeled CVE-asset observations</span></div><div class="card"><b>{report['cvss_only_review_candidates']}</b><span>flagged by hypothetical CVSS ≥ 7 baseline</span></div><div class="card"><b>{report['kev_positive_records_below_cvss_threshold']}</b><span>known-KEV-positive rows below baseline CVSS threshold</span></div><div class="card"><b>{report['risk_queue_p0']}</b><span>exposure/criticality-based first-response queue</span></div></div><h2>Operational decision</h2><p>A severity-only review misses KEV-positive records in the configured scenario. The P0 first-response queue is {report['first_response_share_pct']}% of the modeled findings; review other known-exploited findings as P1 rather than treating them as safe.</p><h2>Evidence quality and limitations</h2><ul>{limitations}</ul><p>Scenario input fingerprint: <code>{report['model_fixture_sha256']}</code>.</p></main></body></html>'''
    (out/'operational-study.html').write_text(html)

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=BASE/'reports');a=p.parse_args()
    report=evaluate_study();write(report,a.out)
    print(f"MODELED scenario: {report['hypothetical_observations']} CVE-asset rows; {report['kev_positive_records_below_cvss_threshold']} KEV positive examples below CVSS 7; no live scan")

if __name__=='__main__':main()
