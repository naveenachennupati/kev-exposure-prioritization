"""CISA KEV + FIRST EPSS enrichment for read-only vulnerability triage.
Input may be real Qualys-style CSV or Trivy JSON. Absence of inventory creates a
public-intelligence watchlist, not an assertion that any enterprise is exposed.
"""
import argparse
from collections import Counter
import csv
from datetime import date
from html import escape
from io import StringIO
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen,Request

ROOT=Path(__file__).resolve().parents[1]
KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
FIRST='https://api.first.org/data/v1/epss'
CISA_MIRROR='https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'


def get_json(url, opener=urlopen):
    request=Request(url,headers={'Accept':'application/json','User-Agent':'SecurityExposureReview/1.0'},method='GET')
    with opener(request,timeout=30) as stream:
        return json.load(stream)


def fetch_kev():
    # Official CISA source first; CISA-maintained GitHub mirror is an explicit fallback.
    try:
        return get_json(KEV)
    except Exception as first_error:
        try: return get_json(CISA_MIRROR)
        except Exception as second_error: raise RuntimeError(f'KEV unavailable from CISA ({first_error}) or official mirror ({second_error})')


def kev_records(payload):
    rows=payload.get('vulnerabilities')
    if not isinstance(rows,list):raise ValueError('Missing CISA KEV vulnerabilities array')
    index={}
    for d in rows:
        cve=d.get('cveID','')
        if cve.startswith('CVE-'):
            index[cve]={'cve':cve,'vendor':d.get('vendorProject',''), 'product':d.get('product',''),
                        'vulnerability':d.get('vulnerabilityName',''),'date_added':d.get('dateAdded',''),
                        'due_date':d.get('dueDate',''),'ransomware':d.get('knownRansomwareCampaignUse','Unknown'),
                        'forensic_triage':d.get('forensicTriage','Unknown')}
    return index


def epss_scores(cves, fetcher=get_json):
    """FIRST API intended for small targeted lookups, not full-dataset bulk sync."""
    out={}; unique=sorted(set(cves))
    if len(unique)>80: raise ValueError('FIRST EPSS API is for targeted lookup; supply a filtered scanner inventory (<=80 CVEs), or use the daily bulk CSV')
    for i in range(0,len(unique),20):
        sub=unique[i:i+20]
        if not sub:continue
        obj=fetcher(FIRST+'?'+urlencode({'cve':','.join(sub)}))
        for row in obj.get('data',[]):
            try:
                score=float(row['epss']); percentile=float(row['percentile'])
            except (ValueError,KeyError,TypeError):continue
            if 0<=score<=1 and 0<=percentile<=1:
                out[row['cve']]={'epss':score,'percentile':percentile,'date':row.get('date')}
    return out


def load_qualys_csv(path):
    """Read a common export schema; explicit column aliases prevent guessing values."""
    res=[]
    with Path(path).open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames:raise ValueError('CSV requires header')
        headers={x.lower().strip():x for x in reader.fieldnames}
        def find(row,*candidates):
            for c in candidates:
                if c.lower() in headers:return row.get(headers[c.lower()],'')
            return ''
        for row in reader:
            raw=find(row,'CVE','CVE ID','CVE_ID')
            if not raw:continue
            for cve in [x.strip().upper() for x in raw.replace(';',',').split(',') if x.strip()]:
                if not cve.startswith('CVE-'):continue
                res.append({'cve':cve,'asset':find(row,'Asset','Host','DNS','IP','Asset Name'),
                            'cvss':find(row,'CVSS','CVSS Base Score','CVSS v3 Base Score'),
                            'exposure':find(row,'Exposure','Internet Exposed'),
                            'criticality':find(row,'Business Criticality','Criticality'),
                            'scanner':'Qualys-style CSV'})
    return res


def load_trivy_json(path):
    data=json.loads(Path(path).read_text())
    results=[]
    for target in data.get('Results',[]):
        for v in target.get('Vulnerabilities') or []:
            cve=v.get('VulnerabilityID','')
            if not cve.startswith('CVE-'):continue
            score=None
            for source in (v.get('CVSS') or {}).values():
                score=source.get('V3Score') or source.get('V2Score')
                if score is not None:break
            results.append({'cve':cve,'asset':target.get('Target',''),'cvss':score,
                            'exposure':'Unknown','criticality':'Unknown','scanner':'Trivy JSON'})
    return results


def priority(record,as_of):
    kev=record['known_exploited'];epss=record.get('epss'); cvss=record.get('cvss')
    exposed=str(record.get('exposure','')).strip().lower() in ('internet','internet-facing','external','yes','true')
    critical=str(record.get('criticality','')).strip().lower() in ('critical','tier 0','tier-0','high')
    factors=[]
    if kev:factors.append('CISA KEV: observed exploitation in the wild')
    if epss is not None and epss>=0.5:factors.append('FIRST EPSS >= 0.50')
    if cvss is not None and cvss>=9:factors.append('CVSS >= 9.0')
    if exposed:factors.append('Asset reported as internet exposed')
    if critical:factors.append('Asset reported as business critical')
    due=date.fromisoformat(record['due_date']) if kev and record.get('due_date') else None
    if due and due<as_of:factors.append('CISA federal remediation due date has passed (not an enterprise SLA)')
    if kev and (exposed or critical):return 'P0',factors
    if kev or (epss is not None and epss>=0.5):return 'P1',factors
    if exposed and cvss is not None and cvss>=8:return 'P1',factors
    if (cvss is not None and cvss>=7) or (epss is not None and epss>=0.10):return 'P2',factors
    return 'P3',factors


def evaluate(kev_payload, findings=None, epss=None, as_of='2026-11-16'):
    index=kev_records(kev_payload); epss=epss or {}; today=date.fromisoformat(as_of)
    inventory_supplied=findings is not None
    # Partial KEV excerpts cannot establish negative membership for unlisted CVEs.
    # Fail closed instead of downgrading potentially exploited scanner findings.
    if inventory_supplied and kev_payload.get('excerpt'):
        missing=sorted({f.get('cve','').strip().upper() for f in findings if f.get('cve','').strip().upper() not in index})
        if missing:
            raise ValueError(f'Partial KEV excerpt cannot classify {len(missing)} unlisted CVE(s). Supply the full current KEV catalog before scanner-wide prioritization: {missing[:3]}')
    if findings is None:
        findings=[{'cve':key,'asset':'','cvss':'','exposure':'Unknown','criticality':'Unknown','scanner':'CISA KEV watchlist'} for key in index]
    output=[]
    for f in findings:
        cve=f.get('cve','').strip().upper()
        if not cve.startswith('CVE-'):continue
        k=index.get(cve)
        ep=epss.get(cve,{})
        try:cvss=float(f['cvss']) if f.get('cvss') not in ('',None) else None
        except(ValueError,TypeError):cvss=None
        item={'cve':cve,'asset':f.get('asset',''),'cvss':cvss,'exposure':f.get('exposure','Unknown'),
              'criticality':f.get('criticality','Unknown'),'scanner':f.get('scanner',''),
              'known_exploited':k is not None,'date_added':(k or {}).get('date_added'),
              'due_date':(k or {}).get('due_date'),'vendor':(k or {}).get('vendor'),
              'product':(k or {}).get('product'),'epss':ep.get('epss'),'epss_percentile':ep.get('percentile'),
              'source_url':f'https://nvd.nist.gov/vuln/detail/{cve}'}
        item['priority'],item['priority_factors']=priority(item,today)
        output.append(item)
    output.sort(key=lambda x: (('P0','P1','P2','P3').index(x['priority']), -(x['epss'] or 0), x['cve'], x['asset']))
    return {'as_of':as_of,'mode':'asset_exposure_queue' if inventory_supplied else 'public_kev_watchlist',
            'catalog_version':kev_payload.get('catalogVersion','unspecified'),
            'kev_source_scope':('selected_official_excerpt_positive_matches_only' if kev_payload.get('excerpt') else 'supplied_catalog_not_marked_as_excerpt'),
            'catalog_release':kev_payload.get('dateReleased','unknown'),
            'cve_records_in_source':len(index),'total_rows':len(output),'priorities':dict(Counter(x['priority'] for x in output)),
            'kev_matches':sum(x['known_exploited'] for x in output),'epss_enriched':sum(x['epss'] is not None for x in output),
            'items':output,
            'interpretation':('Asset exposure requires validation against the asset inventory; findings do not establish exploitability.'
                              if inventory_supplied else 'CISA catalog intelligence only; no organization assets or exposures were assessed.') + (' Source is a selected KEV excerpt: unlisted CVEs have UNKNOWN KEV status until a full catalog is provided.' if kev_payload.get('excerpt') else '')}


def write_outputs(report,folder):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    cols=['priority','cve','asset','known_exploited','epss','cvss','vendor','product','due_date','exposure','criticality','source_url']
    with (folder/'queue.csv').open('w',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore');wr.writeheader();wr.writerows(report['items'])
    (folder/'brief.html').write_text(html_report(report))


def html_report(report):
    r=report
    metrics=''.join(f'<div class="stat"><small>{label}</small><b>{value}</b></div>' for label,value in [('CVE entries',r['total_rows']),('KEV matches',r['kev_matches']),('EPSS enriched',r['epss_enriched']),('P0 / P1',r['priorities'].get('P0',0)+r['priorities'].get('P1',0))])
    trs=''.join('<tr><td><span class="tag">'+escape(x['priority'])+'</span></td><td><a href="'+escape(x['source_url'])+'">'+escape(x['cve'])+'</a></td><td>'+escape(x.get('vendor') or '—')+'</td><td>'+escape(x.get('product') or '—')+'</td><td>'+('Yes' if x['known_exploited'] else 'No')+'</td><td>'+escape(x.get('due_date') or '—')+'</td><td>'+escape(x.get('asset') or 'Not assessed')+'</td></tr>' for x in r['items'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Exposure intelligence</title><style>body{{font:14px Inter,Arial,sans-serif;background:#0e1728;color:#e9f4f7;margin:0}}main{{max-width:1160px;margin:auto;padding:45px 25px}}.eyebrow{{color:#56e1cc;font-size:12px;text-transform:uppercase;letter-spacing:.16em}}h1{{font-size:39px;letter-spacing:-.04em}}.sub{{color:#a6c2d3;line-height:1.7}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:32px 0}}.stat{{border:1px solid #30465d;background:#17243b;border-radius:12px;padding:20px}}.stat small{{color:#93b7c6;display:block}}.stat b{{font-size:31px;display:block;margin-top:6px}}table{{border-collapse:collapse;width:100%;background:#17243b;border-radius:12px;overflow:hidden}}th,td{{text-align:left;padding:13px 10px;border-bottom:1px solid #30465d}}th{{color:#56e1cc}}a{{color:#89e6fa;text-decoration:none}}.overflow{{overflow:auto}}.tag{{background:#584434;border-radius:8px;padding:5px 10px}}.foot{{color:#8fb0c2;font-size:12px;margin-top:22px}}</style></head><body><main><div class="eyebrow">Risk intelligence / vulnerability operations</div><h1>Exploitation-aware triage</h1><p class="sub">{escape(r['mode'].replace('_',' ').title())} · CISA catalog version {escape(r['catalog_version'])} · As of {escape(r['as_of'])}</p><div class="stats">{metrics}</div><div class="overflow"><table><thead><tr><th>Priority</th><th>CVE</th><th>Vendor</th><th>Product</th><th>KEV</th><th>CISA date</th><th>Asset</th></tr></thead><tbody>{trs}</tbody></table></div><div class="foot">{escape(r['interpretation'])} · Official feed: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>. Priority is an explainable review recommendation, not a remediation SLA.</div></main></body></html>'''


def main():
    p=argparse.ArgumentParser(description='Prioritize real CISA KEV intelligence and optional scanner findings')
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--kev-file',type=Path,help='Downloaded official CISA KEV JSON (or curated official excerpt)')
    source.add_argument('--fetch-kev',action='store_true',help='Fetch live canonical CISA KEV JSON')
    inventory=p.add_mutually_exclusive_group()
    inventory.add_argument('--qualys-csv',type=Path)
    inventory.add_argument('--trivy-json',type=Path)
    p.add_argument('--fetch-epss',action='store_true',help='Use FIRST API to enrich a small set of queued CVEs')
    p.add_argument('--as-of',default=date.today().isoformat())
    p.add_argument('--out',type=Path,default=ROOT/'reports')
    args=p.parse_args()
    kev=fetch_kev() if args.fetch_kev else json.loads(args.kev_file.read_text())
    findings=load_qualys_csv(args.qualys_csv) if args.qualys_csv else load_trivy_json(args.trivy_json) if args.trivy_json else None
    cves=[f['cve'] for f in findings] if findings is not None else list(kev_records(kev))
    ep=epss_scores(cves) if args.fetch_epss else {}
    result=evaluate(kev,findings,ep,args.as_of)
    write_outputs(result,args.out)
    print(f"Mode: {result['mode']}; {result['total_rows']} records, {result['kev_matches']} KEV matches, {result['epss_enriched']} EPSS scores")

if __name__=='__main__':main()
