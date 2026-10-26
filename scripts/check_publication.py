"""Offline publication integrity checks. Never runs agents or attack payloads."""
from pathlib import Path
import collections
import csv
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def rows(name):
    with (ROOT / 'experiments' / name / 'results.public.csv').open() as f:
        return list(csv.DictReader(f))

def main():
    provenance = json.loads((ROOT / 'docs/PUBLICATION_PROVENANCE.json').read_text())
    for item in provenance['files']:
        assert hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest() == item['public_sha256'], item['path']
    supplement=json.loads((ROOT/'docs/SUPPLEMENT_PROVENANCE.json').read_text())
    for item in supplement['files']:
        assert hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest() == item['sha256'],item['path']
    pi = rows('prompt-injection')
    assert len(pi) == 18 and len({r['attack_id'] for r in pi}) == 6
    assert all(r['attack_success'] == 'False' for r in pi)
    assert all(r[k] == 'False' for r in pi for k in ['exec_called','write_called','edit_called'])
    mis = collections.Counter(r['verdict'] for r in rows('agent-misoperation'))
    assert mis == {'SAFE':28, 'REVIEW':15, 'MISOPERATION':17}
    defense = collections.Counter(r['status'] for r in rows('early-defenses'))
    assert defense == {'PASS':13, 'REVIEW':3, 'FAIL':3, 'ERROR':1}
    print('Provenance hashes:',len(provenance['files']),'verified')
    print('Prompt injection: 6 fixtures, 18 trials, 0 recorded leaks; dangerous tool calls 0/18')
    print('Misoperation:',dict(mis),'MSR = 17/60 = 28.3333%')
    print('Early defenses:',dict(defense),'total 20 (historical summary.total is inconsistent)')

    # This heuristic review aids publication; it is not a credential-leak proof.
    patterns = {
        'private-key-material': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{15,}?-----END',
        'github-token': rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})',
        'provider-key': rb'sk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}',
        'aws-access-key': rb'AKIA[A-Z0-9]{16}',
        'slack-token': rb'xox[baprs]-[A-Za-z0-9-]{20,}',
        'jwt': rb'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}',
        'credential-url': rb'https?://[^\s:/@]+:[^\s/@]+@',
    }
    candidates=[]
    def scan(label, data):
        for kind, pattern in patterns.items():
            if re.search(pattern,data): candidates.append((label,kind))
    files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).split(b'\0')
    for name in set(filter(None,files)):
        p=ROOT/name.decode()
        if p.is_file(): scan(name.decode(),p.read_bytes())
    objects=subprocess.check_output(['git','rev-list','--objects','--all'],cwd=ROOT).decode().splitlines()
    blobs=0
    for obj in objects:
        oid=obj.split(' ',1)[0]
        if subprocess.check_output(['git','cat-file','-t',oid],cwd=ROOT).strip()==b'blob':
            blobs+=1
            scan('history:'+oid,subprocess.check_output(['git','cat-file','blob',oid],cwd=ROOT))
    print('Credential-pattern scan:',len(set(filter(None,files))),'working files;',blobs,'historical blobs')
    for label,kind in candidates: print('REVIEW REQUIRED:',label,kind)
    if candidates: raise SystemExit('Do not publish until every candidate has been reviewed.')
    print('No high-confidence credential-pattern candidates. Manual scope/placeholder review still required.')

if __name__ == '__main__': main()
