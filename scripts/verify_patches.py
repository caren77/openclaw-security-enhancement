"""Check/apply archived patches to temporary base files; source checkout is read-only.

Usage: python3 -B scripts/verify_patches.py /path/to/openclaw-with-base-commit
This is a mechanical patch check, not a build or dependency check.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BASE='090cb491227e45cdbdc0a65ea2718c8fe62461c9'
source=Path(sys.argv[1]).resolve()
patches=[ROOT/'patches/existing-security-integration.patch', ROOT/'patches/skill-security-scanner.patch']
patches.append(ROOT/'patches/experimental-sandbox-paths.patch')
with tempfile.TemporaryDirectory(prefix='openclaw-patch-check-') as tmp:
    target=Path(tmp)
    subprocess.run(['git','init','--quiet',str(target)],check=True)
    paths=set()
    for patch in patches:
        paths.update(re.findall(r'^--- a/(.+)$',patch.read_text(),re.M))
    for name in paths:
        data=subprocess.check_output(['git','show',f'{BASE}:{name}'],cwd=source)
        p=target/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    for patch in patches:
        subprocess.run(['git','apply','--check',str(patch)],cwd=target,check=True)
        subprocess.run(['git','apply',str(patch)],cwd=target,check=True)
        print('Applied:',patch.name)
    snapshot=ROOT/'src/skill-security-scanner/upstream'
    files=[p for p in snapshot.rglob('*') if p.is_file()]
    for p in files:
        assert p.read_bytes()==(target/p.relative_to(snapshot)).read_bytes(),str(p)
    for p in target.rglob('*.ts'):
        if '.git' not in p.parts:
            original=source/p.relative_to(target)
            assert original.read_bytes()==p.read_bytes(),str(p.relative_to(target))
    print('All patched TypeScript files match research checkout; Scanner snapshot:',len(files),'files match')
