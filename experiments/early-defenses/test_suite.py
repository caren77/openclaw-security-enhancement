#!/usr/bin/env python3
import hashlib,hmac,tempfile
from pathlib import Path
import run_all_defenses as r
def main():
    n=0
    with tempfile.TemporaryDirectory() as td:
        ws=Path(td); r.write_fixture_workspace(ws); a=r.snapshot(ws); assert 'AGENTS.md' in a; n+=1
        (ws/'AGENTS.md').write_text('changed'); b=r.snapshot(ws); assert 'AGENTS.md' in r.diff(a,b); n+=1
        s='abc'; sig=r.sign_plugin('trusted.echo',s); assert r.verify_plugin('trusted.echo',sig,['trusted.echo'],s)[0]; n+=1
        assert not r.verify_plugin('evil',sig,['trusted.echo'],s)[0]; n+=1
        assert not r.verify_plugin('trusted.echo','bad',['trusted.echo'],s)[0]; n+=1
        bk=ws/'backup'; bk.mkdir(); (bk/'AGENTS.md').write_text('base'); r.restore_files(ws,bk,['AGENTS.md']); assert (ws/'AGENTS.md').read_text()=='base'; n+=1
        r.set_read_only([ws/'AGENTS.md'],True); assert not ((ws/'AGENTS.md').stat().st_mode & 0o200); n+=1
        r.set_read_only([ws/'AGENTS.md'],False); assert ((ws/'AGENTS.md').stat().st_mode & 0o200); n+=1
        assert r.excerpt('x'*100,10)=='x'*10; n+=1
        assert r.sha256_file(ws/'AGENTS.md')==hashlib.sha256(b'base').hexdigest(); n+=1
        assert hmac.compare_digest(r.sign_plugin('x','y'),r.sign_plugin('x','y')); n+=1
        assert not hmac.compare_digest(r.sign_plugin('x','y'),r.sign_plugin('z','y')); n+=1
    print(f'{n} unit tests passed')
if __name__=='__main__': main()
