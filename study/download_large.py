"""Download the cited primary raw-data deposit, with resumable integrity checks."""
from common import ROOT,dump
import urllib.request
import time
import hashlib
import json

if __name__=='__main__':
    record=json.loads((ROOT/'study/results/literature/zenodo_record.json').read_text(encoding='utf-8'))
    item=next(x for x in record['files'] if x['key'].endswith('.7z'))
    target=ROOT/'.tools/datasets'/item['key'];target.parent.mkdir(parents=True,exist_ok=True)
    started=time.monotonic();last=started
    for attempt in range(12):
        size=target.stat().st_size if target.exists() else 0
        if size==item['size']:break
        headers={'User-Agent':'CCBHash reproducible evaluation/1.2'}
        if size:headers['Range']=f'bytes={size}-'
        try:
            with urllib.request.urlopen(urllib.request.Request(item['links']['self'],headers=headers),timeout=90) as response:
                if size:assert response.status==206,'Server did not accept resume; refuse to append wrong bytes'
                with target.open('ab' if size else 'wb') as file:
                    while True:
                        chunk=response.read(1024*1024)
                        if not chunk:break
                        file.write(chunk);size+=len(chunk)
                        assert size<=item['size']
                        if time.monotonic()-last>10:
                            print(json.dumps(dict(bytes=size,total=item['size'],elapsed_seconds=round(time.monotonic()-started,1))),flush=True)
                            last=time.monotonic()
            if size==item['size']:break
        except Exception as exc:
            print('Download retry:',type(exc).__name__,str(exc),flush=True)
            time.sleep(min(attempt+1,5))
    assert target.stat().st_size==item['size'],'Incomplete deposit'
    md5=hashlib.md5();sha=hashlib.sha256()
    with target.open('rb') as file:
        while chunk:=file.read(8*1024*1024):md5.update(chunk);sha.update(chunk)
    assert 'md5:'+md5.hexdigest()==item['checksum'],'Deposit checksum mismatch'
    dump(ROOT/'study/results/large_deposit.json',dict(status='downloaded_and_verified',file=item['key'],
         bytes=item['size'],md5=md5.hexdigest(),sha256=sha.hexdigest(),url=item['links']['self'],
         doi='10.5281/zenodo.20439493'))
    print('Primary raw deposit downloaded and verified',flush=True)
