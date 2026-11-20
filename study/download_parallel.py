"""Verified range download of the primary archive, with a bounded worker pool."""
from common import ROOT,dump
import urllib.request
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor,as_completed

if __name__=='__main__':
    meta=json.loads((ROOT/'study/results/literature/zenodo_record.json').read_text(encoding='utf-8'))
    item=next(x for x in meta['files'] if x['key'].endswith('.7z'))
    base=ROOT/'.tools/datasets';target=base/item['key'];parts=base/'parts';parts.mkdir(parents=True,exist_ok=True)
    size=item['size'];chunk_size=64*1024*1024
    if target.exists() and target.stat().st_size==size:
        md5=hashlib.md5();sha=hashlib.sha256()
        with target.open('rb') as source:
            while data:=source.read(8*1024*1024):md5.update(data);sha.update(data)
        if 'md5:'+md5.hexdigest()==item['checksum']:
            dump(ROOT/'study/results/large_deposit.json',dict(status='downloaded_and_verified',file=item['key'],
                bytes=size,md5=md5.hexdigest(),sha256=sha.hexdigest(),url=item['links']['self'],doi='10.5281/zenodo.20439493'))
            print('Existing primary archive independently rehashed and verified',flush=True)
            raise SystemExit(0)
    chunks=[(index,start,min(start+chunk_size,size)-1) for index,start in enumerate(range(0,size,chunk_size))]
    def fetch(chunk):
        index,start,end=chunk;path=parts/f'{index:04d}.part'
        if path.exists() and path.stat().st_size==end-start+1:return end-start+1
        for attempt in range(10):
            try:
                req=urllib.request.Request(item['links']['self'],headers={'Range':f'bytes={start}-{end}','User-Agent':'CCBHash reproducible evaluation/1.2'})
                with urllib.request.urlopen(req,timeout=90) as response:
                    assert response.status==206 and response.headers['Content-Range']==f'bytes {start}-{end}/{size}'
                    with path.open('wb') as f:
                        while data:=response.read(1024*1024):f.write(data)
                assert path.stat().st_size==end-start+1
                return end-start+1
            except Exception:
                if attempt==9:raise
                time.sleep(min(5,attempt+1))
    started=time.monotonic();completed=0
    with ThreadPoolExecutor(max_workers=12) as pool:
        for future in as_completed([pool.submit(fetch,c) for c in chunks]):
            completed+=future.result()
            print(json.dumps(dict(verified_range_bytes=completed,total=size,elapsed_seconds=round(time.monotonic()-started,1))),flush=True)
    md5=hashlib.md5();sha=hashlib.sha256()
    with target.open('wb') as destination:
        for index,start,end in chunks:
            with (parts/f'{index:04d}.part').open('rb') as source:
                while data:=source.read(8*1024*1024):destination.write(data);md5.update(data);sha.update(data)
    assert target.stat().st_size==size and 'md5:'+md5.hexdigest()==item['checksum']
    dump(ROOT/'study/results/large_deposit.json',dict(status='downloaded_and_verified',file=item['key'],
         bytes=size,md5=md5.hexdigest(),sha256=sha.hexdigest(),url=item['links']['self'],doi='10.5281/zenodo.20439493'))
    print('Primary raw deposit downloaded and verified',flush=True)
