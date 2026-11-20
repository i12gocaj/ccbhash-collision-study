"""Stage already received compressed blocks without allocating archive holes."""
from common import *

if __name__=='__main__':
    entries=json.loads((ROOT/'tmp/archive-file-records.json').read_text(encoding='utf-8'));packed={}
    for entry in entries:
        if entry.get('Packed Size'):packed[int(entry['Block'])]=int(entry['Packed Size'])
    parts=ROOT/'.tools/datasets/parts';archive=ROOT/'.tools/datasets/header-only.7z';prefix=0
    with archive.open('r+b') as destination:
        for i in range(1000):
            source=parts/f'{i:04d}.part'
            if not source.exists() or source.stat().st_size!=64*1024*1024:break
            destination.seek(i*64*1024*1024)
            with source.open('rb') as file:
                while data:=file.read(8*1024*1024):destination.write(data);prefix+=len(data)
    end=32;complete=[]
    for block,size in sorted(packed.items()):
        end+=size
        if end<=prefix:complete.append(block)
    assert complete
    print(canonical(dict(contiguous_bytes=prefix,complete_compressed_blocks=complete,max_block=max(complete))))
