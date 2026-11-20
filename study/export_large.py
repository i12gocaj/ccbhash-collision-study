"""Portable columns for independent recounts without the 29 GB source archive."""
from common import *
import csv,gzip,sqlite3,zipfile
import numpy as np

OUT=ROOT/'study/results/large'
if __name__=='__main__':
    summary=json.loads((OUT/'summary.json').read_text(encoding='utf-8'))
    n=summary['counts']['included']
    db=sqlite3.connect(ROOT/'.tools/datasets/work/complete.sqlite')
    assert db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==n
    destination=OUT/'signature_columns.npz'
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as archive:
        for field,width in (('raw',32),('pre_digest',32),('s2',19),('s4',31),('s8',55),('code',32)):
            values=np.empty(n,dtype=f'V{width}')
            for index,(value,) in enumerate(db.execute(f'SELECT {field} FROM records ORDER BY rowid')):
                assert len(value)==width;values[index]=value
            with archive.open(field+'.npy','w',force_zip64=True) as member:np.save(member,values,allow_pickle=False)
            print(canonical(dict(exported_column=field,records=n)),flush=True)
            del values
        raw_numeric=np.empty((n,7),dtype='<i8');diagnostics=np.empty(n,dtype='<u4')
        for index,(numbers,warning_count) in enumerate(db.execute('SELECT numbers,diagnostics FROM records ORDER BY rowid')):
            raw=json.loads(numbers);assert len(raw)==7 and all(isinstance(value,int) and not isinstance(value,bool) for value in raw)
            raw_numeric[index]=raw;assert 0<=warning_count<=4294967295;diagnostics[index]=warning_count
        for field,values in (('raw_numeric',raw_numeric),('diagnostics',diagnostics)):
            with archive.open(field+'.npy','w',force_zip64=True) as member:np.save(member,values,allow_pickle=False)
        del raw_numeric,diagnostics
    with gzip.open(OUT/'record_ids.csv.gz','wt',encoding='utf-8',newline='') as file:
        writer=csv.writer(file);writer.writerow(('record_index','binary','name','address'))
        for index,row in enumerate(db.execute('SELECT binary,name,addr FROM records ORDER BY rowid')):writer.writerow((index,*row))
    db.close()
    dump(OUT/'portable_data.json',dict(status='passed',records=n,
       binary_column_format='NumPy fixed-width void arrays preserve every byte, including trailing zero bytes',
       field_widths=dict(raw=32,pre_digest=32,s2=19,s4=31,s8=55,code=32),
       raw_numeric=dict(dtype='<i8',shape=[n,7],order=[k for k in FIELDS if k not in TEXT_FIELDS]),
       diagnostics=dict(dtype='<u4',description='Original CFG serialization warning count for each record'),
       row_order='Zero-based record_index in record_ids.csv.gz; deterministic binary-summary order and CFG record order',
       signature_order=dict(text=list(TEXT_FIELDS),numeric=[k for k in FIELDS if k not in TEXT_FIELDS]),
       files={p.name:dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(p.open('rb'),'sha256').hexdigest())
              for p in (destination,OUT/'record_ids.csv.gz')}))
    print('Portable complete signature columns exported',flush=True)
