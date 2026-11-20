"""Re-extract the complete four-binary corpus using radare2 5.8.8."""
from common import *
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import subprocess
import time
import run_corpus
from run_corpus import extracted_bytes

OUT=ROOT/'study/results/fresh_corpus'
VERSION='5.8.8'

def extract(file):
    output=OUT/'raw'/ (file.name+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    done=subprocess.run([sys.executable,str(ROOT/'study/run_controlled.py'),'--worker',str(file),
                         '--version',VERSION,'--output',str(output)],capture_output=True,text=True,timeout=180)
    output.with_suffix('.log').write_text(done.stdout+'\n'+done.stderr,encoding='utf-8')
    if done.returncode:
        raise RuntimeError(f'{file.name}: extraction failed; inspect {output.with_suffix(".log")}')
    return json.loads(output.read_text(encoding='utf-8'))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--version',default='5.8.8');args=parser.parse_args()
    VERSION=args.version
    if VERSION!='5.8.8':OUT=ROOT/f'study/results/fresh_corpus_{VERSION}'
    started=time.perf_counter()
    files=sorted((ROOT/'references/binrankbench/tests/test_data/binaries').iterdir())
    with ThreadPoolExecutor(max_workers=4) as pool:
        raw=list(pool.map(extract,files))
    records=[];exclusions=[];sources=[]
    for item in raw:
        sources.append(dict(binary=item['file'],file_sha256=item['file_sha256'],radare_version=item['radare_version'],
                            records=len(item['records'])))
        for rec in item['records']:
            identifier=item['file']+'/'+rec['name']
            if rec['status']!='ok':
                exclusions.append(dict(id=identifier,reason=rec['status']));continue
            records.append(dict(id=identifier,binary=item['file'],name=rec['name'],features=rec['features'],
                                signature=rec['signature'],signature_4bytes=rec['signature_4bytes'],
                                signature_8bytes=rec['signature_8bytes'],
                                recovered_code_sha256=extracted_bytes(rec['raw_code']),
                                extraction_log=rec.get('serialization_diagnostics','')))
    OUT.mkdir(parents=True,exist_ok=True)
    dump(OUT/'records.json',records);dump(OUT/'sources.json',sources);dump(OUT/'exclusions.json',exclusions)
    run_corpus.OUT=OUT
    summary=run_corpus.analyze(records)
    summary.update(input_records=sum(x['records'] for x in sources),included_records=len(records),
                   binary_counts=dict(Counter(x['binary'] for x in records)),exclusion_counts=dict(Counter(x['reason'] for x in exclusions)),
                   schema_adaptation=['regvars -> regpvars; actual afvj bp/sp/reg if required; preserve entries and kinds; block addr -> offset'],
                   elapsed_seconds=time.perf_counter()-started,
                   data_origin=f'Fresh radare2 {VERSION} extraction of all four benign BinRankBench test binaries; original CCBHash reducers with explicitly adapted schema')
    dump(OUT/'summary.json',summary)
    print(canonical({k:v for k,v in summary.items() if k not in ('components','witnesses')}),flush=True)
