"""Repeat the actual hash domain under the original README's Python 3.9.0."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'study'))
from common import *
import csv
from compat import compatible_api

if __name__=='__main__':
    assert sys.version_info[:3]==(3,9,0),sys.version
    hash_checks=0
    for folder in ('corpus','fresh_corpus','fresh_corpus_6.0.4-wasi'):
        records=json.loads((ROOT/f'study/results/{folder}/records.json').read_text(encoding='utf-8'))
        for r in records:
            for w in (2,4,8):
                key='signature' if w==2 else f'signature_{w}bytes'
                assert ccb._features_to_hashes(r['features'],w)==r[key]
                hash_checks+=1
    controlled=json.loads((ROOT/'study/results/controlled/all_records.json').read_text(encoding='utf-8'))
    for item in controlled:
        for record in item['records']:
            if record['status']!='ok':continue
            for w in (2,4,8):
                key='signature' if w==2 else f'signature_{w}bytes'
                assert ccb._features_to_hashes(record['features'],w)==record[key]
                hash_checks+=1
    core=json.loads((ROOT/'study/results/core/summary.json').read_text(encoding='utf-8'))
    texts=0
    for field in core['text']:
        with (ROOT/f'study/results/core/{field}_digests.csv').open(encoding='utf-8',newline='') as f:
            for row in csv.DictReader(f):
                assert ccb._features_to_hashes({field:row['feature_text']})[field]==row['digest_2bytes'];texts+=1
    numeric=0
    with (ROOT/'study/results/core/numeric_intervals.csv').open(encoding='utf-8',newline='') as f:
        for row in csv.DictReader(f):
            for value in range(int(row['low']),int(row['high'])+1):
                assert ccb._features_to_hashes({row['field']:value})[row['field']]==int(row['code']);numeric+=1
    for c in (0,1,127,128,255):
        file=ROOT/'study/data/controlled'/f'constant_{c:03d}.exe'
        actual=compatible_api(file,'5.8.8');expected=controlled[c]['records'][0]['signature']
        assert actual=={'entry0':expected}
    dump(ROOT/'study/results/interpreter_check.json',dict(status='passed',python=sys.version,
         complete_vector_hash_checks=hash_checks,text_digests=texts,numeric_values=numeric,
         compatible_native_api_cases=5,scope='Python 3.9.0 original source parity against Python 3.12 campaign; radare2 5.8.8 API probes'))
    print(canonical(dict(status='passed',hash_checks=hash_checks,texts=texts,numeric=numeric)))
