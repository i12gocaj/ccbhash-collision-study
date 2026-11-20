"""Evaluate every eligible record in the public BinRankBench test fixtures."""
from common import *
from run_controlled import adapt_function
from run_core import counts
from collections import defaultdict, Counter
import contextlib
import csv
import io
import itertools
import math
import re
import time

INPUT = ROOT / 'references/binrankbench/tests/test_data/bin2ml'
OUT = ROOT / 'study/results/corpus'

def extracted_bytes(code):
    blocks=[]
    minimum=min(b.get('addr',b.get('offset')) for b in code[0]['blocks'])
    for b in sorted(code[0]['blocks'],key=lambda x:x.get('addr',x.get('offset'))):
        operations=[]
        for op in b['ops']:
            if 'bytes' not in op: return None
            operations.append(op['bytes'])
        blocks.append([b.get('addr',b.get('offset'))-minimum,operations])
    return digest(blocks)

def load_corpus():
    records, exclusions, sources = [], [], []
    for path in sorted(INPUT.glob('*_finfo.json')):
        binary=path.name[:-len('_finfo.json')]
        info=json.loads(path.read_text()); cfg=json.loads((INPUT/(binary+'_cfg.json')).read_text())
        variables=json.loads((INPUT/(binary+'_fvars.json')).read_text()); graph=json.loads((INPUT/(binary+'_cg.json')).read_text())
        codes={x[0]['name']:x for x in cfg if x}
        assert len(codes)==sum(bool(x) for x in cfg),'Duplicate CFG function names'
        source=dict(binary=binary, info_records=len(info),cfg_records=len(codes),
                    binary_sha256=hashlib.sha256((INPUT.parent/'binaries'/binary).read_bytes()).hexdigest(),
                    json_sha256={x:hashlib.sha256((INPUT/(binary+'_'+x+'.json')).read_bytes()).hexdigest() for x in ('finfo','cfg','fvars','cg')})
        sources.append(source)
        for fn in info:
            identifier=binary+'/'+fn['name']
            if fn['ninstrs']<10 and fn['nbbs']<2:
                exclusions.append(dict(id=identifier,reason='original_filter'));continue
            if fn['name'] not in codes:
                exclusions.append(dict(id=identifier,reason='missing_cfg'));continue
            if fn['name'] not in variables:
                exclusions.append(dict(id=identifier,reason='missing_variables'));continue
            var=variables[fn['name']]
            if not all(k in var for k in ('bp','sp','reg')):
                exclusions.append(dict(id=identifier,reason='incomplete_variable_schema'));continue
            finf=[dict(bpvars=var['bp'],spvars=var['sp'],regpvars=var['reg'])]
            output=io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    features=adapt_function(fn,codes[fn['name']],finf,graph)
                h=signature(features)
                records.append(dict(id=identifier,binary=binary,name=fn['name'],features=features,signature=h,
                                    signature_4bytes=signature(features,4),signature_8bytes=signature(features,8),
                                    recovered_code_sha256=extracted_bytes(codes[fn['name']]),extraction_log=output.getvalue()))
            except Exception as ex:
                exclusions.append(dict(id=identifier,reason='extraction_error',error=repr(ex)))
    return records,exclusions,sources

def analyze(records):
    components={}
    for field in FIELDS:
        raw=[x['features'][field] for x in records]; hashed=[x['signature'][field] for x in records]
        raw_c,hash_c=counts(raw),counts(hashed)
        components[field]=dict(raw=raw_c,processed=hash_c,
                               introduced_pairs=hash_c['collision_pairs']-raw_c['collision_pairs'],
                               mechanism='compression' if field in TEXT_FIELDS else 'quantization')
    pairs=[]; witnesses=[]; thresholds=(.5,.75,.9,1.)
    totals={'all':Counter(),'within_binary':Counter(),'between_binary':Counter()}
    pair_count=0
    with (OUT/'pairs.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['id_a','id_b','same_binary','same_recovered_code','score','score_without_text_compression','score_exact_features','added_compression_weight','full_signature_equal'])
        for a,b in itertools.combinations(records,2):
            same_code=a['recovered_code_sha256'] is not None and a['recovered_code_sha256']==b['recovered_code_sha256']
            if same_code:
                for group in ('all','within_binary' if a['binary']==b['binary'] else 'between_binary'):totals[group]['excluded_equal_recovered_code']+=1
                continue
            pair_count+=1
            h1,h2=a['signature'],b['signature']; f1,f2=a['features'],b['features']
            s=score(h1,h2)
            extra=sum(ccb.weights[k] for k in TEXT_FIELDS if h1[k]==h2[k] and f1[k]!=f2[k])
            uncompressed=s-extra
            exact=sum(ccb.weights[k] for k in FIELDS if f1[k]==f2[k])
            # Floating-point roundoff must not determine threshold membership.
            full=h1==h2
            w.writerow([a['id'],b['id'],a['binary']==b['binary'],same_code,round(s,12),round(uncompressed,12),round(exact,12),round(extra,12),full])
            for group in ('all','within_binary' if a['binary']==b['binary'] else 'between_binary'):
                c=totals[group]; c['pairs']+=1;c['compression_inflated_pairs']+=extra>1e-12;c['full_collisions']+=full
                for threshold in thresholds:
                    c[f'score_ge_{threshold}']+=s>=threshold-1e-12
                    c[f'compression_crosses_{threshold}']+=(s>=threshold-1e-12 and uncompressed<threshold-1e-12)
            if full or (extra>0 and len(witnesses)<20):
                witnesses.append(dict(id_a=a['id'],id_b=b['id'],full_collision=full,score=s,
                                      added_compression_weight=extra,
                                      compressed_fields=[k for k in TEXT_FIELDS if h1[k]==h2[k] and f1[k]!=f2[k]],
                                      classification='different recovered code; semantics not established'))
    return dict(components=components,raw_vectors=counts([x['features'] for x in records]),
                signatures={str(w):counts([x['signature' if w==2 else f'signature_{w}bytes'] for x in records]) for w in (2,4,8)},
                pair_metrics={k:dict(v) for k,v in totals.items()},witnesses=witnesses,
                note='These are descriptive rates of this convenience corpus, not semantic false-positive rates. Pair observations are dependent.')

if __name__=='__main__':
    started=time.perf_counter();OUT.mkdir(parents=True,exist_ok=True)
    records,exclusions,sources=load_corpus()
    assert len({x['id'] for x in records})==len(records)
    dump(OUT/'records.json',records);dump(OUT/'exclusions.json',exclusions);dump(OUT/'sources.json',sources)
    result=analyze(records)
    result.update(input_records=sum(x['info_records'] for x in sources),included_records=len(records),
                  exclusion_counts=dict(Counter(x['reason'] for x in exclusions)),
                  binary_counts=dict(Counter(x['binary'] for x in records)),elapsed_seconds=time.perf_counter()-started,
                  schema_adaptation=['fvars.bp -> bpvars','fvars.sp -> spvars','fvars.reg -> regpvars','CFG block addr -> offset'],
                  data_origin='All four public test binaries and their recovered JSON in BinRankBench commit 6cfda141e0d8ce76d58f1c5e8fc9969b4ba8d8a3; convenience corpus, not the full paper dataset')
    dump(OUT/'summary.json',result)
    print(canonical({k:v for k,v in result.items() if k not in ('components','witnesses')}),flush=True)
