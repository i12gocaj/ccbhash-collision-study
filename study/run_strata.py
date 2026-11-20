"""Stratified complete-signature controls with explicitly shared attributes."""
from common import *
from run_core import counts
import random
import csv

OUT=ROOT/'study/results/strata'
if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True);summaries=[]
    shared_order=('cfg','callgraph','opcodes','args','locals')
    for shared in range(6):
        seed=20261100+shared;rng=random.Random(seed);features=[];signatures={w:[] for w in (2,4,8)}
        path=OUT/f'shared_{shared}.csv'
        with path.open('w',encoding='utf-8',newline='') as file:
            out=csv.writer(file);out.writerow(['index','features','signature_2','signature_4','signature_8'])
            for i in range(20000):
                f=base_features()
                for field in TEXT_FIELDS:
                    if field not in shared_order[:shared]:f[field]=f'{rng.getrandbits(128):032x}'
                features.append(f)
                h={w:signature(f,w) for w in (2,4,8)}
                for w in h:signatures[w].append(h[w])
                out.writerow([i,canonical(f),*[canonical(h[w]) for w in (2,4,8)]])
        assert counts(features)['unique']==20000,'Duplicates are not eligible as compression collisions'
        summaries.append(dict(shared_text_fields=list(shared_order[:shared]),shared_numeric_fields=[k for k in FIELDS if k not in TEXT_FIELDS],
           varying_text_fields=[k for k in TEXT_FIELDS if k not in shared_order[:shared]],seed=seed,inputs=20000,
           signatures={str(w):counts(signatures[w]) for w in signatures}))
    dump(OUT/'summary.json',dict(status='passed',strata=summaries,
       scope='Artificial distinct feature vectors; every numeric field fixed. No program-realizability or semantic false-positive interpretation.'))
    print(canonical(summaries))
