"""Independent raw reconstruction, all labelled pairs, and calibration rule."""
from common import *
from audit_model import independent_features
from verify_results import expected_hash
import csv
from collections import Counter

if __name__=='__main__':
    out=ROOT/'study/results/compiled';records=json.loads((out/'records.json').read_text(encoding='utf-8'))
    summary=json.loads((out/'summary.json').read_text(encoding='utf-8'));indexed={r['id']:r for r in records}
    raw_count=0;emulated=0
    for file in sorted(out.glob('*.raw.json')):
        raw=json.loads(file.read_text(encoding='utf-8'))
        for r in raw['records']:
            identity=raw['file']+'/'+r['name']
            if identity not in indexed:continue
            saved=indexed[identity]
            features,_=independent_features(r['raw_info'],r['raw_code'],r['raw_finf'],raw['raw_callgraph'],r.get('raw_variables'))
            assert features==saved['features']
            for w in (2,4,8):assert expected_hash(features,w)==saved['signature' if w==2 else f'signature_{w}bytes']
            for x,actual,expected in saved['emulation']:
                assert actual==expected==(3*x+3*saved['constant']-1)%4294967296;emulated+=1
            raw_count+=1
    histograms={s:{positive:Counter() for positive in (True,False)} for s in ('calibration','test','cross_split')}
    previous=(-1,-1);count=0;distinct=0
    with (out/'pairs.csv').open(encoding='utf-8',newline='') as file:
        for row in csv.DictReader(file):
            i,j=int(row['index_a']),int(row['index_b']);assert (i,j)>previous and i<j;previous=(i,j)
            a,b=records[i],records[j];label=a['constant']==b['constant'];same=a['code_sha256']==b['code_sha256']
            value=sum(round(ccb.weights[k]*100) for k in FIELDS if a['signature'][k]==b['signature'][k])
            split='calibration' if max(a['constant'],b['constant'])<32 else 'test' if min(a['constant'],b['constant'])>=32 else 'cross_split'
            assert row['positive_same_formula']==str(label) and row['same_bytes']==str(same)
            assert int(row['score_integer'])==value and row['split']==split
            histograms[split][label][value]+=1;count+=1;distinct+=not same
    assert count==len(records)*(len(records)-1)//2==summary['total_pairs']
    assert distinct==summary['distinct_code_pairs']
    for split in ('calibration','test'):
        for result in summary['results'][split]['roc']:
            t=round(result['threshold']*100);pos,neg=histograms[split][True],histograms[split][False]
            assert result['tp']==sum(v for score,v in pos.items() if score>=t)
            assert result['fp']==sum(v for score,v in neg.items() if score>=t)
            assert result['fn']==sum(pos.values())-result['tp']
            assert result['tn']==sum(neg.values())-result['fp']
    calibration=summary['results']['calibration']['roc']
    selected=max(calibration,key=lambda r:(r['balanced_accuracy'],r['threshold']))['threshold']
    assert selected==summary['results']['test']['selected_threshold']
    assert raw_count==1280 and emulated==20480
    dump(out/'verification.json',dict(status='passed',raw_functions=raw_count,emulated_cases=emulated,
        all_pairs=count,thresholds_checked=202,calibration_precedes_test=True))
    print(canonical(dict(status='passed',functions=raw_count,pairs=count)))
