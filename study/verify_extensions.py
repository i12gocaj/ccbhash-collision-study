"""Independent checks for added strata, emulation, diagnostics and statistics."""
from common import *
from verify_results import expected_hash,independent_counts,compare_counts
import csv
import random
import math
from collections import Counter
import numpy as np

if __name__=='__main__':
    checks=[]
    summary=json.loads((ROOT/'study/results/strata/summary.json').read_text(encoding='utf-8'))
    for shared,stratum in enumerate(summary['strata']):
        rng=random.Random(stratum['seed']);features=[];hashes={w:[] for w in (2,4,8)}
        with (ROOT/f'study/results/strata/shared_{shared}.csv').open(encoding='utf-8',newline='') as file:
            for index,row in enumerate(csv.DictReader(file)):
                expected=base_features()
                for field in TEXT_FIELDS:
                    if field not in stratum['shared_text_fields']:expected[field]=f'{rng.getrandbits(128):032x}'
                raw=json.loads(row['features']);assert raw==expected and int(row['index'])==index
                features.append(raw)
                for width in (2,4,8):
                    h=json.loads(row[f'signature_{width}']);assert h==expected_hash(raw,width);hashes[width].append(h)
        assert len(features)==20000 and independent_counts(features)['unique']==20000
        for w in (2,4,8):compare_counts(stratum['signatures'][str(w)],independent_counts(hashes[w]))
    checks.append(dict(test='stratified_controls',raw_inputs=120000,widths=[2,4,8],seed_sequences_verified=True))
    trials=json.loads((ROOT/'study/results/core/birthday_trials.json').read_text(encoding='utf-8'))
    observed=np.array([t['evaluated'] for t in trials]);n=len(observed)
    # Product recurrence independent of the generator's sum-of-log expression.
    cdf=np.zeros(65538);survival=1.
    for i in range(2,len(cdf)):
        survival*=1-(i-1)/65536;cdf[i]=1-survival
    assert cdf[65537]==1.
    empirical=np.array([(observed<=i).mean() for i in range(len(cdf))])
    d=float(np.max(np.abs(empirical-cdf)))
    core=json.loads((ROOT/'study/results/core/summary.json').read_text(encoding='utf-8'))['birthday']
    assert core['null_support']==[2,65537] and core['null_cdf_truncated'] is False
    assert math.isclose(d,core['d'],abs_tol=1e-12)
    generator=np.random.default_rng(core['monte_carlo_seed']);hits=0
    for i in range(core['monte_carlo_replicates']):
        sample=np.searchsorted(cdf,generator.random(n),side='left');assert max(sample)<len(cdf)
        empirical=np.cumsum(np.bincount(sample,minlength=len(cdf)))/n
        statistic=float(np.max(np.abs(empirical-cdf)))
        hits+=statistic>=d
    p=(hits+1)/(core['monte_carlo_replicates']+1)
    assert math.isclose(p,core['monte_carlo_p'],abs_tol=1e-12),(p,core['monte_carlo_p'])
    checks.append(dict(test='birthday_discrete_model_and_monte_carlo',d=d,p=p,replicates=core['monte_carlo_replicates']))
    new=json.loads((ROOT/'study/results/adversarial/summary.json').read_text(encoding='utf-8'))
    assert new['status']=='passed'
    rows=json.loads((ROOT/'study/results/adversarial/emulation.json').read_text(encoding='utf-8'))['rows']
    assert len(rows)==224
    formulas=dict(base=lambda x:(3*x-1)&0xffffffff,reordered=lambda x:(3*x-5)&0xffffffff,
        multiplicity=lambda x:(3*x-3)&0xffffffff,condition_equal=lambda x:1 if x==0 else 2,
        condition_unequal=lambda x:2 if x==0 else 1,nop_41=lambda x:(3*x-1)&0xffffffff,nop_42=lambda x:(3*x-1)&0xffffffff)
    for row in rows:assert row['actual']==formulas[row['function']](row['x'])==row['expected']
    for version in new['versions']:
        raw=json.loads((ROOT/f'study/results/adversarial/{version}_raw.json').read_text(encoding='utf-8'))
        for pair in new['versions'][version]['tested_pairs']:
            a=raw[pair['a']]['records'][0];b=raw[pair['b']]['records'][0]
            for w in (2,4,8):assert expected_hash(a['features'],w)==expected_hash(b['features'],w)
    checks.append(dict(test='additional_binary_witnesses',routines=7,emulated_cases=224,versions=list(new['versions'])))
    interpreter=json.loads((ROOT/'study/results/interpreter_check.json').read_text(encoding='utf-8'))
    assert interpreter['status']=='passed' and interpreter['numeric_values']==70007 and interpreter['text_digests']==243363
    checks.append(dict(test='original_python_version',version='3.9.0',status='passed'))
    dump(ROOT/'study/results/extensions_verification.json',dict(status='passed',checks=checks))
    print(canonical(dict(status='passed',checks=checks)))
