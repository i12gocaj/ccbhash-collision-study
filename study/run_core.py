"""Deterministic core experiments on the unmodified CCBHash implementation."""
from common import *
from collections import Counter, defaultdict
import csv
import itertools
import math
import random
import time
from scipy.stats import binomtest, kstest

OUT = ROOT / 'study/results/core'
OUT.mkdir(parents=True, exist_ok=True)
LIMITS = {
    'ninstrs': list(range(8,40))+list(range(41,80,2))+list(range(81,160,3))+list(range(161,320,4))+list(range(321,1000,5)),
    'indegree': [1,2,3,4,5,6,7,8,10,13,17,22,28,35,43],
    'outdegree': [1,2,3,4,5,6,7,8,9,11,13,16,19,23,28],
    'nvars': [1,2,3,4,5,6,7,8,9,11,13,16,19,23,28],
    'cc': [1,2,3,4,5,6,7,8,9,11,13,16,20,25,31],
    'nblocks': [1,2,3,4,5,6,7,9,12,16,21,27,34,42,51],
    'stackframe': [1,4,8,12,16,20,24,28,40,56,80,120,200,360,620],
}

def counts(values):
    c = Counter(map(canonical, values))
    n = len(values)
    return dict(n=n, unique=len(c), excess=n-len(c), collision_groups=sum(v>1 for v in c.values()),
                collision_pairs=sum(v*(v-1)//2 for v in c.values()), max_group=max(c.values(), default=0))

def numeric():
    result, rows = {}, []
    for field, limits in LIMITS.items():
        bins = defaultdict(list)
        for x in range(10001):
            got = ccb._features_to_hashes({field:x})[field]
            expected = sum(x>=y for y in limits)
            assert got == expected
            bins[got].append(x)
        result[field] = dict(counts([ccb._features_to_hashes({field:x})[field] for x in range(10001)]),
                             thresholds=limits, saturation_from=limits[-1], max_code=len(limits),
                             domain='all integers 0..10000', negative_minus_one=ccb._features_to_hashes({field:-1})[field])
        for b, xs in bins.items():
            rows.append(dict(field=field, code=b, low=xs[0], high=xs[-1], count=len(xs), pairs=len(xs)*(len(xs)-1)//2))
    with (OUT / 'numeric_intervals.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0]); writer.writeheader(); writer.writerows(rows)
    return result

def text_family(field, texts):
    texts = list(texts)
    assert len(set(texts)) == len(texts)
    results = {}
    witnesses = []
    for width in (2,4,8):
        values = [ccb._features_to_hashes({field:x}, n_digits=width)[field] for x in texts]
        results[str(width)] = counts(values)
        results[str(width)]['uniform_expected_pairs'] = len(values)*(len(values)-1)/(2*2**(width*8))
        if width == 2:
            first = {}
            with (OUT / f'{field}_digests.csv').open('w', newline='', encoding='utf-8') as f:
                w=csv.writer(f); w.writerow(['input_index','feature_text','digest_2bytes'])
                for i, (x,y) in enumerate(zip(texts,values)):
                    w.writerow([i,x,y])
                    if y in first and len(witnesses)<3:
                        a,b=base_features(),base_features(); a[field]=texts[first[y]]; b[field]=x
                        ha,hb=signature(a),signature(b)
                        assert a!=b and ha==hb
                        witnesses.append(dict(field=field, input_a=a, input_b=b, signature=ha,
                                              pair_indices=[first[y],i], score=score(ha,hb), classification='feature-level full-signature compression collision; no semantic claim'))
                    first.setdefault(y,i)
            integers = [int(x,16) for x in values]
            results['bit_tests'] = [dict(bit=j, ones=sum(bool(x&(1<<j)) for x in integers), n=len(values),
                                             p=binomtest(sum(bool(x&(1<<j)) for x in integers),len(values),.5).pvalue)
                                   for j in range(16)]
    dump(OUT / f'{field}_witnesses.json', witnesses)
    return results

def graph_texts():
    choices=[()]+[(i,) for i in range(4)]+list(itertools.combinations(range(4),2))
    result=[]
    for outputs in itertools.product(choices,repeat=4):
        blocks=[]
        for i,out in enumerate(outputs):
            block={'offset':4096+16*i,'ops':[]}
            if out: block['jump']=4096+16*out[0]
            if len(out)==2: block['fail']=4096+16*out[1]
            blocks.append(block)
        result.append(ccb._get_cfg([{'blocks':blocks}]))
    assert len(result)==14641 and len(set(result))==14641
    return result

def callgraphs():
    texts=set()
    # All labelled directed graphs on 4 vertices; distinct serialization texts only
    # enter the subsequent digest experiment. Repeated texts are representation aliases.
    for mask in range(1<<16):
        graph=[dict(name=str(i),imports=[str(j) for j in range(4) if mask&(1<<(4*i+j))]) for i in range(4)]
        texts.add(ccb._get_callgraph('0', graph))
    ordered=sorted(texts)
    dump(OUT / 'callgraph_domain.json',dict(labelled_graphs=65536, distinct_texts=len(ordered),
                                          repeated_texts=65536-len(ordered),
                                          caveat='includes unreachable nodes and relabelling; repeated texts do not all denote distinct rooted graph structures'))
    return ordered

def first_collisions():
    rng=random.Random(20261006)
    trials=[]
    for trial in range(200):
        namespace=f'birthday/{trial}/{rng.getrandbits(128):032x}/'
        seen={}
        for i in range(10000):
            text=namespace+str(i)
            h=ccb._features_to_hashes({'name':text})['name']
            if h in seen:
                trials.append(dict(trial=trial, evaluated=i+1, censored=False, a=namespace+str(seen[h]), b=text, digest=h))
                break
            seen[h]=i
        else:
            trials.append(dict(trial=trial,evaluated=10000,censored=True))
    observed=[x['evaluated'] for x in trials]
    def exact_cdf(t):
        n=int(math.floor(t))
        if n<2: return 0.
        if n>65536: return 1.
        return -math.expm1(sum(math.log1p(-k/65536) for k in range(1,n)))
    # Discrete CDF: no continuous KS p-value is reported. Calibrate D by Monte Carlo
    # against the exact discrete distribution, using an independent seed.
    observed.sort(); n=len(observed)
    def statistic(sample):
        # Evaluate both sides of each empirical jump; tied observations form
        # one jump rather than intermediate, nonexistent empirical CDF values.
        grouped=Counter(sample); cumulative=0; maximum=0.
        for v,count in sorted(grouped.items()):
            maximum=max(maximum,abs((cumulative+count)/n-exact_cdf(v)),
                        abs(cumulative/n-exact_cdf(v-1)))
            cumulative+=count
        return maximum
    d=statistic(observed)
    import numpy as np
    sim_rng=np.random.default_rng(610062026)
    # Complete support: a repeat is certain by draw M+1. The previous table
    # ended at 2000 and left a tiny, nonzero tail outside inverse sampling.
    cdf=np.zeros(65538)
    cdf[2:65537]=-np.expm1(np.cumsum(np.log1p(-np.arange(1,65536)/65536)))
    cdf[65537]=1.
    null_stats=[]
    for rep in range(2000):
        sim=np.searchsorted(cdf,sim_rng.random(n),side='left')
        s,frequencies=np.unique(sim,return_counts=True)
        cumulative=np.cumsum(frequencies)
        ds=max(float(np.max(np.abs(cumulative/n-cdf[s]))),
               float(np.max(np.abs((cumulative-frequencies)/n-cdf[np.maximum(s-1,0)]))))
        null_stats.append(ds)
    p=(1+sum(x>=d for x in null_stats))/(len(null_stats)+1)
    dump(OUT/'birthday_trials.json',trials)
    return dict(seed=20261006,trials=200,censored=sum(x['censored'] for x in trials),
                mean=sum(observed)/n,median=(observed[99]+observed[100])/2,
                min=min(observed),max=max(observed),exact_uniform_median=next(k for k in range(2,2000) if exact_cdf(k)>=.5),
                d=d,monte_carlo_p=p,monte_carlo_replicates=2000,monte_carlo_seed=610062026,
                null_support=[2,65537],null_cdf_truncated=False,
                conclusion='comparison with a reference model, not a proof of cryptographic resistance')

def transformations():
    a=[{'blocks':[{'offset':16,'jump':32,'fail':48,'ops':[]},{'offset':32,'ops':[]},{'offset':48,'ops':[]}]}]
    b=json.loads(json.dumps(a)); b[0]['blocks'][0].update(jump=48,fail=32)
    c=json.loads(json.dumps(a)); c[0]['blocks'].reverse()
    d=json.loads(json.dumps(a))
    for block in d[0]['blocks']:
        block['offset']+=4096
        for k in ('jump','fail'):
            if k in block: block[k]+=4096
    operations1=[{'blocks':[{'offset':16,'ops':[{'type':'mov','opcode':'mov eax, 1'},{'type':'add','opcode':'add eax, 2'}]}]}]
    operations2=[{'blocks':[{'offset':16,'ops':[{'type':'add','opcode':'add eax, 999'},{'type':'mov','opcode':'mov ebx, 5'},{'type':'mov'},{'type':'nop'}]}]}]
    v1=[dict(bpvars=[dict(kind='arg',type='int')],spvars=[],regpvars=[])]
    v2=[dict(bpvars=[dict(kind='arg',type='int'),dict(kind='arg',type='int')],spvars=[],regpvars=[])]
    examples=dict(cfg_branch_labels=dict(a=a,b=b,text_a=ccb._get_cfg(a),text_b=ccb._get_cfg(b)),
                  cfg_block_order=dict(text_a=ccb._get_cfg(a),text_b=ccb._get_cfg(c)),
                  cfg_translation=dict(text_a=ccb._get_cfg(a),text_b=ccb._get_cfg(d)),
                  opcodes_order_counts_operands=dict(a=operations1,b=operations2,text_a=ccb._get_opcodes(operations1),text_b=ccb._get_opcodes(operations2)),
                  variable_multiplicity=dict(a=v1,b=v2,text_a=ccb._get_variables(v1),text_b=ccb._get_variables(v2)))
    graph=[dict(name='a',imports=['b','c']),dict(name='b',imports=['c']),dict(name='c',imports=[])]
    other=json.loads(json.dumps(graph)); other[0]['imports'].reverse()
    examples['callgraph_import_order']=dict(a=graph,b=other,text_a=ccb._get_callgraph('a',graph),text_b=ccb._get_callgraph('a',other))
    graph2=[dict(name='a',imports=['a'])]
    examples['callgraph_self_recursion']=dict(input=graph2,text=ccb._get_callgraph('a',graph2))
    dump(OUT / 'transformations.json', examples)
    return examples

def comparisons():
    a=signature(base_features()); b={k: ('ffff' if isinstance(v,str) else 999) for k,v in a.items()}
    # b is an intentionally unmatched comparison control, not a valid CCBHash output.
    return dict(weights_sum=sum(ccb.weights.values()),self_score=score(a,a),
                directional_small_large=ccb.compare_files({'a':a},{'a':a,'b':b}),
                directional_large_small=ccb.compare_files({'a':a,'b':b},{'a':a}),
                empty_left=ccb.compare_files({}, {'a':a}),empty_right=ccb.compare_files({'a':a}, {}),
                repeated_matching=ccb.compare_files({'a':a,'copy':a},{'a':a}),
                caveat='unmatched signature is a comparator control; no population inference')

def synthetic():
    rng=random.Random(20261007)
    feature_rows=[]; hashes=[]
    for i in range(20000):
        f={k:f'{rng.getrandbits(128):032x}' for k in TEXT_FIELDS}
        f.update({k:rng.randrange(10001) for k in LIMITS})
        feature_rows.append(f); hashes.append(signature(f))
    dump(OUT / 'synthetic_features.json',feature_rows)
    return dict(seed=20261007,description='independent random strings and uniform numeric values 0..10000; synthetic feature vectors, not assembly functions',
                raw=counts(feature_rows),signatures=counts(hashes))

if __name__=='__main__':
    started=time.perf_counter()
    result={'numeric':numeric()}; print('Numeric campaign completed',flush=True)
    op_types=sorted(['add','and','call','cmp','div','jmp','lea','load','mov','mul','or','pop','push','ret','sub','xor'])
    var_types=sorted(['int8_t','int16_t','int32_t','int64_t','uint8_t','uint16_t','uint32_t','uint64_t','char','short','int','long','float','double','void *','char *'])
    families={'name':(f'function_{i:05d}' for i in range(65536)),
              'opcodes':(''.join(t+';' for j,t in enumerate(op_types) if i&(1<<j)) for i in range(65536)),
              'args':(''.join(t+';' for j,t in enumerate(var_types) if i&(1<<j)) for i in range(65536))}
    result['text']={}
    for field, texts in families.items():
        result['text'][field]=text_family(field,texts); print('Text family',field,'completed',flush=True)
    result['text']['cfg']=text_family('cfg',graph_texts()); print('CFG completed',flush=True)
    result['text']['callgraph']=text_family('callgraph',callgraphs()); print('Callgraph completed',flush=True)
    # args and locals use exactly the same digest mapping. Record a locals witness
    # without treating the identical experiment as an independent replication.
    args_w=json.loads((OUT/'args_witnesses.json').read_text(encoding='utf-8'))
    locals_w=[]
    for w in args_w:
        a,b=base_features(),base_features(); a['locals']=w['input_a']['args']; b['locals']=w['input_b']['args']
        assert signature(a)==signature(b)
        locals_w.append(dict(input_a=a,input_b=b,signature=signature(a),classification='same mapping as args, not independent'))
    dump(OUT/'locals_witnesses.json',locals_w)
    tests=[dict(field=k,**x) for k,v in result['text'].items() for x in v['bit_tests']]
    ordered=sorted(range(len(tests)),key=lambda i:tests[i]['p']); current=0.
    for rank,i in enumerate(ordered):
        current=max(current,min(1.,tests[i]['p']*(len(tests)-rank)))
        tests[i]['holm_p']=current
    result['uniformity_tests']=tests
    result['birthday']=first_collisions(); print('Birthday completed',flush=True)
    result['transformations']=transformations(); result['comparisons']=comparisons(); result['synthetic']=synthetic()
    result['elapsed_seconds']=time.perf_counter()-started
    dump(OUT/'summary.json',result)
    print('Core campaigns completed:',round(result['elapsed_seconds'],2),'seconds',flush=True)
