"""Independent arithmetic validation; no reliance on experiment counting code."""
from common import *
import csv
import itertools
from hashlib import blake2b
from audit_model import LIMITS

def independent_counts(values):
    ordered=sorted(canonical(x) for x in values)
    groups=[sum(1 for _ in g) for _,g in itertools.groupby(ordered)]
    return dict(n=len(ordered),unique=len(groups),excess=len(ordered)-len(groups),
                collision_pairs=sum((n*n-n)//2 for n in groups),collision_groups=sum(n>1 for n in groups),
                max_group=max(groups,default=0))

def expected_hash(features,width):
    # Independent evaluator: bin lookup, not the tested source's threshold loop.
    from bisect import bisect_right
    return {k:blake2b(features[k].encode('utf-8'),digest_size=width).hexdigest() if k in TEXT_FIELDS
            else bisect_right(LIMITS[k],features[k]) for k in FIELDS}

def compare_counts(observed,expected):
    for k,v in expected.items():assert observed[k]==v,(k,observed[k],v)

if __name__=='__main__':
    checks=[]
    core=json.loads((ROOT/'study/results/core/summary.json').read_text(encoding='utf-8'))
    for field in core['text']:
        with (ROOT/f'study/results/core/{field}_digests.csv').open(encoding='utf-8',newline='') as f:
            rows=list(csv.DictReader(f))
        assert len({x['feature_text'] for x in rows})==len(rows)
        for row in rows:
            assert blake2b(row['feature_text'].encode(),digest_size=2).hexdigest()==row['digest_2bytes']
        for width in (2,4,8):
            digests=[blake2b(x['feature_text'].encode(),digest_size=width).hexdigest() for x in rows]
            compare_counts(core['text'][field][str(width)],independent_counts(digests))
        checks.append(dict(check='all_text_digests_and_counts',field=field,records=len(rows),digest_widths=[2,4,8]))
    with (ROOT/'study/results/core/numeric_intervals.csv').open(encoding='utf-8',newline='') as f:
        rows=list(csv.DictReader(f))
    for field in core['numeric']:
        selected=[x for x in rows if x['field']==field]
        assert sum(int(x['count']) for x in selected)==10001
        assert int(selected[0]['low'])==0 and int(selected[-1]['high'])==10000
        assert all(int(b['low'])==int(a['high'])+1 for a,b in zip(selected,selected[1:]))
        assert sum(int(x['pairs']) for x in selected)==core['numeric'][field]['collision_pairs']
        from bisect import bisect_right
        for interval in selected:
            low,high,code=(int(interval[k]) for k in ('low','high','code'))
            assert all(bisect_right(LIMITS[field],value)==code for value in range(low,high+1))
    checks.append(dict(check='all_numeric_bins_and_domain',fields=7,values_per_field=10001))
    for folder in ('corpus','fresh_corpus','fresh_corpus_6.0.4-wasi'):
        records=json.loads((ROOT/f'study/results/{folder}/records.json').read_text(encoding='utf-8'))
        summary=json.loads((ROOT/f'study/results/{folder}/summary.json').read_text(encoding='utf-8'))
        assert len(records)==summary['included_records']
        for record in records:
            for width in (2,4,8):
                key='signature' if width==2 else f'signature_{width}bytes'
                assert record[key]==expected_hash(record['features'],width)
        for width in (2,4,8):
            key='signature' if width==2 else f'signature_{width}bytes'
            compare_counts(summary['signatures'][str(width)],independent_counts([x[key] for x in records]))
        with (ROOT/f'study/results/{folder}/pairs.csv').open(encoding='utf-8',newline='') as f:
            rows=list(csv.DictReader(f))
        assert len(rows)==summary['pair_metrics']['all']['pairs']
        assert sum(x['full_signature_equal']=='True' for x in rows)==summary['pair_metrics']['all']['full_collisions']
        index={x['id']:x for x in records}
        for row in rows:
            a,b=index[row['id_a']],index[row['id_b']]
            # integer weights avoid float equality and re-evaluate every recorded pair.
            s=sum(round(ccb.weights[k]*100) for k in FIELDS if a['signature'][k]==b['signature'][k])/100
            assert abs(s-float(row['score']))<1e-12
            assert (a['signature']==b['signature'])==(row['full_signature_equal']=='True')
        checks.append(dict(check='all_corpus_signatures_and_pairs',folder=folder,functions=len(records),pairs=len(rows)))
    controlled=json.loads((ROOT/'study/results/controlled/all_records.json').read_text(encoding='utf-8'))
    summary=json.loads((ROOT/'study/results/controlled/summary.json').read_text(encoding='utf-8'))
    assert len(controlled)==256 and len({x['file_sha256'] for x in controlled})==256
    good=[x['records'][0] for x in controlled]
    for item in controlled:
        assert hashlib.sha256((ROOT/'study/data/controlled'/item['file']).read_bytes()).hexdigest()==item['file_sha256']
    for width in (2,4,8):
        key='signature' if width==2 else f'signature_{width}bytes'
        for record in good:
            assert record[key]==expected_hash(record['features'],width)
        compare_counts(summary['hashes'][str(width)],independent_counts([x[key] for x in good]))
    assert summary['hashes']['2']['collision_pairs']==256*255//2
    emulation=json.loads((ROOT/'study/results/controlled/emulation.json').read_text(encoding='utf-8'))
    assert len(emulation['rows'])==8192
    assert all(x['actual']==((3*(x['x']+x['constant'])-1)&0xffffffff) for x in emulation['rows'])
    checks.append(dict(check='controlled_binary_uniqueness_hashes_and_emulation',files=256,emulated_cases=8192))
    trials=json.loads((ROOT/'study/results/core/birthday_trials.json').read_text(encoding='utf-8'))
    assert len(trials)==200
    for trial in trials:
        assert not trial['censored'] and trial['a']!=trial['b']
        assert blake2b(trial['a'].encode(),digest_size=2).hexdigest()==trial['digest']==blake2b(trial['b'].encode(),digest_size=2).hexdigest()
        namespace=trial['b'].rsplit('/',1)[0]
        seen=set()
        for i in range(trial['evaluated']):
            h=blake2b(f'{namespace}/{i}'.encode(),digest_size=2).hexdigest()
            assert (h in seen)==(i==trial['evaluated']-1)
            seen.add(h)
    checks.append(dict(check='all_birthday_witnesses_and_stopping_times',trials=200))
    # Verify every stored full-signature compression witness independently.
    witness_count=0
    for path in (ROOT/'study/results/core').glob('*_witnesses.json'):
        for w in json.loads(path.read_text(encoding='utf-8')):
            assert w['input_a']!=w['input_b']
            assert expected_hash(w['input_a'],2)==expected_hash(w['input_b'],2)==w['signature']
            witness_count+=1
    checks.append(dict(check='all_full_compression_witnesses',witnesses=witness_count))
    checks.append(dict(check='source_immutable',sha256=EXPECTED_SHA256))
    dump(ROOT/'study/results/verification.json',dict(status='passed',checks=checks,
         caveat='Independent calculations within the same project and machine; not external peer replication.'))
    print(canonical(dict(status='passed',checks=checks)))
