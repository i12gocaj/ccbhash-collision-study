"""Reconstruct every raw feature and pair measure; identify coverage defects."""
from common import *
from audit_model import independent_features,LIMITS
from verify_results import independent_counts,expected_hash,compare_counts
from collections import Counter,defaultdict
import csv
import itertools
import math
import struct
from scipy.stats import binomtest
import run_corpus

OUT=ROOT/'study/results/audit'

def file_segments(data):
    if data[:2]==b'MZ':
        nt=struct.unpack_from('<I',data,60)[0];n=struct.unpack_from('<H',data,nt+6)[0]
        size=struct.unpack_from('<H',data,nt+20)[0];optional=nt+24
        magic=struct.unpack_from('<H',data,optional)[0]
        base=struct.unpack_from('<Q' if magic==0x20b else '<I',data,optional+(24 if magic==0x20b else 28))[0]
        segments=[]
        for i in range(n):
            off=optional+size+i*40;vsize,rva,raw_size,raw_offset=struct.unpack_from('<IIII',data,off+8)
            segments.append((base+rva,max(vsize,raw_size),raw_offset,raw_size))
        return segments
    assert data[:4]==b'\x7fELF' and data[4:6]==b'\x02\x01','Expected ELF64 little endian'
    phoff=struct.unpack_from('<Q',data,32)[0];entry_size,n=struct.unpack_from('<HH',data,54)
    segments=[]
    for i in range(n):
        typ,flags,offset,addr,paddr,file_size,memsize,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*entry_size)
        if typ==1:segments.append((addr,memsize,offset,file_size))
    return segments

def check_code_bytes(item,file):
    data=file.read_bytes();segments=file_segments(data);operations=zeros=0
    for row in item['records']:
        if row['status']!='ok':continue
        for block in row['raw_code'][0]['blocks']:
            for op in block['ops']:
                address=op.get('offset',op.get('addr'));raw=bytes.fromhex(op['bytes']);n=len(raw)
                assert n>0 and n==op['size'],(file,row['name'],op)
                matching=[s for s in segments if s[0]<=address and address+n<=s[0]+s[1]]
                assert matching,(file,row['name'],hex(address),'unmapped code')
                start,memsize,offset,size=matching[0];relative=address-start
                backed=max(0,min(n,size-relative));expected=data[offset+relative:offset+relative+backed]+b'\0'*(n-backed)
                assert raw==expected,(file,row['name'],hex(address),'disassembly bytes differ from input')
                operations+=1;zeros+=n-backed
    return dict(instructions_matched_to_input_file=operations,loader_zero_fill_bytes=zeros)

def audit_raw(items,label):
    findings=[];checked=0
    for item in items:
        for row in item['records']:
            if row['status']=='filtered':
                info=row['info'];assert info['ninstrs']<10 and info['nbbs']<2;continue
            assert row['status']=='ok'
            f,diagnostic=independent_features(row['raw_info'],row['raw_code'],row['raw_finf'],item['raw_callgraph'],row.get('raw_variables'))
            assert f==row['features'],(label,item['file'],row['name'],
                {k:(f[k],row['features'][k]) for k in FIELDS if f[k]!=row['features'][k]})
            for w in (2,4,8):
                key='signature' if w==2 else f'signature_{w}bytes'
                assert row[key]==expected_hash(f,w)
            checked+=1
            if diagnostic['external_cfg_edges'] or diagnostic['variables_ignored_by_kind']:
                findings.append(dict(id=item['file']+'/'+row['name'],**diagnostic))
    return dict(functions_reconstructed=checked,functions_with_external_cfg_edges=sum(bool(f['external_cfg_edges']) for f in findings),
                external_cfg_edges=sum(len(f['external_cfg_edges']) for f in findings),
                functions_with_variables_ignored_by_kind=sum(f['variables_ignored_by_kind']>0 for f in findings),details=findings)

def audit_pairs(folder):
    records=json.loads((folder/'records.json').read_text(encoding='utf-8'));index={x['id']:x for x in records}
    assert len(index)==len(records)
    actual=json.loads((folder/'summary.json').read_text(encoding='utf-8'))
    counters={g:Counter() for g in ('all','within_binary','between_binary')};observed=set()
    with (folder/'pairs.csv').open(encoding='utf-8',newline='') as f:
        for row in csv.DictReader(f):
            a,b=index[row['id_a']],index[row['id_b']];pair=tuple(sorted((a['id'],b['id'])))
            assert pair not in observed and a['id']!=b['id'];observed.add(pair)
            full=a['signature']==b['signature'];same=a['binary']==b['binary']
            integer_weights={k:round(ccb.weights[k]*100) for k in FIELDS}
            score=sum(integer_weights[k] for k in FIELDS if a['signature'][k]==b['signature'][k])
            extra=sum(integer_weights[k] for k in TEXT_FIELDS if a['signature'][k]==b['signature'][k] and a['features'][k]!=b['features'][k])
            raw_score=sum(integer_weights[k] for k in FIELDS if a['features'][k]==b['features'][k])
            assert row['same_binary']==str(same) and row['full_signature_equal']==str(full)
            assert float(row['score'])==score/100
            assert float(row['added_compression_weight'])==extra/100
            assert float(row['score_without_text_compression'])==(score-extra)/100
            assert float(row['score_exact_features'])==raw_score/100
            for g in ('all','within_binary' if same else 'between_binary'):
                c=counters[g];c['pairs']+=1;c['full_collisions']+=full;c['compression_inflated_pairs']+=extra>0
                for t in (50,75,90,100):
                    key=str(t/100);c['score_ge_'+key]+=score>=t;c['compression_crosses_'+key]+=(score>=t and score-extra<t)
    # Account for every omitted pair, not just the number written to CSV.
    missing=[]
    for a,b in itertools.combinations(records,2):
        pair=tuple(sorted((a['id'],b['id'])))
        if pair not in observed:
            assert a['recovered_code_sha256'] is not None and a['recovered_code_sha256']==b['recovered_code_sha256']
            missing.append(pair)
            for g in ('all','within_binary' if a['binary']==b['binary'] else 'between_binary'):counters[g]['excluded_equal_recovered_code']+=1
    for g,counter in counters.items():
        for key,value in counter.items():assert actual['pair_metrics'][g].get(key,0)==value,(folder,g,key)
    return dict(pairs_checked=len(observed),excluded_duplicates=missing,all_columns_and_thresholds_verified=True)

if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True);checks={}
    for folder,label in [('fresh_corpus','5.8.8'),('fresh_corpus_6.0.4-wasi','6.0.4-wasi')]:
        path=ROOT/'study/results'/folder
        items=[json.loads(p.read_text(encoding='utf-8')) for p in sorted((path/'raw').glob('*.json'))]
        assert len(items)==4
        for item in items:
            actual_file=ROOT/'references/binrankbench/tests/test_data/binaries'/item['file']
            assert hashlib.sha256(actual_file.read_bytes()).hexdigest()==item['file_sha256']
        code_checks={item['file']:check_code_bytes(item,ROOT/'references/binrankbench/tests/test_data/binaries'/item['file']) for item in items}
        result=audit_raw(items,label);result.update(audit_pairs(path));checks[label]=result
        result['input_byte_verification']=code_checks
        excluded={f['id'] for f in result['details'] if f['external_cfg_edges']}
        records=json.loads((path/'records.json').read_text(encoding='utf-8'))
        clean=[r for r in records if r['id'] not in excluded]
        run_corpus.OUT=ROOT/f'study/results/closed_cfg_corpus_{label}';run_corpus.OUT.mkdir(parents=True,exist_ok=True)
        clean_summary=run_corpus.analyze(clean);clean_summary['included_records']=len(clean)
        dump(run_corpus.OUT/'summary.json',clean_summary);dump(run_corpus.OUT/'records.json',clean)
        checks[label]['closed_cfg_sensitivity']=dict(functions=len(clean),**clean_summary['pair_metrics']['all'])
    controlled=json.loads((ROOT/'study/results/controlled/all_records.json').read_text(encoding='utf-8'))
    checks['controlled_5.8.8']=audit_raw(controlled,'controlled')
    integration=json.loads((ROOT/'study/results/integration/summary.json').read_text(encoding='utf-8'))
    assert integration['status']=='passed'
    for version in ('5.8.8','6.0.4-wasi'):
        items=[json.loads(p.read_text(encoding='utf-8')) for p in sorted((ROOT/'study/results/integration'/version).glob('*.json'))]
        assert len(items)==256
        checks['API_'+version]=audit_raw([x['raw_extraction'] for x in items],version)
        for x in items:
            expected={r['name']:expected_hash(r['features'],2) for r in x['raw_extraction']['records'] if r['status']=='ok'}
            assert x['api_signatures']==x['api_with_graphs_signatures']==expected
    # Directly check all original thresholds, including the region above 10,000.
    witnesses=[]
    for field,limits in LIMITS.items():
        assert limits==sorted(set(limits))
        for x in [0,10000,2**16,2**32,2**64-1,2**256]+[v+d for v in limits for d in (-1,0,1)]:
            assert ccb._features_to_hashes({field:x})[field]==sum(x>=b for b in limits)
        # Every non-singleton interval contains a verifiable complete-vector witness.
        boundaries=[0]+limits+[10001]
        for lo,hi in zip(boundaries,boundaries[1:]):
            if hi-lo<2:continue
            a,b=base_features(),base_features();a[field]=lo;b[field]=lo+1
            ha=signature(a);assert ha==signature(b)
            witnesses.append(dict(field=field,a=a,b=b,signature=ha))
    dump(OUT/'numeric_witnesses.json',witnesses)
    checks['numeric']=dict(complete_collision_witnesses=len(witnesses),all_threshold_boundaries=True,saturation_proof='For x >= max(limits), every threshold comparison is true; output is len(limits).')
    core=json.loads((ROOT/'study/results/core/summary.json').read_text(encoding='utf-8'))
    tests=[]
    for field in core['text']:
        with (ROOT/f'study/results/core/{field}_digests.csv').open(encoding='utf-8',newline='') as f:rows=list(csv.DictReader(f))
        numbers=[int(r['digest_2bytes'],16) for r in rows]
        for t in core['text'][field]['bit_tests']:
            ones=sum((v>>t['bit'])&1 for v in numbers)
            assert t['ones']==ones and t['n']==len(numbers)
            assert math.isclose(t['p'],binomtest(ones,len(numbers),.5).pvalue,rel_tol=1e-12)
            tests.append(dict(field=field,**t))
    ordered=sorted(tests,key=lambda t:t['p']);running=0.
    lookup={(t['field'],t['bit']):t for t in core['uniformity_tests']}
    for i,t in enumerate(ordered):
        running=max(running,min(1.,t['p']*(len(ordered)-i)))
        assert math.isclose(lookup[t['field'],t['bit']]['holm_p'],running,rel_tol=1e-12)
    checks['statistics']=dict(bit_tests_recomputed=len(tests),holm_recomputed=True)
    dump(OUT/'summary.json',dict(status='passed',checks=checks,
         independence='Separate calculations and raw-feature reconstruction within the same project; no external peer review claimed'))
    print(canonical({k:{kk:vv for kk,vv in v.items() if kk!='details'} for k,v in checks.items()}))
