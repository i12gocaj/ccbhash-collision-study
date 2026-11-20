"""Independent array grouping, source accounting and raw-feature reconstruction."""
from common import *
from audit_model import independent_features,LIMITS
from large_model import normalized_code,variables_from_zig
from collections import Counter
import numpy as np
import csv,gzip

OUT=ROOT/'study/results/large'
def reference_callgraph(root,graph):
    lookup={}
    for item in graph:
        if item['name'] not in lookup:lookup[item['name']]=item['imports']
    pending=[root];active={root};head=0;ids={};edges={}
    while head<len(pending):
        node=pending[head];head+=1;active.remove(node);ids[node]=str(head-1)
        if node not in lookup or node in edges:continue
        targets={};edges[node]=targets
        for target in lookup[node]:
            if target not in targets:
                targets[target]=None
                if target not in active:pending.append(target);active.add(target)
    return ''.join(ids[node]+':'+','.join(ids[target] for target in targets)+';' for node,targets in edges.items())

def pairs(sizes):return int(np.sum(sizes*(sizes-1)//2,dtype=np.int64))

if __name__=='__main__':
    summary=json.loads((OUT/'summary.json').read_text(encoding='utf-8'))
    archive=json.loads((OUT/'archive_inventory.json').read_text(encoding='utf-8'))
    expected={}
    suffixes=('_cg.json','_finfo.json','_func-cfg.jsonl','_zigs.json')
    for item in archive:
        for suffix in suffixes:
            if item['Path'].endswith(suffix):
                identity=item['Path'].replace('\\','/')[:-len(suffix)]
                expected.setdefault(identity,{})[suffix]=item['CRC'];break
    assert len(expected)==summary['binaries']==5489
    totals=Counter();identities=set()
    for file in (OUT/'binary_summaries').glob('*.json'):
        record=json.loads(file.read_text(encoding='utf-8'));identity=record['identity']
        assert identity not in identities;identities.add(identity)
        assert record['status']=='passed' and record['input_crc32']==expected[identity]
        counts=record['counts'];assert counts['input_functions']==sum(counts.get(k,0) for k in
             ('included','original_filter','missing_cfg','missing_variables'))
        totals.update(counts)
    assert identities==set(expected) and dict(totals)==summary['counts']
    portable=json.loads((OUT/'portable_data.json').read_text(encoding='utf-8'))
    for filename,record in portable['files'].items():
        with (OUT/filename).open('rb') as file:assert hashlib.file_digest(file,'sha256').hexdigest()==record['sha256']
    data=np.load(OUT/'signature_columns.npz',allow_pickle=False);code=data['code'];n=len(code)
    assert n==totals['included']==portable['records']
    raw_numeric=data['raw_numeric'];diagnostics=data['diagnostics']
    numeric=tuple(k for k in FIELDS if k not in TEXT_FIELDS)
    assert raw_numeric.shape==(n,7) and raw_numeric.dtype==np.dtype('<i8')
    assert tuple(portable['raw_numeric']['order'])==numeric
    expected_bins=np.column_stack([np.searchsorted(LIMITS[field],raw_numeric[:,index],side='right') for index,field in enumerate(numeric)]).astype(np.uint8)
    assert len(diagnostics)==n and int(diagnostics.sum())==totals['serialization_diagnostics']
    assert int(np.count_nonzero(diagnostics))==totals['functions_with_diagnostics']
    minimum_blocks=int(raw_numeric[:,numeric.index('nblocks')].min())
    idcounts=Counter();rows=0;binary_ids=np.empty(n,dtype=np.uint16);binary_lookup={name:i for i,name in enumerate(sorted(expected))};first_rows={}
    with gzip.open(OUT/'record_ids.csv.gz','rt',encoding='utf-8',newline='') as file:
        reader=csv.DictReader(file)
        for index,row in enumerate(reader):
            assert int(row['record_index'])==index and row['binary'] in expected
            if idcounts[row['binary']]<3:first_rows.setdefault(row['binary'],[]).append((index,row['name'],int(row['address'])))
            idcounts[row['binary']]+=1;binary_ids[index]=binary_lookup[row['binary']];rows+=1
    assert rows==n
    project_counts=Counter();architecture_counts=Counter();compiler_counts=Counter();optimisation_counts=Counter()
    for identity in expected:
        project,binary=identity.split('/',1);size=idcounts[identity]
        project_counts[project]+=size;architecture_counts[binary.split('-',1)[0]]+=size
        compiler_counts[binary.split('-',1)[1].split('-O',1)[0]]+=size
        option=binary.split('-O',1)[1].split('_',1)[0] if '-O' in binary else 'unknown'
        optimisation_counts['O'+option]+=size
    for field,counts in (('projects',project_counts),('architectures',architecture_counts),('compilers',compiler_counts),('optimisations',optimisation_counts)):
        assert dict(counts)==summary[field],field
    within_possible=sum(size*(size-1)//2 for size in idcounts.values());all_possible=n*(n-1)//2
    _,code_sizes=np.unique(code,return_counts=True);equal_code=pairs(code_sizes)
    assert summary['pair_domains']==dict(all=all_possible,within_binary=within_possible,across_binaries=all_possible-within_possible,
                                        equal_recovered_code=equal_code,distinct_recovered_code=all_possible-equal_code)
    checked={}
    for field in ('raw','pre_digest','s2','s4','s8'):
        values=data[field];assert len(values)==n
        if field.startswith('s'):
            assert np.array_equal(values.view(np.uint8).reshape(n,values.dtype.itemsize)[:,-7:],expected_bins)
        _,sizes=np.unique(values,return_counts=True)
        joint=np.empty(n,dtype=[('signature',values.dtype),('code',code.dtype)])
        joint['signature']=values;joint['code']=code
        _,duplicates=np.unique(joint,return_counts=True)
        result=dict(functions=n,unique=len(sizes),collision_classes=int(np.count_nonzero(sizes>1)),
             excess=int(np.sum(sizes-1)),max_class=int(sizes.max()),all_equal_pairs=pairs(sizes),
             equal_recovered_code_pairs=pairs(duplicates),distinct_recovered_code_collision_pairs=pairs(sizes)-pairs(duplicates))
        assert result==summary['collision_counts'][field],(field,result)
        del joint
        pair_groups=np.empty(n,dtype=[('signature',values.dtype),('binary',binary_ids.dtype)])
        pair_groups['signature']=values;pair_groups['binary']=binary_ids
        _,within_sizes=np.unique(pair_groups,return_counts=True);within_equal=pairs(within_sizes)
        del pair_groups,within_sizes
        joint=np.empty(n,dtype=[('signature',values.dtype),('code',code.dtype),('binary',binary_ids.dtype)])
        joint['signature']=values;joint['code']=code;joint['binary']=binary_ids
        _,within_duplicates=np.unique(joint,return_counts=True);within_samecode=pairs(within_duplicates)
        inside=dict(all_equal_pairs=within_equal,equal_recovered_code_pairs=within_samecode,
                    distinct_recovered_code_collision_pairs=within_equal-within_samecode)
        assert summary['collision_pair_partition'][field]==dict(within_binary=inside,across_binaries={k:result[k]-v for k,v in inside.items()})
        checked[field]=result;print(canonical(dict(verified_column=field,records=n)),flush=True)
        del joint,values,sizes,duplicates,within_duplicates
    samples=0;sample_identities=set()
    sample_columns={field:data[field] for field in ('raw','pre_digest','s2','s4','s8')}
    for file in sorted((OUT/'validation_samples').glob('*.json')):
        raw=json.loads(file.read_text(encoding='utf-8'));identity=raw['identity']
        assert identity in expected and identity not in sample_identities;sample_identities.add(identity)
        stem=hashlib.sha256(identity.encode()).hexdigest()
        assert file.stem==stem
        record=json.loads((OUT/'binary_summaries'/(stem+'.json')).read_text(encoding='utf-8'))
        assert idcounts[identity]==record['counts'].get('included',0)
        assert len(raw['samples'])==min(3,record['counts'].get('included',0))
        for item,(index,name,address) in zip(raw['samples'],first_rows.get(identity,[]),strict=True):
            assert name==item['info']['name'] and address==item['info'].get('addr',item['info'].get('offset'))
            rebuilt,_=independent_features(item['info'],normalized_code(item['cfg']),variables_from_zig(item['zig']),[])
            rebuilt['callgraph']=reference_callgraph(item['info']['name'],raw['raw_callgraph'])
            assert rebuilt==item['features']
            assert [rebuilt[k] for k in numeric]==raw_numeric[index].tolist()
            assert hashlib.sha256(canonical(rebuilt).encode()).digest()==bytes(sample_columns['raw'][index])
            keys={}
            for width in (2,4,8):
                h=ccb._features_to_hashes(rebuilt,width);assert h==item['signatures'][str(width)]
                keys[width]=b''.join(bytes.fromhex(h[k]) for k in TEXT_FIELDS)+bytes(h[k] for k in numeric)
                assert keys[width]==bytes(sample_columns[f's{width}'][index])
            texts=b''.join(hashlib.sha256(rebuilt[k].encode()).digest() for k in TEXT_FIELDS)
            assert hashlib.sha256(texts+keys[2][-7:]).digest()==bytes(sample_columns['pre_digest'][index])
            minimum=min(block.get('addr',block.get('offset')) for block in item['cfg']['blocks'])
            blocks=[[block.get('addr',block.get('offset'))-minimum,[op['bytes'] for op in block['ops']]]
                    for block in sorted(item['cfg']['blocks'],key=lambda b:b.get('addr',b.get('offset')))]
            assert hashlib.sha256(canonical(blocks).encode()).digest()==bytes(code[index])
            samples+=1
        if len(sample_identities)%500==0:print(canonical(dict(verified_raw_profiles=len(sample_identities),vectors=samples)),flush=True)
    assert sample_identities==set(expected)
    data.close()
    dump(OUT/'verification.json',dict(status='passed',binaries=5489,records=n,
       source_files_crc32='All selected archive members matched',input_accounting='Every finfo function classified exactly once',
       grouping='Independent NumPy exact fixed-byte grouping of every record and signature/code combination',
       raw_vectors_reconstructed=samples,raw_samples_linked_to_portable_columns=True,project_and_build_counts_verified=True,
       numeric_values_independently_verified=n*7,minimum_included_nblocks=minimum_blocks,
       per_record_serialization_diagnostics_verified=True,all_widths_verified=True,counts=checked))
    print('Complete primary archive evaluation independently verified',flush=True)
