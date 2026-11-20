"""Stream the primary raw archive and recompute the immutable CCBHash model."""
from common import *
from large_model import deposit_features,indexed_graph
from native_callgraph import NativeCallgraph
from run_corpus import extracted_bytes
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED,as_completed
from collections import Counter
import argparse
import subprocess
import sqlite3
import shutil
import struct
import time
import zlib

OUT=ROOT/'study/results/large';CACHE=ROOT/'.tools/datasets/work';ARCHIVE=ROOT/'.tools/datasets/Marcelli-Dataset-1_r2-604-aaa_raw_data.7z'
SUFFIXES=('_cg.json','_finfo.json','_func-cfg.jsonl','_zigs.json')
NUMERIC=tuple(k for k in FIELDS if k not in TEXT_FIELDS)

def signature_key(features,width):
    signature=ccb._features_to_hashes(features,width)
    return b''.join(bytes.fromhex(signature[k]) for k in TEXT_FIELDS)+bytes(signature[k] for k in NUMERIC)

def process_binary(task):
    identity,files,crcs=task;project,binary=identity.split('/',1)
    destination=OUT/'binary_summaries';destination.mkdir(parents=True,exist_ok=True)
    stem=hashlib.sha256(identity.encode()).hexdigest();summary_file=destination/(stem+'.json')
    dbfile=CACHE/'databases'/(stem+'.sqlite');dbfile.parent.mkdir(parents=True,exist_ok=True)
    if summary_file.exists() and dbfile.exists():
        saved=json.loads(summary_file.read_text(encoding='utf-8'))
        if saved.get('input_crc32')==crcs:return saved
    graph=json.loads(Path(files['_cg.json']).read_bytes());adj=NativeCallgraph(indexed_graph(graph))
    info=json.loads(Path(files['_finfo.json']).read_bytes());variables=json.loads(Path(files['_zigs.json']).read_bytes())
    varmap={v['addr']:v for v in variables};assert len(varmap)==len(variables),'Duplicate zignature address'
    infomap={fn.get('addr',fn.get('offset')):fn for fn in info}
    assert len(infomap)==len(info),'Duplicate function address'
    codes={};counts=Counter();samples=[]
    db=sqlite3.connect(dbfile);db.execute('DROP TABLE IF EXISTS records')
    db.execute('CREATE TABLE records (name TEXT,addr INTEGER,code BLOB,raw BLOB,s2 BLOB,s4 BLOB,s8 BLOB,numbers TEXT,texts BLOB,diagnostics INTEGER)')
    visited=set();source_cfgs=0;started=time.monotonic()
    cfgfile=files.get('_func-cfg.jsonl')
    if cfgfile:
        with Path(cfgfile).open('rb') as file:
            for line in file:
                if not line.strip():continue
                cfg=json.loads(line);source_cfgs+=1;address=cfg.get('offset',cfg.get('addr'))
                assert address not in visited,'Duplicate CFG address';visited.add(address)
                fn=infomap.get(address)
                if fn is None:counts['cfg_without_finfo']+=1;continue
                if fn['ninstrs']<10 and fn['nbbs']<2:continue
                if address not in varmap:counts['missing_variables']+=1;continue
                features,diagnostics=deposit_features(fn,cfg,varmap[address],adj)
                assert set(features)==set(FIELDS)
                code=bytes.fromhex(extracted_bytes([cfg]))
                rawkey=hashlib.sha256(canonical(features).encode()).digest()
                keys=[signature_key(features,w) for w in (2,4,8)]
                numbers=canonical([features[k] for k in NUMERIC])
                texts=b''.join(hashlib.sha256(features[k].encode()).digest() for k in TEXT_FIELDS)
                db.execute('INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?)',(fn['name'],address,code,rawkey,*keys,numbers,texts,diagnostics.lines))
                counts['included']+=1;counts['serialization_diagnostics']+=diagnostics.lines
                if diagnostics.lines:counts['functions_with_diagnostics']+=1
                if len(samples)<3:samples.append(dict(info=fn,cfg=cfg,zig=varmap[address],features=features,
                       signatures={str(w):ccb._features_to_hashes(features,w) for w in (2,4,8)}))
                if counts['included']%500==0:db.commit()
    for address,fn in infomap.items():
        if fn['ninstrs']<10 and fn['nbbs']<2:counts['original_filter']+=1
        elif address not in visited:counts['missing_cfg']+=1
    counts['input_functions']=len(info);counts['cfg_records']=source_cfgs
    adj.close()
    assert counts['included']+counts['original_filter']+counts['missing_cfg']+counts['missing_variables']==len(info),counts
    db.commit();db.close()
    dump(OUT/'validation_samples'/(stem+'.json'),dict(identity=identity,raw_callgraph=graph,samples=samples))
    result=dict(identity=identity,counts=dict(counts),input_crc32=crcs,database=stem+'.sqlite',
                elapsed_seconds=round(time.monotonic()-started,3),status='passed')
    dump(summary_file,result)
    # Remove only this job's own temporary input copies, after its committed database exists.
    for file in files.values():Path(file).unlink()
    return result

def inventory(archive=ARCHIVE):
    listing=subprocess.check_output([str(ROOT/'.tools/7zip/7zr.exe'),'l','-slt',str(archive)],text=True,encoding='utf-8')
    result=[]
    for block in listing.split('\n\n'):
        record=dict(line.split(' = ',1) for line in block.splitlines() if ' = ' in line)
        if 'Path' in record and int(record.get('Size','0'))>0 and record.get('Block') is not None:
            assert not Path(record['Path']).is_absolute() and '..' not in Path(record['Path']).parts
            result.append(record)
    assert result
    return result

def aggregate():
    files=sorted((OUT/'binary_summaries').glob('*.json'));summaries=[json.loads(f.read_text(encoding='utf-8')) for f in files]
    records=json.loads((OUT/'archive_inventory.json').read_text(encoding='utf-8'))
    expected={r['Path'].replace('\\','/').removesuffix(next(s for s in SUFFIXES if r['Path'].endswith(s)))
              for r in records if r['Path'].endswith(SUFFIXES)}
    assert len(expected)==5489 and {s['identity'] for s in summaries}==expected
    assert all(s['status']=='passed' for s in summaries)
    database=CACHE/'complete.sqlite';connection=sqlite3.connect(database)
    connection.execute('PRAGMA cache_size=-131072')
    connection.execute('DROP TABLE IF EXISTS records')
    connection.execute('CREATE TABLE records (binary TEXT,name TEXT,addr INTEGER,code BLOB,raw BLOB,s2 BLOB,s4 BLOB,s8 BLOB,numbers TEXT,texts BLOB,diagnostics INTEGER,pre_digest BLOB)')
    within={field:Counter() for field in ('raw','pre_digest','s2','s4','s8')};within_possible_pairs=0
    copied=0
    for binary_index,item in enumerate(summaries,1):
        src=sqlite3.connect(CACHE/'databases'/item['database'])
        rows=src.execute('SELECT * FROM records ORDER BY rowid')
        local={field:Counter() for field in within};local_n=0
        while batch:=rows.fetchmany(10000):
            additions=[]
            for row in batch:
                pre=hashlib.sha256(row[8]+row[4][-7:]).digest();additions.append((item['identity'],*row,pre));local_n+=1
                for field,key in (('raw',row[3]),('pre_digest',pre),('s2',row[4]),('s4',row[5]),('s8',row[6])):
                    local[field][(key,row[2])]+=1
            connection.executemany('INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                additions)
        assert local_n==item['counts'].get('included',0)
        within_possible_pairs+=local_n*(local_n-1)//2
        for field,joint in local.items():
            sizes=Counter()
            for (key,code),size in joint.items():sizes[key]+=size
            equal=sum(size*(size-1)//2 for size in sizes.values())
            samecode=sum(size*(size-1)//2 for size in joint.values())
            within[field].update(dict(all_equal_pairs=equal,equal_recovered_code_pairs=samecode,
                                     distinct_recovered_code_collision_pairs=equal-samecode))
        src.close();connection.commit()
        copied+=local_n
        if binary_index%500==0:print(canonical(dict(aggregated_profiles=binary_index,functions=copied)),flush=True)
    n=connection.execute('SELECT COUNT(*) FROM records').fetchone()[0]
    def count(column):
        pairs=groups=excess=unique=maximum=0
        for size, in connection.execute(f'SELECT COUNT(*) FROM records GROUP BY {column}'):
            unique+=1;maximum=max(maximum,size)
            if size>1:groups+=1;pairs+=size*(size-1)//2;excess+=size-1
        duplicate_pairs=0
        for size, in connection.execute(f'SELECT COUNT(*) FROM records GROUP BY {column},code HAVING COUNT(*)>1'):
            duplicate_pairs+=size*(size-1)//2
        print(canonical(dict(counted_column=column,functions=n,unique=unique)),flush=True)
        return dict(functions=n,unique=unique,collision_classes=groups,excess=excess,max_class=maximum,
                    all_equal_pairs=pairs,equal_recovered_code_pairs=duplicate_pairs,
                    distinct_recovered_code_collision_pairs=pairs-duplicate_pairs)
    collision_counts={key:count(key) for key in ('raw','pre_digest','s2','s4','s8')}
    stages={key:collision_counts[key]['distinct_recovered_code_collision_pairs'] for key in collision_counts}
    assert stages['raw']<=stages['pre_digest']<=min(stages[k] for k in ('s2','s4','s8'))
    total_possible_pairs=n*(n-1)//2
    duplicate_code_pairs=sum(size*(size-1)//2 for size, in connection.execute('SELECT COUNT(*) FROM records GROUP BY code'))
    pair_domains=dict(all=total_possible_pairs,within_binary=within_possible_pairs,
                     across_binaries=total_possible_pairs-within_possible_pairs,
                     equal_recovered_code=duplicate_code_pairs,distinct_recovered_code=total_possible_pairs-duplicate_code_pairs)
    partition={field:dict(within_binary=dict(counts),across_binaries={metric:collision_counts[field][metric]-counts[metric]
                  for metric in counts}) for field,counts in within.items()}
    totals=Counter();projects=Counter();architectures=Counter();compilers=Counter();optimisations=Counter()
    for item in summaries:
        totals.update(item['counts']);project,binary=item['identity'].split('/',1)
        parts=binary.split('-',2);projects[project]+=item['counts'].get('included',0);architectures[parts[0]]+=item['counts'].get('included',0)
        compiler=binary.split('-',1)[1].split('-O',1)[0];compilers[compiler]+=item['counts'].get('included',0)
        opt=binary.split('-O',1)[1].split('_',1)[0] if '-O' in binary else 'unknown';optimisations['O'+opt]+=item['counts'].get('included',0)
    witnesses=[]
    for key in ('s2','s4','s8'):
        classes={value:dict(width=key,class_size=size,members=[]) for value,size in connection.execute(
             f'SELECT {key},COUNT(*) FROM records GROUP BY {key} HAVING COUNT(*)>1 ORDER BY {key} LIMIT 20')}
        for value,binary,name,addr,code,raw in connection.execute(f'SELECT {key},binary,name,addr,hex(code),hex(raw) FROM records ORDER BY rowid'):
            if value in classes and len(classes[value]['members'])<12:classes[value]['members'].append([binary,name,addr,code,raw])
        witnesses.extend(classes.values())
    dump(OUT/'collision_witnesses.json',witnesses)
    dump(OUT/'summary.json',dict(status='passed',binaries=len(summaries),counts=dict(totals),projects=dict(projects),
        architectures=dict(architectures),compilers=dict(compilers),optimisations=dict(optimisations),collision_counts=collision_counts,
        pair_domains=pair_domains,collision_pair_partition=partition,
        mechanism_pairs=dict(representation=stages['raw'],added_by_quantisation=stages['pre_digest']-stages['raw'],
                 added_by_text_digest={k:stages[k]-stages['pre_digest'] for k in ('s2','s4','s8')}),
        source='Original CCBHash reducers/digests/weights; indexed equivalent callgraph; deposited r2 6.0.4 metadata with validated schema',
        all_pairs_counted_by_exact_grouping=True,raw_equality_key='SHA-256 of canonical complete raw vector',
        recovered_code_equality_key='SHA-256 of relative block layout and recovered instruction bytes'))
    connection.close();print(canonical(dict(status='passed',binaries=len(summaries),functions=n,counts=collision_counts)),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--aggregate-only',action='store_true');p.add_argument('--max-block',type=int);p.add_argument('--min-block',type=int);p.add_argument('--archive-path');p.add_argument('--workers',type=int,default=4);args=p.parse_args()
    OUT.mkdir(parents=True,exist_ok=True);CACHE.mkdir(parents=True,exist_ok=True)
    if args.aggregate_only:aggregate();sys.exit()
    archive=Path(args.archive_path) if args.archive_path else ARCHIVE
    if args.max_block is None:
        deposit=json.loads((ROOT/'study/results/large_deposit.json').read_text(encoding='utf-8'));assert deposit['status']=='downloaded_and_verified'
    records=inventory(archive);dump(OUT/'archive_inventory.json',records)
    selected=[r for r in records if r['Path'].endswith(SUFFIXES)]
    groups={}
    for record in selected:
        path=record['Path'].replace('\\','/');suffix=next(s for s in SUFFIXES if path.endswith(s));identity=path[:-len(suffix)]
        groups.setdefault(identity,[]).append(record)
    skip=set()
    for identity,group in groups.items():
        stem=hashlib.sha256(identity.encode()).hexdigest();summary=OUT/'binary_summaries'/(stem+'.json')
        if args.min_block is not None and max(int(r['Block']) for r in group)<args.min_block:skip.add(identity);continue
        if args.max_block is not None and max(int(r['Block']) for r in group)>args.max_block:skip.add(identity);continue
        if summary.exists() and (CACHE/'databases'/(stem+'.sqlite')).exists():
            saved=json.loads(summary.read_text(encoding='utf-8'))
            actual={next(s for s in SUFFIXES if r['Path'].endswith(s)):r['CRC'] for r in group}
            if saved.get('input_crc32')==actual:skip.add(identity)
    selected=[r for r in selected if r['Path'].replace('\\','/').removesuffix(next(s for s in SUFFIXES if r['Path'].endswith(s))) not in skip]
    if not selected:
        if args.max_block is None:aggregate()
        sys.exit()
    batch_name=f'{args.min_block if args.min_block is not None else 0}-{args.max_block if args.max_block is not None else "all"}'
    listing=CACHE/('selected-files-'+batch_name+'.txt');listing.write_text('\n'.join(r['Path'] for r in selected),encoding='utf-8')
    stderr=(CACHE/('extraction-'+batch_name+'.log')).open('w',encoding='utf-8')
    child=subprocess.Popen([str(ROOT/'.tools/7zip/7zr.exe'),'x',str(archive),'-so','-i@'+str(listing),'-bso0','-bse2','-mmt=4'],stdout=subprocess.PIPE,stderr=stderr)
    pending=[];current=None;files={};crcs={};done=0
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        def submit():
            if not files:return
            assert all(k in files for k in ('_cg.json','_finfo.json','_zigs.json')),(current,files)
            pending.append(pool.submit(process_binary,(current,dict(files),dict(crcs))))
        for entry in selected:
            path=entry['Path'].replace('\\','/');suffix=next(s for s in SUFFIXES if path.endswith(s));identity=path[:-len(suffix)]
            if current is not None and identity!=current:
                submit();files={};crcs={}
                while len(pending)>=2*args.workers:
                    ready,_=wait(pending,return_when=FIRST_COMPLETED)
                    future=next(f for f in pending if f in ready);pending.remove(future)
                    result=future.result();done+=1
                    print(canonical(dict(binary=result['identity'],completed_binaries=done,functions=result['counts'].get('included',0))),flush=True)
            current=identity;destination=CACHE/(hashlib.sha256(identity.encode()).hexdigest()+suffix)
            remaining=int(entry['Size']);crc=0
            with destination.open('wb') as file:
                while remaining:
                    data=child.stdout.read(min(8*1024*1024,remaining));assert data,'Archive stdout ended before expected file size'
                    file.write(data);remaining-=len(data);crc=zlib.crc32(data,crc)
            assert f'{crc:08X}'==entry['CRC'],(path,'file CRC mismatch: archive order or integrity error')
            files[suffix]=str(destination);crcs[suffix]=f'{crc:08X}'
        submit()
        for future in as_completed(pending):
            result=future.result();done+=1
            print(canonical(dict(binary=result['identity'],completed_binaries=done,functions=result['counts'].get('included',0))),flush=True)
    assert child.stdout.read()==b'' and child.wait()==0
    stderr.close()
    if args.max_block is None:aggregate()
    else:print('Verified prefix processed; global deposit verification and remaining blocks still required',flush=True)
