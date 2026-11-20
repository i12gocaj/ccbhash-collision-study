"""Exhaustive four-node traversal parity and actual schema round trips."""
from common import *
from large_model import callgraph_text,indexed_graph,variables_from_zig,normalized_code
from compat import raw_pipe
import itertools
import copy,contextlib,io
from native_callgraph import NativeCallgraph

if __name__=='__main__':
    checked=0
    for mask in range(65536):
        graph=[dict(name=str(i),imports=[str(j) for j in range(4) if mask&(1<<(4*i+j))]) for i in range(4)]
        adjacency=indexed_graph(graph);native=NativeCallgraph(adjacency)
        expected=ccb._get_callgraph('0',graph)
        assert callgraph_text('0',adjacency)==native.text('0')==expected
        native.close()
        checked+=1
    for folder in ('fresh_corpus','fresh_corpus_6.0.4-wasi'):
        for raw in (ROOT/f'study/results/{folder}/raw').glob('*.json'):
            data=json.loads(raw.read_text(encoding='utf-8'));graph=data['raw_callgraph'];adj=indexed_graph(graph);native=NativeCallgraph(adj)
            for record in data['records']:
                if record['status']=='ok':
                    assert callgraph_text(record['name'],adj)==native.text(record['name'])==record['features']['callgraph'];checked+=1
            native.close()
    targeted=[('absent',[]),('root',[dict(name='root',imports=['absent','absent'])]),
       ('root',[dict(name='root',imports=['a']),dict(name='root',imports=['b']),dict(name='a',imports=['root'])]),
       ('β',[dict(name='β',imports=['café']),dict(name='café',imports=['β','external'])]),
       ('0',[dict(name=str(i),imports=[str((i+j*j+1)%100) for j in range(10)]) for i in range(100)])]
    for root,graph in targeted:
        adjacency=indexed_graph(graph);native=NativeCallgraph(adjacency)
        assert native.text(root)==callgraph_text(root,adjacency)==ccb._get_callgraph(root,graph)
        native.close()
    matched=0;cfg_roundtrips=0
    for file in sorted((ROOT/'references/binrankbench/tests/test_data/binaries').iterdir()):
        r=raw_pipe(file,'6.0.4-wasi')
        try:
            r.cmd('aaa');info=r.cmdj('aflj');r.cmd('zg');zigs={z['addr']:z for z in r.cmdj('zj')}
            for fn in info:
                r.cmd('s '+str(fn['addr']));variables=r.cmdj('afvj')
                code=r.cmdj('agfj')
                if code:
                    with contextlib.redirect_stdout(io.StringIO()):baseline=ccb._get_cfg(normalized_code(code[0]))
                    for absent in (None,18446744073709551615):
                        exported=copy.deepcopy(code[0])
                        for block in exported['blocks']:
                            if 'offset' in block:block['addr']=block.pop('offset')
                            for key in ('fail','jump'):block.setdefault(key,absent)
                        with contextlib.redirect_stdout(io.StringIO()):rebuilt=ccb._get_cfg(normalized_code(exported))
                        assert rebuilt==baseline,(file.name,fn['name'],absent)
                        cfg_roundtrips+=1
                zig=zigs.get(fn['addr'])
                if zig is None:continue
                source=variables_from_zig(zig)[0]
                for storage,expected in (('bp','bpvars'),('sp','spvars'),('reg','regpvars')):
                    actual={(v['name'],v['type'],v['kind']) for v in variables[storage]}
                    rebuilt={(v['name'],v['type'],v['kind']) for v in source[expected]}
                    assert actual==rebuilt,(file.name,fn['name'],storage)
                    matched+=len(actual)
        finally:r.quit()
    assert checked>=65536 and matched>0
    dump(ROOT/'study/results/large_model_verification.json',dict(status='passed',callgraph_cases=checked,
        variable_entries_roundtripped=matched,storage_and_role_distinguished=True,cfg_optional_destination_roundtrips=cfg_roundtrips,
        cfg_schema_source='references/binrankbench/binrankbench/common/utils.py: ADDR_SENTINEL and is_address_placeholder',
        cfg_schema_source_sha256=hashlib.sha256((ROOT/'references/binrankbench/binrankbench/common/utils.py').read_bytes()).hexdigest(),
        native_backend=json.loads((ROOT/'.tools/native/native_callgraph.json').read_text(encoding='utf-8')),
        native_and_python_serializers_match_original=True,additional_targeted_graph_cases=len(targeted)))
    print(canonical(dict(status='passed',callgraph_cases=checked,variable_entries=matched)))
