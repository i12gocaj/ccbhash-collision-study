"""Independent reconstruction of source constants and raw-radare features."""
from common import *
import ast
import copy

def source_limits():
    tree=ast.parse(SOURCE.read_text(encoding='utf-8'));limits={}
    function=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='_features_to_hashes')
    for condition in ast.walk(function):
        if not isinstance(condition,ast.If) or not isinstance(condition.test,ast.Compare):continue
        test=condition.test
        if not isinstance(test.left,ast.Name) or test.left.id!='feature' or len(test.comparators)!=1:continue
        field=test.comparators[0]
        if not isinstance(field,ast.Constant) or field.value in TEXT_FIELDS:continue
        assignment=next(x for x in condition.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='limits' for t in x.targets))
        expression=ast.Expression(assignment.value)
        limits[field.value]=eval(compile(expression,'immutable source constants','eval'),{'__builtins__':{},'range':range})
    assert set(limits)==set(FIELDS)-set(TEXT_FIELDS)
    return limits

LIMITS=source_limits()

def independent_features(info,code,finf,graph,raw_vars=None):
    f=finf[0]
    if 'bpvars' in f:
        groups=[f['bpvars'],f['spvars'],f.get('regpvars',f.get('regvars'))]
    else:
        assert raw_vars is not None
        groups=[raw_vars[k] for k in ('bp','sp','reg')]
    assert all(isinstance(g,list) for g in groups)
    args=sorted({v['type'] for g in groups for v in g if v['kind']=='arg'})
    locals=sorted({v['type'] for g in groups for v in g if v['kind']=='var'})
    types=set()
    for block in code[0]['blocks']:
        for op in block['ops']:
            t=str(op['type'])
            if t=='nop':continue
            for keyword in ('cmp','jmp','call','push'):
                if keyword in t:t=keyword
            types.add(t)
    blocks=code[0]['blocks'];addresses=[b.get('offset',b.get('addr')) for b in blocks]
    assert len(addresses)==len(set(addresses))
    cfg='';external=[]
    for i,b in enumerate(blocks):
        targets=[b[k] for k in ('fail','jump') if k in b]
        # Source sorts hexadecimal strings, not integer addresses.
        targets.sort(key=hex);fragment=str(i)+':'
        for target in targets:
            if target in addresses:fragment+=str(addresses.index(target))+','
            else:external.append(dict(block=i,target=target))
        # Reproduce the original final-character removal, including its defect
        # when all targets are outside the extracted function.
        cfg+=(fragment[:-1] if targets else fragment)+';'
    adjacency={}
    for fn in graph:adjacency.setdefault(fn['name'],fn['imports'])
    queue=[info['name']];ids={};edges={};visits=0
    while queue:
        node=queue.pop(0);ids[node]=str(visits);visits+=1
        if node not in adjacency:continue
        edges.setdefault(node,[])
        for dest in adjacency[node]:
            if dest not in edges[node]:
                edges[node].append(dest)
                if dest not in queue:queue.append(dest)
        assert visits<=1+sum(len(set(v)) for v in adjacency.values())
    call=''.join(ids[node]+':'+','.join(ids[d] for d in destinations)+';' for node,destinations in edges.items())
    features=dict(name=info['name'],nvars=info.get('nargs',0)+info.get('nlocals',0),
        args=''.join(t+';' for t in args),locals=''.join(t+';' for t in locals),
        opcodes=''.join(t+';' for t in sorted(types)),cfg=cfg,callgraph=call,
        nblocks=info['nbbs'],cc=info['cc'],indegree=info['indegree'],outdegree=info['outdegree'],
        ninstrs=info['ninstrs'],stackframe=info['stackframe'])
    ignored_registers=sum(v['kind'] not in ('arg','var') for g in groups for v in g)
    return features,dict(external_cfg_edges=external,variables_ignored_by_kind=ignored_registers)
