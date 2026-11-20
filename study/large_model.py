"""Indexed equivalent of the immutable traversal plus explicit deposit schema.

Equivalence invariant for every finite input graph: adjacency selects the first
record with a given name, exactly as the original linear search and break do.
The deque has the same ordered pending nodes as the original list, and queued
is exactly its set of members. Edges preserve insertion order and are inserted
once; known is exactly the membership set of that node's edge list. Thus both
implementations pop, reassign visit IDs and append identical nodes at every
step. The final serialization is unchanged. Exhaustive four-node tests and
actual extracted graphs check the implementation of these invariants.
"""
from common import *
from collections import deque
import io
import contextlib

def indexed_graph(graph):
    result={}
    for item in graph:result.setdefault(item['name'],item['imports'])
    return result

def callgraph_text(root,adjacency):
    queue=deque([root]);queued={root};ids={};edges={};count=0
    while queue:
        node=queue.popleft();queued.remove(node);ids[node]=str(count);count+=1
        if node not in adjacency:continue
        # Every unique outgoing edge was inserted on this node's first visit.
        # A revisit still changes its ID, but cannot enqueue any new target.
        if node in edges:continue
        edges[node]=[];known=set()
        for target in adjacency[node]:
            if target not in known:
                edges[node].append(target);known.add(target)
                if target not in queued:queue.append(target);queued.add(target)
    return ''.join(ids[node]+':'+','.join(ids[target] for target in targets)+';' for node,targets in edges.items())

def normalized_code(cfg):
    # bin2ml materializes absent optional destinations as null / u64::MAX.
    # Both denote absence in this schema, as verified against direct r2 JSON.
    cfg=dict(cfg);blocks=[]
    for original in cfg['blocks']:
        block=dict(original)
        if 'offset' not in block:block['offset']=block['addr']
        for key in ('fail','jump'):
            if block.get(key) in (None,-1,18446744073709551615):block.pop(key,None)
        blocks.append(block)
    cfg['blocks']=blocks
    return [cfg]

def variables_from_zig(zig):
    # r/b/s describe storage location in zignatures, not the arg/var role.
    groups={'bpvars':[],'spvars':[],'regpvars':[]}
    for var in zig['vars']:
        storage={'b':'bpvars','s':'spvars','r':'regpvars'}[var['kind']]
        role='reg' if var['kind']=='r' else 'arg' if var['isarg'] else 'var'
        groups[storage].append(dict(name=var['name'],type=var['type'],kind=role))
    return [groups]

class Diagnostics(io.TextIOBase):
    def __init__(self):self.lines=0;self.samples=[]
    def write(self,text):
        self.lines+=text.count('\n')
        if text.strip() and len(self.samples)<3:self.samples.append(text.strip())
        return len(text)

def deposit_features(info,cfg,variables,adjacency):
    code=normalized_code(cfg);finf=variables_from_zig(variables)
    v=ccb._get_variables(finf);diagnostics=Diagnostics()
    with contextlib.redirect_stdout(diagnostics):cfg_text=ccb._get_cfg(code)
    features=dict(name=info['name'],nvars=info.get('nargs',0)+info.get('nlocals',0),
        args=v['args'],locals=v['vars'],opcodes=ccb._get_opcodes(code),cfg=cfg_text,
        callgraph=adjacency.text(info['name']) if hasattr(adjacency,'text') else callgraph_text(info['name'],adjacency),nblocks=info['nbbs'],cc=info['cc'],
        indegree=info['indegree'],outdegree=info['outdegree'],ninstrs=info['ninstrs'],stackframe=info['stackframe'])
    return features,diagnostics
