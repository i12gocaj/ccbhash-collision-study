"""Check the independent full-corpus verifier's traversal against the source."""
from common import *
from verify_large import reference_callgraph

if __name__=='__main__':
    cases=0
    for mask in range(65536):
        graph=[dict(name=str(i),imports=[str(j) for j in range(4) if mask&(1<<(4*i+j))]) for i in range(4)]
        assert reference_callgraph('0',graph)==ccb._get_callgraph('0',graph)
        cases+=1
    for folder in ('fresh_corpus','fresh_corpus_6.0.4-wasi'):
        for file in (ROOT/f'study/results/{folder}/raw').glob('*.json'):
            data=json.loads(file.read_text(encoding='utf-8'))
            for record in data['records']:
                if record['status']=='ok':
                    assert reference_callgraph(record['name'],data['raw_callgraph'])==record['features']['callgraph']
                    cases+=1
    assert cases==66476
    dump(ROOT/'study/results/large_reference_verification.json',dict(status='passed',
        callgraph_cases=cases,source='All four-node directed graphs and all included functions in both fresh extractions',
        verifier_sha256=hashlib.sha256((ROOT/'study/verify_large.py').read_bytes()).hexdigest()))
    print(canonical(dict(status='passed',reference_callgraph_cases=cases)),flush=True)
