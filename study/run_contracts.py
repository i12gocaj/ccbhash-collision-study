"""Assertions for API behavior, ties, graph serialization and input boundaries."""
from common import *
from audit_model import independent_features
import copy
import math
import random
import tempfile

if __name__=='__main__':
    checks=[]
    def checked(name,condition,**details):
        assert condition,name
        checks.append(dict(test=name,status='passed',**details))
    a=signature(base_features())
    checked('determinism',all(signature(base_features())==a for _ in range(1000)))
    for w in (1,2,4,8,64):
        out=ccb._features_to_hashes({'name':'función_é_漢字'},w)
        checked(f'utf8_digest_{w}',out['name']==hashlib.blake2b('función_é_漢字'.encode('utf-8'),digest_size=w).hexdigest())
    for w in (0,65):
        try:ccb._features_to_hashes({'name':'abc'},w)
        except ValueError:checks.append(dict(test=f'invalid_digest_size_{w}',status='passed',expected_exception='ValueError'))
        else:raise AssertionError('Invalid digest size accepted')
    for x,name,value in [(-1,'negative',0),(0,'zero',0),(1.5,'fractional',1),(math.nan,'nan',0),(math.inf,'inf',15)]:
        checked('numeric_'+name,ccb._features_to_hashes({'cc':x})['cc']==value)
    checked('unknown_field_is_ignored',ccb._features_to_hashes({'unknown':'text'})=={})
    for name,args in [('missing_variables', [dict(bpvars=[],spvars=[],regvars=[])]),('empty_variables',[])]:
        try:ccb._get_variables(args)
        except Exception as ex:checked(name,str(ex)=='Error to get variables')
        else:raise AssertionError(name)
    single=dict(a=a);expected=round(sum(ccb.weights.values()),12)
    checked('empty_left',ccb.compare_files({},single)==(None,None))
    checked('empty_right',ccb.compare_files(single,{})==({'a':(0,'')},0))
    part=ccb.compare_files({'p':{'opcodes':a['opcodes']}},single)
    checked('incomplete_left',part==({'p':(.25,'a')},.25))
    try:ccb.compare_files(single,{'p':{'opcodes':a['opcodes']}})
    except KeyError:checks.append(dict(test='incomplete_right',status='passed',expected_exception='KeyError'))
    else:raise AssertionError('Incomplete destination silently accepted')
    # Valid complete-vector comparison controls; no out-of-range 999 codes.
    f={k:f'unmatched/{k}' if k in TEXT_FIELDS else 10000 for k in FIELDS};b=signature(f)
    checked('unmatched_control',all(a[k]!=b[k] for k in FIELDS))
    small_large=ccb.compare_files({'a':a},{'a':a,'b':b})[1]
    large_small=ccb.compare_files({'a':a,'b':b},{'a':a})[1]
    checked('directed_mean',abs(small_large-1)<1e-12 and abs(large_small-.5)<1e-12)
    checked('many_to_one',abs(ccb.compare_files({'a':a,'copy':a},{'target':a})[1]-1)<1e-12)
    first=ccb.compare_files({'x':a},{'first':a,'second':a})[0]['x'][1]
    second=ccb.compare_files({'x':a},{'second':a,'first':a})[0]['x'][1]
    checked('tie_order',first=='first' and second=='second')
    # Cross-check source entrypoints on 2,016 pairs of actual recovered signatures.
    rows=json.loads((ROOT/'study/results/fresh_corpus/records.json').read_text(encoding='utf-8'))
    sample=random.Random(20261010).sample(rows,64);pairs=0
    import itertools
    for x,y in itertools.combinations(sample,2):
        reference=sum(round(ccb.weights[k]*100) for k in FIELDS if x['signature'][k]==y['signature'][k])/100
        forward=ccb.compare_files({'x':x['signature']},{'y':y['signature']})[1]
        reverse=ccb.compare_files({'y':y['signature']},{'x':x['signature']})[1]
        direct=ccb.compare_function(x['signature'],{'family':{'file':{'y':y['signature']}}})['family/file/y']
        assert max(abs(v-reference) for v in (forward,reverse,direct))<1e-12
        pairs+=1
    checked('actual_pair_symmetry_and_entrypoints',pairs==2016,pairs=pairs)
    masks=0
    for mask in range(1<<len(FIELDS)):
        candidate={k:(a[k] if mask&(1<<i) else b[k]) for i,k in enumerate(FIELDS)}
        reference=sum(round(ccb.weights[k]*100) for i,k in enumerate(FIELDS) if mask&(1<<i))/100
        forward=ccb.compare_files({'a':a},{'c':candidate})[1]
        reverse=ccb.compare_files({'c':candidate},{'a':a})[1]
        direct=ccb.compare_function(a,{'f':{'b':{'c':candidate}}})['f/b/c']
        assert max(abs(v-reference) for v in (forward,reverse,direct))<1e-12
        masks+=1
    checked('all_component_equality_patterns',masks==8192,patterns=masks)
    shifted_input=[dict(blocks=[dict(offset=0x10,jump=0xf0,fail=0x100,ops=[]),dict(offset=0xf0,ops=[]),dict(offset=0x100,ops=[])])]
    translated=copy.deepcopy(shifted_input)
    for block in translated[0]['blocks']:
        for key in ('offset','jump','fail'):
            if key in block:block[key]+=0x1000
    before,after=ccb._get_cfg(shifted_input),ccb._get_cfg(translated)
    checked('hex_address_translation_counterexample',before!=after,input=shifted_input,translated=translated,before=before,after=after)
    self_graph=[dict(name='a',imports=['a'])]
    checked('self_recursion',ccb._get_callgraph('a',self_graph)=='1:1;')
    mutual=[dict(name='a',imports=['b']),dict(name='b',imports=['a'])]
    checked('mutual_recursion',ccb._get_callgraph('a',mutual)=='2:1;1:2;')
    duplicate=[dict(name='a',imports=['b','b']),dict(name='b',imports=[])]
    checked('duplicate_call_edges',ccb._get_callgraph('a',duplicate)=='0:1;1:;')
    graph=[dict(name='a',imports=['b']),dict(name='b',imports=[])]
    renamed=[dict(name='x',imports=['y']),dict(name='y',imports=[])]
    checked('call_node_labels',ccb._get_callgraph('a',graph)==ccb._get_callgraph('x',renamed))
    ordered=[dict(name='a',imports=['b','c']),dict(name='b',imports=['c']),dict(name='c',imports=[])]
    reverse_order=copy.deepcopy(ordered);reverse_order[0]['imports'].reverse()
    checked('call_import_order_changes_text',ccb._get_callgraph('a',ordered)!=ccb._get_callgraph('a',reverse_order))
    unreachable=graph+[dict(name='other',imports=['other'])]
    checked('unreachable_nodes',ccb._get_callgraph('a',graph)==ccb._get_callgraph('a',unreachable))
    with tempfile.TemporaryDirectory(dir=ROOT/'study',prefix='storage-contract-') as directory:
        path=Path(directory)/'database.json';data={'familia_ñ':{'archivo_é':{'función':a}}}
        ccb.save_db(data,str(path));checked('unicode_persistence',ccb.get_db(str(path))==data)
    # Loss of identity through concatenation is a separate API property.
    catalog={'family/a':{'b':{'c':a}},'family':{'a/b':{'c':b}}}
    identity=ccb.compare_function(a,catalog)
    checked('database_identifier_concatenation_collision',len(identity)==1 and set(identity)=={'family/a/b/c'},
            scope='Artificial database names; not assumed to be legal Windows path components')
    dump(ROOT/'study/results/contracts.json',dict(status='passed',checks=checks,seed=20261010))
    print(canonical(dict(status='passed',assertion_groups=len(checks),actual_pairs=2016,equality_patterns=masks)))
