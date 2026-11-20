"""Characterize API edge cases, graph invariances and storage behavior."""
from common import *
import contextlib
import io
import math
import tempfile

def outcome(name, function):
    try:
        value=function()
        return dict(test=name,status='returned',value=value)
    except Exception as ex:
        return dict(test=name,status='raised',exception=type(ex).__name__,message=str(ex))

if __name__=='__main__':
    f=base_features();h=signature(f)
    rows=[]
    rows.append(dict(test='repeatability_1000',status='checked',all_equal=all(signature(f)==h for _ in range(1000))))
    for width in (0,1,2,4,8,64,65):
        rows.append(outcome(f'digest_width_{width}',lambda width=width:ccb._features_to_hashes({'name':'abc'},width)))
    for value,label in [(-1,'negative'),(0,'zero'),(1.5,'fractional'),(float('nan'),'nan'),(float('inf'),'infinity')]:
        rows.append(outcome(f'numeric_{label}',lambda value=value:ccb._features_to_hashes({'cc':value})))
    rows.extend([
        outcome('unknown_feature',lambda:ccb._features_to_hashes({'unknown':'abc'})),
        outcome('missing_variables_key',lambda:ccb._get_variables([dict(bpvars=[],spvars=[],regvars=[])])),
        outcome('empty_variables_list',lambda:ccb._get_variables([])),
        outcome('incomplete_left_signature',lambda:ccb.compare_files({'x':{'opcodes':h['opcodes']}},{'y':h})),
        outcome('incomplete_right_signature',lambda:ccb.compare_files({'x':h},{'y':{'opcodes':h['opcodes']}})),
        outcome('non_string_text_feature',lambda:ccb._features_to_hashes({'name':123})),
        outcome('empty_cfg',lambda:ccb._get_cfg([])),
        outcome('empty_callgraph',lambda:ccb._get_callgraph('absent',[])),
        outcome('self_recursive_callgraph',lambda:ccb._get_callgraph('a',[dict(name='a',imports=['a'])])),
        outcome('mutually_recursive_callgraph',lambda:ccb._get_callgraph('a',[dict(name='a',imports=['b']),dict(name='b',imports=['a'])])),
        outcome('duplicate_call_edges',lambda:ccb._get_callgraph('a',[dict(name='a',imports=['b','b']),dict(name='b',imports=[])])),
        outcome('distinct_call_labels_same_topology',lambda:[ccb._get_callgraph('a',[dict(name='a',imports=['b']),dict(name='b',imports=[])]),
                                                            ccb._get_callgraph('x',[dict(name='x',imports=['y']),dict(name='y',imports=[])])]),
        outcome('empty_file_left',lambda:ccb.compare_files({}, {'y':h})),
        outcome('empty_file_right',lambda:ccb.compare_files({'x':h}, {})),
        outcome('same_function_comparison',lambda:ccb.compare_function(h,{'family':{'file':{'x':h}}})),
    ])
    with tempfile.TemporaryDirectory(prefix='ccbhash-storage-',dir=ROOT/'study') as directory:
        db=Path(directory)/'db.json';original={'family':{'file':{'entry0':h}}}
        ccb.save_db(original,str(db));loaded=ccb.get_db(str(db))
        rows.append(dict(test='database_roundtrip',status='checked',all_equal=loaded==original,
                         outer_json_type=type(json.loads(db.read_text())).__name__))
    # Two external targets are excluded by the serializer in the same way. Capture
    # its diagnostic, and avoid mislabelling this as a valid internal-graph collision.
    for target in (32,48):
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture):
            result=ccb._get_cfg([{'blocks':[{'offset':16,'jump':target,'ops':[]}]}])
        rows.append(dict(test=f'external_cfg_target_{target}',status='returned',value=result,log=capture.getvalue(),
                         domain='edge outside extracted function'))
    dump(ROOT/'study/results/robustness.json',rows)
    print('Characterized',len(rows),'API and representation cases')
