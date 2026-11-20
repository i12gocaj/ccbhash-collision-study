"""Fail closed on the complete, declared experimental protocol."""
from common import *

def read(name):
    return json.loads((ROOT/'study/results'/name).read_text(encoding='utf-8'))

if __name__=='__main__':
    rows=[]
    for name in ('verification.json','audit/summary.json','extensions_verification.json',
                 'contracts.json','integration/summary.json','adversarial/summary.json',
                 'strata/summary.json','interpreter_check.json'):
        data=read(name)
        assert data['status']=='passed',name
        rows.append(dict(evidence=name,status='passed'))
    for name in ('compiled/verification.json','large_model_verification.json','large_reference_verification.json','large/verification.json','publication_audit.json'):
        assert read(name)['status']=='passed',name
        rows.append(dict(evidence=name,status='passed'))
    model=read('large_model_verification.json')
    assert model['native_and_python_serializers_match_original'] and model['callgraph_cases']==66476
    assert model['cfg_optional_destination_roundtrips']==1298 and model['variable_entries_roundtripped']==2659
    reference=read('large_reference_verification.json')
    assert reference['callgraph_cases']==66476
    assert reference['verifier_sha256']==hashlib.sha256((ROOT/'study/verify_large.py').read_bytes()).hexdigest()
    compiled=read('compiled/summary.json')
    assert compiled['functions']==1280 and compiled['emulated_cases']==20480
    assert len(compiled['architectures'])==4 and len(compiled['optimisations'])==5
    deposit=read('large_deposit.json');large=read('large/summary.json')
    assert deposit['status']=='downloaded_and_verified' and deposit['bytes']==29071158824
    assert large['status']=='passed' and large['binaries']==5489
    assert large['counts']['input_functions']==sum(large['counts'].get(k,0) for k in
          ('included','original_filter','missing_cfg','missing_variables'))
    large_verified=read('large/verification.json')
    assert large_verified['numeric_values_independently_verified']==large['counts']['included']*7
    assert large_verified['raw_samples_linked_to_portable_columns'] and large_verified['per_record_serialization_diagnostics_verified']
    rows.append(dict(evidence='large/summary.json',status='passed'))
    controlled=read('controlled/summary.json')
    assert controlled['successful_functions']==256 and not controlled['adapted_worker_errors']
    assert controlled['emulation']['checks']==8192 and controlled['emulation']['all_passed']
    assert controlled['hashes']['2']['collision_pairs']==32640
    rows.append(dict(evidence='controlled/summary.json',status='passed'))
    for version,folder,n in (('5.8.8','fresh_corpus',468),('6.0.4-wasi','fresh_corpus_6.0.4-wasi',472)):
        data=read(folder+'/summary.json')
        assert data['included_records']==n
        assert data['exclusion_counts']=={'filtered':177}
        assert data['input_records']==n+177
        integration=read('integration/summary.json')['versions'][version]
        assert integration['files']==256 and integration['api_calls']==512 and integration['zero_extraction_errors']
        rows.append(dict(evidence=folder+'/summary.json',status='passed'))
    core=read('core/summary.json')
    assert len(core['numeric'])==7 and all(v['n']==10001 for v in core['numeric'].values())
    assert core['birthday']['trials']==200 and core['birthday']['censored']==0
    assert core['birthday']['null_support']==[2,65537] and core['birthday']['null_cdf_truncated'] is False
    publication=read('publication_audit.json')
    assert publication['verifier_sha256']==hashlib.sha256((ROOT/'study/publication_audit.py').read_bytes()).hexdigest()
    assert publication['arithmetic']['score_patterns']==8192 and publication['arithmetic']['calibration_selection_exact_rational']
    assert publication['symbolic']['routines']==263 and publication['symbolic']['domain_cardinality']==2**32
    assert publication['partitions']['records']==large['counts']['included']
    assert publication['partitions']['mechanisms']==large['mechanism_pairs']
    assert publication['partitions']['four_and_eight_byte_partitions_identical_to_pre_digest']
    assert len(read('contracts.json')['checks'])==35
    rows.append(dict(evidence='core/summary.json',status='passed'))
    runtime=read('runtime_resolution.json')
    assert runtime['code_and_data_unchanged']
    runtime['completion_status']='passed: both complete controlled APIs and the four real binaries evaluated'
    dump(ROOT/'study/results/runtime_resolution.json',runtime)
    dump(ROOT/'study/results/protocol_completion.json',dict(
        status='passed',scope='Every campaign in PROTOCOL.md, including the compiled family and the complete primary archive',
        pending_protocol_tests=[],unexpected_valid_input_execution_failures=[],checks=rows,
        input_accounting=large['counts'],original_source_unchanged=True))
    print(canonical(dict(status='passed',evidence_groups=len(rows),pending_protocol_tests=[])))
