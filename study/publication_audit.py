"""Publication review: exact arithmetic, symbolic PE returns and nested partitions.

This internal review complements the raw-data and CSV verifiers. It does not
claim external peer review or a proof that every possible future test is covered.
"""
from common import ROOT, SOURCE, FIELDS, TEXT_FIELDS, ccb, dump
from audit_model import LIMITS
from fractions import Fraction
from collections import Counter
import ast
import hashlib
import json
import math
import struct
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_REG, X86_OP_IMM

OUT=ROOT/'study/results/publication_audit.json'
MOD=1<<32

def read(name):
    return json.loads((ROOT/'study/results'/name).read_text(encoding='utf-8'))

def exact_weights():
    source=SOURCE.read_text(encoding='utf-8');tree=ast.parse(source)
    assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and
                    any(isinstance(t,ast.Name) and t.id=='weights' for t in n.targets))
    return {ast.literal_eval(k):Fraction(ast.get_source_segment(source,v))
            for k,v in zip(assignment.value.keys,assignment.value.values)}

def weights_and_thresholds():
    weights=exact_weights();assert tuple(weights)==FIELDS
    assert all(w>0 for w in weights.values()) and sum(weights.values())==1
    integer={k:int(100*w) for k,w in weights.items()}
    assert all(Fraction(integer[k],100)==w for k,w in weights.items())
    base={k:0 for k in FIELDS};maximum_error=0.
    for mask in range(1<<13):
        other={k:0 if mask&(1<<i) else 1 for i,k in enumerate(FIELDS)}
        exact=sum(weights[k] for k in FIELDS if base[k]==other[k])
        actual=ccb.compare_files({'source':base},{'destination':other})[1]
        maximum_error=max(maximum_error,abs(float(exact)-actual))
        assert abs(float(exact)-actual)<1e-12
        assert (exact==1)==(mask==8191)==(base==other)
    capacity=2**(6*16)*(len(LIMITS['ninstrs'])+1)
    for field in LIMITS:
        assert LIMITS[field]==sorted(set(LIMITS[field]))
        assert all(isinstance(v,int) and v>=0 for v in LIMITS[field])
        if field!='ninstrs':capacity*=len(LIMITS[field])+1
    assert capacity==2**128
    compiled=read('compiled/summary.json');all_records=1280
    assert compiled['total_pairs']==math.comb(all_records,2)
    assert math.gcd(3,MOD)==1 and pow(3,-1,MOD)*3%MOD==1
    assert len({3*c%MOD for c in range(256)})==256
    for split in ('calibration','test'):
        result=compiled['results'][split]
        assert result['pairs']==math.comb(640,2)
        assert result['positives']==32*math.comb(20,2)==6080
        assert result['negatives']==math.comb(32,2)*20**2==198400
        for row in result['roc']:
            tp,fn,fp,tn=(row[k] for k in ('tp','fn','fp','tn'))
            assert tp+fn==6080 and fp+tn==198400
            tpr=Fraction(tp,tp+fn);fpr=Fraction(fp,fp+tn)
            ba=(tpr+1-fpr)/2
            for key,value in (('tpr',tpr),('fpr',fpr),('balanced_accuracy',ba)):
                assert abs(row[key]-float(value))<1e-14
        if split=='calibration':
            chosen=max(result['roc'],key=lambda r:((Fraction(r['tp'],6080)+
                         Fraction(r['tn'],198400))/2,Fraction(str(r['threshold']))))
            selected=chosen['threshold']
        assert result['selected_threshold']==selected==.58
    return dict(score_patterns=8192,weights_sum=str(sum(weights.values())),
        maximum_float_error=maximum_error,nominal_capacity_bits=128,
        compiler_metrics_checked=202,calibration_selection_exact_rational=True,
        return_difference_invertibility_verified=True)

def pe_code(path,length):
    """Resolve entry-point RVA independently of the fixture generator."""
    data=path.read_bytes();assert data[:2]==b'MZ'
    pe=struct.unpack_from('<I',data,0x3c)[0];assert data[pe:pe+4]==b'PE\0\0'
    machine,sections=struct.unpack_from('<HH',data,pe+4);assert machine==0x8664
    optional_size=struct.unpack_from('<H',data,pe+20)[0];opt=pe+24
    assert struct.unpack_from('<H',data,opt)[0]==0x20b
    entry=struct.unpack_from('<I',data,opt+16)[0]
    for index in range(sections):
        section=opt+optional_size+40*index
        vsize,rva,rsize,offset=struct.unpack_from('<IIII',data,section+8)
        if rva<=entry<rva+vsize:
            start=offset+entry-rva
            assert entry-rva+length<=vsize and entry-rva+length<=rsize
            return data[start:start+length]
    raise AssertionError('Entry point outside sections')

def symbolic_return(code,zero_input):
    """Affine expressions (a*x+b mod 2^32) on each of the two x==0 paths.

    The whitelist is deliberately small: any instruction or operand outside
    the supported witnesses fails the review rather than being ignored.
    """
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    instructions=list(decoder.disasm(code,0))
    assert sum(i.size for i in instructions)==len(code)
    by_address={i.address:i for i in instructions};pc=0;steps=0
    registers={'ecx':(0,0) if zero_input else (1,0)};zflag=None
    def value(op):
        if op.type==X86_OP_IMM:return (0,op.imm%MOD)
        assert op.type==X86_OP_REG
        return registers[instruction.reg_name(op.reg)]
    while True:
        steps+=1;assert steps<=100 and pc in by_address
        instruction=by_address[pc];ops=instruction.operands;mnemonic=instruction.mnemonic
        next_pc=pc+instruction.size
        if mnemonic=='ret':
            assert not ops and 'eax' in registers
            return registers['eax'],steps
        if mnemonic=='nop':assert not ops
        elif mnemonic in ('je','jne'):
            assert len(ops)==1 and ops[0].type==X86_OP_IMM and zflag is not None
            take=zflag if mnemonic=='je' else not zflag
            if take:next_pc=ops[0].imm
        elif mnemonic=='cmp':
            assert len(ops)==2 and instruction.reg_name(ops[0].reg)=='ecx'
            assert ops[1].type==X86_OP_IMM and ops[1].imm==0
            zflag=zero_input
        else:
            assert ops[0].type==X86_OP_REG
            destination=instruction.reg_name(ops[0].reg)
            assert destination in ('eax','edx')
            if mnemonic=='mov':assert len(ops)==2;expression=value(ops[1])
            elif mnemonic=='xor':
                assert len(ops)==2 and ops[1].type==X86_OP_REG and ops[0].reg==ops[1].reg
                expression=(0,0)
            elif mnemonic in ('add','sub'):
                assert len(ops)==2
                a,b=registers[destination];c,d=value(ops[1]);sign=1 if mnemonic=='add' else -1
                expression=((a+sign*c)%MOD,(b+sign*d)%MOD)
            elif mnemonic=='imul':
                assert len(ops)==3 and ops[2].type==X86_OP_IMM
                a,b=value(ops[1]);factor=ops[2].imm
                expression=(a*factor%MOD,b*factor%MOD)
            elif mnemonic in ('or','and'):
                assert len(ops)==2 and ops[1].type==X86_OP_IMM
                assert ops[1].imm%MOD==(0 if mnemonic=='or' else MOD-1)
                expression=registers[destination]
            else:raise AssertionError((mnemonic,instruction.op_str))
            registers[destination]=expression
            # Arithmetic instructions change flags. Only a following CMP
            # establishes the predicate used for conditional branching.
            zflag=None
        pc=next_pc

def symbolic_witnesses():
    controlled=json.loads((ROOT/'study/data/controlled/manifest.json').read_text())
    adversarial=json.loads((ROOT/'study/data/adversarial/manifest.json').read_text())
    proofs=[]
    for family,rows in (('controlled',controlled),('adversarial',adversarial)):
        for row in rows:
            code=pe_code(ROOT/f'study/data/{family}'/row['file'],len(bytes.fromhex(row['code_hex'])))
            assert code==bytes.fromhex(row['code_hex'])
            name=row['file'].removesuffix('.exe');returns={}
            for zero in (True,False):
                actual,steps=symbolic_return(code,zero)
                if family=='controlled':expected=(3,(3*row['constant']-1)%MOD)
                elif name=='condition_equal':expected=(0,1 if zero else 2)
                elif name=='condition_unequal':expected=(0,2 if zero else 1)
                else:expected=(3,{'base':-1,'reordered':-5,'multiplicity':-3,'nop_41':-1,'nop_42':-1}[name]%MOD)
                if zero:expected=(0,expected[1])
                assert actual==expected,(name,zero,actual,expected)
                returns['x=0' if zero else 'x!=0']=dict(coefficient=actual[0],constant=actual[1],steps=steps)
            proofs.append(dict(file=f'{family}/{row["file"]}',code_sha256=hashlib.sha256(code).hexdigest(),returns=returns))
    assert len(proofs)==263
    return dict(routines=263,path_domains=['x=0','x!=0'],domain_cardinality=MOD,
        method='Independent PE parser, Capstone byte decoding and whitelisted modular affine execution',
        proofs=proofs)

def partition_review():
    summary=read('large/summary.json');data=np.load(ROOT/'study/results/large/signature_columns.npz',allow_pickle=False)
    values={key:data[key] for key in ('raw','pre_digest','s2','s4','s8','code')}
    n=len(values['raw']);assert n==7224074
    # Prove the empirical maps are functions on equality classes. This is
    # needed before differences of pair counts can be attributed to stages.
    nesting=[]
    for finer,coarser in (('raw',('pre_digest',)),('pre_digest',('s2','s4','s8'))):
        order=np.argsort(values[finer],kind='stable');ordered=values[finer][order]
        equal=ordered[1:]==ordered[:-1]
        for key in coarser:
            target=values[key][order]
            assert np.all((target[1:]==target[:-1])[equal]),(finer,key)
            nesting.append(dict(finer=finer,coarser=key,equal_adjacencies_verified=int(equal.sum())))
        del order,ordered,equal,target
        print('Equality-class refinement checked:',finer,flush=True)
    counts={}
    for key in ('raw','pre_digest','s2','s4','s8'):
        column=values[key];unique,sizes=np.unique(column,return_counts=True)
        # Python integers also check that no fixed-width count can overflow.
        total=sum(math.comb(int(size),2) for size in sizes)
        joint=np.empty(n,dtype=[('signature',column.dtype),('code',values['code'].dtype)])
        joint['signature']=column;joint['code']=values['code']
        _,code_sizes=np.unique(joint,return_counts=True)
        same=sum(math.comb(int(size),2) for size in code_sizes)
        result=dict(unique=len(unique),all_equal_pairs=total,equal_recovered_code_pairs=same,
                    distinct_recovered_code_collision_pairs=total-same)
        assert all(summary['collision_counts'][key][k]==v for k,v in result.items())
        counts[key]=result
        del unique,sizes,joint,code_sizes
        print('Stage pair counts checked:',key,flush=True)
    # Every target class contains a stored record, and each stored record
    # has a pre-digest key: this map is surjective. A surjection between
    # finite sets of equally many classes is bijective. Thus 4/8-byte
    # equality partitions equal the pre-digest partition, not only its totals.
    for key in ('s4','s8'):assert counts[key]['unique']==counts['pre_digest']['unique']
    distinct=lambda key:counts[key]['distinct_recovered_code_collision_pairs']
    mechanisms=dict(representation=distinct('raw'),added_by_quantisation=distinct('pre_digest')-distinct('raw'),
                    added_by_text_digest={key:distinct(key)-distinct('pre_digest') for key in ('s2','s4','s8')})
    assert mechanisms==summary['mechanism_pairs']
    assert distinct('s2')==mechanisms['representation']+mechanisms['added_by_quantisation']+mechanisms['added_by_text_digest']['s2']
    assert math.comb(n,2)==summary['pair_domains']['all']
    assert sum(summary['pair_domains'][key] for key in ('within_binary','across_binaries'))==math.comb(n,2)
    data.close()
    return dict(records=n,counts=counts,nested_partitions=nesting,mechanisms=mechanisms,
        four_and_eight_byte_partitions_identical_to_pre_digest=True,
        pair_denominators_exact_python_integers=True,
        identity_convention='Raw/pre-digest/recovered-code identity uses SHA-256 keys; signature equality uses exact bytes')

if __name__=='__main__':
    result=dict(status='passed',review_kind='Internal logic and mathematics review',
        arithmetic=weights_and_thresholds(),symbolic=symbolic_witnesses(),partitions=partition_review(),
        statistical_support=read('core/summary.json')['birthday']['null_support'],
        external_peer_review=False)
    assert result['statistical_support']==[2,65537]
    result['verifier_sha256']=hashlib.sha256((ROOT/'study/publication_audit.py').read_bytes()).hexdigest()
    dump(OUT,result)
    print('Publication logic and mathematics review passed',flush=True)
