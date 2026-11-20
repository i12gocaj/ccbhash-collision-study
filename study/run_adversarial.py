"""Real binary witnesses for ordering, multiplicity, conditions and quantization."""
from common import *
from fixtures import pe64,make_constant
from keystone import Ks,KS_ARCH_X86,KS_MODE_64
from run_controlled import worker
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RAX,UC_X86_REG_RSP
import random
import struct

DATA=ROOT/'study/data/adversarial';OUT=ROOT/'study/results/adversarial'
DATA.mkdir(parents=True,exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)

if __name__=='__main__':
    base,_,_=make_constant(0)
    branch='mov eax, 1; xor edx, edx; add edx, 0; cmp ecx, 0; CONDITION take; mov eax, 2; or eax, 0; add eax, 0; ret; take: and eax, -1; sub eax, 0; ret'
    assembly=dict(base=base,
        reordered=base.replace('imul eax, eax, 3; sub eax, 2','sub eax, 2; imul eax, eax, 3'),
        multiplicity=base.replace('add eax, 1; ret','sub eax, 1; ret'),
        condition_equal=branch.replace('CONDITION','je'),condition_unequal=branch.replace('CONDITION','jne'),
        nop_41=base[:-3]+'nop; '*31+'ret',nop_42=base[:-3]+'nop; '*32+'ret')
    expected=dict(base=lambda x:(3*x-1)&0xffffffff,reordered=lambda x:(3*x-5)&0xffffffff,
        multiplicity=lambda x:(3*x-3)&0xffffffff,condition_equal=lambda x:1 if x==0 else 2,
        condition_unequal=lambda x:2 if x==0 else 1,nop_41=lambda x:(3*x-1)&0xffffffff,nop_42=lambda x:(3*x-1)&0xffffffff)
    manifest=[];code_map={};emulation=[];rng=random.Random(20261009)
    inputs=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(26)]
    for name,asm in assembly.items():
        code,count=Ks(KS_ARCH_X86,KS_MODE_64).asm(asm);code=bytes(code);file=DATA/(name+'.exe');file.write_bytes(pe64(code))
        code_map[name]=code
        manifest.append(dict(file=file.name,assembly=asm,code_hex=code.hex(),instructions=count,sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
        uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(0x100000,4096);uc.mem_write(0x100000,code);uc.mem_map(0x200000,4096)
        assert file.read_bytes()[512:512+len(code)]==code
        for x in inputs:
            uc.reg_write(UC_X86_REG_RCX,x);uc.reg_write(UC_X86_REG_RSP,0x200800)
            uc.mem_write(0x200800,struct.pack('<Q',0x100000+len(code)))
            uc.emu_start(0x100000,0x100000+len(code),count=1000)
            actual=uc.reg_read(UC_X86_REG_RAX)&0xffffffff
            assert actual==expected[name](x),(name,x,actual)
            emulation.append(dict(function=name,x=x,actual=actual,expected=expected[name](x)))
    dump(DATA/'manifest.json',manifest);dump(OUT/'emulation.json',dict(seed=20261009,rows=emulation,checks=len(emulation)))
    results={}
    for version in ('5.8.8','6.0.4-wasi'):
        raw={name:worker(DATA/(name+'.exe'),version) for name in assembly}
        dump(OUT/(version+'_raw.json'),raw)
        records={name:item['records'][0] for name,item in raw.items()}
        pairs=[]
        for a,b,mechanism,semantically_equal in [
            ('base','reordered','instruction order omitted',False),
            ('base','multiplicity','instruction multiplicities omitted',False),
            ('reordered','multiplicity','order and multiplicities omitted',False),
            ('condition_equal','condition_unequal','branch condition normalized',False),
            ('nop_41','nop_42','NOP omission plus instruction-count quantization',True)]:
            ra,rb=records[a],records[b]
            for width in (2,4,8):
                k='signature' if width==2 else f'signature_{width}bytes'
                assert ra[k]==rb[k],(version,a,b,width)
            assert all((expected[a](x)==expected[b](x))==semantically_equal for x in inputs)
            pairs.append(dict(a=a,b=b,full_collision=True,raw_features_equal=ra['features']==rb['features'],
                              differing_features=[k for k in FIELDS if ra['features'][k]!=rb['features'][k]],
                              mechanism=mechanism,return_values_equal=semantically_equal))
        results[version]=dict(functions=len(records),tested_pairs=pairs,all_passed=True)
    dump(OUT/'summary.json',dict(status='passed',versions=results,emulated_cases=len(emulation),
         proof='Arithmetic: returns 3x-1, 3x-5, 3x-3 modulo 2^32 differ for every x; inverted conditional returns 1 versus 2 for every x; inserting NOP leaves the arithmetic result unchanged.',
         scope='Seven actual PE64 routines; controlled witnesses, not an operational malware false-positive estimate'))
    print('Seven binary witnesses verified on both disassembler runtimes; 224 emulations passed.')
