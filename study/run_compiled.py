"""Labelled compiler/architecture stress corpus, with byte-level emulation."""
from common import *
from run_controlled import worker
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import subprocess
import csv
import random
import struct
import numpy as np
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_ARCH_ARM,UC_MODE_ARM,UC_ARCH_ARM64,UC_ARCH_RISCV,UC_MODE_RISCV64
from unicorn import x86_const as xr,arm_const as ar,arm64_const as aa,riscv_const as rr

DATA=ROOT/'study/data/compiled';OUT=ROOT/'study/results/compiled'
TARGETS={'x64':'x86_64-linux-musl','arm32':'arm-linux-musleabihf','arm64':'aarch64-linux-musl','riscv64':'riscv64-linux-musl'}
OPTS=('O0','O1','O2','O3','Os')

def source_symbols(path):
    data=path.read_bytes();bits=data[4];endian='<' if data[5]==1 else '>'
    if bits==2:
        shoff=struct.unpack_from(endian+'Q',data,40)[0];entry,count=struct.unpack_from(endian+'HH',data,58)
        fmt=endian+'IIQQQQIIQQ';symfmt=endian+'IBBHQQ'
    else:
        shoff=struct.unpack_from(endian+'I',data,32)[0];entry,count=struct.unpack_from(endian+'HH',data,46)
        fmt=endian+'IIIIIIIIII';symfmt=endian+'IIIBBH'
    sections=[struct.unpack_from(fmt,data,shoff+i*entry) for i in range(count)];result={}
    for section in sections:
        if section[1]!=2:continue
        strings=sections[section[6]];names=data[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4],section[4]+section[5],section[9]):
            values=struct.unpack_from(symfmt,data,offset)
            if bits==2:name,info,other,index,value,size=values
            else:name,value,size,info,other,index=values
            text=names[name:names.find(b'\0',name)].decode()
            if not text.startswith('case_'):continue
            assert info&15==2
            file_offset=sections[index][4]+value
            result[0x8000000+file_offset]=dict(symbol=text,constant=int(text.split('_')[-1]),
                 code_bytes=data[file_offset:file_offset+size])
    assert len(result)==64
    return result

def emulate(record,architecture,inputs):
    blocks=record['raw_code'][0]['blocks'];ops=[op for b in blocks for op in b['ops']]
    first=min(op.get('offset',op.get('addr')) for op in ops);last=max(op.get('offset',op.get('addr'))+op['size'] for op in ops)
    code=bytearray(last-first)
    for op in ops:
        address=op.get('offset',op.get('addr'))
        code[address-first:address-first+op['size']]=bytes.fromhex(op['bytes'])
    if architecture=='x64':config=(UC_ARCH_X86,UC_MODE_64,xr.UC_X86_REG_RDI,xr.UC_X86_REG_RAX,xr.UC_X86_REG_RSP,None)
    elif architecture=='arm32':config=(UC_ARCH_ARM,UC_MODE_ARM,ar.UC_ARM_REG_R0,ar.UC_ARM_REG_R0,ar.UC_ARM_REG_SP,ar.UC_ARM_REG_LR)
    elif architecture=='arm64':config=(UC_ARCH_ARM64,0,aa.UC_ARM64_REG_X0,aa.UC_ARM64_REG_X0,aa.UC_ARM64_REG_SP,aa.UC_ARM64_REG_LR)
    else:config=(UC_ARCH_RISCV,UC_MODE_RISCV64,rr.UC_RISCV_REG_A0,rr.UC_RISCV_REG_A0,rr.UC_RISCV_REG_SP,rr.UC_RISCV_REG_RA)
    arch,mode,arg,ret,sp,link=config;uc=Uc(arch,mode)
    uc.mem_map(0x100000,0x10000);uc.mem_write(0x100000,bytes(code));uc.mem_map(0x200000,0x10000);uc.mem_map(0x300000,4096)
    constant=record['source_constant'];rows=[]
    for x in inputs:
        uc.reg_write(arg,x);uc.reg_write(sp,0x208000)
        if link is None:uc.mem_write(0x208000,struct.pack('<Q',0x300000))
        else:uc.reg_write(link,0x300000)
        uc.emu_start(0x100000,0x300000,count=1000)
        actual=uc.reg_read(ret)&0xffffffff;expected=(3*(x+constant)-1)&0xffffffff
        assert actual==expected,(architecture,record['name'],x,actual,expected)
        rows.append((x,actual,expected))
    return bytes(code),rows

if __name__=='__main__':
    DATA.mkdir(parents=True,exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
    source='typedef unsigned int u32;\n'
    for c in range(64):
        source+=f'__attribute__((noinline)) u32 case_{c:02d}(u32 x) {{ volatile u32 v=x; v += {c}u; v ^= 0u; v += 0u; v *= 3u; v -= 2u; v |= 0u; v &= 0xffffffffu; v += 1u; return v; }}\n'
    src=DATA/'arithmetic.c';src.write_text(source,encoding='ascii')
    zig=next((ROOT/'.tools/zig/0.14.1').rglob('zig.exe'))
    cells=[(arch,opt) for arch in TARGETS for opt in OPTS]
    def compile_cell(cell):
        arch,opt=cell;file=DATA/f'{arch}_{opt}.o'
        cmd=[str(zig),'cc','-target',TARGETS[arch],'-'+opt,'-ffreestanding','-fno-stack-protector','-fno-inline','-c',str(src),'-o',str(file)]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        assert result.returncode==0,(cell,result.stderr)
        return dict(architecture=arch,optimisation=opt,file=file.name,command=cmd,
                    sha256=hashlib.sha256(file.read_bytes()).hexdigest())
    with ThreadPoolExecutor(max_workers=4) as pool:manifest=list(pool.map(compile_cell,cells))
    dump(DATA/'manifest.json',manifest)
    rng=random.Random(20261011);inputs=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(10)]
    records=[];emulated=0
    for item in manifest:
        raw=worker(DATA/item['file'],'6.0.4-wasi');dump(OUT/(item['file']+'.raw.json'),raw)
        symbols=source_symbols(DATA/item['file'])
        good=[r for r in raw['records'] if r['status']=='ok' and r['raw_info'].get('addr',r['raw_info'].get('offset')) in symbols]
        assert len(good)==64,(item['file'],len(good))
        for r in good:
            symbol=symbols[r['raw_info'].get('addr',r['raw_info'].get('offset'))]
            r['source_constant']=symbol['constant']
            code,rows=emulate(r,item['architecture'],inputs);emulated+=len(rows)
            assert code==symbol['code_bytes'],(item['file'],symbol['symbol'],'recovered bytes must match ELF symbol bytes')
            records.append(dict(id=item['file']+'/'+r['name'],architecture=item['architecture'],optimisation=item['optimisation'],
                constant=symbol['constant'],source_symbol=symbol['symbol'],features=r['features'],signature=r['signature'],
                signature_4bytes=r['signature_4bytes'],signature_8bytes=r['signature_8bytes'],
                code_sha256=hashlib.sha256(code).hexdigest(),emulation=rows))
        print('Compiled and emulated:',item['file'],flush=True)
    assert len(records)==1280 and emulated==20480
    dump(OUT/'records.json',records)
    weights=np.array([round(ccb.weights[k]*100) for k in FIELDS],dtype=np.uint16)
    matrix=np.array([[int(r['signature'][k],16) if k in TEXT_FIELDS else r['signature'][k] for k in FIELDS] for r in records],dtype=np.uint64)
    pairs=np.triu_indices(len(records),1);a,b=pairs
    scores=np.zeros(len(a),dtype=np.uint16)
    for column,weight in enumerate(weights):scores+=(matrix[a,column]==matrix[b,column])*weight
    labels=np.array([r['constant'] for r in records]);positive=labels[a]==labels[b]
    codes=np.array([r['code_sha256'] for r in records]);distinct=codes[a]!=codes[b]
    splits={'calibration':(labels[a]<32)&(labels[b]<32),'test':(labels[a]>=32)&(labels[b]>=32)}
    results={}
    selected=None
    for split,mask in splits.items():
        stats=[]
        for threshold in range(101):
            prediction=scores>=threshold
            tp=int((mask&positive&prediction).sum());fn=int((mask&positive&~prediction).sum())
            fp=int((mask&~positive&prediction).sum());tn=int((mask&~positive&~prediction).sum())
            stats.append(dict(threshold=threshold/100,tp=tp,fn=fn,fp=fp,tn=tn,
                              tpr=tp/(tp+fn),fpr=fp/(fp+tn),balanced_accuracy=(tp/(tp+fn)+tn/(tn+fp))/2))
        if split=='calibration':selected=max(stats,key=lambda s:(s['balanced_accuracy'],s['threshold']))['threshold']
        chosen=next(s for s in stats if s['threshold']==selected)
        results[split]=dict(pairs=int(mask.sum()),positives=int((mask&positive).sum()),negatives=int((mask&~positive).sum()),
            selected_threshold=selected,metrics_at_selected_threshold=chosen,
            harmful_full_collisions=int((mask&~positive&(scores==100)&distinct).sum()),
            roc=stats)
    with (OUT/'pairs.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.writer(f);writer.writerow(['index_a','index_b','positive_same_formula','same_bytes','score_integer','split'])
        for i,j,label,same,s in zip(a,b,positive,~distinct,scores):
            split='calibration' if labels[i]<32 and labels[j]<32 else 'test' if labels[i]>=32 and labels[j]>=32 else 'cross_split'
            writer.writerow([int(i),int(j),bool(label),bool(same),int(s),split])
    dump(OUT/'summary.json',dict(status='passed',compiler=subprocess.check_output([str(zig),'cc','--version'],text=True).splitlines()[0],
        architectures=list(TARGETS),optimisations=list(OPTS),functions=len(records),emulated_cases=emulated,seed=20261011,
        label_rule='Same c gives identical unsigned-return formula; different c gives different return for every 32-bit x',
        split_rule='Constants 0..31 calibrate; constants 32..63 test; mixed pairs excluded from calibration/test',
        total_pairs=len(a),distinct_code_pairs=int(distinct.sum()),results=results,
        interpretation='Compiler-generated labelled stress family; uncertainty is clustered by source formula, not independent pairs'))
    print(canonical(dict(status='passed',functions=len(records),emulated_cases=emulated,selected_threshold=selected)))
