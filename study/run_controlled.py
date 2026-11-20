"""Real disassembly, native API probes, explicit input adaptation and emulation."""
from common import *
import argparse
import contextlib
import copy
import io
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
import r2pipe
from compat import raw_pipe, normalize_variables

OUT = ROOT / 'study/results/controlled'

def worker_fingerprint():
    names=('run_controlled.py','compat.py','common.py','wasi_launcher.py')
    return hashlib.sha256(b''.join((ROOT/'study'/name).read_bytes() for name in names)).hexdigest()

def adapt_function(info, code, finf, global_graph):
    """Only rename schema keys; never monkeypatch CCBHash or invent features."""
    code=copy.deepcopy(code)
    for block in code[0]['blocks']:
        if 'offset' not in block:
            block['offset']=block['addr']
    finf=copy.deepcopy(finf)
    for item in finf:
        if 'regpvars' not in item:
            # Upstream expects regpvars; radare emits regvars. Preserve kinds/types.
            item['regpvars']=item.get('regvars',[])
    variables=ccb._get_variables(finf)
    features=dict(name=info['name'], nvars=info.get('nargs',0)+info.get('nlocals',0),
                  args=variables['args'],locals=variables['vars'],opcodes=ccb._get_opcodes(code),
                  nblocks=info['nbbs'],cc=info['cc'],indegree=info['indegree'],outdegree=info['outdegree'],
                  ninstrs=info['ninstrs'],cfg=ccb._get_cfg(code),
                  callgraph=ccb._get_callgraph(info['name'],global_graph),stackframe=info['stackframe'])
    return features

def worker(file,version,native=False):
    if version!='6.0.4-wasi': configure_radare(version)
    file=Path(file)
    if native:
        log=io.StringIO()
        with contextlib.redirect_stdout(log):
            result=ccb.calculate_ccbhash(str(file))
        return dict(file=file.name,file_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                    radare_version=version,mode='native_unmodified_API',signatures=result,log=log.getvalue())
    r2=raw_pipe(file,version)
    try:
        r2.cmd('aaa')
        info=r2.cmdj('aflj'); graph=r2.cmdj('agCj'); records=[]
        for fn in info:
            if fn['ninstrs']<10 and fn['nbbs']<2:
                records.append(dict(name=fn['name'],status='filtered',info=fn)); continue
            r2.cmd(f"s {fn.get('offset',fn.get('addr'))}")
            code=r2.cmdj('agj'); finf=r2.cmdj('afij')
            raw_variables=r2.cmdj('afvj') if finf and 'bpvars' not in finf[0] else None
            adapted_finf=normalize_variables(finf,raw_variables)
            log=io.StringIO()
            with contextlib.redirect_stdout(log):
                features=adapt_function(fn,code,adapted_finf,graph)
            records.append(dict(name=fn['name'],status='ok',features=features,signature=signature(features),
                                signature_4bytes=signature(features,4),signature_8bytes=signature(features,8),
                                raw_info=fn,raw_code=code,raw_finf=finf,raw_variables=raw_variables,
                                serialization_diagnostics=log.getvalue()))
        return dict(file=file.name,file_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                    radare_version=version,mode='original_core_with_documented_input_schema_adaptation',
                    adaptations=['regvars -> regpvars (unchanged entries/kinds)',
                                 'if afij omits variables: actual afvj bp/sp/reg -> bpvars/spvars/regpvars',
                                 'block addr -> offset if required'],
                    raw_callgraph=graph,records=records)
    finally:
        r2.quit()

def run_job(file,version,native=False):
    path=OUT/version/('native' if native else 'adapted')/(file.stem+'.json')
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists() and os.environ.get('CCBHASH_FORCE_CONTROLLED')!='1':
        cached=json.loads(path.read_text(encoding='utf-8'))
        if (cached.get('file')==file.name and cached.get('radare_version')==version
                and cached.get('worker_fingerprint')==worker_fingerprint()
                and cached.get('file_sha256')==hashlib.sha256(file.read_bytes()).hexdigest()):
            return cached
    command=[sys.executable,str(Path(__file__).resolve()),'--worker',str(file),'--version',version,'--output',str(path)]
    if native: command.append('--native')
    try:
        done=subprocess.run(command,capture_output=True,text=True,timeout=45)
        (path.with_suffix('.log')).write_text(done.stdout+'\n'+done.stderr,encoding='utf-8')
        if done.returncode: return dict(file=file.name,status='worker_error',returncode=done.returncode)
        return json.loads(path.read_text(encoding='utf-8'))
    except subprocess.TimeoutExpired:
        return dict(file=file.name,status='timeout',timeout_seconds=45)

def emulate():
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RAX, UC_X86_REG_RSP
    from fixtures import make_constant
    rows=[]; rng=random.Random(20261008)
    inputs=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(26)]
    for c in range(256):
        _,expected_code,_=make_constant(c)
        pe_file=ROOT/'study/data/controlled'/f'constant_{c:03d}.exe'
        code=pe_file.read_bytes()[512:512+len(expected_code)]
        assert code==expected_code,'Emulation must evaluate the code present in the studied PE file'
        emulator=Uc(UC_ARCH_X86,UC_MODE_64)
        emulator.mem_map(0x100000,4096); emulator.mem_write(0x100000,code)
        emulator.mem_map(0x200000,4096)
        for x in inputs:
            emulator.reg_write(UC_X86_REG_RCX,x); emulator.reg_write(UC_X86_REG_RSP,0x200800)
            # Stop immediately before RET: the return value is already established.
            emulator.emu_start(0x100000,0x100000+len(code)-1,count=100)
            actual=emulator.reg_read(UC_X86_REG_RAX)&0xffffffff
            expected=(3*(x+c)-1)&0xffffffff
            assert actual==expected,(c,x,actual,expected)
            rows.append(dict(constant=c,x=x,actual=actual,expected=expected))
    dump(OUT/'emulation.json',dict(seed=20261008,inputs=inputs,checks=len(rows),rows=rows,
         proof='f_c(x)=3(x+c)-1 mod 2^32. Since gcd(3,2^32)=1, any two distinct c in 0..255 have different return values for every 32-bit x. This is a proof for this generated family, not general program equivalence.'))
    return dict(checks=len(rows),functions=256,inputs_per_function=32,all_passed=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--worker'); p.add_argument('--version',default='5.8.8'); p.add_argument('--output');p.add_argument('--native',action='store_true');p.add_argument('--force',action='store_true');args=p.parse_args()
    if args.force: os.environ['CCBHASH_FORCE_CONTROLLED']='1'
    if args.worker:
        result=worker(args.worker,args.version,args.native)
        result['worker_fingerprint']=worker_fingerprint()
        dump(args.output,result);sys.exit()
    started=time.perf_counter();OUT.mkdir(parents=True,exist_ok=True)
    files=sorted((ROOT/'study/data/controlled').glob('*.exe'))
    assert len(files)==256, 'The complete controlled family is required'
    probes=[]
    # All 256 native calls are made, and every empty result is classified as failure.
    for version in ('5.8.8','6.0.4'):
        try:
            startup=subprocess.run([str(configure_radare(version)),'-v'],capture_output=True,text=True,timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            probes.append(dict(version=version,attempted=0,status='radare_runtime_unavailable',
                               reason=type(exc).__name__,note='not counted as a collision'))
            continue
        if startup.returncode:
            probes.append(dict(version=version,attempted=0,status='radare_runtime_unavailable',
                               startup_exit_code=startup.returncode,stderr=startup.stderr,
                               note='not counted as a CCBHash extraction failure or collision'))
            print('Radare runtime unavailable',version,startup.returncode,flush=True)
            continue
        with ThreadPoolExecutor(max_workers=4) as pool:
            native=list(pool.map(lambda file:run_job(file,version,True),files))
        probes.append(dict(version=version,attempted=len(native),nonempty=sum(bool(x.get('signatures')) for x in native),
                           empty=sum(x.get('signatures')=={} for x in native),worker_errors=sum('status' in x for x in native)))
        print('Native probes completed',version,flush=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        records=list(pool.map(lambda file:run_job(file,'5.8.8'),files))
    dump(OUT/'all_records.json',records)
    good=[rec for item in records for rec in item.get('records',[]) if rec['status']=='ok']
    assert all('status' not in item for item in records), 'Controlled extraction worker failed'
    assert len(good)==256, 'A controlled function was omitted'
    from run_core import counts
    summary=dict(native_probes=probes,adapted_attempted=len(files),adapted_worker_errors=[x for x in records if 'status' in x],
                 successful_functions=len(good),distinct_feature_vectors=counts([x['features'] for x in good]),
                 hashes={str(w):counts([x['signature' if w==2 else f'signature_{w}bytes'] for x in good]) for w in (2,4,8)},
                 emulation=emulate(),elapsed_seconds=time.perf_counter()-started)
    dump(OUT/'summary.json',summary)
    print(canonical(summary),flush=True)
