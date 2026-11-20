"""Check both original API entrypoints with schema/transport compatibility."""
from common import *
from compat import compatible_api
from run_controlled import worker
from concurrent.futures import ThreadPoolExecutor
import argparse
import contextlib
import io
import subprocess

OUT=ROOT/'study/results/integration'

def job(file,version):
    path=OUT/version/(file.stem+'.json');path.parent.mkdir(parents=True,exist_ok=True)
    done=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker',str(file),
                         '--version',version,'--output',str(path)],capture_output=True,text=True,timeout=60)
    path.with_suffix('.log').write_text(done.stdout+'\n'+done.stderr,encoding='utf-8')
    assert done.returncode==0,(file,version,done.stderr)
    return json.loads(path.read_text(encoding='utf-8'))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--worker');p.add_argument('--version');p.add_argument('--output');args=p.parse_args()
    if args.worker:
        file=Path(args.worker);capture=io.StringIO()
        with contextlib.redirect_stdout(capture):
            recovered=worker(file,args.version)
            actual=compatible_api(file,args.version)
            with_graphs,cfg,call=compatible_api(file,args.version,True)
        expected={x['name']:x['signature'] for x in recovered['records'] if x['status']=='ok'}
        assert len(expected)==1 and actual==expected==with_graphs
        assert set(actual)==set(cfg)==set(call)
        assert not capture.getvalue(),'Controlled cases must not produce serialization diagnostics'
        dump(args.output,dict(file=file.name,file_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                              version=args.version,raw_extraction=recovered,api_signatures=actual,
                              api_with_graphs_signatures=with_graphs,cfg=cfg,callgraph=call,status='passed'))
        sys.exit()
    files=sorted((ROOT/'study/data/controlled').glob('*.exe'))
    summaries={}
    for version in ('5.8.8','6.0.4-wasi'):
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows=list(pool.map(lambda f:job(f,version),files))
        assert len(rows)==256 and all(x['status']=='passed' for x in rows)
        from run_core import counts
        summaries[version]=dict(files=len(rows),api_calls=2*len(rows),zero_extraction_errors=True,
                                signatures=counts([x['api_signatures']['entry0'] for x in rows]))
        print('Both API entrypoints passed for all controlled inputs:',version,flush=True)
    dump(OUT/'summary.json',dict(status='passed',versions=summaries,
         meaning='Original API source executed with explicit schema/transport adapter; no changes to reducers, quantization, digests or weights'))
