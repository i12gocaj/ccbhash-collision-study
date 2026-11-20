"""Pin inputs, capture provenance, and check every packaged file with SHA-256."""
from pathlib import Path
import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from package import selected_files, ROOT

sys.dont_write_bytecode=True
if os.name=='nt' and (ROOT/'.tools/python').is_dir():sys.path.insert(0,str(ROOT/'.tools/python'))
PINNED=ROOT/'study/INPUT_SHA256.json'
MANIFEST=ROOT/'study/SHA256SUMS.json'

def sha(path):
    with path.open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()
def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False,sort_keys=True),encoding='utf-8')

def check(mapping):
    for name,record in mapping.items():
        file=ROOT/name
        assert file.is_file(),f'Missing file: {name}'
        assert sha(file)==record['sha256'],f'Changed file: {name}'
        assert file.stat().st_size==record['bytes'],f'Changed file size: {name}'

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--snapshot-inputs',action='store_true')
    p.add_argument('--check-inputs',action='store_true')
    p.add_argument('--verify-manifest',action='store_true')
    args=p.parse_args()
    if args.snapshot_inputs:
        inputs=[f for f in selected_files() if f.relative_to(ROOT).parts[0] in ('ccbhash-src','references')]
        write(PINNED,{f.relative_to(ROOT).as_posix():dict(sha256=sha(f),bytes=f.stat().st_size) for f in inputs})
        print('Input snapshot created; this option is only for authoring a new study version.')
        sys.exit()
    check(json.loads(PINNED.read_text(encoding='utf-8')))
    # CRLF working copy (Windows campaigns) or LF commit blob: same text.
    assert sha(ROOT/'ccbhash-src/ccbhash.py') in ('a1d7857c84b262ef50d84e068400e9e2b715e2ec13d1ce6357a12545dd0d1b45','5522164c0b595db171c74b298b79db23c7dff6185d0232c9c449deacf2946193')
    if args.check_inputs:
        print('Pinned input SHA-256 verification passed.');sys.exit()
    if args.verify_manifest:
        data=json.loads(MANIFEST.read_text(encoding='utf-8'));check(data['files'])
        print(f"Manifest passed: {len(data['files'])} files.");sys.exit()
    requirements=(ROOT/'study/requirements.txt').read_text(encoding='utf-8').splitlines()
    packages={line.split('==')[0]:importlib.metadata.version(line.split('==')[0]) for line in requirements if line}
    assert all(packages[line.split('==')[0]]==line.split('==')[1] for line in requirements if line),'Installed package version differs from the reproducibility lock'
    controlled=json.loads((ROOT/'study/results/controlled/summary.json').read_text(encoding='utf-8'))
    radarezip=ROOT/'.tools/radare/radare2-5.8.8-w64.zip'
    write(ROOT/'study/results/provenance.json',dict(
        study_version='1.3',cutoff_date='2026-10-06',object=dict(
            repository='https://github.com/pblprz/ccbhash',commit='fd40d49973f5129c171dc5849ec6a8bb5fdd88a0',
            file='ccbhash-src/ccbhash.py',sha256=sha(ROOT/'ccbhash-src/ccbhash.py')),
        fixture_repository=dict(url='https://github.com/valbucci/binrankbench',commit='6cfda141e0d8ce76d58f1c5e8fc9969b4ba8d8a3'),
        runtime=dict(python=sys.version,os=platform.platform(),machine=platform.machine(),
                     processor=platform.processor(),packages=packages),
        radare2=dict(used=['5.8.8 native','6.0.4 official WASI with documented host stack'],zip_sha256=sha(radarezip) if radarezip.exists() else None,
                     native_probes=controlled['native_probes'],resolution=json.loads((ROOT/'study/results/runtime_resolution.json').read_text(encoding='utf-8'))),
        python39=json.loads((ROOT/'study/results/interpreter_check.json').read_text(encoding='utf-8')),
        compiler=dict(zig='0.14.1',archive_sha256=sha(ROOT/'.tools/zig/zig-0.14.1.zip'),
                      clang=json.loads((ROOT/'study/results/compiled/summary.json').read_text(encoding='utf-8'))['compiler']),
        primary_deposit=json.loads((ROOT/'study/results/large_deposit.json').read_text(encoding='utf-8')),
        archive_reader=dict(version='7zr 26.03',sha256=sha(ROOT/'.tools/7zip/7zr.exe')),
        graph_accelerator=json.loads((ROOT/'.tools/native/native_callgraph.json').read_text(encoding='utf-8')),
        seeds=dict(birthday=20261006,birthday_mc=610062026,synthetic=20261007,emulation=20261008,adversarial=20261009,contracts=20261010,compiled=20261011,strata=list(range(20261100,20261106))),
        manifests='SHA256 checks detect changed files; they are not a digital signature or independent timestamp.',
        external_replication=False))
    files=[f for f in selected_files() if f!=MANIFEST]
    write(MANIFEST,dict(algorithm='SHA-256',excluded=['study/SHA256SUMS.json','output/*.zip','output/package_checks.json',
         '.tools/','.git/','tmp/','__pycache__/','references/binrankbench/evaluation/intermediate/',
         'references/binrankbench/evaluation/output/','references/binrankbench/evaluation/build_output/'],
         files={f.relative_to(ROOT).as_posix():dict(sha256=sha(f),bytes=f.stat().st_size) for f in files}))
    print(json.dumps(dict(manifest_files=len(files),input_verification='passed')))
