"""Build a self-contained evidence archive; preserve third-party licenses/source."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ARCHIVE=ROOT/'output/CCBHASH_ESTUDIO_REPRODUCIBLE.zip'

def selected_files():
    files=[ROOT/name for name in ('README.md','CITATION.cff','LICENSE') if (ROOT/name).is_file()]
    for name in ('study','output','docs','ccbhash-src','references/binrankbench'):
        for p in (ROOT/name).rglob('*'):
            if not p.is_file(): continue
            rel=p.relative_to(ROOT)
            if any(x in ('.git','__pycache__','.pytest_cache') for x in rel.parts): continue
            if rel.parts[:3]==('references','binrankbench','evaluation') and len(rel.parts)>3:
                if rel.parts[3] in ('intermediate','output','build_output'): continue
            if p.suffix in ('.pyc','.zip') or p==ROOT/'output/package_checks.json': continue
            if p.name=='.env' or p.name.startswith('._') or p.name=='.DS_Store': continue
            if p.name in ('CAMBIOS.md','download_large.py','prepare_prefix.py'): continue
            if p.name=='pilot_x64.o': continue
            files.append(p)
    return sorted(set(files),key=lambda x:x.relative_to(ROOT).as_posix())

if __name__=='__main__':
    files=selected_files()
    assert (ROOT/'study/SHA256SUMS.json') in files
    ARCHIVE.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(ARCHIVE,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for index,path in enumerate(files,1):
            name=path.relative_to(ROOT).as_posix()
            entry=zipfile.ZipInfo(name,date_time=(2026,10,6,0,0,0))
            entry.compress_type=zipfile.ZIP_STORED if path.suffix in ('.npz','.gz') else zipfile.ZIP_DEFLATED
            entry.external_attr=0o100644 << 16
            with path.open('rb') as source,archive.open(entry,'w',force_zip64=True) as destination:
                while chunk:=source.read(8*1024*1024):destination.write(chunk)
            if index%1000==0:print(json.dumps(dict(packaged_files=index,total_files=len(files))),flush=True)
    print('Archive written; checking all ZIP CRCs and the archived SHA-256 manifest',flush=True)
    with zipfile.ZipFile(ARCHIVE) as archive:
        assert archive.testzip() is None
        names=archive.namelist()
        assert len(names)==len(set(names))==len(files)
        assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in names)
        checks=json.loads(archive.read('study/SHA256SUMS.json'))
        for name,record in checks['files'].items():
            sha=hashlib.sha256();size=0
            with archive.open(name) as source:
                while chunk:=source.read(8*1024*1024):sha.update(chunk);size+=len(chunk)
            assert size==record['bytes']
            assert sha.hexdigest()==record['sha256'],name
    result=dict(archive=ARCHIVE.name,files=len(files),bytes=ARCHIVE.stat().st_size,
                sha256=hashlib.file_digest(ARCHIVE.open('rb'),'sha256').hexdigest(),zip_crc='passed',
                archived_manifest='passed',path_safety='passed')
    (ROOT/'output/package_checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
