"""Expose the LLVM C-stack pointer so the host can give it separate memory.

Only the export section is extended. All code/data/global sections of the
official module are byte-for-byte unchanged. Original artifact is retained.
"""
from common import *

def uleb(value):
    result=bytearray()
    while True:
        byte=value&127;value>>=7
        result.append(byte|(128 if value else 0))
        if not value:return bytes(result)

def read_leb(data,pos,signed=False):
    result=shift=0
    while True:
        byte=data[pos];pos+=1;result|=(byte&127)<<shift;shift+=7
        if byte<128:break
    if signed and byte&64:result-=1<<shift
    return result,pos

def sections(data):
    pos=8;out=[]
    while pos<len(data):
        kind=data[pos];size,start=read_leb(data,pos+1)
        out.append((kind,data[start:start+size]));pos=start+size
    return out

if __name__=='__main__':
    wasm=next((ROOT/'.tools/radare/6.0.4-wasi').rglob('radare2.wasm'))
    original=wasm.read_bytes();parsed=sections(original)
    assert hashlib.sha256(original).hexdigest()=='4ffea034036a151dedd655a4f5c3fc85579b93209fbfb88fcf048f7dd6ee607c'
    glob=next(payload for kind,payload in parsed if kind==6)
    n,pos=read_leb(glob,0)
    # The official LLVM module has exactly one mutable i32 global: its C SP.
    assert n==1 and glob[pos:pos+3]==b'\x7f\x01\x41',glob[:30].hex()
    initial_sp,end=read_leb(glob,pos+3,True);assert glob[end:]==b'\x0b'
    name=b'__study_stack_pointer';new=bytearray(original[:8])
    for kind,payload in parsed:
        if kind==7:
            count,start=read_leb(payload,0)
            payload=uleb(count+1)+payload[start:]+uleb(len(name))+name+b'\x03\x00'
        new.extend(bytes([kind])+uleb(len(payload))+payload)
    modified=wasm.with_name('radare2-hoststack.wasm');modified.write_bytes(new)
    unchanged=[kind for (kind,a),(_,b) in zip(parsed,sections(new)) if kind!=7 and a==b]
    assert all(a==b for (kind,a),(_,b) in zip(parsed,sections(new)) if kind!=7)
    dump(ROOT/'study/results/runtime_resolution.json',dict(
        radare_version='6.0.4',distribution='Official WASI with host-side C stack allocation',
        wasi_zip_sha256='11ba96d1bfa97f6ee41a9a06c2ef39772b3521df110979365490901e3c523ec0',
        original_wasm_sha256=hashlib.sha256(original).hexdigest(),
        host_export_wasm_sha256=hashlib.sha256(new).hexdigest(),
        original_stack_pointer=initial_sp,added_host_stack_bytes=64*1024*1024,
        modified_section='Export only: add access to the existing mutable LLVM C stack pointer',
        preserved_sections=unchanged,code_and_data_unchanged=True,
        windows_native_failure='0xC00000FD; unmodified 32-bit and 64-bit builds',
        initial_wasi_failure='Out-of-bounds memory trap during recursion; eliminated for the evaluated binaries by relocating the C stack into grown memory',
        completion_status='pending execution verification'))
    print(canonical(dict(initial_sp=initial_sp,original_sha256=hashlib.sha256(original).hexdigest())))
