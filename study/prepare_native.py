"""Build the auditable graph accelerator using the pinned Zig toolchain."""
from common import *
import subprocess
if __name__=='__main__':
    zig=ROOT/'.tools/zig/0.14.1/zig-x86_64-windows-0.14.1/zig.exe'
    source=ROOT/'study/native_callgraph.c';destination=ROOT/'.tools/native/native_callgraph.dll'
    destination.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([str(zig),'cc','-O3','-shared','-std=c11','-target','x86_64-windows-gnu',str(source),'-o',str(destination)],check=True)
    dump(destination.with_suffix('.json'),dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
         dll_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),compiler='Zig 0.14.1 / Clang 19.1.7',target='x86_64-windows-gnu'))
    print('Graph accelerator compiled from the supplied C source')
