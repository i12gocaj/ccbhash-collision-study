"""Run the official, checksum-pinned radare2 6.0.4 WASI build on Windows."""
from pathlib import Path
import hashlib
import os
import sys
ROOT=Path(__file__).resolve().parents[1]
if os.name=='nt' and (ROOT/'.tools/python').is_dir():sys.path.insert(0,str(ROOT/'.tools/python'))
import wasmtime

engine=wasmtime.Engine()
wasm=next((ROOT/'.tools/radare/6.0.4-wasi').rglob('radare2-hoststack.wasm'))
cache=wasm.with_suffix('.wasmtime49.cwasm')
if '--compile' in sys.argv:
    module=wasmtime.Module.from_file(engine,str(wasm))
    cache.write_bytes(module.serialize())
    print('Compiled pinned WASI module for this local runtime.');sys.exit()
# Deserialization is restricted to the locally compiled module, outside the
# distribution archive. Remove the cache and recompile on another machine.
module=wasmtime.Module.deserialize_file(engine,str(cache)) if cache.exists() else wasmtime.Module.from_file(engine,str(wasm))
store=wasmtime.Store(engine)
wasi=wasmtime.WasiConfig()
wasi.argv=['radare2']+sys.argv[1:]
wasi.preopen_dir(str(ROOT),'/workspace')
wasi.preopen_dir(str(ROOT/'.tools/radare/6.0.4/radare2-6.0.4-w64'),'/usr/local')
wasi.preopen_dir(str(ROOT/'.tools/radare/6.0.4/radare2-6.0.4-w64/share'),'/usr/local/share/radare2/6.0.4')
wasi.inherit_stdin();wasi.inherit_stdout();wasi.inherit_stderr()
store.set_wasi(wasi)
linker=wasmtime.Linker(engine);linker.define_wasi()
instance=linker.instantiate(store,module)
memory=instance.exports(store)['memory']
memory.grow(store,1024) # 64 MiB exclusively allocated for the C linear stack.
instance.exports(store)['__study_stack_pointer'].set_value(store,memory.data_len(store)-16)
try:
    instance.exports(store)['_start'](store)
except wasmtime.ExitTrap as ex:
    sys.exit(ex.code)
