from common import *
import contextlib
import io
import r2pipe

configure_radare()
file = ROOT / 'study/data/controlled/constant_001.exe'
log = io.StringIO()
with contextlib.redirect_stdout(log):
    result = ccb.calculate_ccbhash(str(file))
r2 = r2pipe.open(str(file), flags=['-2'])
r2.cmd('aaa')
raw = {command: r2.cmdj(command) for command in ('aflj', 'afij', 'agj', 'agCj', 'afvj')}
r2.quit()
dump(ROOT / 'study/results/probe.json', dict(native_result=result, native_log=log.getvalue(), raw=raw))
print(canonical(dict(native_result=result, native_log=log.getvalue(), schemas={k: list(v[0]) if isinstance(v,list) and v else type(v).__name__ for k,v in raw.items()})))
