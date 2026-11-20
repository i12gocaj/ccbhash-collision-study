from common import *
from compat import *
file=ROOT/'study/data/controlled/constant_000.exe'
r2=raw_pipe(file,'6.0.4-wasi')
try:
    r2.cmd('aaa')
    for command in ('aflj','agCj','afij','afvj'):
        print(command,canonical(r2.cmdj(command)),flush=True)
finally:r2.quit()
print('COMPATIBLE_API',canonical(compatible_api(file,'6.0.4-wasi')),flush=True)
