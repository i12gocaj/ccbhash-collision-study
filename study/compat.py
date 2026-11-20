"""Transport/schema adapters; original CCBHash reducers and hash are unchanged."""
from common import *
import copy
import subprocess
import re
from types import SimpleNamespace

class WasiPipe:
    def __init__(self,file):
        guest='/workspace/'+Path(file).resolve().relative_to(ROOT).as_posix()
        self.process=subprocess.Popen([sys.executable,str(ROOT/'study/wasi_launcher.py'),'-q0','-e','scr.prompt=false','-e','scr.color=0',guest],
                                      stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self._receive()
    def _receive(self):
        data=bytearray()
        while True:
            byte=self.process.stdout.read(1)
            if byte==b'\0':
                # WASI's q0 loop retains a textual prompt before the payload.
                # Remove only this exact transport prefix, never JSON content.
                return re.sub(r'^\[0x[0-9a-fA-F]+\]> ', '', data.decode('utf-8'))
            if not byte:raise RuntimeError(f'WASI process ended unexpectedly: {self.process.poll()}')
            data.extend(byte)
    def cmd(self,command):
        self.process.stdin.write((command+'\n').encode());self.process.stdin.flush()
        return self._receive()
    def cmdj(self,command):return json.loads(self.cmd(command))
    def quit(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'q!\n');self.process.stdin.flush()
            except (OSError,BrokenPipeError):pass
            self.process.wait(timeout=10)
        self.process.stdin.close();self.process.stdout.close()

def raw_pipe(file,version):
    if version=='6.0.4-wasi':return WasiPipe(file)
    import r2pipe
    executable=configure_radare(version)
    return r2pipe.open(str(file),flags=['-2'],radare2home=str(executable.parent))

def normalize_info(value):
    value=copy.deepcopy(value)
    for item in value:
        if 'offset' not in item:
            item['offset']=item['addr']
    return value

def normalize_variables(value,afvj=None):
    value=copy.deepcopy(value)
    for item in value:
        if 'bpvars' not in item:
            assert afvj is not None,'Missing actual afvj variable data'
            item.update(bpvars=afvj['bp'],spvars=afvj['sp'],regpvars=afvj['reg'])
        elif 'regpvars' not in item:
            item['regpvars']=item['regvars']
    return value

def normalize_code(value):
    value=copy.deepcopy(value)
    for function in value:
        for block in function['blocks']:
            if 'offset' not in block:block['offset']=block['addr']
    return value

class SchemaPipe:
    def __init__(self,file,version):self.inner=raw_pipe(file,version);self.closed=False
    def cmd(self,command):return self.inner.cmd(command)
    def cmdj(self,command):
        value=self.inner.cmdj(command)
        if command=='aflj':
            if not value:raise ValueError('No functions were detected; refuse the original unbounded retry loop')
            return normalize_info(value)
        if command=='agj':return normalize_code(value)
        if command=='afij':
            vars=self.inner.cmdj('afvj') if value and 'bpvars' not in value[0] else None
            return normalize_variables(value,vars)
        return value
    def quit(self):
        if not self.closed:self.inner.quit();self.closed=True

def compatible_api(file,version,graphs=False):
    original_pipe=ccb.r2pipe
    pipes=[]
    def opened(name):
        pipe=SchemaPipe(name,version);pipes.append(pipe);return pipe
    ccb.r2pipe=SimpleNamespace(open=opened)
    try:
        function=ccb.calculate_ccbhash_and_graphs if graphs else ccb.calculate_ccbhash
        return function(str(file))
    finally:
        ccb.r2pipe=original_pipe
        for pipe in pipes:pipe.quit()
