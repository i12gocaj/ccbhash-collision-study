"""Native exact serializer; names stay in Python and the C ABI uses indices."""
from common import *
import ctypes
from array import array

class NativeCallgraph:
    _library=None
    def __init__(self,adjacency):
        path=ROOT/'.tools/native/native_callgraph.dll'
        if self.__class__._library is None:
            provenance=json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
            assert provenance['source_sha256']==hashlib.sha256((ROOT/'study/native_callgraph.c').read_bytes()).hexdigest()
            assert provenance['dll_sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
            library=ctypes.CDLL(str(path))
            library.ccb_graph_create.argtypes=[ctypes.c_uint32,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64),ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_ubyte)]
            library.ccb_graph_create.restype=ctypes.c_void_p
            library.ccb_graph_text.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint64)];library.ccb_graph_text.restype=ctypes.c_void_p
            library.ccb_graph_destroy.argtypes=[ctypes.c_void_p];library.ccb_graph_destroy.restype=None
            self.__class__._library=library
        self.library=self.__class__._library;self.handle=None
        self.names={name:i for i,name in enumerate(adjacency)}
        for targets in adjacency.values():
            for target in targets:
                if target not in self.names:self.names[target]=len(self.names)
        assert len(self.names)<2**32
        self.offsets=array('Q',[0]);self.targets=array('I');self.present=array('B')
        for name in self.names:
            self.present.append(name in adjacency)
            self.targets.extend(self.names[target] for target in dict.fromkeys(adjacency.get(name,[])))
            self.offsets.append(len(self.targets))
        assert self.offsets.itemsize==8 and self.targets.itemsize==4
        self.buffers=((ctypes.c_uint64*len(self.offsets)).from_buffer(self.offsets),
          (ctypes.c_uint32*len(self.targets)).from_buffer(self.targets),
          (ctypes.c_ubyte*len(self.present)).from_buffer(self.present))
        if self.names:
            self.handle=self.library.ccb_graph_create(len(self.names),len(self.targets),*self.buffers)
            if not self.handle:raise MemoryError('Cannot allocate graph workspace')
    def text(self,root):
        if root not in self.names:return ''
        length=ctypes.c_uint64();pointer=self.library.ccb_graph_text(self.handle,self.names[root],ctypes.byref(length))
        if not pointer:raise RuntimeError('Native graph serialization failed its queue bound')
        return ctypes.string_at(pointer,length.value).decode('ascii')
    def close(self):
        if self.handle:self.library.ccb_graph_destroy(self.handle);self.handle=None
    def __del__(self):
        if getattr(self,'handle',None):self.close()
