"""Create benign, minimal PE64 fixtures; no malware and no external compiler."""
import struct
from common import ROOT, dump
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def pe64(code):
    header = bytearray(512)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3c, 0x80)
    header[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', header, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into('<H', header, opt, 0x20b)
    struct.pack_into('<I', header, opt+4, ((len(code)+511)//512)*512)
    struct.pack_into('<II', header, opt+16, 0x1000, 0x1000)
    struct.pack_into('<Q', header, opt+24, 0x140000000)
    struct.pack_into('<II', header, opt+32, 0x1000, 0x200)
    struct.pack_into('<HH', header, opt+40, 6, 0)
    struct.pack_into('<HH', header, opt+48, 6, 0)
    struct.pack_into('<II', header, opt+56, ((len(code)+4095)//4096+1)*4096, 0x200)
    struct.pack_into('<HH', header, opt+68, 3, 0)
    struct.pack_into('<QQQQ', header, opt+72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into('<I', header, opt+108, 16)
    sec = opt+240
    header[sec:sec+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', header, sec+8, len(code), 0x1000, ((len(code)+511)//512)*512, 512)
    struct.pack_into('<I', header, sec+36, 0x60000020)
    return bytes(header) + code + b'\0' * ((-len(code)) % 512)

def make_constant(constant):
    asm = f'mov eax, ecx; add eax, {constant}; xor edx, edx; add eax, edx; imul eax, eax, 3; sub eax, 2; or eax, 0; and eax, -1; add eax, 1; ret'
    code, count = Ks(KS_ARCH_X86, KS_MODE_64).asm(asm)
    return asm, bytes(code), count

if __name__ == '__main__':
    directory = ROOT / 'study/data/controlled'
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for c in range(256):
        asm, code, count = make_constant(c)
        file = directory / f'constant_{c:03d}.exe'
        file.write_bytes(pe64(code))
        rows.append(dict(file=file.name, constant=c, assembly=asm, code_hex=code.hex(),
                         instruction_count=count, behavior='(3 * (x + constant) - 1) modulo 2^32'))
    dump(directory / 'manifest.json', rows)
    print('Created 256 controlled PE64 inputs')
