"""Load the immutable object of study, without patching its implementation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
# Pinned Windows wheels from setup.ps1; other systems use their own environment.
if os.name == 'nt' and (ROOT / '.tools/python').is_dir():
    sys.path.insert(0, str(ROOT / '.tools/python'))
SOURCE = ROOT / 'ccbhash-src/ccbhash.py'
EXPECTED_SHA256 = 'a1d7857c84b262ef50d84e068400e9e2b715e2ec13d1ce6357a12545dd0d1b45'
# EXPECTED_SHA256 is the CRLF working copy used in the Windows campaigns; the
# commit blob itself (LF line endings) hashes to EXPECTED_LF_SHA256. Both are the same text.
EXPECTED_LF_SHA256 = '5522164c0b595db171c74b298b79db23c7dff6185d0232c9c449deacf2946193'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() in (EXPECTED_SHA256, EXPECTED_LF_SHA256), 'Source changed: refuse to reuse study results'
spec = importlib.util.spec_from_file_location('ccbhash_under_study', SOURCE)
ccb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ccb)
FIELDS = tuple(ccb.weights)
TEXT_FIELDS = ('name', 'cfg', 'callgraph', 'opcodes', 'args', 'locals')

def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def signature(features, width=2):
    out = ccb._features_to_hashes(features, n_digits=width)
    assert set(out) == set(FIELDS), 'Incomplete signature must not be counted as a collision'
    return out

def score(a, b):
    return sum(ccb.weights[k] for k in FIELDS if a[k] == b[k])

def base_features():
    return dict(name='entry0', cfg='0:;', callgraph='', opcodes='add;and;mov;mul;or;ret;sub;xor;',
                args='', locals='', ninstrs=10, indegree=0, outdegree=0,
                cc=1, nblocks=1, nvars=0, stackframe=0)

def configure_radare(version='5.8.8'):
    matches = list((ROOT / '.tools/radare' / version).rglob('radare2.exe'))
    if not matches:
        raise FileNotFoundError(f'radare2 {version} is not installed locally')
    os.environ['PATH'] = str(matches[0].parent) + os.pathsep + os.environ.get('PATH', '')
    return matches[0]
