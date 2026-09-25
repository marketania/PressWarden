#!/usr/bin/env python3
# Temporary transfer correction, never shipped. Only the approved image is written.
import base64, hashlib, json, subprocess, zlib
from pathlib import Path
response=json.loads(subprocess.check_output(['gh','api','repos/marketania/PressWarden/git/blobs/4c3704e616e3ac4b8d97ffa8a5f55c1ef19e2336'],text=True))
data=base64.b64decode(response['content'])
assert len(data)==28325
prefix=zlib.decompress(base64.b64decode(Path('.github/audit-staging/art-prefix.b64').read_text(),validate=True))
assert len(prefix)==4096 and hashlib.sha256(prefix).hexdigest()=='ab79918ebd26e5aa363aa4beb691ce1856b5e1ca45444e0ac1a02e2f500f5f8b'
# Prior chunk diagnostics verified every source chunk after 4096 at offset +3.
result=prefix+data[4099:]
assert len(result)==28322 and hashlib.sha256(result).hexdigest()=='b233844db9fa3ba73b9478b3617ca3bcb080988cc2d081faa71523da8d2f4110'
out=Path('docs/assets/press-tool-family.webp');out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(result)
print('Approved artwork reconstructed byte-for-byte and verified: 28322 bytes.')
