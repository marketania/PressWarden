#!/usr/bin/env python3
# Temporary transfer verification, never shipped. No source or client files read.
import base64, hashlib, json, subprocess
from pathlib import Path
hashes = ['90501d04959246cd3df04d6e904b4c23675d8754075611183216ab16c6ac3a6c','0f1028efc8b3898ff19170f6431e5c8b17e95a133a725508f2c732c5ade3b55a','891fc81eeed887eb47ea73e59502a26463eb5a9939edf8c8be1fe8d8dc641ffd','d62a30375385e9761e83873fc348a3f8e99e5cb346af22bcf4da44e351de9e6c','c645314141b241b454eed78c374ef55806681e8b23021b2954b7225de783cd75','6ab89145d1a09de649dfb9eb250136b11efb9af8ea428c454944191b122dadd6','53594e93194f7db081babd341ec7e7d56acc5850b6441dc9140ffb26c33a4c96','b24ff166f880c47986233894c1c38e36bcd8d61dadeee39152b94928f7cb5dbe','797443dae51608208a629355aa7b2b9fe62d5a67cc47ea43cf2de9857add0ceb','9dd0f19c94fbbc6030355130f1c505205fb594e39411cc6347534aa6a074436d','2fc7ff9bf370f60cd948a5d199dd9d40384b635ca55491cc0838d8facf4fd990','f11d090078de2f51193c24322f56932f0ce41ab2adb64297f69605c8333db17a','82956f25aef1b1ad282f5ddbaa10046645c3a7c25581f113c4fe925b0fac2d8b','2bfdde923a72a86e166342a1334deb120b8f65749a4adf1cfa00d84ba12589b5','e9c52cc5499d9b2a22a546885f7f64ca9d94bbd10a0c4dc1ce8195d1977e9c08','7297adea47798bfcb6de7e1ab761281dd89e852b06f8739f7cb26e09804a943e','3b910aa6d150889b726676fa3153254208fdb64540f581b3e6b4f9f27eccd222','85671e189728306797b0412b4f5ecf18acbbad13adfcee5d162a42dcd398b698','fa99bf6ee6b72dfc926eddc883242870f98e0319921fc12562967d5d73495e6e','54c56ed17ca3e499ad4ef1e54983ab3d776f3d3d148c62c04740c396e2fbc81b','04a691f275ee3005b147e73e3f7ce2d37eda8094cf1d2e14c78eb7482ff92a07','fe161be2770fcc17fa1c0caf0a50052867be93249c5ac305632d247bafa80333','6168c6ae3cc4d0dac5b968c111dfaa483251dabe811556398db8010945277787','0c18b44057e4a8b9f39f317b2bc864057e067c04144d23e80217823597f93c71','13bcf018a2be80ace01e0e2075544e555efee0d6bc741e77bc735ceabcc731ec','b64301cfe2e86e892ffd7dc145641eefa8b4a79a38d1362c067340dbae59163d','b0e7bc06406121d4fe695e0b106851c6f5834f215fe81b381b1f3c006c8be773','dc2845d1caf6362683c838582a7b87512376a4c9e67acb9d99658c17edd3ea13']
response=json.loads(subprocess.check_output(['gh','api','repos/marketania/PressWarden/git/blobs/4c3704e616e3ac4b8d97ffa8a5f55c1ef19e2336'],text=True))
data=base64.b64decode(response['content']); print('Transferred bytes:',len(data))
parts=[];missing=[]
for i,h in enumerate(hashes):
    n=min(1024,28322-i*1024)
    candidates=range(max(0,i*1024-256),min(len(data)-n,i*1024+256)+1)
    found=None
    for pos in candidates:
        part=data[pos:pos+n]
        if hashlib.sha256(part).hexdigest()==h:
            found=part; print('Verified chunk',i,'offset',pos-i*1024);break
    if found is None:
        fix=Path('.github/audit-staging')/('art-'+str(i)+'.b64')
        if fix.exists():
            found=base64.b64decode(fix.read_text(),validate=True)
            assert len(found)==n and hashlib.sha256(found).hexdigest()==h
        else:missing.append(i)
    parts.append(found)
if missing:
    print('Missing approved chunks:',missing)
    raise SystemExit(2)
result=b''.join(parts)
assert hashlib.sha256(result).hexdigest()=='b233844db9fa3ba73b9478b3617ca3bcb080988cc2d081faa71523da8d2f4110'
out=Path('docs/assets/press-tool-family.webp');out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(result)
print('Approved artwork verified and reconstructed byte-for-byte.')
