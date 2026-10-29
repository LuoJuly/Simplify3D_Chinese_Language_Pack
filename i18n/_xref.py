"""Find how a UI string is referenced inside Simplify3D.exe."""
import struct
import sys

path = r"C:\Program Files\Simplify3D-5.1.2\Simplify3D.exe"
data = open(path, "rb").read()
e = struct.unpack_from("<I", data, 0x3C)[0]
coff = e + 4
nsec = struct.unpack_from("<H", data, coff + 2)[0]
optsz = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
sec_off = opt + optsz
sections = []
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o:o + 8].split(b"\x00")[0].decode("latin1")
    vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, o + 8)
    sections.append((name, va, vsize, raw, rawsize))

def off_to_rva(off):
    for name, va, vs, raw, rs in sections:
        if raw and raw <= off < raw + rs:
            return va + (off - raw)
    return None

def rva_to_off(rva):
    for name, va, vs, raw, rs in sections:
        span = max(vs, rs)
        if raw and va <= rva < va + span:
            return raw + (rva - va)
    return None

needle = sys.argv[1].encode()
hits = []
start = 0
while True:
    i = data.find(needle, start)
    if i < 0:
        break
    if i == 0 or data[i - 1] == 0:
        if i + len(needle) < len(data) and data[i + len(needle)] == 0:
            hits.append(i)
    start = i + 1
print("exact cstring hits", [hex(h) for h in hits])

text = next(s for s in sections if s[0] == ".text")
rdata = next(s for s in sections if s[0] == ".rdata")
_, tva, tvs, traw, trs = text
_, rva0, rvs, rraw, rrs = rdata

for hoff in hits:
    rva = off_to_rva(hoff)
    va = image_base + rva
    print(f"string rva={rva:#x} va={va:#x}")
    # RIP-relative refs in .text
    code = data[traw:traw + trs]
    refs = []
    # scan for ModRM rip-relative lea/mov: opcode group
    i = 0
    n = len(code)
    while i < n - 7:
        # look for [rip+disp32] which is ModRM mod=00 rm=101, preceded by opcode
        # common: 48 8D 0D / 48 8D 15 / 4C 8D 05 / 48 8B 05 etc.
        b0 = code[i]
        # REX
        if b0 in (0x48, 0x4C, 0x4D, 0x49, 0x4E) and i + 7 <= n:
            op = code[i + 1]
            modrm = code[i + 2]
            if op in (0x8D, 0x8B, 0x8A, 0x3B, 0x3A, 0x80, 0x81, 0x83) or (op == 0x8D):
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from("<i", code, i + 3)[0]
                    insn_rva = tva + i
                    target = insn_rva + 7 + disp
                    if target == rva:
                        refs.append(insn_rva)
            i += 1
            continue
        i += 1
    print("rip refs", len(refs))
    for insn_rva in refs[:12]:
        ioff = rva_to_off(insn_rva)
        window = data[ioff:ioff + 48]
        print(f"  insn rva={insn_rva:#x} bytes={window[:24].hex()}")

    # absolute pointer qwords in rdata equal to VA (after preferred base; file has unrelocated base)
    ptr = struct.pack("<Q", va)
    prefs = []
    s = rraw
    end = rraw + rrs
    while True:
        j = data.find(ptr, s, end)
        if j < 0:
            break
        prefs.append(off_to_rva(j))
        s = j + 1
    print("rdata qwords", [hex(x) for x in prefs[:20]], "count", len(prefs))
