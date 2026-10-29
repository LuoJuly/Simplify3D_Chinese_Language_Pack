"""Collect tr()/translate() source strings from Simplify3D.exe."""
import struct
from collections import defaultdict

path = r"C:\Program Files\Simplify3D-5.1.2\Simplify3D.exe"
data = open(path, "rb").read()
e = struct.unpack_from("<I", data, 0x3C)[0]
opt = e + 24
nsec = struct.unpack_from("<H", data, e + 6)[0]
sec_off = opt + struct.unpack_from("<H", data, e + 20)[0]
secs = []
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o:o + 8].split(b"\x00")[0].decode("latin1")
    vs, va, rs, raw = struct.unpack_from("<IIII", data, o + 8)
    secs.append((name, va, vs, raw, rs))
text = next(s for s in secs if s[0] == ".text")
tva, traw, trs = text[1], text[3], text[4]
code = data[traw:traw + trs]

TARGETS = {0x1008FF0, 0x1003170}

def rva_to_off(rva):
    for n, va, vs, raw, rs in secs:
        if raw and va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None

def cstr(rva, limit=240):
    off = rva_to_off(rva)
    if off is None:
        return None
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        return None
    raw = data[off:end]
    if not raw or any(b < 9 or b > 126 for b in raw):
        return None
    return raw.decode("ascii")

# one pass: 4C 8D 05 disp32 = lea r8, [rip+disp]
hits = defaultdict(int)
n = len(code)
i = 0
while i < n - 12:
    if code[i] == 0x4C and code[i + 1] == 0x8D and code[i + 2] == 0x05:
        disp = struct.unpack_from("<i", code, i + 3)[0]
        insn = tva + i
        target = insn + 7 + disp
        window = code[i:i + 32]
        rel_at = window.find(b"\xe8", 7)
        if 7 <= rel_at <= 24:
            rel = struct.unpack_from("<i", window, rel_at + 1)[0]
            call_insn = insn + rel_at
            dest = call_insn + 5 + rel
            if dest in TARGETS:
                hits[target] += 1
        i += 7
        continue
    i += 1

print("unique tr sources", len(hits))
strings = []
for rva, count in hits.items():
    s = cstr(rva)
    if not s:
        continue
    strings.append((count, s))
strings.sort(key=lambda x: (-x[0], x[1].lower()))
out = r"D:\Software_Development\Simplify3D\i18n\tr_sources.txt"
with open(out, "w", encoding="utf-8") as f:
    for c, s in strings:
        f.write(f"{c}\t{s}\n")
print("written", len(strings), "to", out)
# show a sample of likely UI
shown = 0
for c, s in strings:
    if " " in s and any(ch.isalpha() for ch in s) and not s.startswith("Q"):
        print(f"{c:3} {s[:110]}")
        shown += 1
        if shown >= 80:
            break
