# -*- coding: utf-8 -*-
"""启动 Simplify3D：默认英文保持不变，选择简体中文时才在内存中挂上译文。"""
import ctypes
import json
import os
import re
import struct
import sys
import time
from ctypes import wintypes

from zh_table import T

INSTALL_DIR = r"C:\Program Files\Simplify3D-5.1.2"
EXE_PATH = os.path.join(INSTALL_DIR, "Simplify3D.exe")
LOG_PATH = os.path.join(os.environ.get("LOCALAPPDATA", "."), "Simplify3D", "zh-launch.log")

TRANSLATE_RVA = 0x1003170
FROMUTF8_RVA = 0xF7EF40
STOLEN = bytes.fromhex("5541574156415541545657534883ec78")

CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x001F0FFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.c_void_p, ctypes.c_void_p,
]
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
kernel32.FlushInstructionCache.restype = wintypes.BOOL
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def log(msg):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")


def fnv1a(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def placeholders(text: str):
    # Qt 按编号替换，译文里 %1 %2 的顺序可以和英文不同。
    return tuple(sorted(re.findall(r"%\d+", text)))


def checked_pairs():
    bad = []
    pairs = []
    for en, zh in T.items():
        if not zh or zh == en:
            continue
        if placeholders(en) != placeholders(zh):
            bad.append(en)
            continue
        pairs.append((en.encode("utf-8"), zh.encode("utf-8")))
    if bad:
        raise SystemExit("占位符不一致:\n" + "\n".join(bad))
    return pairs


def _rel32(at, target):
    # at is the offset of the rel32 field (instruction end - 4)
    return struct.pack("<i", target - (at + 4))


def assemble(mask, table_off, blob_off, fromutf8, tramp_off):
    """生成钩子。所有地址相对代码起始，表和字符串在同一分配块内。"""
    code = bytearray()
    fixups = []  # (rel_pos, target_label)

    def label_pos():
        return len(code)

    labels = {}

    def mark(name):
        labels[name] = len(code)

    def b(data):
        code.extend(data)

    def jcc(op, name):
        # op is 0F 84 / 0F 85 / 0F 83
        b(op)
        fixups.append((len(code), name))
        b(b"\x00\x00\x00\x00")

    def jmp(name):
        b(b"\xE9")
        fixups.append((len(code), name))
        b(b"\x00\x00\x00\x00")

    # test r8, r8
    b(b"\x4D\x85\xC0")
    jcc(b"\x0F\x84", "tramp")
    # cmp byte ptr [r8], 0
    b(b"\x41\x80\x38\x00")
    jcc(b"\x0F\x84", "tramp")
    # 7 pushes keep the stack 16-byte aligned for the later call.
    # rdx is the translation context and must be restored on a miss.
    b(b"\x53\x56\x57\x41\x54\x41\x55\x52\x41\x57")  # rbx rsi rdi r12 r13 rdx r15
    b(b"\x48\x89\xCB")          # mov rbx, rcx
    b(b"\x49\x8B\xF0")          # mov rsi, r8
    b(b"\x41\xBC" + struct.pack("<I", 0x811C9DC5))  # mov r12d, offset
    b(b"\x31\xC9")              # xor ecx, ecx
    mark("hash")
    b(b"\x0F\xB6\x04\x0E")      # movzx eax, byte [rsi+rcx]
    b(b"\x84\xC0")              # test al, al
    jcc(b"\x0F\x84", "hashed")
    b(b"\x81\xF9" + struct.pack("<I", 512))  # cmp ecx, 512
    jcc(b"\x0F\x83", "miss")
    # xor r12d, eax
    b(b"\x41\x31\xC4")          # xor r12d, eax
    # imul r12d, r12d, 16777619
    b(b"\x45\x69\xE4" + struct.pack("<I", 0x01000193))
    b(b"\xFF\xC1")              # inc ecx
    jmp("hash")
    mark("hashed")
    b(b"\x41\x89\xCD")          # mov r13d, ecx   length
    b(b"\x44\x89\xE0")          # mov eax, r12d
    b(b"\x25" + struct.pack("<I", mask))  # and eax, mask
    mark("probe")
    b(b"\x89\xC2")              # mov edx, eax
    b(b"\x6B\xD2\x14")          # imul edx, edx, 20
    # lea rdi, [rip + disp] ; disp patched to table_off
    lea_table = len(code)
    b(b"\x48\x8D\x3D\x00\x00\x00\x00")
    b(b"\x48\x01\xD7")          # add rdi, rdx
    b(b"\x83\x7F\x04\x00")      # cmp dword [rdi+4], 0  en_len
    jcc(b"\x0F\x84", "miss")
    b(b"\x44\x3B\x27")          # cmp r12d, [rdi]
    jcc(b"\x0F\x85", "next")
    b(b"\x44\x3B\x6F\x04")      # cmp r13d, [rdi+4]
    jcc(b"\x0F\x85", "next")
    b(b"\x44\x8B\x47\x08")      # mov r8d, [rdi+8] en_off
    lea_blob_en = len(code)
    b(b"\x4C\x8D\x1D\x00\x00\x00\x00")  # lea r11, [rip+blob]
    b(b"\x4D\x01\xD8")          # add r8, r11
    b(b"\x31\xD2")              # xor edx, edx
    mark("cmpb")
    b(b"\x41\x39\xD5")          # cmp r13d, edx
    jcc(b"\x0F\x84", "hit")
    b(b"\x44\x0F\xB6\x1C\x16")  # movzx r11d, byte [rsi+rdx]
    b(b"\x45\x3A\x1C\x10")      # cmp r11b, [r8+rdx]
    jcc(b"\x0F\x85", "next")
    b(b"\xFF\xC2")              # inc edx
    jmp("cmpb")
    mark("next")
    b(b"\xFF\xC0")              # inc eax
    b(b"\x25" + struct.pack("<I", mask))
    jmp("probe")
    mark("hit")
    b(b"\x8B\x57\x10")          # mov edx, [rdi+16] zh_len
    b(b"\x8B\x4F\x0C")          # mov ecx, [rdi+12] zh_off
    lea_blob_zh = len(code)
    b(b"\x4C\x8D\x05\x00\x00\x00\x00")  # lea r8, [rip+blob]
    b(b"\x49\x01\xC8")          # add r8, rcx
    b(b"\x4C\x89\xC1")          # mov rcx, r8
    # mov rax, fromutf8
    mov_from = len(code)
    b(b"\x48\xB8" + b"\x00" * 8)
    b(b"\xFF\xD0")              # call rax
    b(b"\x48\x89\x03")          # mov [rbx], rax
    b(b"\x48\x89\xD8")          # mov rax, rbx
    b(b"\x41\x5F\x5A\x41\x5D\x41\x5C\x5F\x5E\x5B")  # pop r15 rdx r13 r12 rdi rsi rbx
    b(b"\xC3")
    mark("miss")
    b(b"\x48\x89\xD9")          # mov rcx, rbx   restore QString*
    b(b"\x4C\x8B\xC6")          # mov r8, rsi    restore source text
    b(b"\x41\x5F\x5A\x41\x5D\x41\x5C\x5F\x5E\x5B")
    jmp("tramp")
    mark("tramp")
    # trampoline is outside this buffer; jump via absolute later.
    # Placeholder jmp, patched to tramp_off.
    if len(code) > 0x260:
        raise SystemExit(f"hook too large: {len(code)}")

    def patch_rel(at, target):
        struct.pack_into("<i", code, at, target - (at + 4))

    for at, name in fixups:
        patch_rel(at, labels[name])

    # lea rdi, [rip+disp] at lea_table, disp starts at lea_table+3, end at +7
    patch_rel(lea_table + 3, table_off)
    patch_rel(lea_blob_en + 3, blob_off)
    patch_rel(lea_blob_zh + 3, blob_off)
    struct.pack_into("<Q", code, mov_from + 2, fromutf8)

    # The jmp("tramp") already points at mark("tramp") which is inside code.
    # Real trampoline lives at tramp_off. Overwrite that jmp.
    # Find last E9 before tramp label... the miss path jmp tramp is the one
    # immediately before mark tramp. labels["tramp"] is the jmp target we set
    # to itself. Replace by patching that fixup. Easier: at labels['tramp']
    # we emit nothing yet. The jmp("tramp") lands there. Change it to tramp_off.
    # Re-patch the fixup that targets "tramp" from the miss path only.
    # Both early jz and the miss jmp use "tramp". Early jz should go to the
    # real trampoline (stolen bytes), not to an empty label inside the hook.
    # I marked "tramp" at the end. Early jcc also targets "tramp".
    # So labels["tramp"] should BE tramp_off, but fixups were computed inside
    # the code buffer. Relative jumps cannot target outside unless tramp_off
    # is the destination offset in the SAME allocation, and rel is from the
    # instruction in the code (offset 0 of allocation). Yes: target tramp_off
    # is an offset in the allocation, and instruction offsets are also from
    # the start. patch_rel uses target - (at+4), which is correct if both
    # are allocation offsets. So set the tramp fixups to tramp_off instead
    # of labels["tramp"].
    for at, name in fixups:
        if name == "tramp":
            patch_rel(at, tramp_off)
    return code


def build_image(pairs, fromutf8_addr, resume_addr, tramp_is_ret=False):
    items = []
    strings = bytearray()
    for en, zh in pairs:
        en_off = len(strings)
        strings += en
        zh_off = len(strings)
        strings += zh
        items.append((fnv1a(en), len(en), en_off, zh_off, len(zh)))
    size = 1
    while size < max(2, len(items) * 2):
        size *= 2
    mask = size - 1
    slots = [None] * size
    for item in items:
        i = item[0] & mask
        while slots[i] is not None:
            i = (i + 1) & mask
        slots[i] = item
    table = bytearray()
    for slot in slots:
        if slot is None:
            table += b"\x00" * 20
        else:
            table += struct.pack("<IIIII", *slot)

    code_size = 0x280
    tramp_off = code_size
    table_off = tramp_off + 48
    blob_off = table_off + len(table)
    code = assemble(mask, table_off, blob_off, fromutf8_addr, tramp_off)
    if len(code) > code_size:
        raise SystemExit("code does not fit")
    code += b"\xCC" * (code_size - len(code))
    if tramp_is_ret:
        # cmp byte ptr [r8], 'N'; then write 0x11 or 0x22 through rcx
        tramp = bytes.fromhex("4180384E7507C70111000000C3C70122000000C3")
        tramp += b"\x90" * (48 - len(tramp))
    else:
        tramp = STOLEN + b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", resume_addr)
        tramp += b"\x90" * (48 - len(tramp))
    if len(tramp) != 48:
        raise SystemExit(f"trampoline is {len(tramp)} bytes, table offset assumes 48")
    image = code + tramp + table + strings
    return image, code_size


def self_test():
    pairs = [(b"Help", "帮助".encode("utf-8")), (b"Prepare to Print", "准备打印".encode("utf-8"))]
    # fromUtf8 stub: mov rax, 0x42; ret  sits at the end, we pass its address
    # Build with a dummy fromutf8, then we place a stub in local memory and rebuild.
    image, code_size = build_image(pairs, 0, 0, tramp_is_ret=True)
    stub = b"\x48\xB8" + struct.pack("<Q", 0x42) + b"\xC3"
    mem = kernel32.VirtualAlloc(None, len(image) + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem:
        raise OSError("VirtualAlloc failed")
    addr = mem if isinstance(mem, int) else ctypes.cast(mem, ctypes.c_void_p).value
    stub_addr = addr + len(image)
    image, code_size = build_image(pairs, stub_addr, 0, tramp_is_ret=True)
    raw = ctypes.create_string_buffer(bytes(image))
    ctypes.memmove(addr, raw, len(image))
    raw_stub = ctypes.create_string_buffer(stub)
    ctypes.memmove(stub_addr, raw_stub, len(stub))
    proto = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    func = proto(addr)
    out = ctypes.c_uint64(0)
    src = ctypes.create_string_buffer(b"Help")
    func(ctypes.addressof(out), None, ctypes.addressof(src), None)
    if out.value != 0x42:
        raise SystemExit(f"hit test failed: {out.value:#x}")
    out = ctypes.c_uint64(7)
    src = ctypes.create_string_buffer(b"Not a translated string")
    func(ctypes.addressof(out), None, ctypes.addressof(src), None)
    if out.value != 0x11:
        raise SystemExit(f"miss test did not restore rcx: {out.value:#x}")
    # second string
    out = ctypes.c_uint64(0)
    src = ctypes.create_string_buffer(b"Prepare to Print")
    func(ctypes.addressof(out), None, ctypes.addressof(src), None)
    if out.value != 0x42:
        raise SystemExit("second hit failed")
    print("self-test ok", len(checked_pairs()), "translations")
    self_test_arg()
    return True


def image_base_of(process):
    pbi = PROCESS_BASIC_INFORMATION()
    retlen = ctypes.c_ulong(0)
    status = ntdll.NtQueryInformationProcess(process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(retlen))
    if status != 0:
        raise OSError(f"NtQueryInformationProcess {status:#x}")
    base = ctypes.c_uint64(0)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(process, ctypes.c_void_p(pbi.PebBaseAddress + 0x10), ctypes.byref(base), 8, ctypes.byref(read))
    if not ok:
        raise OSError("ReadProcessMemory PEB failed")
    return base.value


def qstring_header(text):
    """Qt 5.15 QStringData：size 在 +4，UTF-16 偏移在 +0x10。ref = -1，避免被释放。"""
    encoded = text.encode("utf-16le") + b"\x00\x00"
    blob = struct.pack("<iiIIQ", -1, len(text), len(text) + 1, 0, 24) + encoded
    if len(blob) % 8:
        blob += b"\x00" * (8 - len(blob) % 8)
    return blob



def alloc_near(process, base, size):
    granularity = 0x10000
    for step in range(1, 0x800):
        for sign in (-1, 1):
            hint = (base + sign * step * granularity) & ~(granularity - 1)
            if hint < 0x10000:
                continue
            remote = kernel32.VirtualAllocEx(
                process, ctypes.c_void_p(hint), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            if remote:
                return remote if isinstance(remote, int) else ctypes.cast(remote, ctypes.c_void_p).value
    remote = kernel32.VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not remote:
        return 0
    return remote if isinstance(remote, int) else ctypes.cast(remote, ctypes.c_void_p).value



SETTERS = (
    # 这些函数收到的 rdx 是标题 QString*。prologue 停在栈保护之前，避免把 rip 相对寻址挪走。
    (0xCAF3C0, bytes.fromhex("415741565657534883ec504889d3"), 0xCAF3CE),
    (0xCAD610, bytes.fromhex("41565657534883ec484889d34889ce"), 0xCAD61F),
)


def build_swap_image(resume_vas, rewrite=True, setters=SETTERS):
    """进入时 rdx 是标题。匹配则换成静态中文 QString，再执行原来的 prologue。"""
    code = bytearray()
    fixups = []
    labels = {}
    entries = []

    def mark(name):
        labels[name] = len(code)

    def b(data):
        code.extend(data)

    def jcc(op, name):
        b(op)
        fixups.append((len(code), name))
        b(b"\x00\x00\x00\x00")

    def near_jmp(name):
        b(b"\xE9")
        fixups.append((len(code), name))
        b(b"\x00\x00\x00\x00")

    def rip(name):
        fixups.append((len(code), name, 4))
        b(b"\x00\x00\x00\x00")

    material = "按Material自动配置"
    quality = "按Quality自动配置"
    zh_material = "按材料自动配置"
    zh_quality = "按质量自动配置"

    def emit_compare(length, utf16_label, yes):
        b(b"\x41\x83\xFA" + bytes([length]))  # cmp r10d, length
        jcc(b"\x0F\x85", "after_" + yes)
        b(b"\x56\x57\x51")
        b(b"\x4C\x89\xDE")
        b(b"\x48\x8D\x3D")
        rip(utf16_label)
        b(b"\xB9" + struct.pack("<I", length))
        b(b"\xFC")
        b(b"\xF3\x66\xA7")
        b(b"\x59\x5F\x5E")
        jcc(b"\x0F\x84", yes)
        mark("after_" + yes)

    for i, ((rva, stolen, resume_rva), resume_va) in enumerate(zip(setters, resume_vas)):
        entries.append(len(code))
        if rewrite:
            b(b"\x53")
            b(b"\x41\x54")
            b(b"\x48\x89\xD3")
            b(b"\x4C\x8D\x25")
            rip(f"after{i}")
            near_jmp("shared")
            mark(f"after{i}")
            b(b"\x41\x5C")
            b(b"\x5B")
        b(stolen)
        b(b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", resume_va))

    if rewrite:
        mark("shared")
        b(b"\x48\x85\xDB")
        jcc(b"\x0F\x84", "leave")
        b(b"\x48\x8B\x03")
        b(b"\x48\x85\xC0")
        jcc(b"\x0F\x84", "leave")
        b(b"\x44\x8B\x50\x04")          # mov r10d, [rax+4]，避开 rcx/rdx
        b(b"\x4C\x8B\x58\x10")
        b(b"\x49\x01\xC3")
        emit_compare(len(material), "utf16_material", "use_material")
        emit_compare(len(quality), "utf16_quality", "use_quality")
        near_jmp("leave")
        mark("use_material")
        b(b"\x48\x8D\x05")
        rip("hdr_material")
        b(b"\x48\x89\x03")
        near_jmp("leave")
        mark("use_quality")
        b(b"\x48\x8D\x05")
        rip("hdr_quality")
        b(b"\x48\x89\x03")
        mark("leave")
        b(b"\x41\xFF\xE4")
        while len(code) % 8:
            code.append(0xCC)
        labels["utf16_material"] = len(code)
        code += material.encode("utf-16le")
        labels["utf16_quality"] = len(code)
        code += quality.encode("utf-16le")
        while len(code) % 8:
            code.append(0)
        labels["hdr_material"] = len(code)
        code += qstring_header(zh_material)
        labels["hdr_quality"] = len(code)
        code += qstring_header(zh_quality)

    for item in fixups:
        if len(item) == 2:
            pos, name = item
            rel = labels[name] - (pos + 4)
        else:
            pos, name, end = item
            rel = labels[name] - (pos + end)
        struct.pack_into("<i", code, pos, rel)
    return bytes(code), entries



def install_arg_hook(process, base):
    mode = os.environ.get("S3D_TITLE", "1")
    if mode == "0":
        log("title stub skipped")
        return
    rewrite = mode != "pass"
    resumes = [base + resume for _, _, resume in SETTERS]
    image, entries = build_swap_image(resumes, rewrite)
    remote_addr = alloc_near(process, base, len(image))
    if not remote_addr:
        raise OSError("无法分配自动配置译文")
    written = ctypes.c_size_t(0)
    buf = (ctypes.c_char * len(image)).from_buffer_copy(image)
    if not kernel32.WriteProcessMemory(process, ctypes.c_void_p(remote_addr), buf, len(image), ctypes.byref(written)):
        raise OSError("写入自动配置译文失败")
    for (rva, stolen, _), off in zip(SETTERS, entries):
        site = base + rva
        got = ctypes.create_string_buffer(len(stolen))
        read = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(process, ctypes.c_void_p(site), got, len(stolen), ctypes.byref(read)):
            raise OSError("无法读取自动配置标题函数")
        if got.raw != stolen:
            raise OSError("自动配置标题函数和 5.1.2 不一致，已取消，没有改动已安装的文件。")
        patch = b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", remote_addr + off)
        patch += b"\x90" * (len(stolen) - len(patch))
        if len(patch) != len(stolen):
            raise OSError("自动配置补丁长度不对")
        old = wintypes.DWORD(0)
        if not kernel32.VirtualProtectEx(process, ctypes.c_void_p(site), len(patch), PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
            raise OSError("无法修改自动配置标题函数")
        patch_buf = ctypes.create_string_buffer(patch)
        if not kernel32.WriteProcessMemory(process, ctypes.c_void_p(site), patch_buf, len(patch), ctypes.byref(written)):
            raise OSError("无法挂上自动配置译文")
        kernel32.VirtualProtectEx(process, ctypes.c_void_p(site), len(patch), old, ctypes.byref(old))
        kernel32.FlushInstructionCache(process, ctypes.c_void_p(site), len(patch))
    kernel32.FlushInstructionCache(process, ctypes.c_void_p(remote_addr), len(image))
    log(f"title stub remote={remote_addr:#x} size={len(image)} rewrite={int(rewrite)}")


def self_test_arg():
    headers = {
        "按Material自动配置": ctypes.create_string_buffer(qstring_header("按Material自动配置")),
        "按Quality自动配置": ctypes.create_string_buffer(qstring_header("按Quality自动配置")),
        "Hello": ctypes.create_string_buffer(qstring_header("Hello")),
    }
    setters = ((0, bytes.fromhex("4889c8"), 0),)
    mem = kernel32.VirtualAlloc(None, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem:
        raise OSError("VirtualAlloc failed")
    addr = mem if isinstance(mem, int) else ctypes.cast(mem, ctypes.c_void_p).value
    ret_addr = addr
    caller = addr + 1
    image, entries = build_swap_image([ret_addr], True, setters)
    if entries != [0]:
        raise SystemExit(f"入口偏移不对: {entries}")
    caller_code = bytes.fromhex("4889cae900000000")
    blob = b"\xC3" + caller_code + image
    ctypes.memmove(addr, ctypes.create_string_buffer(blob), len(blob))

    def read_text(header_addr):
        size = ctypes.c_int.from_address(header_addr + 4).value
        return ctypes.string_at(header_addr + 24, size * 2).decode("utf-16le")

    def call(mixed):
        slot = ctypes.c_uint64(ctypes.addressof(headers[mixed]))
        proto = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)
        kept = proto(caller)(ctypes.addressof(slot))
        if kept != ctypes.addressof(slot):
            raise SystemExit(f"控件指针被改掉了: {kept:#x}")
        return slot.value

    got = call("按Material自动配置")
    if read_text(got) != "按材料自动配置":
        raise SystemExit(f"材料标题替换失败: {read_text(got)!r}")
    got = call("按Quality自动配置")
    if read_text(got) != "按质量自动配置":
        raise SystemExit(f"质量标题替换失败: {read_text(got)!r}")
    got = call("Hello")
    if read_text(got) != "Hello":
        raise SystemExit(f"其他标题被替换了: {read_text(got)!r}")
    print("arg-hook ok")


def launch_english():
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(EXE_PATH, None, None, None, False, 0, None, INSTALL_DIR, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise OSError(f"无法启动程序 ({ctypes.get_last_error()})")
    kernel32.CloseHandle(pi.hThread)
    kernel32.CloseHandle(pi.hProcess)


def launch_chinese():
    if struct.calcsize("P") != 8:
        raise OSError("需要 64 位 Python。")
    if not os.path.isfile(EXE_PATH):
        raise OSError("找不到 " + EXE_PATH)
    pairs = checked_pairs()
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(
        EXE_PATH, None, None, None, False, CREATE_SUSPENDED, None, INSTALL_DIR,
        ctypes.byref(si), ctypes.byref(pi),
    )
    if not ok:
        raise OSError(f"无法启动程序 ({ctypes.get_last_error()})")
    try:
        base = image_base_of(pi.hProcess)
        mz = ctypes.c_ushort(0)
        read = ctypes.c_size_t(0)
        kernel32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(base), ctypes.byref(mz), 2, ctypes.byref(read))
        if mz.value != 0x5A4D:
            raise OSError(f"程序映像无效: {base:#x}")
        target = base + TRANSLATE_RVA
        got = ctypes.create_string_buffer(len(STOLEN))
        if not kernel32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(target), got, len(STOLEN), ctypes.byref(read)):
            raise OSError("无法读取程序代码")
        if got.raw != STOLEN:
            raise OSError("这不是 Simplify3D 5.1.2 的对应版本，已取消，没有改动已安装的文件。")
        fromutf8 = base + FROMUTF8_RVA
        resume = target + len(STOLEN)
        image, _ = build_image(pairs, fromutf8, resume, tramp_is_ret=False)
        remote = kernel32.VirtualAllocEx(pi.hProcess, None, len(image), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not remote:
            raise OSError("无法分配译文内存")
        remote_addr = remote if isinstance(remote, int) else ctypes.cast(remote, ctypes.c_void_p).value
        written = ctypes.c_size_t(0)
        buf = (ctypes.c_char * len(image)).from_buffer_copy(bytes(image))
        if not kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(remote_addr), buf, len(image), ctypes.byref(written)):
            raise OSError("写入译文失败")
        if written.value != len(image):
            raise OSError("译文没有完整写入")
        patch = b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", remote_addr) + b"\x90\x90"
        if len(patch) != len(STOLEN):
            raise OSError("补丁长度不对")
        old = wintypes.DWORD(0)
        if not kernel32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(target), len(patch), PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
            raise OSError("无法修改程序代码页")
        patch_buf = ctypes.create_string_buffer(patch)
        if not kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(target), patch_buf, len(patch), ctypes.byref(written)):
            raise OSError("无法挂上中文钩子")
        kernel32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(target), len(patch), old, ctypes.byref(old))
        kernel32.FlushInstructionCache(pi.hProcess, ctypes.c_void_p(target), len(patch))
        kernel32.FlushInstructionCache(pi.hProcess, ctypes.c_void_p(remote_addr), len(image))
        install_arg_hook(pi.hProcess, base)
        log(f"chinese hook base={base:#x} remote={remote_addr:#x} strings={len(pairs)}")
        if kernel32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
            raise OSError(f"无法继续运行程序 ({ctypes.get_last_error()})")
    except Exception:
        kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        raise
    kernel32.CloseHandle(pi.hThread)
    kernel32.CloseHandle(pi.hProcess)


def message(text):
    ctypes.windll.user32.MessageBoxW(None, text, "Simplify3D 中文语言包", 0x10)


def choose():
    import tkinter as tk

    picked = {"lang": None}

    def set_lang(lang):
        picked["lang"] = lang
        root.destroy()

    root = tk.Tk()
    root.title("Simplify3D 语言")
    root.resizable(False, False)
    root.configure(bg="white")
    tk.Label(
        root,
        text="默认语言仍是英文。\n请选择这一次要使用的语言。",
        font=("Microsoft YaHei UI", 12),
        bg="white",
        justify="left",
    ).pack(padx=28, pady=(22, 12))
    row = tk.Frame(root, bg="white")
    row.pack(pady=(0, 22))
    tk.Button(row, text="English（默认）", width=18, font=("Microsoft YaHei UI", 11), command=lambda: set_lang("en")).pack(side="left", padx=8)
    tk.Button(row, text="简体中文", width=18, font=("Microsoft YaHei UI", 11), command=lambda: set_lang("zh")).pack(side="left", padx=8)
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 3
    root.geometry(f"+{x}+{y}")
    root.mainloop()
    return picked["lang"]


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "--self-test":
        self_test()
        return 0
    if mode not in ("--zh", "--en"):
        mode = {"zh": "--zh", "en": "--en"}.get(choose() or "", "")
        if not mode:
            return 0
    try:
        if mode == "--zh":
            launch_chinese()
        else:
            launch_english()
    except Exception as exc:
        log(repr(exc))
        message(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
