# -*- coding: utf-8 -*-
"""启动 Simplify3D。双击启动器直接进入简体中文；--choose 才弹出语言选择。"""
import ctypes
import json
import os
import re
import struct
import sys
import time
from ctypes import wintypes

from zh_table import T

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

INSTALL_DIR = r"C:\Program Files\Simplify3D-5.1.2"
EXE_PATH = os.path.join(INSTALL_DIR, "Simplify3D.exe")
LOG_PATH = os.path.join(os.environ.get("LOCALAPPDATA", "."), "Simplify3D", "zh-launch.log")

TRANSLATE_RVA = 0x1003170
FROMUTF8_RVA = 0xF7EF40
STOLEN = bytes.fromhex("5541574156415541545657534883ec78")

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
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
kernel32.SetDllDirectoryW.argtypes = [wintypes.LPCWSTR]
kernel32.SetDllDirectoryW.restype = wintypes.BOOL
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


# 这些寄存器在比较标题时会改掉，先写进桩里的槽，不能 push。
# 虚拟机按原函数的栈深留了一段空隙，多出来的 push 会把后面的浮点指针盖成空。
_SPILL_STORE = {
    "rax": b"\x48\x89\x05",
    "rcx": b"\x48\x89\x0D",
    "rdx": b"\x48\x89\x15",
    "rsi": b"\x48\x89\x35",
    "rdi": b"\x48\x89\x3D",
    "r10": b"\x4C\x89\x15",
    "r11": b"\x4C\x89\x1D",
    "r12": b"\x4C\x89\x25",
}
_SPILL_LOAD = {
    "rax": b"\x48\x8B\x05",
    "rcx": b"\x48\x8B\x0D",
    "rdx": b"\x48\x8B\x15",
    "rsi": b"\x48\x8B\x35",
    "rdi": b"\x48\x8B\x3D",
    "r10": b"\x4C\x8B\x15",
    "r11": b"\x4C\x8B\x1D",
    "r12": b"\x4C\x8B\x25",
}
_SPILL_ORDER = ("rax", "rcx", "rdx", "rsi", "rdi", "r10", "r11", "r12")


def build_swap_image(resume_vas, rewrite=True, setters=SETTERS, gate_vas=None, frame_gate=False):
    """进入时 rdx 是标题。匹配则换成静态中文 QString，再执行原来的 prologue。

    比较和替换都不使用栈。调用方（尤其是虚拟机）按原来的栈深保留空隙，
    多出来的 push 会在导入模型时留下空的浮点指针。
    """
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
    if not 0 < len(material) < 128 or not 0 < len(quality) < 128:
        raise SystemExit("标题长度超出比较指令的立即数")

    def spill(kind):
        table = _SPILL_STORE if kind == "store" else _SPILL_LOAD
        for name in _SPILL_ORDER:
            b(table[name])
            rip("spill_" + name)

    def emit_compare(length, utf16_label, yes):
        # r10d 是字符数，r11 是 UTF-16 数据，rdx 仍是 QString*。
        b(b"\x41\x83\xFA" + bytes([length]))  # cmp r10d, length
        jcc(b"\x0F\x85", "after_" + yes)
        b(b"\x4C\x89\xDE")          # mov rsi, r11
        b(b"\x48\x8D\x3D")
        rip(utf16_label)
        b(b"\xB9" + struct.pack("<I", length))
        b(b"\xFC")                  # cld。调用约定要求 DF 为 0，不要改成 std。
        b(b"\xF3\x66\xA7")          # repe cmpsw
        jcc(b"\x0F\x84", yes)
        mark("after_" + yes)

    def emit_resume(stolen, resume_va):
        b(stolen)
        b(b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", resume_va))

    def emit_flag_restore():
        # AL 是保存的 OF。先做加法把 OF 设回去，sahf 再恢复其余标志且不动 OF。
        b(b"\x66\x8B\x05")
        rip("fast_ax")
        b(b"\x04\x7F")                                  # add al, 0x7f
        b(b"\x9E")                                      # sahf
        b(b"\x48\x8B\x05")
        rip("fast_rax")

    def emit_frame_entry(i, stolen, resume_va, ret_off):
        """先执行原来的 prologue，再用它自己的栈帧做比较，不额外占栈，也不写全局槽。"""
        b(stolen)
        b(b"\x48\x89\x44\x24\x28")                      # mov [rsp+0x28], rax
        b(b"\x9F")                                      # lahf
        b(b"\x0F\x90\xC0")                              # seto al
        b(b"\x66\x89\x44\x24\x30")                      # mov [rsp+0x30], ax
        b(b"\x48\x8B\x84\x24" + struct.pack("<I", ret_off))
        b(b"\x48\x3B\x05")
        rip(f"gate{i}")
        jcc(b"\x0F\x85", f"frame_restore{i}")
        b(b"\x48\x89\x0C\x24")                          # mov [rsp], rcx
        b(b"\x48\x89\x74\x24\x08")                      # mov [rsp+8], rsi
        b(b"\x48\x89\x7C\x24\x10")                      # mov [rsp+0x10], rdi
        b(b"\x4C\x89\x54\x24\x18")                      # mov [rsp+0x18], r10
        b(b"\x4C\x89\x5C\x24\x20")                      # mov [rsp+0x20], r11
        b(b"\x48\x8D\x7C\x24\x40")                      # lea rdi, [rsp+0x40]
        b(b"\x31\xC0")
        b(b"\x66\xAB")                                  # stosw，探测进入时的 DF
        b(b"\x48\x8D\x44\x24\x42")
        b(b"\x48\x39\xC7")
        b(b"\x0F\x94\x44\x24\x32")                      # sete [rsp+0x32]
        b(b"\xFC")
        b(b"\x48\x81\xFA\x00\x00\x01\x00")
        jcc(b"\x0F\x82", f"frame_done{i}")
        b(b"\x48\x89\xD0")
        b(b"\x48\xC1\xE8\x2F")
        jcc(b"\x0F\x85", f"frame_done{i}")
        b(b"\x48\x8B\x02")
        b(b"\x48\x3D\x00\x00\x01\x00")
        jcc(b"\x0F\x82", f"frame_done{i}")
        b(b"\x48\x89\xC1")
        b(b"\x48\xC1\xE9\x2F")
        jcc(b"\x0F\x85", f"frame_done{i}")
        b(b"\x44\x8B\x50\x04")
        b(b"\x41\x83\xFA\x01")
        jcc(b"\x0F\x8C", f"frame_done{i}")
        b(b"\x41\x83\xFA\x40")
        jcc(b"\x0F\x8F", f"frame_done{i}")
        b(b"\x4C\x8B\x58\x10")
        b(b"\x49\x81\xFB\x00\x00\x01\x00")
        jcc(b"\x0F\x87", f"frame_done{i}")
        b(b"\x49\x01\xC3")
        emit_compare(len(material), "utf16_material", f"hitm{i}")
        emit_compare(len(quality), "utf16_quality", f"hitq{i}")
        near_jmp(f"frame_done{i}")
        mark(f"hitm{i}")
        b(b"\x48\x8D\x05")
        rip("hdr_material")
        b(b"\x48\x89\x02")
        near_jmp(f"frame_done{i}")
        mark(f"hitq{i}")
        b(b"\x48\x8D\x05")
        rip("hdr_quality")
        b(b"\x48\x89\x02")
        mark(f"frame_done{i}")
        b(b"\x4C\x8B\x5C\x24\x20")
        b(b"\x4C\x8B\x54\x24\x18")
        b(b"\x48\x8B\x7C\x24\x10")
        b(b"\x48\x8B\x74\x24\x08")
        b(b"\x48\x8B\x0C\x24")
        b(b"\x80\x7C\x24\x32\x00")                      # cmp byte [rsp+0x32], 0
        jcc(b"\x0F\x85", f"frame_restore{i}")
        b(b"\xFD")                                      # 进入时 DF 为 1
        mark(f"frame_restore{i}")
        b(b"\x66\x8B\x44\x24\x30")
        b(b"\x04\x7F")
        b(b"\x9E")
        b(b"\x48\x8B\x44\x24\x28")
        b(b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", resume_va))

    for i, ((rva, stolen, resume_rva), resume_va) in enumerate(zip(setters, resume_vas)):
        entries.append(len(code))
        if rewrite and frame_gate:
            gate = gate_vas[i] if gate_vas is not None else 0
            if rva == 0xCAF3C0 and gate:
                emit_frame_entry(i, stolen, resume_va, 0x78)
            else:
                emit_resume(stolen, resume_va)
            continue
        if rewrite:
            # 只改从控件构造函数进来的那一次。导入模型时虚拟机会直接调用这两个函数，
            # 在那里读标题会让导入停在「正在导入」。
            if gate_vas is not None:
                # 不能 push：虚拟机把空隙紧挨着 rsp。也不能留下被 cmp 改过的标志。
                b(b"\x48\x89\x05")
                rip("fast_rax")
                b(b"\x9F")                              # lahf
                b(b"\x0F\x90\xC0")                      # seto al
                b(b"\x66\x89\x05")
                rip("fast_ax")
                b(b"\x48\x8B\x04\x24")                  # mov rax, [rsp]
                b(b"\x48\x3B\x05")
                rip(f"gate{i}")
                jcc(b"\x0F\x84", f"slow{i}")
                emit_flag_restore()
                emit_resume(stolen, resume_va)
                mark(f"slow{i}")
                emit_flag_restore()
            spill("store")
            b(b"\x4C\x8D\x25")      # lea r12, [rip+after]
            rip(f"after{i}")
            near_jmp("shared")
            mark(f"after{i}")
            spill("load")
        emit_resume(stolen, resume_va)

    if rewrite:
        mark("shared")
        # 原函数不改 DF。虚拟机会带着 DF=1 调用，比较前先记下来，离开时还原。
        b(b"\x48\x8D\x3D")
        rip("df_probe")
        b(b"\x31\xC0")                              # xor eax, eax
        b(b"\x66\xAB")                              # stosw，方向由进入时的 DF 决定
        b(b"\x48\x8D\x05")
        rip("df_after")
        b(b"\x48\x39\xC7")                          # cmp rdi, rax
        b(b"\x0F\x94\x05")
        rip("df_clear")                             # DF 为 0 时记 1
        b(b"\xFC")                                  # 比较本身向前走
        # rdx 不是可读的 QString* 时直接离开，避免在桩里访问空指针。
        b(b"\x48\x81\xFA\x00\x00\x01\x00")          # cmp rdx, 0x10000
        jcc(b"\x0F\x82", "leave")                   # jb
        b(b"\x48\x89\xD0")                          # mov rax, rdx
        b(b"\x48\xC1\xE8\x2F")                      # shr rax, 47
        jcc(b"\x0F\x85", "leave")
        b(b"\x48\x8B\x02")                          # mov rax, [rdx]
        b(b"\x48\x3D\x00\x00\x01\x00")              # cmp rax, 0x10000
        jcc(b"\x0F\x82", "leave")
        b(b"\x48\x89\xC1")                          # mov rcx, rax
        b(b"\x48\xC1\xE9\x2F")                      # shr rcx, 47
        jcc(b"\x0F\x85", "leave")
        b(b"\x44\x8B\x50\x04")                      # mov r10d, [rax+4]
        b(b"\x41\x83\xFA\x01")                      # cmp r10d, 1
        jcc(b"\x0F\x8C", "leave")                   # jl
        b(b"\x41\x83\xFA\x40")                      # cmp r10d, 64
        jcc(b"\x0F\x8F", "leave")                   # jg
        b(b"\x4C\x8B\x58\x10")                      # mov r11, [rax+0x10]
        b(b"\x49\x81\xFB\x00\x00\x01\x00")          # cmp r11, 0x10000
        jcc(b"\x0F\x87", "leave")                   # ja
        b(b"\x49\x01\xC3")                          # add r11, rax
        emit_compare(len(material), "utf16_material", "use_material")
        emit_compare(len(quality), "utf16_quality", "use_quality")
        near_jmp("leave")
        mark("use_material")
        b(b"\x48\x8D\x05")
        rip("hdr_material")
        b(b"\x48\x89\x02")                          # mov [rdx], rax
        near_jmp("leave")
        mark("use_quality")
        b(b"\x48\x8D\x05")
        rip("hdr_quality")
        b(b"\x48\x89\x02")
        mark("leave")
        b(b"\x8A\x05")
        rip("df_clear")
        b(b"\x84\xC0")                              # test al, al
        jcc(b"\x0F\x85", "df_ok")                   # 进入时 DF 已是 0
        b(b"\xFD")                                  # std，还原进入时的 DF
        mark("df_ok")
        b(b"\x41\xFF\xE4")                          # jmp r12
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
        while len(code) % 8:
            code.append(0)
        for name in _SPILL_ORDER:
            labels["spill_" + name] = len(code)
            code += b"\x00" * 8
        labels["df_base"] = len(code)
        code += b"\x00\x00"
        labels["df_probe"] = len(code)
        code += b"\x00\x00"
        labels["df_after"] = len(code)
        code += b"\x00\x00"
        labels["df_clear"] = len(code)
        code += b"\x00"
        if gate_vas is not None:
            while len(code) % 8:
                code.append(0)
            labels["fast_rax"] = len(code)
            code += b"\x00" * 8
            labels["fast_ax"] = len(code)
            code += b"\x00\x00"
            for i, gate in enumerate(gate_vas):
                labels[f"gate{i}"] = len(code)
                code += struct.pack("<Q", 0 if gate is None else gate)

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
    # 0xCAF290 在 0xCAF3A7 调用第一个标题函数，返回地址是 0xCAF3AC。
    # 自动配置标题从这里送进去。另一个函数没有这条路径，保持原样。
    gates = [base + 0xCAF3AC if rva == 0xCAF3C0 else 0 for rva, _, _ in SETTERS]
    image, entries = build_swap_image(
        resumes, rewrite, gate_vas=gates if rewrite else None, frame_gate=rewrite
    )
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

    # 返回地址对不上时保持原文；从构造函数返回地址进来才替换。
    gate_mem = kernel32.VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not gate_mem:
        raise OSError("VirtualAlloc failed")
    gaddr = gate_mem if isinstance(gate_mem, int) else ctypes.cast(gate_mem, ctypes.c_void_p).value
    call_ret = gaddr + 9
    hook = gaddr + 32
    image, _ = build_swap_image([gaddr], True, setters, gate_vas=[call_ret])
    rel = hook - call_ret
    wrapper = bytes.fromhex("4889ca") + b"\xE8" + struct.pack("<i", rel) + b"\xC3"
    ctypes.memmove(gaddr, b"\xC3" + wrapper, 1 + len(wrapper))
    ctypes.memmove(hook, image, len(image))
    plain = ctypes.create_string_buffer(qstring_header("按Material自动配置"))
    slot = ctypes.c_uint64(ctypes.addressof(plain))
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(hook)(ctypes.addressof(slot))
    if slot.value != ctypes.addressof(plain):
        raise SystemExit("非构造调用也被替换了")
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(gaddr + 1)(ctypes.addressof(slot))
    if read_text(slot.value) != "按材料自动配置":
        raise SystemExit(f"构造调用没有替换标题: {read_text(slot.value)!r}")

    # 安装时走的路径：先执行原来的 prologue，只用函数自己的栈帧判断返回地址。
    frame_mem = kernel32.VirtualAlloc(None, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not frame_mem:
        raise OSError("VirtualAlloc failed")
    faddr = frame_mem if isinstance(frame_mem, int) else ctypes.cast(frame_mem, ctypes.c_void_p).value
    epi = faddr
    caller = faddr + 0x20
    hook = faddr + 0x80
    call_ret = caller + 8
    epi_code = bytes.fromhex("4883c4505b5f5e415e415fc3")
    stolen = bytes.fromhex("415741565657534883ec504889d3")
    frame_setters = ((0xCAF3C0, stolen, 0),)
    image, _ = build_swap_image([epi], True, frame_setters, gate_vas=[call_ret], frame_gate=True)
    rel = hook - call_ret
    caller_code = bytes.fromhex("4889ca") + b"\xE8" + struct.pack("<i", rel) + b"\xC3"
    ctypes.memmove(epi, epi_code, len(epi_code))
    ctypes.memmove(caller, caller_code, len(caller_code))
    ctypes.memmove(hook, image, len(image))
    plain = ctypes.create_string_buffer(qstring_header("按Material自动配置"))
    slot = ctypes.c_uint64(ctypes.addressof(plain))
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(hook)(ctypes.addressof(slot))
    if slot.value != ctypes.addressof(plain):
        raise SystemExit("直接调用标题函数也被替换了")
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(caller)(ctypes.addressof(slot))
    if read_text(slot.value) != "按材料自动配置":
        raise SystemExit(f"帧内门控没有替换材料标题: {read_text(slot.value)!r}")
    quality_hdr = ctypes.create_string_buffer(qstring_header("按Quality自动配置"))
    slot = ctypes.c_uint64(ctypes.addressof(quality_hdr))
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(caller)(ctypes.addressof(slot))
    if read_text(slot.value) != "按质量自动配置":
        raise SystemExit(f"帧内门控没有替换质量标题: {read_text(slot.value)!r}")
    hello = ctypes.create_string_buffer(qstring_header("Hello"))
    slot = ctypes.c_uint64(ctypes.addressof(hello))
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(caller)(ctypes.addressof(slot))
    if slot.value != ctypes.addressof(hello):
        raise SystemExit("帧内门控改了其他标题")
    print("arg-hook ok")


def child_environment():
    """PyInstaller 把解压目录加进 DLL 搜索路径，子进程会一直占着里面的 VCRUNTIME140.dll。"""
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return None
    kernel32.SetDllDirectoryW(None)
    skip = {"TCL_LIBRARY", "TK_LIBRARY", "_MEIPASS2", "PYTHONHOME", "PYTHONPATH", "PYTHONNOUSERSITE"}
    needle = meipass.lower()
    rows = []
    for key, value in os.environ.items():
        if key.upper() in skip:
            continue
        if needle in value.lower():
            if key.upper() == "PATH":
                value = os.pathsep.join(part for part in value.split(os.pathsep) if part and needle not in part.lower())
            else:
                continue
        rows.append(f"{key}={value}")
    return ctypes.create_unicode_buffer("\0".join(rows) + "\0\0")


def spawn_flags(base, env):
    return base | CREATE_UNICODE_ENVIRONMENT if env is not None else base


def launch_english():
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    env = child_environment()
    ok = kernel32.CreateProcessW(
        EXE_PATH, None, None, None, False, spawn_flags(0, env),
        ctypes.cast(env, ctypes.c_void_p) if env is not None else None,
        INSTALL_DIR, ctypes.byref(si), ctypes.byref(pi),
    )
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
    env = child_environment()
    ok = kernel32.CreateProcessW(
        EXE_PATH, None, None, None, False, spawn_flags(CREATE_SUSPENDED, env),
        ctypes.cast(env, ctypes.c_void_p) if env is not None else None,
        INSTALL_DIR, ctypes.byref(si), ctypes.byref(pi),
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
    mode = argv[1] if len(argv) > 1 else "--zh"
    if mode == "--self-test":
        self_test()
        return 0
    if mode == "--choose":
        mode = {"zh": "--zh", "en": "--en"}.get(choose() or "", "")
        if not mode:
            return 0
    if mode not in ("--zh", "--en"):
        message("无法识别的启动参数。")
        return 1
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
