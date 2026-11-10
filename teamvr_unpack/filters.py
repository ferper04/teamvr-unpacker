"""Inno Setup's x86 CALL/JMP transform ("TransformCallInstructions", version 3, Compression.Base.pas).

Executables are stored with relative E8/E9 targets turned into absolute ones for better compression.
File data is (de)transformed in 64 KiB buffers: AddrOffset is the buffer's position in the file and the
last 4 bytes of every buffer are never touched. Setup.e32 is transformed as a single buffer.
"""
import re

_E8E9 = re.compile(rb"[\xe8\xe9]")
FILE_BUFFER = 65536


def transform_call_instructions(buf, encode, addr_offset=0):
    b = bytearray(buf)
    size = len(b)
    if size < 5:
        return bytes(b)
    lim = size - 4
    i = 0
    while True:
        m = _E8E9.search(b, i, lim)
        if not m:
            break
        i = m.start() + 1
        if b[i + 3] in (0x00, 0xFF):
            addr = (addr_offset + i + 4) & 0xFFFFFF
            rel = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)
            if not encode:
                rel = (rel - addr) & 0xFFFFFF
            if rel & 0x800000:
                b[i + 3] ^= 0xFF
            if encode:
                rel = (rel + addr) & 0xFFFFFF
            b[i] = rel & 0xFF
            b[i + 1] = (rel >> 8) & 0xFF
            b[i + 2] = (rel >> 16) & 0xFF
        i += 4
    return bytes(b)
