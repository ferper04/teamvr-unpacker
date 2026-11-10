"""Inno Setup 6.x container layer: SetupLdr offset table, checksummed compressed blocks, Setup.e32.

Stock Inno protects every structure with CRC32. The Team V.R build replaces CRC32 with
xxHash32 (seed 0) everywhere; the checksum family is detected from the offset table.
"""
import lzma
import struct
import zlib

import xxhash

from .filters import transform_call_instructions

TABLE_ID = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
SETUP_ID_PREFIX = b"Inno Setup Setup Data ("


def crc32(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def xxh32(b):
    return xxhash.xxh32_intdigest(b, seed=0)


CHECKSUMS = {"crc32": crc32, "xxh32": xxh32}


class FormatError(Exception):
    pass


def lzma1_raw_decompress(data, max_out=None):
    """Inno LZMA1 stream: 5-byte properties header followed by raw LZMA data (no end marker required)."""
    if len(data) < 5:
        raise FormatError("LZMA1 stream too short")
    p0 = data[0]
    if p0 >= 9 * 5 * 5:
        raise FormatError("invalid LZMA properties byte 0x%02x" % p0)
    lc, lp, pb = p0 % 9, (p0 // 9) % 5, p0 // 45
    dict_size = struct.unpack_from("<I", data, 1)[0]
    if max_out:
        dict_size = max(4096, min(dict_size, max_out))
    filt = {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}
    dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt])
    return dec.decompress(data[5:]), (lc, lp, pb, dict_size)


class OffsetTable:
    FIELDS = ("version", "total_size", "offset_exe", "usize_exe", "crc_exe", "offset0", "offset1", "table_crc")

    def __init__(self, raw, pos):
        self.raw = raw
        self.pos = pos
        vals = struct.unpack_from("<8I", raw, 12)
        for k, v in zip(self.FIELDS, vals):
            setattr(self, k, v)
        self.checksum = None
        for name, fn in CHECKSUMS.items():
            if fn(raw[:40]) == self.table_crc:
                self.checksum = name
                break
        if self.checksum is None:
            raise FormatError("loader offset table checksum matches neither CRC32 nor xxHash32")
        if self.version != 1:
            raise FormatError("unsupported offset table version %d" % self.version)


class Installer:
    """Read-only access to an Inno Setup 6.x single-file installer."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.size = self.f.tell()
        head = self._read(0, min(self.size, 32 << 20))
        pos = head.find(TABLE_ID)
        if pos < 0:
            raise FormatError("no Inno Setup loader offset table (rDlPtS) found - not an Inno Setup 5.1.5+ installer?")
        self.table = OffsetTable(head[pos:pos + 44], pos)
        self.checksum_name = self.table.checksum
        self.checksum = CHECKSUMS[self.checksum_name]
        if self.table.offset1 == 0:
            raise FormatError("disk-spanning installer (setup-1.bin slices) is not supported")
        sid = self._read(self.table.offset0, 64)
        if not sid.startswith(SETUP_ID_PREFIX):
            raise FormatError("setup-0 ID not found at offset %d" % self.table.offset0)
        self.setup_id = sid.rstrip(b"\0").decode("latin1")
        self.lzma_props = []

    def close(self):
        self.f.close()

    def _read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    # --- compressed blocks (TCompressedBlockReader) -------------------------------------------
    def read_block(self, off):
        """Return (decompressed bytes, end offset). Layout: u32 check, u32 stored size, u8 compressed,
        then 4 KiB chunks each preceded by a u32 check of the chunk."""
        hdr = self._read(off, 9)
        check, stored, compressed = struct.unpack("<IIB", hdr)
        if self.checksum(hdr[4:]) != check:
            raise FormatError("block header checksum mismatch at offset %d" % off)
        raw = self._read(off + 9, stored)
        if len(raw) != stored:
            raise FormatError("block at %d truncated" % off)
        data = bytearray()
        i = 0
        while i < len(raw):
            c = struct.unpack_from("<I", raw, i)[0]
            chunk = raw[i + 4:i + 4 + 4096]
            if self.checksum(chunk) != c:
                raise FormatError("block chunk checksum mismatch at offset %d" % (off + 9 + i))
            data += chunk
            i += 4 + len(chunk)
        if compressed:
            out, props = lzma1_raw_decompress(bytes(data))
            self.lzma_props.append(props)
            return out, off + 9 + stored
        return bytes(data), off + 9 + stored

    def setup0_blocks(self):
        b1, end1 = self.read_block(self.table.offset0 + 64)
        b2, end2 = self.read_block(end1)
        return b1, b2

    def engine(self):
        """Decompress and verify the embedded Setup.e32 (the program that performs the install)."""
        t = self.table
        f = self._read(t.offset_exe, 9)
        check, stored, compressed = struct.unpack("<IIB", f)
        if self.checksum(f[4:]) != check:
            raise FormatError("Setup.e32 block header checksum mismatch")
        raw = self._read(t.offset_exe + 9, stored)
        data = bytearray()
        i = 0
        while i < len(raw):
            c = struct.unpack_from("<I", raw, i)[0]
            chunk = raw[i + 4:i + 4 + 4096]
            if self.checksum(chunk) != c:
                raise FormatError("Setup.e32 chunk checksum mismatch")
            data += chunk
            i += 4 + len(chunk)
        out, props = lzma1_raw_decompress(bytes(data)) if compressed else (bytes(data), None)
        out = transform_call_instructions(out, encode=False, addr_offset=0)
        if len(out) != t.usize_exe:
            raise FormatError("Setup.e32 size %d != expected %d" % (len(out), t.usize_exe))
        if self.checksum(out) != (t.crc_exe & 0xFFFFFFFF):
            raise FormatError("Setup.e32 checksum mismatch")
        return out, props
