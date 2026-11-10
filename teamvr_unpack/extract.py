"""File data extraction: chunk decryption, decompression, call-instruction filter, hash verification."""
import bz2
import hashlib
import lzma
import os
import re
import shutil
import struct
import zlib

import xxhash

from .container import FormatError
from .crypto import arc4_chunk_cipher, xchacha20
from .filters import FILE_BUFFER, transform_call_instructions
from .structs import filetime_to_datetime

ZLB = b"zlb\x1a"


class ChunkStream:
    """Sequential reader over one (optionally encrypted) compressed chunk of setup-1 data."""

    def __init__(self, f, offset, csize, cipher, compressed, total_out):
        self.f = f
        f.seek(offset)
        if f.read(4) != ZLB:
            raise FormatError("missing chunk marker at offset %d" % offset)
        if callable(cipher):        # Inno 6.3: 8-byte salt after the marker, not counted in csize
            cipher = cipher(f.read(8))
        self.left = csize
        self.cipher = cipher
        self.pending = b""
        self.method = "stored"
        self.dec = None
        head = self._raw(min(16, csize))
        if compressed:
            self.method, self.dec = self._make_decompressor(head, total_out)
        else:
            self.pending = head
        self._head = head if compressed else b""
        self._fed = False

    def _raw(self, n):
        n = min(n, self.left)
        b = self.f.read(n)
        if len(b) != n:
            raise FormatError("unexpected end of file inside chunk")
        self.left -= n
        return self.cipher.update(b) if self.cipher else b

    @staticmethod
    def _make_decompressor(head, total_out):
        cap = max(1 << 16, total_out)
        b0 = head[0]
        if b0 <= 40 and len(head) > 1 and (head[1] in (0x01,) or head[1] >= 0xE0):
            dsz = 0xFFFFFFFF if b0 == 40 else (2 | (b0 & 1)) << (b0 // 2 + 11)
            filt = {"id": lzma.FILTER_LZMA2, "dict_size": min(dsz, cap, 1536 << 20)}
            return "lzma2", ("lzma2", lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt]), 1)
        if head[:3] == b"BZh":
            return "bzip2", ("bz2", bz2.BZ2Decompressor(), 0)
        if b0 == 0x78 and (b0 * 256 + head[1]) % 31 == 0:
            return "zlib", ("zlib", zlib.decompressobj(), 0)
        if b0 < 225:
            lc, lp, pb = b0 % 9, (b0 // 9) % 5, b0 // 45
            dsz = struct.unpack_from("<I", head, 1)[0]
            filt = {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": max(4096, min(dsz, cap))}
            return "lzma1(lc=%d)" % lc, ("lzma1", lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt]), 5)
        raise FormatError("unknown chunk compression (first byte 0x%02x)" % b0)

    def _feed(self):
        kind, d, skip = self.dec
        if not self._fed:
            data = self._head[skip:]
            self._fed = True
        else:
            if self.left <= 0:
                raise FormatError("chunk data exhausted")
            data = self._raw(1 << 20)
        return data

    def read(self, n):
        out = [self.pending[:n]]
        got = len(out[0])
        self.pending = self.pending[n:]
        if self.dec is None:
            while got < n:
                b = self._raw(n - got)
                if not b:
                    raise FormatError("stored chunk exhausted")
                out.append(b); got += len(b)
            return b"".join(out)
        kind, d, _ = self.dec
        while got < n:
            want = n - got
            if kind in ("lzma1", "lzma2", "bz2"):
                data = self._feed() if d.needs_input else b""
                piece = d.decompress(data, max_length=want)
            else:  # zlib
                data = getattr(self, "_ztail", b"") or self._feed()
                piece = d.decompress(data, want)
                self._ztail = d.unconsumed_tail
            out.append(piece); got += len(piece)
        return b"".join(out)

    def skip(self, n):
        while n > 0:
            k = min(n, 1 << 20)
            self.read(k)
            n -= k


_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_relpath(dest):
    parts = []
    for comp in dest.replace("/", "\\").split("\\"):
        comp = _BAD.sub("_", comp).strip().rstrip(".")
        if comp in ("", ".", ".."):
            continue
        parts.append(comp)
    return os.path.join(*parts) if parts else "_unnamed"


def _hash_ctx(hash_len):
    return hashlib.sha256() if hash_len == 32 else (hashlib.sha1() if hash_len == 20 else xxhash.xxh3_128())


def _hash_match(stored, ctx):
    d = ctx.digest()
    return stored in (d, d[::-1])


def extract_all(inst, setup, outdir, key=None, select=None, log=print):
    """Extract every file location. Returns a list of result dicts."""
    locs = setup["locations"]
    hash_len = setup["hash_len"]
    dests = {}
    for fe in setup["entries"]["File"]:
        if fe["LocationEntry"] >= 0:
            dests.setdefault(fe["LocationEntry"], []).append(fe["DestName"])
    chunks = {}
    for l in locs:
        if l["FirstSlice"] != 0 or l["LastSlice"] != 0:
            raise FormatError("multi-slice data not supported")
        chunks.setdefault((l["FirstSlice"], l["StartOffset"]), []).append(l)
    results = []
    used_paths = {}
    base1 = inst.table.offset1
    for (slice_, start), group in sorted(chunks.items(), key=lambda kv: kv[0][1]):
        group.sort(key=lambda l: l["ChunkSuboffset"])
        first = group[0]
        enc = "ChunkEncrypted" in first["flag_names"]
        comp = "ChunkCompressed" in first["flag_names"]
        if select is not None and not any(select(l, dests.get(l["index"], [])) for l in group):
            continue
        if enc and key is None:
            for l in group:
                results.append(dict(location=l["index"], dests=dests.get(l["index"], []), size=l["OriginalSize"],
                                    status="skipped: encrypted, no key"))
            continue
        if not enc:
            cipher = None
        elif isinstance(key, tuple) and key[0] == "arc4":
            cipher = lambda salt, pw=key[1]: arc4_chunk_cipher(pw, salt)
        else:
            cipher = xchacha20(key, setup["nonce"].pack(start, slice_))
        total = max(l["ChunkSuboffset"] + l["OriginalSize"] for l in group)
        cs = ChunkStream(inst.f, base1 + start, first["ChunkCompressedSize"], cipher, comp, total)
        log("chunk @%d: %d file(s), %s%s, %d bytes stored" % (start, len(group), cs.method,
                                                             ", encrypted" if enc else "", first["ChunkCompressedSize"]))
        pos = 0
        for l in group:
            if l["ChunkSuboffset"] < pos:
                raise FormatError("overlapping file data in chunk")
            cs.skip(l["ChunkSuboffset"] - pos)
            pos = l["ChunkSuboffset"]
            names = dests.get(l["index"]) or ["_unreferenced\\location%03d.bin" % l["index"]]
            rel = safe_relpath(names[0])
            if rel in used_paths:
                rel = rel + ".loc%d" % l["index"]
            used_paths[rel] = l["index"]
            path = os.path.join(outdir, rel)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            ctx = _hash_ctx(hash_len); sha = hashlib.sha256()
            call_opt = "CallInstructionOptimized" in l["flag_names"]
            remaining = l["OriginalSize"]; foff = 0
            with open(path, "wb") as out:
                while remaining:
                    n = min(FILE_BUFFER, remaining)
                    buf = cs.read(n)
                    if call_opt:
                        buf = transform_call_instructions(buf, encode=False, addr_offset=foff & 0xFFFFFFFF)
                    ctx.update(buf); sha.update(buf); out.write(buf)
                    remaining -= n; foff += n
            pos += l["OriginalSize"]
            ok = _hash_match(l["Hash"], ctx)
            ts = filetime_to_datetime(l["SourceTimeStamp"])
            if ts:
                try:
                    os.utime(path, (ts.timestamp(), ts.timestamp()))
                except (OSError, OverflowError, ValueError):
                    pass
            for extra in names[1:]:
                p2 = os.path.join(outdir, safe_relpath(extra))
                os.makedirs(os.path.dirname(p2) or ".", exist_ok=True)
                shutil.copyfile(path, p2)
            results.append(dict(location=l["index"], dests=names, path=rel, size=l["OriginalSize"],
                                sha256=sha.hexdigest(), hash_ok=ok, encrypted=enc, compression=cs.method,
                                call_filter=call_opt, timestamp=ts.isoformat() if ts else None,
                                status="ok" if ok else "HASH MISMATCH"))
            log("  [%s] %10d  %s" % ("ok" if ok else "BAD", l["OriginalSize"], names[0]))
    return results
