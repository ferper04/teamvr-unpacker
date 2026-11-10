"""Command-line interface.

    python -m teamvr_unpack info    SETUP.exe
    python -m teamvr_unpack list    SETUP.exe
    python -m teamvr_unpack extract SETUP.exe -o OUTDIR [-p PASSWORD ...] [--bruteforce] [--engine]
"""
import argparse
import json
import os
import sys

from . import __version__
from .container import FormatError, Installer
from .crypto import DEFAULT_CANDIDATES, KeyFinder, KeyFinder63, Nonce
from .extract import extract_all
from .ifps import IFPS
from .report import iss, triage
from .structs import ParseError, parse_setup0


def load(path):
    inst = Installer(path)
    b1, b2 = inst.setup0_blocks()
    setup = parse_setup0(b1, b2, inst.setup_id)
    if setup["layout"] == "6.4":
        setup["nonce"] = Nonce(setup["header"]["EncryptionBaseNonce"])
    fp = []
    if inst.checksum_name == "xxh32":
        fp.append("xxHash32 instead of CRC32 for every integrity check")
    if any(p and p[0] != 3 for p in inst.lzma_props):
        fp.append("non-default LZMA literal context (lc=%d) in header blocks" % inst.lzma_props[0][0])
    if setup["salt_len"] == 64:
        fp.append("64-byte KDF salt (stock: 16) - Team V.R key derivation (keyed BLAKE2b)")
    if setup["hash_len"] == 16:
        fp.append("16-byte XXH3-128 file hashes (stock: 32-byte SHA-256)")
    if fp and "6.4.2" in inst.setup_id:
        fp.append("SetupID left as %r although the format changed" % inst.setup_id)
    if setup["layout"] == "6.3":
        fp.append("Inno 6.3 layout (ARC4 + SHA-1 password hash, SHA-1 file hashes)")
        variant = "teamvr-6.3" if fp[:-1] else "stock-6.3"
    else:
        variant = "teamvr" if setup["salt_len"] == 64 else "stock"
    return inst, setup, variant, fp


def find_key(setup, variant, passwords, bruteforce, log):
    locs = setup["locations"]
    if not any("ChunkEncrypted" in l["flag_names"] for l in locs):
        return None, None
    if setup["layout"] == "6.3":
        return KeyFinder63(setup["header"]).try_passwords(passwords + ([] if passwords else DEFAULT_CANDIDATES))
    kf = KeyFinder(variant, setup["header"])
    pw, key = kf.try_passwords(passwords + ([] if passwords else DEFAULT_CANDIDATES))
    if key is None and bruteforce and variant == "teamvr":
        log("brute-forcing the effective password bytes (Team V.R KDF length bug) ...")
        pw, key = kf.bruteforce_teamvr(progress=lambda L: log("  no match with %d hashed byte(s)" % L))
    return pw, key


def cmd_info(args):
    inst, setup, variant, fp = load(args.installer)
    h = setup["header"]
    print("file          :", args.installer)
    print("format        :", inst.setup_id, "| variant:", variant)
    for f in fp:
        print("  fingerprint :", f)
    print("app           : %s %s  (publisher: %s)" % (h["AppName"], h["AppVersion"], h["AppPublisher"]))
    print("default dir   :", h["DefaultDirName"])
    print("entries       :", {k: len(v) for k, v in setup["entries"].items() if v})
    enc = sum("ChunkEncrypted" in l["flag_names"] for l in setup["locations"])
    print("files         : %d data locations, %d encrypted" % (len(setup["locations"]), enc))
    if enc:
        pw, key = find_key(setup, variant, args.password or [], args.bruteforce, print)
        print("password      :", repr(pw) if key else "not found (use -p or --bruteforce)")
    code = h["CompiledCodeText"]
    imports = []
    if code:
        try:
            imports = IFPS(code).imports()
        except ValueError as e:
            print("[Code]        : could not parse (%s)" % e)
        print("[Code] imports:", ", ".join(imports))
    print("\nnotable behaviour:")
    for n in triage(setup, imports) or ["(nothing flagged)"]:
        print("  -", n)
    return 0


def cmd_list(args):
    inst, setup, variant, fp = load(args.installer)
    dests = {}
    for fe in setup["entries"]["File"]:
        if fe["LocationEntry"] >= 0:
            dests.setdefault(fe["LocationEntry"], []).append(fe)
    for l in setup["locations"]:
        for fe in dests.get(l["index"], [None]):
            print("%3d %12d %-4s %-3s %s%s" % (l["index"], l["OriginalSize"],
                                               "enc" if "ChunkEncrypted" in l["flag_names"] else "",
                                               "x86" if "CallInstructionOptimized" in l["flag_names"] else "",
                                               fe["DestName"] if fe else "<no file entry>",
                                               ("   [%s]" % fe["Components"]) if fe and fe["Components"] else ""))
    return 0


def cmd_extract(args):
    inst, setup, variant, fp = load(args.installer)
    out = args.output
    os.makedirs(out, exist_ok=True)
    meta = os.path.join(out, "_setup")
    os.makedirs(meta, exist_ok=True)
    print("format: %s, variant: %s" % (inst.setup_id, variant))
    for f in fp:
        print("  -", f)
    pw, key = find_key(setup, variant, args.password or [], args.bruteforce, print)
    if any("ChunkEncrypted" in l["flag_names"] for l in setup["locations"]):
        print("password:", repr(pw) if key else "NOT FOUND - encrypted files will be skipped")
    h = setup["header"]
    code = h["CompiledCodeText"]
    imports = []
    if code:
        open(os.path.join(meta, "code.ifps"), "wb").write(code)
        try:
            prog = IFPS(code); imports = prog.imports()
            open(os.path.join(meta, "code_disasm.txt"), "w", encoding="utf-8").write(prog.disassemble())
        except ValueError as e:
            print("warning: [Code] not disassembled:", e)
    open(os.path.join(meta, "install_script.iss"), "w", encoding="utf-8").write(iss(setup))
    notes = triage(setup, imports)
    open(os.path.join(meta, "triage.txt"), "w", encoding="utf-8").write("\n".join(notes) + "\n")
    for kind in ("WizardImages", "WizardSmallImages"):
        for i, img in enumerate(setup["images"][kind]):
            ext = ".png" if img[:4] == b"\x89PNG" else ".bmp"
            open(os.path.join(meta, "%s_%d%s" % (kind, i, ext)), "wb").write(img)
    for k in ("LicenseText", "InfoBeforeText", "InfoAfterText"):
        if h[k]:
            open(os.path.join(meta, k + ".txt"), "wb").write(h[k])
    if args.engine:
        eng, _ = inst.engine()
        open(os.path.join(meta, "Setup.e32"), "wb").write(eng)
        print("engine: Setup.e32 (%d bytes) verified and saved" % len(eng))
    results = extract_all(inst, setup, out, key=key)
    bad = [r for r in results if r.get("status") != "ok"]

    def clean(o):
        if isinstance(o, bytes): return o.hex() if len(o) <= 64 else "<%d bytes>" % len(o)
        if isinstance(o, dict): return {k: clean(v) for k, v in o.items() if k != "nonce"}
        if isinstance(o, list): return [clean(v) for v in o]
        return o
    json.dump(dict(tool="teamvr-unpack " + __version__, installer=os.path.abspath(args.installer),
                   setup_id=inst.setup_id, variant=variant, fingerprints=fp, password=pw, files=results,
                   triage=notes, header={k: clean(v) for k, v in h.items() if k != "CompiledCodeText"},
                   entries=clean({k: v for k, v in setup["entries"].items() if k != "Language"}),
                   locations=clean(setup["locations"])),
              open(os.path.join(meta, "manifest.json"), "w", encoding="utf-8"), indent=1, default=str)
    print("\n%d file(s) extracted, %d problem(s); metadata in %s" % (len(results) - len(bad), len(bad), meta))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="teamvr-unpack", description="Static unpacker for Inno Setup 6.3.x / 6.4.x installers, "
                                 "including the modified Team V.R variant. Never executes the installer.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, hlp in (("info", cmd_info, "summary, fingerprints and behaviour triage"),
                          ("list", cmd_list, "list files"), ("extract", cmd_extract, "extract everything")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("installer")
        p.add_argument("-p", "--password", action="append", help="password candidate (repeatable)")
        p.add_argument("--bruteforce", action="store_true", help="Team V.R only: brute-force the effective password bytes")
        if name == "extract":
            p.add_argument("-o", "--output", required=True, help="output directory")
            p.add_argument("--engine", action="store_true", help="also save the embedded Setup.e32 engine")
        p.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (FormatError, ParseError) as e:
        print("error:", e, file=sys.stderr)
        return 2
