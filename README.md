# teamvr-unpack

A static unpacker and analyser for **Inno Setup 6.3.x and 6.4.x** installers, including the
**modified "Team V.R" variants**. Team V.R builds its installers with a privately rebuilt Inno Setup
engine whose altered checksums, header layout, key derivation and file hashes break innounp and
innoextract.

It lets you see **exactly what an installer would do**, including every file, registry value,
`[Run]` entry and the compiled `[Code]` script, **without running it**.

```
$ python -m teamvr_unpack info setup.exe
format        : Inno Setup Setup Data (6.4.2) | variant: teamvr
  fingerprint : xxHash32 instead of CRC32 for every integrity check
  fingerprint : non-default LZMA literal context (lc=4) in header blocks
  fingerprint : 64-byte KDF salt (stock: 16) - Team V.R key derivation (keyed BLAKE2b)
  fingerprint : 16-byte XXH3-128 file hashes (stock: 32-byte SHA-256)
  fingerprint : SetupID left as 'Inno Setup Setup Data (6.4.2)' although the format changed
files         : 23 data locations, 22 encrypted
password      : 'Zet0'
notable behaviour:
  - [Run] {tmp}\Helper.cmd runs AUTOMATICALLY during install, hidden window
  - [Registry] HKLM\SYSTEM\...\Session Manager\Environment : ... (machine-wide, NOT removed on uninstall)
  - [Code] imports SHELLEXEC - can open files/URLs/programs
```

## What it does

* Parses the SetupLdr offset table, the checksummed setup-0 blocks and every record type
  (header, languages, types, components, tasks, dirs, files, icons, INI, registry, delete, run).
  The parser must consume the header block exactly, which serves as a strong format check.
* Detects the layout (6.3 / 6.4) from the SetupID and stock vs Team V.R automatically
  (CRC32/xxHash32, 16/64-byte salt, SHA-256/XXH3-128).
* Recovers the password: from `-p` candidates, from built-in defaults, or with `--bruteforce`
  (Team V.R 6.4 only, using their KDF length bug; usually under 2 seconds).
* Decrypts (XChaCha20 for 6.4, ARC4 for 6.3), decompresses (LZMA1, LZMA2, bzip2, zlib, stored),
  reverses Inno's x86 call filter, writes files under their install paths (`{app}\…`, `{cf}\…`,
  `{tmp}\…`) and **verifies every file** against the hash stored in the installer
  (SHA-256, XXH3-128 or SHA-1).
* Writes metadata to `OUT/_setup/`:
  `install_script.iss` (reconstructed script), `triage.txt` (things worth reviewing), `code.ifps` +
  `code_disasm.txt` (Pascal Script bytecode and disassembly), `manifest.json` (everything parsed),
  wizard images, license/info texts and, with `--engine`, the verified `Setup.e32`.

The format changes are documented in [docs/FORMAT.md](docs/FORMAT.md).

## Install and use

```
pip install -r requirements.txt          # cryptography, xxhash
# or install it as a command:  pip install .   ->   teamvr-unpack info setup.exe
python -m teamvr_unpack info    setup.exe
python -m teamvr_unpack list    setup.exe
python -m teamvr_unpack extract setup.exe -o out [-p PASSWORD]... [--bruteforce] [--engine]
```

Python 3.9+. Pure Python apart from those two libraries. Works on Windows, Linux and macOS.

## Safety

* The tool only **reads** the installer. It never executes the installer, its `[Code]` script, any
  DLL inside it, or any extracted file.
* Extracted files are as untrusted as the installer. Analyse them in a VM.
* Output paths are sanitised (no `..`, no drive letters), so a hostile installer cannot write outside
  the output directory.

## Verified against

| Installer | Result |
|---|---|
| Official `innosetup-6.4.2.exe` (stock, 96 files) | all SHA-256 verified; extracted ISCC.exe/ISCmplr.dll keep their valid Authenticode signatures |
| Stock 6.4.2 test builds: LZMA2 solid + encryption, LZMA1 + encryption, bzip2 | byte-identical to the source files; wrong password rejected |
| A 2025 Team V.R release (Inno 6.4.2 based, 23 files, 1 GB unpacked) | all XXH3-128 verified, identical to an independent manual extraction |
| Official `innosetup-6.3.0` … `6.3.3` (stock, 94 files each) | all SHA-1 verified |
| A Team V.R release built on Inno 6.3 (89 files, ARC4-encrypted) | 89/89 SHA-1 verified |

Unit tests: `python -m unittest discover -s tests -v` (includes the HChaCha20 vector from
draft-irtf-cfrg-xchacha). Set `TVR_SAMPLE=path\to\setup.exe` to also run an end-to-end extraction.

## Limitations

* Inno Setup **6.3.x and 6.4.x** record layouts only (tested with 6.3.0–6.3.3 and 6.4.2). Earlier
  versions (for example the Inno 6.1-based Team V.R releases) and 6.5+ use other layouts and are not
  supported yet. Contributions welcome.
* Single-file installers only (no `DiskSpanning` / `setup-1.bin` slices).
* If Team V.R changes their engine again, `info` will show which check fails. Start from
  docs/FORMAT.md.

## Legal

This is a security research and malware analysis tool: it shows what an installer contains and
does, so you don't have to run it. It does not crack, patch or license any software. Use it only on
files you are allowed to analyse.

MIT licensed. Not affiliated with Inno Setup / Jordan Russell / Martijn Laan.
