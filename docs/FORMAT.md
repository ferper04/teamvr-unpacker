# The Team V.R Inno Setup variant: format notes

Team V.R ships installers built with a **privately modified and recompiled Inno Setup 6.4.2**.
The changes do not alter what Inno can do. They exist to make standard tools (innounp,
innoextract) fail, so the payload can only be inspected by running the installer. Everything below
was reversed statically and checked against the official Inno Setup 6.4.2 source
(`jrsoftware/issrc`, tag `is-6_4_2`) and the official signed `Setup.e32`.

## 1. Stock Inno Setup 6.4.2 layout (single-file installer)

```
setup.exe
 ├─ SetupLdr (Delphi PE)              RCDATA #11111 = TSetupLdrOffsetTable
 │     'rDlPtS'CD E6 D7 7B 0B 2A | Version=1 | TotalSize | OffsetEXE | UncompressedSizeEXE
 │     | CRCEXE | Offset0 | Offset1 | TableCRC            (all u32, TableCRC over the first 40 bytes)
 ├─ @Offset1  setup-1: file data, one or more chunks:  'zlb'#26 + [encrypted] compressed stream
 ├─ @Offset0  setup-0: 64-byte SetupID 'Inno Setup Setup Data (6.4.2)'
 │            block 1: TSetupHeader + all entry records + wizard images [+ decompressor DLL]
 │            block 2: TSetupFileLocationEntry[NumFileLocationEntries]
 └─ @OffsetEXE  Setup.e32 (the program that performs the install), LZMA1 + x86 call filter
```

*Compressed block* (`TCompressedBlockReader`): `u32 CRC(next 5 bytes) | u32 StoredSize |
u8 Compressed`, then the stored bytes as 4 KiB chunks, each preceded by a `u32 CRC`. The payload is
LZMA1 (5-byte properties header).

*Records* (`SECompressedBlockRead`): every `String` field is `u32 byte length + UTF-16LE`, every
`AnsiString` is `u32 length + bytes`, followed verbatim by the fixed-size rest of the packed record.
Delphi `set of N` fields take `ceil(N/8)` bytes.

*Encryption* (6.4+): `key = PBKDF2-HMAC-SHA256(UTF-16LE(password), Salt[16], Iterations, 32)`.
`PasswordTest` = the first 4 bytes of XChaCha20(key, BaseNonce with `RandomXorFirstSlice xor -1`)
applied to zeros. Each chunk uses XChaCha20 with the nonce `BaseNonce`, where
`RandomXorStartOffset ^= StartOffset` and `RandomXorFirstSlice ^= FirstSlice`. The keystream starts
right after the `zlb`#26 marker.

*Executables* flagged `foCallInstructionOptimized` are stored with Inno's E8/E9 transform. It is
applied **per 64 KiB buffer**: AddrOffset = buffer position, and the last 4 bytes of each buffer are left alone.

## 2. What Team V.R changed

| # | Stock 6.4.2 | Team V.R build | Effect on tools |
|---|---|---|---|
| 1 | CRC32 everywhere: offset table, `CRCEXE`, block headers, every 4 KiB chunk | **xxHash32, seed 0** | "setup files are corrupted" |
| 2 | LZMA `lc=3` (props `5D`) | **`lc=4`** (props `5E`) in header blocks, Setup.e32 and LZMA2 file chunks | harmless to liblzma; trips decoders with hard-coded props |
| 3 | `TSetupKDFSalt = array[0..15]` | **64-byte salt**, so every later header field moves by 48 bytes | header misparsed |
| 4 | PBKDF2-HMAC-SHA256, 200000 iterations | **`BLAKE2b-512(key = salt64, msg = UTF16(pw)[:len(pw)])[16:48]`**; the iteration field is still written (200000) but never read | wrong key |
| 5 | `SHA256Sum` (32 bytes) per file location (record 87 bytes) | **XXH3-128** (16 bytes, record 71 bytes) | location table misparsed |
| 6 | Inno's own source asks you to change `SetupID` after altering records | **ID left as `Inno Setup Setup Data (6.4.2)`** | tools pick the 6.4.2 parser and fail silently |

**The KDF length bug.** Their `GenerateEncryptionKey` passes `Length(Password)`, a character count,
as the byte count of a UTF-16 buffer. Only half the password is hashed, so for `Zet0` the key
depends only on `Z\0e\0` and `Zet0`…`Zet9`, `Zeus`, … are all valid. A 4-character password
therefore has two characters of entropy. `--bruteforce` uses this and recovers keys in about a second.

`TestPassword` and all ChaCha code are unchanged (byte-identical logic to the official engine), as is
the `CheckPassword` fallback.

## 3. Their Setup.e32 engine

* Rebuilt two days after the official 6.4.2 release, from `B:\issrc-{2025-03-12}-…\`
  (the official build path is `D:\Coding\Is\Issrc\`). It is about 228 KB larger.
* Adds a hash library (`IShashes\blake2b.pas`, `blake2s.pas`, `sha3.pas`, `hashes.pas`, plus xxHash),
  VCL Styles (skinned wizard) and printing/metafile units.
* **Adds Pascal Script functions** that installer scripts may import: `GetIpAddresses`,
  `InetAddr2AnsiString`, `GetIfTables` (enumerate IPs and network adapters through iphlpapi), FileTime/SystemTime
  converters, `GetSHA3_256OfFile`. They run only if a script imports them, so always check the
  `[Code]` import list (`teamvr-unpack info` prints it and flags these names).
* New imports compared with the official engine include `iphlpapi!GetIfTable/GetIpAddrTable`,
  `wsock32!inet_ntoa`, `netapi32!NetWkstaGetInfo` and `advapi32!RegConnectRegistryW`/hive save and load APIs.
  WinHTTP is standard (Inno's downloader).

## 4. Script patterns seen in their releases

* The password page is filled in by `[Code]`: the script builds `"Zet" + IntToStr(<seconds delta>)`
  from single characters of an alphabet table (so the string never appears as a literal), writes it
  into `WizardForm.PasswordEdit` and clicks *Next* itself. `CheckPassword` always returns True.
* A CPU feature helper (`cputest.dll`, 2015, exports `hasSSE2/SSSE3/AVX/AVX2/XOP`) in `{tmp}`.
* A clickable label on the wizard that `ShellExec`s a link to their site (only on click).
* Helpers dropped to `{tmp}` with `deleteafterinstall` and run from `[Run]` **without** `postinstall`,
  i.e. automatically and hidden. Review these first.
* Registry and environment changes without `uninsdelete*` flags, which persist after uninstall.

## 5. Inno Setup 6.3.x (and Team V.R's 6.3-based builds)

The `Inno Setup Setup Data (6.3.0)` format is shared by Inno 6.3.0–6.3.3 and used by Team V.R's
2024 builds. It differs from 6.4:

* 32 header strings and BackColor fields; 49 header options.
* Password check: `PasswordHash = SHA1("PasswordCheckHash" + PasswordSalt[8] + UTF-16LE(password))`.
* Encryption is ARC4 per chunk: after the `zlb`#26 marker comes an 8-byte salt;
  `key = SHA1(salt + UTF-16LE(password))`, and the first 1000 keystream bytes are discarded.
* File hashes are SHA-1 (20 bytes).

The Team V.R 6.3 build examined uses the same auto-filled `Zet…` password page, but stock 6.3
cryptography.

## 6. Reproducing the analysis

1. `teamvr-unpack extract setup.exe -o out --engine`
2. Compare `out/_setup/Setup.e32` against the official `Setup.e32` of the same Inno version.
3. Read `out/_setup/install_script.iss`, `triage.txt` and `code_disasm.txt`.
4. Hash every extracted file against the vendor's original installer, where you have one.
