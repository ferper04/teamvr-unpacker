"""Deserialiser for the Inno Setup 6.3.x / 6.4.x setup-0 header (TSetupHeader + entry records).

Layouts follow Projects/Src/Shared.Struct.pas of issrc tag is-6_4_2. Each record is stored as its
String fields (u32 byte length + UTF-16LE), then AnsiString fields (u32 length + bytes), then the
remaining fixed-size part of the packed record verbatim (internal fields included).

Variant knobs (detected automatically, see parse_setup0):
  salt_len   16 (stock TSetupKDFSalt) or 64 (Team V.R)
  hash_len   32 (stock SHA256Sum in TSetupFileLocationEntry) or 16 (Team V.R XXH3-128)
"""
import struct
import datetime


class ParseError(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def take(self, n):
        if self.p + n > len(self.d):
            raise ParseError("read past end at %d (+%d of %d)" % (self.p, n, len(self.d)))
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def ustr(self):
        n = self.u32()
        if n > 64 << 20:
            raise ParseError("implausible string length %d at %d" % (n, self.p - 4))
        return self.take(n).decode("utf-16le", "replace")

    def astr(self):
        n = self.u32()
        if n > 512 << 20:
            raise ParseError("implausible AnsiString length %d at %d" % (n, self.p - 4))
        return self.take(n)

    def fixed(self, spec):
        out = {}
        for name, kind in spec:
            if kind == "u8":
                out[name] = self.take(1)[0]
            elif kind == "u16":
                out[name] = struct.unpack("<H", self.take(2))[0]
            elif kind == "i16":
                out[name] = struct.unpack("<h", self.take(2))[0]
            elif kind == "i32":
                out[name] = struct.unpack("<i", self.take(4))[0]
            elif kind == "u32":
                out[name] = struct.unpack("<I", self.take(4))[0]
            elif kind == "i64":
                out[name] = struct.unpack("<q", self.take(8))[0]
            elif kind == "u64":
                out[name] = struct.unpack("<Q", self.take(8))[0]
            elif kind == "ver":
                w, nt, sp = struct.unpack("<IIH", self.take(10))
                out[name] = {"win": w, "nt": nt, "nt_sp": sp}
            elif kind == "guid":
                out[name] = self.take(16).hex()
            elif kind.startswith("bytes:"):
                out[name] = self.take(int(kind[6:]))
            elif kind.startswith("set:"):
                n = int(kind[4:])
                out[name] = int.from_bytes(self.take((n + 7) // 8), "little")
            else:
                raise ValueError(kind)
        return out

    def record(self, strings, ansi, spec):
        r = {}
        for s in strings:
            r[s] = self.ustr()
        for s in ansi:
            r[s] = self.astr()
        r.update(self.fixed(spec))
        return r


VER = "ver"
HEADER_STRINGS = [
    "AppName", "AppVerName", "AppId", "AppCopyright", "AppPublisher", "AppPublisherURL", "AppSupportPhone",
    "AppSupportURL", "AppUpdatesURL", "AppVersion", "DefaultDirName", "DefaultGroupName", "BaseFilename",
    "UninstallFilesDir", "UninstallDisplayName", "UninstallDisplayIcon", "AppMutex", "DefaultUserInfoName",
    "DefaultUserInfoOrg", "DefaultUserInfoSerial", "AppReadmeFile", "AppContact", "AppComments", "AppModifyPath",
    "CreateUninstallRegKey", "Uninstallable", "CloseApplicationsFilter", "SetupMutex", "ChangesEnvironment",
    "ChangesAssociations", "ArchitecturesAllowed", "ArchitecturesInstallIn64BitMode",
    "CloseApplicationsFilterExcludes"]
HEADER_ANSI = ["LicenseText", "InfoBeforeText", "InfoAfterText", "CompiledCodeText"]
COUNT_NAMES = ["Language", "CustomMessage", "Permission", "Type", "Component", "Task", "Dir", "File",
               "FileLocation", "Icon", "Ini", "Registry", "InstallDelete", "UninstallDelete", "Run", "UninstallRun"]
HEADER_OPTIONS = [
    "DisableStartupPrompt", "CreateAppDir", "AllowNoIcons", "AlwaysRestart", "AlwaysUsePersonalGroup",
    "EnableDirDoesntExistWarning", "Password", "AllowRootDirectory", "DisableFinishedPage", "UsePreviousAppDir",
    "UsePreviousGroup", "UpdateUninstallLogAppName", "UsePreviousSetupType", "DisableReadyMemo",
    "AlwaysShowComponentsList", "FlatComponentsList", "ShowComponentSizes", "UsePreviousTasks", "DisableReadyPage",
    "AlwaysShowDirOnReadyPage", "AlwaysShowGroupOnReadyPage", "AllowUNCPath", "UserInfoPage",
    "UsePreviousUserInfo", "UninstallRestartComputer", "RestartIfNeededByRun", "ShowTasksTreeLines",
    "AllowCancelDuringInstall", "WizardImageStretch", "AppendDefaultDirName", "AppendDefaultGroupName",
    "EncryptionUsed", "SetupLogging", "SignedUninstaller", "UsePreviousLanguage", "DisableWelcomePage",
    "CloseApplications", "RestartApplications", "AllowNetworkDrive", "ForceCloseApplications",
    "AppNameHasConsts", "UsePreviousPrivileges", "WizardResizable", "UninstallLogging"]


def header_spec(salt_len):
    spec = [("Num" + n, "i32") for n in COUNT_NAMES]
    spec += [("MinVersion", VER), ("OnlyBelowVersion", VER), ("WizardStyle", "u8"),
             ("WizardSizePercentX", "i32"), ("WizardSizePercentY", "i32"), ("WizardImageAlphaFormat", "u8"),
             ("PasswordTest", "i32"), ("EncryptionKDFSalt", "bytes:%d" % salt_len),
             ("EncryptionKDFIterations", "i32"), ("EncryptionBaseNonce", "bytes:24"),
             ("ExtraDiskSpaceRequired", "i64"), ("SlicesPerDisk", "i32"), ("UninstallLogMode", "u8"),
             ("DirExistsWarning", "u8"), ("PrivilegesRequired", "u8"),
             ("PrivilegesRequiredOverridesAllowed", "set:2"), ("ShowLanguageDialog", "u8"),
             ("LanguageDetectionMethod", "u8"), ("CompressMethod", "u8"), ("DisableDirPage", "u8"),
             ("DisableProgramGroupPage", "u8"), ("UninstallDisplaySize", "i64"), ("Options", "set:46")]
    return spec


# Inno Setup 6.3.x (issrc is-6_3_0 Projects/Src/Struct.pas): no CloseApplicationsFilterExcludes string,
# BackColor/BackColor2, SHA-1 PasswordHash + 8-byte PasswordSalt (ARC4 era), 49 header options.
HEADER_STRINGS_63 = HEADER_STRINGS[:-1]
HEADER_OPTIONS_63 = [
    "DisableStartupPrompt", "CreateAppDir", "AllowNoIcons", "AlwaysRestart", "AlwaysUsePersonalGroup",
    "WindowVisible", "WindowShowCaption", "WindowResizable", "WindowStartMaximized", "EnableDirDoesntExistWarning",
    "Password", "AllowRootDirectory", "DisableFinishedPage", "UsePreviousAppDir", "BackColorHorizontal",
    "UsePreviousGroup", "UpdateUninstallLogAppName", "UsePreviousSetupType", "DisableReadyMemo",
    "AlwaysShowComponentsList", "FlatComponentsList", "ShowComponentSizes", "UsePreviousTasks", "DisableReadyPage",
    "AlwaysShowDirOnReadyPage", "AlwaysShowGroupOnReadyPage", "AllowUNCPath", "UserInfoPage",
    "UsePreviousUserInfo", "UninstallRestartComputer", "RestartIfNeededByRun", "ShowTasksTreeLines",
    "AllowCancelDuringInstall", "WizardImageStretch", "AppendDefaultDirName", "AppendDefaultGroupName",
    "EncryptionUsed", "SetupLogging", "SignedUninstaller", "UsePreviousLanguage", "DisableWelcomePage",
    "CloseApplications", "RestartApplications", "AllowNetworkDrive", "ForceCloseApplications",
    "AppNameHasConsts", "UsePreviousPrivileges", "WizardResizable", "UninstallLogging"]


def header_spec_63():
    spec = [("Num" + n, "i32") for n in COUNT_NAMES]
    spec += [("MinVersion", VER), ("OnlyBelowVersion", VER), ("BackColor", "i32"), ("BackColor2", "i32"),
             ("WizardStyle", "u8"), ("WizardSizePercentX", "i32"), ("WizardSizePercentY", "i32"),
             ("WizardImageAlphaFormat", "u8"), ("PasswordHash", "bytes:20"), ("PasswordSalt", "bytes:8"),
             ("ExtraDiskSpaceRequired", "i64"), ("SlicesPerDisk", "i32"), ("UninstallLogMode", "u8"),
             ("DirExistsWarning", "u8"), ("PrivilegesRequired", "u8"),
             ("PrivilegesRequiredOverridesAllowed", "set:2"), ("ShowLanguageDialog", "u8"),
             ("LanguageDetectionMethod", "u8"), ("CompressMethod", "u8"), ("DisableDirPage", "u8"),
             ("DisableProgramGroupPage", "u8"), ("UninstallDisplaySize", "i64"), ("Options", "set:49")]
    return spec


VV = [("MinVersion", VER), ("OnlyBelowVersion", VER)]
ENTRY_SPECS = {
    "Language": (["Name", "LanguageName", "DialogFontName", "TitleFontName", "WelcomeFontName", "CopyrightFontName"],
                 ["Data", "LicenseText", "InfoBeforeText", "InfoAfterText"],
                 [("LanguageID", "u32"), ("DialogFontSize", "i32"), ("TitleFontSize", "i32"),
                  ("WelcomeFontSize", "i32"), ("CopyrightFontSize", "i32"), ("RightToLeft", "u8")]),
    "CustomMessage": (["Name", "Value"], [], [("LangIndex", "i32")]),
    "Permission": ([], ["Permissions"], []),
    "Type": (["Name", "Description", "Languages", "Check"], [],
             VV + [("Options", "set:1"), ("Typ", "u8"), ("Size", "i64")]),
    "Component": (["Name", "Description", "Types", "Languages", "Check"], [],
                  [("ExtraDiskSpaceRequired", "i64"), ("Level", "i32"), ("Used", "u8")] + VV +
                  [("Options", "set:5"), ("Size", "i64")]),
    "Task": (["Name", "Description", "GroupDescription", "Components", "Languages", "Check"], [],
             [("Level", "i32"), ("Used", "u8")] + VV + [("Options", "set:5")]),
    "Dir": (["DirName", "Components", "Tasks", "Languages", "Check", "AfterInstall", "BeforeInstall"], [],
            [("Attribs", "i32")] + VV + [("PermissionsEntry", "i16"), ("Options", "set:5")]),
    "File": (["SourceFilename", "DestName", "InstallFontName", "StrongAssemblyName", "Components", "Tasks",
              "Languages", "Check", "AfterInstall", "BeforeInstall"], [],
             VV + [("LocationEntry", "i32"), ("Attribs", "i32"), ("ExternalSize", "i64"),
                   ("PermissionsEntry", "i16"), ("Options", "set:32"), ("FileType", "u8")]),
    "Icon": (["IconName", "Filename", "Parameters", "WorkingDir", "IconFilename", "Comment", "Components", "Tasks",
              "Languages", "Check", "AfterInstall", "BeforeInstall", "AppUserModelID"], [],
             [("AppUserModelToastActivatorCLSID", "guid")] + VV +
             [("IconIndex", "i32"), ("ShowCmd", "i32"), ("CloseOnExit", "u8"), ("HotKey", "u16"),
              ("Options", "set:6")]),
    "Ini": (["Filename", "Section", "Entry", "Value", "Components", "Tasks", "Languages", "Check", "AfterInstall",
             "BeforeInstall"], [], VV + [("Options", "set:5")]),
    "Registry": (["Subkey", "ValueName", "ValueData", "Components", "Tasks", "Languages", "Check", "AfterInstall",
                  "BeforeInstall"], [],
                 VV + [("RootKey", "u32"), ("PermissionsEntry", "i16"), ("Typ", "u8"), ("Options", "set:12")]),
    "InstallDelete": (["Name", "Components", "Tasks", "Languages", "Check", "AfterInstall", "BeforeInstall"], [],
                      VV + [("DeleteType", "u8")]),
    "Run": (["Name", "Parameters", "WorkingDir", "RunOnceId", "StatusMsg", "Verb", "Description", "Components",
             "Tasks", "Languages", "Check", "AfterInstall", "BeforeInstall"], [],
            VV + [("ShowCmd", "i32"), ("Wait", "u8"), ("Options", "set:12")]),
}
ENTRY_SPECS["UninstallDelete"] = ENTRY_SPECS["InstallDelete"]
ENTRY_SPECS["UninstallRun"] = ENTRY_SPECS["Run"]
ENTRY_ORDER = ["Language", "CustomMessage", "Permission", "Type", "Component", "Task", "Dir", "File", "Icon", "Ini",
               "Registry", "InstallDelete", "UninstallDelete", "Run", "UninstallRun"]

LOC_FLAGS = ["VersionInfoValid", "VersionInfoNotValid", "TimeStampInUTC", "IsUninstExe", "CallInstructionOptimized",
             "ApplyTouchDateTime", "ChunkEncrypted", "ChunkCompressed", "SolidBreak"]


def location_spec(hash_len):
    return [("FirstSlice", "i32"), ("LastSlice", "i32"), ("StartOffset", "i32"), ("ChunkSuboffset", "i64"),
            ("OriginalSize", "i64"), ("ChunkCompressedSize", "i64"), ("Hash", "bytes:%d" % hash_len),
            ("SourceTimeStamp", "u64"), ("FileVersionMS", "u32"), ("FileVersionLS", "u32"),
            ("Flags", "set:9"), ("Sign", "u8")]


def _parse_block1(data, salt_len):
    r = Reader(data)
    if salt_len == "6.3":
        hdr = r.record(HEADER_STRINGS_63, HEADER_ANSI, header_spec_63())
    else:
        hdr = r.record(HEADER_STRINGS, HEADER_ANSI, header_spec(salt_len))
    if not all(0 <= hdr["Num" + n] < 1_000_000 for n in COUNT_NAMES):
        raise ParseError("implausible entry counts")
    entries = {}
    for kind in ENTRY_ORDER:
        s, a, spec = ENTRY_SPECS[kind]
        entries[kind] = [r.record(s, a, spec) for _ in range(hdr["Num" + kind])]
    images = {}
    for kind in ("WizardImages", "WizardSmallImages"):
        n = struct.unpack("<i", r.take(4))[0]
        if not 0 <= n < 64:
            raise ParseError("implausible wizard image count %d" % n)
        images[kind] = [r.take(struct.unpack("<i", r.take(4))[0]) for _ in range(n)]
    extra = None
    if r.p < len(data):     # stock: decompressor DLL for zip/bzip setups; anything else is unexpected
        n = struct.unpack("<i", r.take(4))[0]
        extra = r.take(n)
    if r.p != len(data):
        raise ParseError("%d unparsed bytes at end of header block" % (len(data) - r.p))
    return hdr, entries, images, extra


def parse_setup0(block1, block2, setup_id=""):
    """Try stock and Team V.R layouts; the right one consumes block 1 exactly.
    salt_len is 16/64 for the 6.4 layouts or the string "6.3" for the Inno 6.3 (ARC4/SHA-1) layout."""
    errors = {}
    layouts = ("6.3", 16, 64) if "(6.3." in setup_id else (16, 64, "6.3")
    for salt_len in layouts:
        try:
            hdr, entries, images, extra = _parse_block1(block1, salt_len)
            break
        except (ParseError, UnicodeDecodeError, struct.error) as e:
            errors[salt_len] = str(e)
    else:
        raise ParseError("header did not parse with any known layout: %s" % errors)
    n = hdr["NumFileLocation"]
    if n == 0:
        hash_len = 32
        locs = []
    else:
        if len(block2) % n:
            raise ParseError("file-location block size %d not a multiple of %d entries" % (len(block2), n))
        rec = len(block2) // n
        hash_len = rec - 55
        if hash_len not in (16, 20, 32):
            raise ParseError("unexpected file-location record size %d" % rec)
        r = Reader(block2)
        locs = [r.fixed(location_spec(hash_len)) for _ in range(n)]
    for i, l in enumerate(locs):
        l["index"] = i
        l["flag_names"] = [f for b, f in enumerate(LOC_FLAGS) if l["Flags"] >> b & 1]
    return dict(header=hdr, entries=entries, images=images, decompressor_dll=extra, locations=locs,
                salt_len=salt_len, hash_len=hash_len, layout="6.3" if salt_len == "6.3" else "6.4",
                header_option_names=HEADER_OPTIONS_63 if salt_len == "6.3" else HEADER_OPTIONS)


def filetime_to_datetime(ft):
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
