"""Human-readable reconstruction of the install script and a triage of notable behaviour."""
import re

ROOTS = {0x80000000: "HKCR", 0x80000001: "HKCU", 0x80000002: "HKLM", 0x80000003: "HKU", 0x80000005: "HKCC"}
REG_TYPES = ["none", "string", "expandsz", "dword", "binary", "multisz", "qword"]
REG_FLAGS = ["createvalueifdoesntexist", "uninsdeletevalue", "uninsclearvalue", "uninsdeletekey",
             "uninsdeletekeyifempty", "preservestringtype", "deletekey", "deletevalue", "noerror", "dontcreatekey",
             "32bit", "64bit"]
RUN_FLAGS = ["shellexec", "skipifdoesntexist", "postinstall", "unchecked", "skipifsilent", "skipifnotsilent",
             "hidewizard", "32bit", "64bit", "runasoriginaluser", "dontlogparameters", "logoutput"]
FILE_FLAGS = ["confirmoverwrite", "uninsneveruninstall", "restartreplace", "deleteafterinstall", "regserver",
              "regtypelib", "sharedfile", "comparetimestamp", "fontisnttruetype", "skipifsourcedoesntexist",
              "overwritereadonly", "replacesameversion", "customdestname", "onlyifdestfileexists", "noregerror",
              "uninsrestartdelete", "onlyifdoesntexist", "ignoreversion", "promptifolder", "dontcopy",
              "uninsremovereadonly", "recursesubdirs", "replacesameversionifcontentsdiffer", "nocompression?",
              "uninsnosharedfileprompt", "createallsubdirs", "32bit", "64bit", "externalsizepreset",
              "setntfscompression", "unsetntfscompression", "gacinstall"]
DIR_FLAGS = ["uninsneveruninstall", "deleteafterinstall", "uninsalwaysuninstall", "setntfscompression",
             "unsetntfscompression"]
DELETE_TYPES = ["files", "filesandordirs", "dirifempty"]
PRIV = ["none", "poweruser", "admin", "lowest"]


def bits(v, names):
    return [n for i, n in enumerate(names) if v >> i & 1]


def q(s):
    return '"%s"' % s.replace('"', '""')


def _opt(name, val):
    return '; %s: %s' % (name, q(val)) if val else ''


def iss(setup):
    h, E = setup["header"], setup["entries"]
    L = ["; Reconstructed by teamvr-unpack (field values from the compiled setup; not the original .iss)", "",
         "[Setup]"]
    for k in ("AppName", "AppVersion", "AppVerName", "AppId", "AppPublisher", "AppPublisherURL", "AppCopyright",
              "DefaultDirName", "DefaultGroupName", "UninstallDisplayName", "Uninstallable", "CreateUninstallRegKey",
              "ArchitecturesAllowed", "ArchitecturesInstallIn64BitMode", "ChangesEnvironment", "ChangesAssociations"):
        if h.get(k):
            L.append("%s=%s" % (k, h[k]))
    L.append("PrivilegesRequired=%s" % (PRIV[h["PrivilegesRequired"]] if h["PrivilegesRequired"] < 4 else h["PrivilegesRequired"]))
    from .structs import HEADER_OPTIONS
    L.append("; header options: %s" % " ".join(bits(h["Options"], setup.get("header_option_names", HEADER_OPTIONS))))
    if E["Type"]:
        L += ["", "[Types]"] + ['Name: %s; Description: %s' % (q(t["Name"]), q(t["Description"])) for t in E["Type"]]
    if E["Component"]:
        L += ["", "[Components]"] + ['Name: %s; Description: %s; Types: %s' % (q(c["Name"]), q(c["Description"]), c["Types"])
                                     for c in E["Component"]]
    if E["Task"]:
        L += ["", "[Tasks]"] + ['Name: %s; Description: %s%s' % (q(t["Name"]), q(t["Description"]), _opt("Components", t["Components"]))
                                for t in E["Task"]]
    if E["Dir"]:
        L += ["", "[Dirs]"] + ['Name: %s%s; Flags: %s' % (q(d["DirName"]), _opt("Components", d["Components"]),
                                                          " ".join(bits(d["Options"], DIR_FLAGS))) for d in E["Dir"]]
    if E["File"]:
        L += ["", "[Files]"]
        for f in E["File"]:
            if f["LocationEntry"] < 0 and f["FileType"] == 1:
                L.append("; (uninstaller entry)"); continue
            L.append('Source: <location %d>; DestName: %s%s%s%s; Flags: %s' % (
                f["LocationEntry"], q(f["DestName"]), _opt("Components", f["Components"]), _opt("Tasks", f["Tasks"]),
                _opt("Check", f["Check"]), " ".join(bits(f["Options"], FILE_FLAGS))))
    if E["Icon"]:
        L += ["", "[Icons]"] + ['Name: %s; Filename: %s; Parameters: %s' % (q(i["IconName"]), q(i["Filename"]), q(i["Parameters"]))
                                for i in E["Icon"]]
    if E["Ini"]:
        L += ["", "[INI]"] + ['Filename: %s; Section: %s; Key: %s; String: %s' % (q(i["Filename"]), q(i["Section"]), q(i["Entry"]), q(i["Value"]))
                              for i in E["Ini"]]
    if E["Registry"]:
        L += ["", "[Registry]"]
        for r in E["Registry"]:
            L.append('Root: %s; Subkey: %s; ValueType: %s; ValueName: %s; ValueData: %s%s; Flags: %s' % (
                ROOTS.get(r["RootKey"], hex(r["RootKey"])), q(r["Subkey"]),
                REG_TYPES[r["Typ"]] if r["Typ"] < 7 else r["Typ"], q(r["ValueName"]), q(r["ValueData"]),
                _opt("Components", r["Components"]), " ".join(bits(r["Options"], REG_FLAGS))))
    for sec, key in (("InstallDelete", "InstallDelete"), ("UninstallDelete", "UninstallDelete")):
        if E[key]:
            L += ["", "[%s]" % sec] + ['Type: %s; Name: %s' % (DELETE_TYPES[d["DeleteType"]] if d["DeleteType"] < 3 else d["DeleteType"], q(d["Name"]))
                                       for d in E[key]]
    for sec, key in (("Run", "Run"), ("UninstallRun", "UninstallRun")):
        if E[key]:
            L += ["", "[%s]" % sec]
            for r in E[key]:
                fl = bits(r["Options"], RUN_FLAGS)
                if r["ShowCmd"] == 0: fl.append("runhidden")
                elif r["ShowCmd"] in (2, 6, 7): fl.append("runminimized")
                elif r["ShowCmd"] == 3: fl.append("runmaximized")
                fl.append(["waituntilterminated", "nowait", "waituntilidle"][r["Wait"]] if r["Wait"] < 3 else str(r["Wait"]))
                L.append('Filename: %s; Parameters: %s%s%s%s; Flags: %s' % (
                    q(r["Name"]), q(r["Parameters"]), _opt("WorkingDir", r["WorkingDir"]), _opt("Verb", r["Verb"]),
                    _opt("Description", r["Description"]), " ".join(fl)))
    L += ["", "[Code]", "; compiled Pascal Script: see code.ifps / code_disasm.txt", ""]
    return "\n".join(L)


RISKY_IMPORTS = {
    "EXEC": "can run programs", "EXECASORIGINALUSER": "can run programs", "SHELLEXEC": "can open files/URLs/programs",
    "SHELLEXECASORIGINALUSER": "can open files/URLs/programs", "CREATEOLEOBJECT": "COM automation (e.g. WScript.Shell)",
    "GETACTIVEOLEOBJECT": "COM automation", "DOWNLOADTEMPORARYFILE": "downloads from the internet",
    "CREATEDOWNLOADPAGE": "downloads from the internet", "SAVESTRINGTOFILE": "writes files",
    "SAVESTRINGSTOFILE": "writes files", "SAVESTRINGSTOUTF8FILE": "writes files", "FILECOPY": "copies files",
    "DELETEFILE": "deletes files", "DELTREE": "deletes directory trees", "RENAMEFILE": "renames files",
    "REGWRITESTRINGVALUE": "writes registry", "REGWRITEEXPANDSTRINGVALUE": "writes registry",
    "REGWRITEDWORDVALUE": "writes registry", "REGWRITEBINARYVALUE": "writes registry",
    "REGWRITEMULTISTRINGVALUE": "writes registry", "REGDELETEVALUE": "deletes registry values",
    "REGDELETEKEYINCLUDINGSUBKEYS": "deletes registry keys", "EXTRACTTEMPORARYFILE": "drops embedded files",
    "UNPINSHELLLINK": "shell links", "CREATESHELLLINK": "creates shortcuts",
    # functions added to Pascal Script by the Team V.R engine build
    "GETIPADDRESSES": "Team V.R extension: enumerates IP addresses", "GETIFTABLES": "Team V.R extension: enumerates network adapters",
    "INETADDR2ANSISTRING": "Team V.R extension: formats IP addresses",
}
PERSIST_KEYS = re.compile(r"\\(Run|RunOnce|RunServices|Winlogon|Image File Execution Options|AppInit_DLLs|Services|"
                          r"Policies|Environment|ShellServiceObjectDelayLoad|Explorer\\Shell Folders|Active Setup)\b", re.I)


def triage(setup, imports):
    E = setup["entries"]; notes = []
    for r in E["Run"]:
        fl = bits(r["Options"], RUN_FLAGS)
        when = "after install, only if the user leaves the checkbox ticked" if "postinstall" in fl else "AUTOMATICALLY during install"
        notes.append("[Run] %s runs %s%s%s" % (r["Name"], when, ", hidden window" if r["ShowCmd"] == 0 else "",
                                               (" with parameters " + q(r["Parameters"])) if r["Parameters"] else ""))
    for r in E["UninstallRun"]:
        notes.append("[UninstallRun] %s runs on uninstall" % r["Name"])
    for r in E["Registry"]:
        root = ROOTS.get(r["RootKey"], hex(r["RootKey"]))
        fl = bits(r["Options"], REG_FLAGS)
        tags = []
        if PERSIST_KEYS.search("\\" + r["Subkey"]): tags.append("sensitive key")
        if root == "HKLM": tags.append("machine-wide")
        if not any(f.startswith("unins") for f in fl): tags.append("NOT removed on uninstall")
        notes.append("[Registry] %s\\%s : %s = %s (%s)" % (root, r["Subkey"], r["ValueName"], r["ValueData"], ", ".join(tags) or "-"))
    for f in E["File"]:
        d = f["DestName"].lower()
        if re.match(r"\{(sys|syswow64|win|commonstartup|userstartup|startup)\}", d):
            notes.append("[Files] writes into a system/startup folder: %s" % f["DestName"])
        if d.startswith("{tmp}") and re.search(r"\.(exe|dll|cmd|bat|ps1|vbs|js)$", d):
            notes.append("[Files] drops %s to the temp folder (helper used during setup)" % f["DestName"])
    for d in E["InstallDelete"]:
        notes.append("[InstallDelete] deletes %s" % d["Name"])
    for imp in imports:
        base = imp.split(" ")[0].upper()
        if base in RISKY_IMPORTS:
            notes.append("[Code] imports %s - %s" % (imp, RISKY_IMPORTS[base]))
        elif imp.lower().startswith("dll:"):
            notes.append("[Code] calls native DLL function: %s" % imp)
    return notes
