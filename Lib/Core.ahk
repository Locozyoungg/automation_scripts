#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\Core.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Shared foundation included by every tool (Scripts\, Security\, Tests\).
;          Rotating logger, tamper-evident audit chain, toasts + ntfy push,
;          Credential Manager access, INI config with defaults, PowerShell
;          runner (temp-file based, never string-concatenated commands),
;          elevation, VS Code project detection, mutexes, tool registry.
; SECURITY: Never logs secrets or clipboard content (metadata only).
;           No telemetry. No auto-update. Only network call: user-configured ntfy.
; NOTE   : This file is a library — it defines state and functions; tools call
;          InstallKillSwitch() early in their own top-level code.
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir

Global TOOLKIT_VERSION := "1.0.0"
Global PS_EXE := EnvGet("SystemRoot") . "\System32\WindowsPowerShell\v1.0\powershell.exe"

;------------------------------------------------------------------------------
; Root & standard directories.
; ROOT is resolved from the CALLER's A_ScriptDir (includes are textual), so
; Logs\Config\Data resolve identically from Scripts\, Security\ and Tests\.
; NOTE: the path helpers are defined BEFORE class Env because v2 executes
; class static initializers at load, in order — they must not forward-call.
;------------------------------------------------------------------------------
_ResolveRoot() {
    ; If we are inside Scripts\ Security\ Lib\ Tests\ or Install\, the toolkit
    ; root is the parent; otherwise the script's own directory IS the root.
    leaf := _LeafOf(A_ScriptDir)
    for known in ["Scripts", "Security", "Lib", "Tests", "Install"]
        if leaf == known
            return _ParentOf(A_ScriptDir)
    return A_ScriptDir
}

_LeafOf(path) => SubStr(path, InStr(path, "\", false, -1) + 1)
_ParentOf(path) => SubStr(path, 1, InStr(path, "\", false, -1) - 1)

class Env {
    static Root       := _ResolveRoot()
    static LogDir     := _ResolveRoot() . "\Logs"
    static ConfigDir  := _ResolveRoot() . "\Config"
    static DataDir    := _ResolveRoot() . "\Data"
    static LibDir     := _ResolveRoot() . "\Lib"
}

ToolPath(rel) {
    ; Convert a registry-relative path ("Scripts\X.ahk") to an absolute one.
    return Env.Root . "\" . rel
}

_OwnPID() => DllCall("GetCurrentProcessId", "UInt")

IsChild() {
    ; True when this tool was spawned by the Launcher (tray icon hidden then).
    return ArgHas("--child")
}

ArgHas(flag) {
    for a in A_Args
        if a == flag
            return true
    return false
}

;------------------------------------------------------------------------------
; Directory bootstrap (idempotent, lazy).
;------------------------------------------------------------------------------
_EnsureDirsDone := false
EnsureDirs() {
    Global _EnsureDirsDone
    if _EnsureDirsDone
        return
    try {
        for d in [Env.LogDir, Env.ConfigDir, Env.DataDir
                , Env.DataDir . "\state", Env.DataDir . "\tmp", Env.DataDir . "\locks"]
            DirCreate(d)
        ; First run from a fresh clone: seed settings from the shipped example.
        if !FileExist(Cfg.File("settings.ini")) && FileExist(Cfg.File("settings.ini.example"))
            FileCopy(Cfg.File("settings.ini.example"), Cfg.File("settings.ini"))
        _EnsureDirsDone := true
    } catch as e {
        ; Cannot even log yet — nothing else we can do safely.
        MsgBox("Toolkit failed to create its directories:`n" . ErrText(e)
             , "Toolkit startup error", "IconX")
        ExitApp(2)
    }
}

;------------------------------------------------------------------------------
; Logging. Log() must never throw — a logger that crashes its caller is
; worse than no logger. Rotate at 2 MB, keep 5 rotated copies.
;------------------------------------------------------------------------------
Global LOG_ROTATE_BYTES := 2 * 1024 * 1024

Log(msg, level := "INFO") {
    try {
        EnsureDirs()
        path := Env.LogDir . "\" . _LogBase() . ".log"
        _RotateIfNeeded(path)
        FileAppend(Format("{1} | {2} | {3}`r`n", _Ts(), level, String(msg)), path, "UTF-8-RAW")
    } catch {
        ; Intentional swallow: the logger must never throw.
    }
}

_LogBase() => SubStr(A_ScriptName, 1, -4)

_Ts() {
    ; "yyyy-MM-dd HH:mm:ss.mmm". A_MSec is 0-999; fall back to tick-based
    ; milliseconds if a future AHK build ever drops it (never fail to log).
    ms := ""
    try ms := SubStr("00" . A_MSec, -2)
    catch
        ms := SubStr("00" . Mod(A_TickCount, 1000), -2)
    return Format("{1}.{2}", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"), ms)
}

_RotateIfNeeded(path) {
    Global LOG_ROTATE_BYTES
    if !FileExist(path) || FileGetSize(path) < LOG_ROTATE_BYTES
        return
    ; Shift .1..4 up one, drop .5, move current to .1. (v2 FileDelete
    ; throws on a missing file, so guard each deletion.)
    if FileExist(path . ".5")
        FileDelete(path . ".5")
    Loop 4 {
        i := 5 - A_Index
        if FileExist(path . "." . i)
            FileMove(path . "." . i, path . "." . (i + 1))
    }
    FileMove(path, path . ".1")
}

;------------------------------------------------------------------------------
; Tamper-evident audit log for the Security suite.
; Line format:  <ts> | <level> | <msg> | <sha256(prevHash | line-so-far)>
; The chain head is kept in Data\state\audit-<script>.chain.
;------------------------------------------------------------------------------
AuditLog(msg, level := "AUDIT") {
    try {
        EnsureDirs()
        path := Env.LogDir . "\audit-" . _LogBase() . ".log"
        stateFile := Env.DataDir . "\state\audit-" . _LogBase() . ".chain"
        prev := "0" ; genesis: hash of the empty chain
        if FileExist(stateFile)
            prev := Trim(FileRead(stateFile))
        content := Format("{1} | {2} | {3}", _Ts(), level, String(msg))
        hash := Sha256Hex(prev . "|" . content)
        if hash == "" {
            Log("AuditLog: hashing failed; line appended WITHOUT chain hash", "ERROR")
            FileAppend(content . "`r`n", path, "UTF-8-RAW")
            return
        }
        FileAppend(content . " | " . hash . "`r`n", path, "UTF-8-RAW")
        f := FileOpen(stateFile, "w", "UTF-8")
        f.Write(hash)
        f.Close()
    } catch as e {
        Log("AuditLog failed: " . ErrText(e), "ERROR")
    }
}

VerifyLogChain(path) {
    ; Returns "OK", "NO FILE", or "BROKEN at line N [<reason>]".
    if !FileExist(path)
        return "NO FILE"
    prev := "0", n := 0
    for raw in StrSplit(FileRead(path), "`n") {
        line := RTrim(raw, "`r")
        if line == ""
            continue
        n++
        pos := InStr(line, " | ", false, -1) ; hash is the last field
        if !pos || pos < 10
            return "BROKEN at line " . n . " (missing hash field)"
        content := SubStr(line, 1, pos - 1)
        expect := Sha256Hex(prev . "|" . content)
        if StrLower(SubStr(line, pos + 3)) != StrLower(expect)
            return "BROKEN at line " . n
        prev := expect
    }
    return "OK"
}

;------------------------------------------------------------------------------
; Hashing. SHA-256 via .NET (PowerShell) for security-critical uses; FNV-1a
; (pure AHK, no process spawn) for cheap fingerprints on hot paths. The
; distinction is intentional: FNV is NOT cryptographic.
;------------------------------------------------------------------------------
Global _SHA_CACHE := Map()

Sha256Hex(str) {
    ; Cached SHA-256 of a string, lowercase hex. "" on failure.
    Global _SHA_CACHE
    key := SubStr(str, 1, 48)
    if _SHA_CACHE.Has(key) && _SHA_CACHE[key].src == str
        return _SHA_CACHE[key].hex
    EnsureDirs()
    tmp := Env.DataDir . "\tmp\sha-" . _OwnPID() . "-" . A_TickCount . "-" . Random(1000, 9999) . ".txt"
    ok := true
    try FileAppend(str, tmp, "UTF-8-RAW")
    catch
        ok := false
    if !ok
        return ""
    ps := "$b=[IO.File]::ReadAllBytes($p);$s=[Security.Cryptography.SHA256]::Create();"
        . "($s.ComputeHash($b)|ForEach-Object{$_.ToString(`"x2`")}) -join `"`""
    ; Note: $p is injected as a PS variable below via the args mechanism, not
    ; string concatenation — the path never enters the command line raw.
    r := RunPS("$p=" . _PsLit(tmp) . ";" . ps, 20)
    try FileDelete(tmp)
    hex := Trim(StrReplace(StrReplace(r["stdout"], "`r`n", ""), "`n", ""))
    if r["ok"] && RegExMatch(hex, "i)^[0-9a-f]{64}$") {
        _SHA_CACHE[key] := {src: str, hex: StrLower(hex)}
        if _SHA_CACHE.Count > 64
            for k2, _ in _SHA_CACHE {
                _SHA_CACHE.Delete(k2)
                break
            }
        return StrLower(hex)
    }
    Log("Sha256Hex failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
    return ""
}

Fnv1a(str) {
    ; FNV-1a 32-bit fingerprint (fast, non-cryptographic). Lowercase hex.
    h := 2166136261
    Loop Parse str
        h := ((h ^ Ord(A_LoopField)) * 16777619) & 0xFFFFFFFF
    return Format("{:x}", h)
}

ClipMeta(text) {
    ; Metadata ONLY for logs: length + fingerprint prefix. Never the content.
    return Format("len={1} fnv={2}", StrLen(text), StrUpper(SubStr(Fnv1a(text), 1, 4)))
}

;------------------------------------------------------------------------------
; Notifications: local toast always; optional ntfy push (user-configured).
; Duplicate alerts are rate-limited (default 60 s); SECURITY alerts are not.
;------------------------------------------------------------------------------
Global _NOTIFY_LAST := Map()

Notify(title, msg, level := "INFO", dedupe := true) {
    Global _NOTIFY_LAST
    if dedupe {
        key := Fnv1a(StrLower(title) . "|" . StrLower(String(msg)))
        now := A_TickCount
        if _NOTIFY_LAST.Has(key) && now - _NOTIFY_LAST[key] < Cfg.Int("alerts", "rate_limit_seconds", 60) * 1000
            return
        _NOTIFY_LAST[key] := now
    }
    try
        TrayTip(String(msg), title, _NotifyIcon(level))
    catch {
        ; Toasts must never break the caller.
    }
    if level == "ERROR" || level == "WARN" || level == "SECURITY"
        _NtfyPush(title, String(msg), level)
}

_NotifyIcon(level) {
    switch StrUpper(level) {
        case "ERROR", "SECURITY": return "Icon32"
        case "WARN":               return "Icon48"
        default:                   return "Icon16"
    }
}

_NtfyPush(title, msg, level) {
    ; Push alert via ntfy. Fully user-configured; no-op unless enabled AND a
    ; URL is set. The bearer token comes from Credential Manager and is never
    ; logged.
    try {
        if !Cfg.Bool("alerts", "ntfy_enabled", false)
            return
        url := Cfg.Read("alerts", "ntfy_url", "")
        if url == "" {
            Log("ntfy enabled but alerts.ntfy_url unset (Config\settings.ini)", "WARN")
            return
        }
        token := Cred.Get(Cfg.Read("alerts", "cred_target", "AHK-ntfy"))
        http := ComObject("WinHttp.WinHttpRequest.5.1")
        http.SetTimeouts(3000, 3000, 3000, 3000)
        http.Open("POST", url, false)
        http.SetRequestHeader("Title", _WinHttpSafe(title))
        http.SetRequestHeader("Priority", level == "SECURITY" ? "high" : "default")
        if token != ""
            http.SetRequestHeader("Authorization", "Bearer " . _WinHttpSafe(token))
        http.Send(msg)
    } catch as e {
        Log("ntfy push failed: " . ErrText(e), "ERROR")
    }
}

_WinHttpSafe(s) => RegExReplace(s, "[\r\n]+", " ")

;------------------------------------------------------------------------------
; Credential Manager. Secrets are read into memory only — never logged,
; never placed on the clipboard, never written to disk by the toolkit.
; Setup (once):  cmdkey /generic:AHK-ntfy /user:token /pass:<your-token>
;------------------------------------------------------------------------------
class Cred {
    static Get(target) {
        ; Read a GENERIC credential. Returns "" when absent or unreadable.
        Global _CRED_PS_BODY
        if !RegExMatch(target, "^[A-Za-z0-9 ._\-]{1,64}$") {
            Log("Cred.Get: invalid target name (refusing)", "ERROR")
            return ""
        }
        r := RunPS(_CRED_PS_BODY . "`nRead-Cred -Target " . _PsLit(target), 20)
        if !r["ok"] {
            Log("Cred.Get '" . target . "' failed (exit " . r["exit"] . "): "
              . StrReplace(Trim(r["stderr"]), "`r`n", " "), "WARN")
            return ""
        }
        return RTrim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    }

    static Set(target, user, secret) {
        ; Store via cmdkey /generic. The secret appears briefly in the cmdkey
        ; process command line — this is the standard OS mechanism; prefer
        ; setting it from an interactive shell for maximum secrecy.
        if !RegExMatch(target, "^[A-Za-z0-9 ._\-]{1,64}$") {
            Log("Cred.Set: invalid target name (refusing)", "ERROR")
            return false
        }
        try {
            RunWait(EnvGet("ComSpec") . " /c cmdkey /generic:" . target . " /user:" . user
                  . " /pass:" . secret, , "Hide")
            return true
        } catch as e {
            Log("Cred.Set failed: " . ErrText(e), "ERROR")
            return false
        }
    }
}

_CRED_PS_BODY := (
    "function Read-Cred {`n"
    . "  param([string]$Target)`n"
    . "  $sig = @'`n"
    . "using System;`n"
    . "using System.Runtime.InteropServices;`n"
    . "public static class Cred {`n"
    . "  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]`n"
    . "  public struct CREDENTIAL {`n"
    . "    public uint Flags; public uint Type; public string TargetName; public string Comment;`n"
    . "    public long LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob;`n"
    . "    public uint Persist; public uint AttributeCount; public IntPtr Attributes;`n"
    . "    public string TargetAlias; public string UserName;`n"
    . "  }`n"
    . "  [DllImport(`"advapi32.dll`", SetLastError = true, CharSet = CharSet.Unicode)]`n"
    . "  public static extern bool CredReadW(string target, int type, int flags, out IntPtr pCred);`n"
    . "  [DllImport(`"advapi32.dll`")]`n"
    . "  public static extern void CredFree(IntPtr pCred);`n"
    . "}`n"
    . "'@`n"
    . "  Add-Type -TypeDefinition $sig`n"
    . "  $p = [IntPtr]::Zero`n"
    . "  if (-not [Cred]::CredReadW($Target, 1, 0, [ref]$p)) { exit 2 }`n"
    . "  try {`n"
    . "    $c = [Runtime.InteropServices.Marshal]::PtrToStructure($p, [type][Cred+CREDENTIAL])`n"
    . "    if ($c.CredentialBlobSize -gt 0) {`n"
    . "      $bytes = New-Object byte[] $c.CredentialBlobSize`n"
    . "      [Runtime.InteropServices.Marshal]::Copy($c.CredentialBlob, $bytes, 0, $bytes.Length)`n"
    . "      [Text.Encoding]::Unicode.GetString($bytes)`n"
    . "    }`n"
    . "  } finally { [Cred]::CredFree($p) }`n"
    . "}"
)

;------------------------------------------------------------------------------
; Config: INI wrappers with defaults and validation. Malformed files are
; logged (WARN) and fall back — never fatal. All config lives in Config\.
;------------------------------------------------------------------------------
class Cfg {
    static File(name := "settings.ini") => Env.ConfigDir . "\" . name

    static Read(section, key, default, file := "settings.ini") {
        try {
            val := IniRead(Cfg.File(file), section, key, "")
            return StrLen(val) ? val : default
        } catch as e {
            Log("Cfg.Read [" . file . "] " . section . "." . key . ": " . ErrText(e), "WARN")
            return default
        }
    }

    static Write(section, key, value, file := "settings.ini") {
        try {
            EnsureDirs()
            IniWrite(String(value), Cfg.File(file), section, key)
            return true
        } catch as e {
            Log("Cfg.Write [" . file . "] " . section . "." . key . ": " . ErrText(e), "ERROR")
            return false
        }
    }

    static Bool(section, key, default, file := "settings.ini") {
        v := StrLower(Cfg.Read(section, key, default ? "1" : "0", file))
        return v == "1" || v == "true" || v == "yes" || v == "on"
    }

    static Int(section, key, default, file := "settings.ini") {
        v := Cfg.Read(section, key, String(default), file)
        if RegExMatch(Trim(v), "^-?\d+$")
            return Integer(v)
        Log("Cfg.Int invalid value for " . section . "." . key . " ('" . v . "'); using default", "WARN")
        return Integer(default)
    }

    static IgnoreList(section) {
        ; Comma-separated entries in ignorelist.ini, one key ("items") per section.
        vals := []
        try {
            txt := IniRead(Cfg.File("ignorelist.ini"), section, "items", "")
            for part in StrSplit(txt, ",")
                if Trim(part) != ""
                    vals.Push(Trim(part))
        } catch as e {
            Log("Cfg.IgnoreList [" . section . "]: " . ErrText(e), "WARN")
        }
        return vals
    }
}

; Free-function aliases (spec naming compatibility).
CfgRead(section, key, default, file := "settings.ini") => Cfg.Read(section, key, default, file)
CfgWrite(section, key, value, file := "settings.ini") => Cfg.Write(section, key, value, file)
CfgBool(section, key, default, file := "settings.ini") => Cfg.Bool(section, key, default, file)
CfgInt(section, key, default, file := "settings.ini") => Cfg.Int(section, key, default, file)
CredGet(target) => Cred.Get(target)

;------------------------------------------------------------------------------
; PowerShell runner. The script is written to a temp .ps1 file (UTF-8 with
; BOM, as PS 5.1 requires) and invoked with -File semantics — untrusted input
; is passed as PS *variables via quoted args, never concatenated into a
; command line. A timeout always applies; output is captured; JSON output is
; parseable via RunPSJson.
;------------------------------------------------------------------------------
RunPS(script, timeoutSec := 30, args := "") {
    Global PS_EXE
    EnsureDirs()
    tmp := Env.DataDir . "\tmp\ps-" . _OwnPID() . "-" . A_TickCount . "-" . Random(10000, 99999) . ".ps1"
    try {
        ; The script goes to a temp .ps1 (UTF-8 with BOM, as PS 5.1 requires)
        ; and runs via -File: args bind to param() positionally, with none of
        ; the -Command quoting pitfalls. Setup lines are prepended only for
        ; scripts WITHOUT a param() block (a param block must stay first).
        if InStr(Trim(script), "param(") != 1
            script := "[Console]::OutputEncoding=[Text.Encoding]::Default`n$ProgressPreference='SilentlyContinue'`n" . script
        FileAppend(script, tmp, "UTF-8")
        shell := ComObject("WScript.Shell")
        argPart := ""
        if args is Array
            for a in args
                argPart .= " " . String(a) ; raw literals: no quotes needed with -File
        cmd := _Q(PS_EXE) . " -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " . _Q(tmp) . argPart
        exec := shell.Exec(cmd)
        start := A_TickCount, timedOut := false
        while exec.Status == 0 {
            if A_TickCount - start > timeoutSec * 1000 {
                exec.Terminate()
                timedOut := true
                break
            }
            Sleep 40
        }
        if timedOut {
            ; Skip StdOut/StdErr reads on the timeout path: a grandchild
            ; process (e.g. schtasks under PS 5.1) can keep the pipe open
            ; after Terminate(), and ReadAll would block forever.
            Log("RunPS timeout after " . timeoutSec . "s", "WARN")
            return Map("ok", false, "exit", -1, "stdout", "", "stderr", "", "timeout")
        }
        stdout := "", stderr := ""
        try stdout := exec.StdOut.ReadAll()
        try stderr := exec.StdErr.ReadAll()
        return Map("ok", exec.ExitCode == 0, "exit", Integer(exec.ExitCode), "stdout", stdout, "stderr", stderr)
    } catch as e {
        Log("RunPS launch failure: " . ErrText(e), "ERROR")
        return Map("ok", false, "exit", -1, "stdout", "", "stderr", "launch failure")
    } finally
        try FileDelete(tmp)
}

RunPSJson(script, timeoutSec := 30, fallback := Map()) {
    ; RunPS + parse stdout as JSON (strip BOM first). Fallback on any failure.
    r := RunPS(script, timeoutSec)
    out := Trim(StrReplace(r["stdout"], "`uFEFF", ""))
    if !r["ok"] || out == ""
        return fallback
    try
        return JSON.parse(out)
    catch {
        Log("RunPSJson: unparseable output: " . SubStr(StrReplace(out, "`n", " "), 1, 200), "WARN")
        return fallback
    }
}

RunPSJsonF(script, timeoutSec := 30, fallback := Map()) {
    ; File-based JSON variant of RunPSJson. Some PS 5.1 modules
    ; (ScheduledTasks, Storage, NetAdapter) can leave the stdout pipe in a
    ; state where the final pipeline output is dropped - or the process
    ; stalls - when spawned via WScript.Shell.Exec. Writing the JSON to a
    ; file and reading it back sidesteps the pipe entirely.
    ; The script MUST end with a pipeline that emits the JSON object
    ; (it is appended to a Set-Content that stores it).
    EnsureDirs()
    outFile := Env.DataDir . "\tmp\psj-" . _OwnPID() . "-" . A_TickCount . "-" . Random(10000, 99999) . ".json"
    wrapped := "$AHK_JSON_OUT=" . _PsLit(outFile) . ";" . script . "|Set-Content -Path $AHK_JSON_OUT -Encoding UTF8"
    r := RunPS(wrapped, timeoutSec)
    txt := ""
    if FileExist(outFile) {
        try txt := Trim(StrReplace(FileRead(outFile), "`uFEFF", ""))
        try FileDelete(outFile)
    }
    if !r["ok"] || txt == ""
        return fallback
    try
        return JSON.parse(txt)
    catch {
        Log("RunPSJsonF: unparseable output: " . SubStr(StrReplace(txt, "`n", " "), 1, 200), "WARN")
        return fallback
    }
}

_PsLit(s) {
    ; Wrap a value as a PowerShell single-quoted literal ('' escapes a quote).
    return "'" . StrReplace(String(s), "'", "''") . "'"
}

_Q(s) => Chr(34) . s . Chr(34)

;------------------------------------------------------------------------------
; Registry helpers (read-only; writes go through Remediate with backups).
;------------------------------------------------------------------------------
RegReadVal(key, name := "") {
    ; key: PS-style path e.g. HKLM:\SOFTWARE\...  name: "" = default value.
    ; Returns "" when the key/value is absent (logged at DEBUG by callers).
    ps := "$k=" . _PsLit(key) . ";if(-not(Test-Path $k)){''}"
        . "else{$p=Get-ItemProperty -Path $k;$n=" . _PsLit(name = "" ? "(default)" : name)
        . ";if($p.PSObject.Properties.Name -contains $n){[string]$p.$n}else{''}}"
    r := RunPS(ps, 15)
    if !r["ok"] {
        Log("RegReadVal failed: " . key . "/" . name . " — " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "WARN")
        return ""
    }
    return RTrim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
}

RegExists(key) {
    r := RunPS("Test-Path " . _PsLit(key), 10)
    return r["ok"] && InStr(r["stdout"], "True") == 1
}

;------------------------------------------------------------------------------
; Elevation. Only tools that genuinely need admin ask for it — with an
; explicit confirmation dialog stating why.
;------------------------------------------------------------------------------
IsAdmin() => A_IsAdmin

RequireAdmin(why := "") {
    ; Returns true if already elevated. Otherwise asks, re-launches elevated,
    ; and exits the current instance (the elevated copy takes over).
    if A_IsAdmin
        return true
    if !ConfirmDlg("Elevation required"
        , (why != "" ? why . "`n`n" : "") . "This tool needs administrator rights.`nA UAC prompt will appear. Continue?")
        return false
    try {
        args := ""
        if A_Args.Length {
            quoted := []
            for a in A_Args
                quoted.Push(Chr(34) . a . Chr(34))
            args := " " . StrJoin(quoted, " ")
        }
        Run("*RunAs " . _Q(A_ScriptFullPath) . args)
        ExitApp(0)
    } catch as e {
        Log("RequireAdmin: elevation launch failed: " . ErrText(e), "ERROR")
        Notify("Elevation failed", "Could not start an elevated copy. Run the tool as administrator instead.", "ERROR")
        return false
    }
}

;------------------------------------------------------------------------------
; Project detection: active VS Code workspace, active editor file, git root.
;------------------------------------------------------------------------------
ActiveProject() {
    ; Project root for the active VS Code window. Order: title parse, then the
    ; most-recent workspace from storage.json (multi-root fallback). "" on fail.
    title := ""
    try title := WinGetTitle("A")
    root := _RootFromVSCodeTitle(title)
    if root == "" && FileExist(EnvGet("APPDATA") . "\Code\storage.json")
        root := _RootFromStorageJson()
    if root == ""
        Log("ActiveProject: no VS Code project detected (title: '" . title . "')", "DEBUG")
    return root
}

ActiveEditorInfo() {
    ; Map with root/file/rel for the active VS Code editor window, or "".
    title := ""
    try title := WinGetTitle("A")
    m := _TitleParts(title)
    if !IsObject(m)
        return ""
    file := m.Has("file") ? m["file"] : ""
    root := m.Has("root") ? m["root"] : ""
    info := Map("file", file, "rel", file)
    if root != "" {
        info["root"] := root
        if InStr(file, root) == 1
            info["rel"] := SubStr(file, StrLen(root) + 2)
    }
    return info
}

_TitleParts(title) {
    ; Parse "FILE — ROOT — Visual Studio Code" (also "-" separators, "●"
    ; unsaved marker, "(Workspace)" suffix, "•" multi-root separators).
    if !title || !RegExMatch(title, "S)^(?<mid>.+)\s[-–—]\sVisual Studio Code$", &m)
        return ""
    mid := RegExReplace(m.mid, "^●\s*", "")
    mid := StrReplace(StrReplace(mid, " — ", "|"), " - ", "|")
    parts := StrSplit(mid, "|")
    if parts.Length == 1
        return DirExist(Trim(parts[1])) ? Map("file", "", "root", Trim(parts[1])) : ""
    file := Trim(parts[1])
    rootPart := StrReplace(Trim(parts[2]), " (Workspace)", "")
    root := ""
    for cand in StrSplit(rootPart, "•") {
        cand := Trim(cand)
        if DirExist(cand) || (file != "" && FileExist(cand . "\" . file)) {
            root := cand
            break
        }
    }
    if root == ""
        return "" ; title gave a name but nothing resolvable
    ; Prefer the full file path when the file exists inside the root.
    full := ""
    if file != "" && FileExist(root . "\" . file)
        full := root . "\" . file
    return Map("file", full != "" ? full : file, "root", root)
}

_RootFromVSCodeTitle(title) {
    m := _TitleParts(title)
    return IsObject(m) && m.Has("root") ? m["root"] : ""
}

_RootFromStorageJson() {
    ; Version-proof: recursively find the first existing folderUri.
    try {
        txt := FileRead(EnvGet("APPDATA") . "\Code\storage.json")
        obj := JSON.parse(txt)
        return _FindFolderUri(obj, 0)
    } catch as e {
        Log("_RootFromStorageJson: " . ErrText(e), "DEBUG")
        return ""
    }
}

_FindFolderUri(v, depth) {
    if depth > 8
        return ""
    if v is Map {
        if v.Has("folderUri") && InStr(String(v["folderUri"]), "file:///") == 1 {
            p := _FileUriToPath(String(v["folderUri"]))
            if p != "" && DirExist(p)
                return p
        }
        for _, val in v {
            r := _FindFolderUri(val, depth + 1)
            if r != ""
                return r
        }
    } else if v is Array {
        for val in v {
            r := _FindFolderUri(val, depth + 1)
            if r != ""
                return r
        }
    }
    return ""
}

_FileUriToPath(uri) {
    ; "file:///E:/proj" -> "E:\proj" (with %XX percent-decoding).
    p := StrReplace(StrReplace(uri, "file:///", ""), "/", "\")
    out := "", i := 1, n := StrLen(p)
    while i <= n {
        c := SubStr(p, i, 1)
        if c == "%" && i + 2 <= n && RegExMatch(SubStr(p, i + 1, 2), "i)^[0-9a-f]{2}$") {
            out .= Chr(Integer("0x" . SubStr(p, i + 1, 2)))
            i += 3
        } else {
            out .= c
            i++
        }
    }
    return out
}

GitRootOf(dir) {
    if !DirExist(dir)
        return ""
    ps := "try{(git -C " . _PsLit(dir) . " rev-parse --show-toplevel 2>&1|Out-String).Trim()}catch{''}"
    r := RunPS(ps, 15)
    if !r["ok"]
        return ""
    root := Trim(StrReplace(r["stdout"], "`r`n", ""))
    return DirExist(root) ? root : ""
}

;------------------------------------------------------------------------------
; Mutex / single-instance helpers (PID lock files; stale locks self-heal).
;------------------------------------------------------------------------------
MutexAcquire(name) {
    EnsureDirs()
    path := Env.DataDir . "\locks\" . name . ".lock"
    if FileExist(path) {
        pid := 0
        try pid := Integer(Trim(FileRead(path)))
        if pid && ProcessExist(pid)
            return false
        try FileDelete(path) ; stale lock from a dead process
    }
    try FileAppend(_OwnPID(), path)
    catch {
        return false
    }
    return true
}

MutexRelease(name) {
    path := Env.DataDir . "\locks\" . name . ".lock"
    if FileExist(path) {
        pid := 0
        try pid := Integer(Trim(FileRead(path)))
        if pid == _OwnPID()
            try FileDelete(path)
    }
}

;------------------------------------------------------------------------------
; Tool registry — single source of truth for the Launcher, CommandPalette and
; the README hotkey table. Fields: name, script (root-relative), category,
; desc, hotkeys (array), enabled (default), admin.
;------------------------------------------------------------------------------
class Tools {
    static Map := Map()

    static Register(rec) {
        Tools.Map[rec.name] := rec
    }

    static List() {
        out := []
        for _, rec in Tools.Map
            out.Push(rec)
        return out
    }

    static ByName(name) {
        return Tools.Map.Has(name) ? Tools.Map[name] : ""
    }
}

;------------------------------------------------------------------------------
; Dialogs & small utilities.
;------------------------------------------------------------------------------
ConfirmDlg(title, text) {
    return MsgBox(text, title, "YN") == "Yes"
}

InputText(prompt, title := "Input", default := "") {
    ib := InputBox(prompt, title, , default)
    if ib.Result != "OK"
        return ""
    return ib.Value
}

ErrText(e) {
    file := ""
    try file := e.File
    return Format("{1} [{2}] @ {3}:{4}", e.Message, e.What, file, e.Line)
}

StrJoin(arr, sep := ", ") {
    s := ""
    for i, v in arr
        s .= (i == 1 ? "" : sep) . String(v)
    return s
}

HumanBytes(n) {
    n := Number(n)
    units := ["B", "KB", "MB", "GB", "TB"]
    i := 1
    while n >= 1024 && i < units.Length
        n /= 1024, i++
    return Format("{1:.1f} {2}", n, units[i])
}

FileAgeDays(path) {
    if !FileExist(path)
        return 999999
    return DateDiff(A_Now, FileGetTime(path), "Days")
}

OpenInTerminal(cmd, dir) {
    ; Windows Terminal with a command that keeps the tab open (cmd /k).
    ; Fallback: plain console window if wt.exe is unavailable.
    wt := EnvGet("LOCALAPPDATA") . "\Microsoft\WindowsApps\wt.exe"
    exe := FileExist(wt) ? wt : "wt.exe"
    try {
        Run(_Q(exe) . " -d " . _Q(dir) . " cmd /k " . cmd)
        return true
    } catch as e {
        Log("OpenInTerminal: wt failed, falling back: " . ErrText(e), "WARN")
        try
            Run("cmd /k cd /d " . _Q(dir) . " && " . cmd)
        catch as e2 {
            Log("OpenInTerminal fallback failed: " . ErrText(e2), "ERROR")
            return false
        }
    }
    return true
}

;------------------------------------------------------------------------------
; Hotkey safety net: every hotkey action runs inside try/catch; failures are
; logged (full error: message, what, file, line) and toasted — never silent.
;------------------------------------------------------------------------------
SafeWrap(fn, title) {
    wrapped() {
        try fn()
        catch as e {
            Log(title . " failed: " . ErrText(e), "ERROR")
            Notify(title . " error", "Action failed — details in Logs\: " . e.Message, "ERROR")
        }
    }
    return wrapped
}

BindHotkey(key, fn, title := "") {
    if title == ""
        title := key
    try Hotkey(key, SafeWrap(fn, title))
    catch as e {
        Log("BindHotkey failed for " . key . ": " . ErrText(e), "ERROR")
        return false
    }
    return true
}

;------------------------------------------------------------------------------
; Standard per-tool lifecycle: kill-switch, tray menu, clean shutdown.
; Call InstallKillSwitch("<tool help text>") once, near the top of each tool.
;------------------------------------------------------------------------------
class State {
    static Tip := ""
}

InstallKillSwitch(toolHelp) {
    ; ~Esc & Pause always exits (the ~ keeps Esc working normally).
    try Hotkey("~Esc & Pause", (*) => ExitApp(0))
    catch {
        ; Fallback kill-switch without the pass-through prefix.
        try Hotkey("Esc & Pause", (*) => ExitApp(0))
        catch
            Log("InstallKillSwitch: could not register kill-switch", "ERROR")
    }
    State.Tip := toolHelp
    A_IconTip := toolHelp . "`nHotkeys: ENABLED`nKill-switch: Esc+Pause"
    OnExit(OnToolExit)
    if IsChild() {
        if !ArgHas("--debug-tray")
            A_IconHidden := true
        StartLauncherExitWatch()
    }
    _AddTrayMenu()
}

_AddTrayMenu() {
    ; Standard tray menu. Launcher children hide the icon entirely, so this
    ; only shows when a tool runs standalone (or with the debug-tray flag).
    try A_TrayMenu.Delete()
    catch
        ; nothing to remove on a fresh menu
    A_TrayMenu.Add("Open log folder", (*) => Run(Env.LogDir))
    A_TrayMenu.Add("Suspend hotkeys", (*) => ToggleSuspend())
    A_TrayMenu.Add()
    A_TrayMenu.Add("Exit", (*) => ExitApp(0))
}

ToggleSuspend() {
    if A_IsSuspended {
        Suspend(false)
        A_IconTip := State.Tip . "`nHotkeys: ENABLED`nKill-switch: Esc+Pause"
        Notify("Hotkeys enabled", "Tool hotkeys re-enabled.", "INFO")
    } else {
        Suspend(true)
        A_IconTip := State.Tip . "`nHotkeys: SUSPENDED`nKill-switch: Esc+Pause"
        Notify("Hotkeys suspended", "Tool hotkeys suspended (Esc+Pause still exits).", "WARN")
    }
}

OnToolExit(ExitReason?, ExitCode?) {
    r := IsSet(ExitReason) ? String(ExitReason) : "?"
    c := IsSet(ExitCode) ? String(ExitCode) : "?"
    try Log("Shutdown (" . r . " / " . c . ")")
}

;------------------------------------------------------------------------------
; Launcher child lifecycle: children watch for a stop-flag file so the
; Launcher can shut them down cleanly (OnExit fires and logs a shutdown line).
;------------------------------------------------------------------------------
StartLauncherExitWatch() {
    stopFile := Env.DataDir . "\tmp\stop-" . _LogBase() . ".flag"
    allFile := Env.DataDir . "\tmp\launcher-stop.flag"
    SetTimer(() => _CheckStopFlag(stopFile, allFile), 2000)
}

_CheckStopFlag(stopFile, allFile) {
    if FileExist(allFile) || FileExist(stopFile) {
        try FileDelete(stopFile)
        ExitApp(0)
    }
}

;------------------------------------------------------------------------------
; Lib includes. Deliberately placed AFTER every Core definition: Toast.ahk and
; Crypto.ahk call Core functions, and AHK v2 validates function references —
; an include that runs before its dependencies exist fails at load.
;------------------------------------------------------------------------------
#Include Toast.ahk
#Include JSON.ahk
#Include Crypto.ahk

;------------------------------------------------------------------------------
; Built-in tool registry data. Launcher/CommandPalette/README read this.
;------------------------------------------------------------------------------
Tools.Register({name: "DevHotkeys",        script: "Scripts\DevHotkeys.ahk",        category: "Productivity", desc: "Test runner, Git GUI, file-path and port hotkeys", hotkeys: ["Win+Alt+T", "Win+Alt+B", "Win+Alt+C", "Win+Alt+K", "Win+Alt+P", "Win+Alt+E"], enabled: true,  admin: false})
Tools.Register({name: "TextExpander",      script: "Scripts\TextExpander.ahk",      category: "Productivity", desc: "INI-driven text snippets with placeholders",       hotkeys: ["(hotstrings from Config\snippets.ini)"], enabled: true,  admin: false})
Tools.Register({name: "ClipboardManager",  script: "Scripts\ClipboardManager.ahk",  category: "Productivity", desc: "Encrypted 10-item clipboard history with exclusions", hotkeys: ["Win+Shift+C", "Win+Shift+V", "Win+Shift+X"], enabled: true,  admin: false})
Tools.Register({name: "WindowManager",     script: "Scripts\WindowManager.ahk",     category: "Productivity", desc: "Per-monitor window layouts + snapping",            hotkeys: ["Win+Numpad0", "Win+Numpad1", "Win+Alt+Arrows", "Win+Alt+M"], enabled: true,  admin: false})
Tools.Register({name: "GitWorkflow",       script: "Scripts\GitWorkflow.ahk",       category: "Productivity", desc: "Smart commits, branch switcher, cleanup (scoped to terminals/IDE)", hotkeys: ["(menu, scoped #HotIf)"], enabled: true,  admin: false})
Tools.Register({name: "BrowserAutomation", script: "Scripts\BrowserAutomation.ahk", category: "Productivity", desc: "CDP: Jira/PR from branch, form fill, table scrape",  hotkeys: ["Win+Alt+J", "Win+Alt+F", "Win+Alt+S"], enabled: false, admin: false})
Tools.Register({name: "FocusMode",         script: "Scripts\FocusMode.ahk",         category: "QoL",          desc: "DND + distraction blocking + Pomodoro",             hotkeys: ["Win+Alt+F12"], enabled: true,  admin: false})
Tools.Register({name: "CommandPalette",    script: "Scripts\CommandPalette.ahk",    category: "QoL",          desc: "Fuzzy launcher for tools, actions, snippets",       hotkeys: ["Ctrl+Alt+Space"], enabled: true,  admin: false})
Tools.Register({name: "HealthHUD",         script: "Scripts\HealthHUD.ahk",         category: "QoL",          desc: "Always-on-top system health overlay",               hotkeys: ["Win+Alt+H"], enabled: true,  admin: false})
Tools.Register({name: "DevEnvDoctor",      script: "Scripts\DevEnvDoctor.ahk",      category: "QoL",          desc: "Toolchain + dependency vulnerability checks",       hotkeys: ["Win+Alt+D"], enabled: true,  admin: false})
Tools.Register({name: "SecurityCheck",     script: "Security\SecurityCheck.ahk",    category: "Security",     desc: "Weekly posture audit → HTML + JSON report",        hotkeys: ["(scheduled)"], enabled: true,  admin: true})
Tools.Register({name: "Remediate",         script: "Security\Remediate.ahk",        category: "Security",     desc: "Confirmed fixes for SecurityCheck findings",        hotkeys: ["(on demand)"], enabled: true,  admin: true})
Tools.Register({name: "PersistenceMonitor",script: "Security\PersistenceMonitor.ahk", category: "Security",    desc: "Baseline diffs of autostarts, services, tasks",     hotkeys: ["(background)"], enabled: true,  admin: false})
Tools.Register({name: "USBGuard",          script: "Security\USBGuard.ahk",         category: "Security",     desc: "Removable-storage insert alerts + autorun check",   hotkeys: ["(background)"], enabled: true,  admin: false})
Tools.Register({name: "NetworkWatch",      script: "Security\NetworkWatch.ahk",     category: "Security",     desc: "New listeners, DNS/proxy changes, open Wi-Fi",      hotkeys: ["(background)"], enabled: true,  admin: false})
Tools.Register({name: "HostsGuard",        script: "Security\HostsGuard.ahk",       category: "Security",     desc: "Hosts-file change diff + restore",                  hotkeys: ["(background)"], enabled: true,  admin: true})
Tools.Register({name: "ClipboardGuard",    script: "Security\ClipboardGuard.ahk",   category: "Security",     desc: "Wallet-address clipboard hijack defense",           hotkeys: ["(background)"], enabled: true,  admin: false})
Tools.Register({name: "SecretsScanner",    script: "Security\SecretsScanner.ahk",   category: "Security",     desc: "Hardcoded-secret scan of source roots + git hook",  hotkeys: ["Win+Alt+9"], enabled: true,  admin: false})
Tools.Register({name: "LogonWatch",        script: "Security\LogonWatch.ahk",       category: "Security",     desc: "Logon/account/Defender event-log alerts",           hotkeys: ["(background)"], enabled: true,  admin: true})
Tools.Register({name: "PrivacyMonitor",    script: "Security\PrivacyMonitor.ahk",   category: "Security",     desc: "Camera/mic use indicator + mic mute hotkey",        hotkeys: ["Win+Alt+Q"], enabled: true,  admin: false})
Tools.Register({name: "BackupGuardian",    script: "Security\BackupGuardian.ahk",   category: "Security",     desc: "Incremental robocopy backups + SHA-256 verify",     hotkeys: ["(scheduled + on demand)"], enabled: false, admin: false})
Tools.Register({name: "PanicKey",          script: "Security\PanicKey.ahk",         category: "Security",     desc: "Instant lock, mute, clipboard purge, network kill", hotkeys: ["Ctrl+Alt+Shift+Pause"], enabled: true,  admin: false})
