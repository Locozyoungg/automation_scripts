#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\HostsGuard.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Watches C:\Windows\System32\drivers\etc\hosts for changes (30 s).
;          On first run it snapshots the file to Config\baseline\hosts.bak +
;          hosts.sha256. A change raises a SECURITY alert + audit entry and
;          offers to restore the baseline (restore = explicit confirm + UAC,
;          current file is backed up first to Data\baselines).
; USAGE  : Launcher child (default) or standalone.
;          --selftest : hashing + baseline helpers on temp copies only.
; SECURITY: Read-only by default. Restore only on explicit confirmation.
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
#Include ..\Lib\Core.ahk

Pass := 0
Fail := 0
Out(msg) {
    try FileAppend(msg . "`n", "*")
    Log(msg, "TEST")
}
Check(name, cond, detail := "") {
    Global Pass, Fail
    if cond {
        Pass++
        Out("PASS | " . name)
    } else {
        Fail++
        Out("FAIL | " . name . (detail != "" ? " | " . detail : ""))
    }
}

if ArgHas("--selftest") {
    EnsureDirs()
    hosts := _HG_HostsFile()
    Check("hosts file readable + hashable", FileExist(hosts) && StrLen(Sha256Hex(FileRead(hosts))) == 64)
    fx := Env.DataDir . "\tmp\hg-fixture"
    if DirExist(fx)
        DirDelete(fx, true)
    DirCreate(fx)
    FileAppend("127.0.0.1 localhost`n", fx . "\hosts")
    Check("baseline create writes bak + hash", _HG_MakeBaseline(fx . "\hosts", fx . "\hosts.bak", fx . "\hosts.sha256"))
    Check("baseline verify: clean passes", _HG_Verify(fx . "\hosts", fx . "\hosts.bak", fx . "\hosts.sha256"))
    FileAppend("1.2.3.4 evil.example`n", fx . "\hosts")
    Check("baseline verify: tamper detected", !_HG_Verify(fx . "\hosts", fx . "\hosts.bak", fx . "\hosts.sha256"))
    DirDelete(fx, true)
    Check("change detection on same content", !_HG_Changed(Sha256Hex("abc"), Sha256Hex("abc")))
    Check("change detection on diff content", _HG_Changed(Sha256Hex("abc"), Sha256Hex("abd")))
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("HostsGuard`nWatches the hosts file (30 s) + optional restore.`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Baseline helpers (explicit paths - testable without touching the real file)
;------------------------------------------------------------------------------
_HG_HostsFile() => EnvGet("SystemRoot") . "\System32\drivers\etc\hosts"
_HG_BakFile() => Env.ConfigDir . "\baseline\hosts.bak"
_HG_HashFile() => Env.ConfigDir . "\baseline\hosts.sha256"

_HG_MakeBaseline(hostsPath, bakPath, hashPath) {
    try {
        FileCopy(hostsPath, bakPath, true)
        FileAppend(Sha256Hex(FileRead(hostsPath)), hashPath)
        return true
    } catch as e {
        Log("HostsGuard: baseline failed: " . ErrText(e), "ERROR")
        return false
    }
}

_HG_Verify(hostsPath, bakPath, hashPath) {
    if !FileExist(bakPath) || !FileExist(hashPath) || !FileExist(hostsPath)
        return false
    return Sha256Hex(FileRead(hostsPath)) == Trim(FileRead(hashPath))
}

_HG_Changed(prevHash, curHash) {
    return prevHash != "" && curHash != "" && prevHash != curHash
}

_HG_LastHashFile() => Env.DataDir . "\state\hostsguard.json"

_HG_ReadLast() {
    try {
        obj := JSON.parse(FileRead(_HG_LastHashFile()))
        if obj.Has("hash")
            return String(obj["hash"])
    } catch {
        ; first run
    }
    return ""
}

_HG_WriteLast(hash) {
    try FileAppend(JSON.stringify(Map("hash", hash)), _HG_LastHashFile())
}

_HG_Restore() {
    ; Current (tampered) file is preserved first, then the baseline is restored.
    backup := Env.DataDir . "\baselines\hosts-" . FormatTime(A_Now, "yyyyMMdd-HHmmss") . ".bak"
    try FileCopy(_HG_HostsFile(), backup, true)
    if !RequireAdmin("Restoring C:\Windows\System32\drivers\etc\hosts requires administrator rights.")
        return
    ok := false
    try {
        FileCopy(_HG_BakFile(), _HG_HostsFile(), true)
        ok := _HG_Verify(_HG_HostsFile(), _HG_BakFile(), _HG_HashFile())
    } catch as e {
        Log("HostsGuard: restore failed: " . ErrText(e), "ERROR")
    }
    AuditLog("HostsGuard: restore from baseline - " . (ok ? "ok (verified)" : "FAILED"))
    Notify("HostsGuard", ok ? "Hosts file restored from baseline and verified." : "Restore failed - see Logs\audit-HostsGuard.log.", ok ? "INFO" : "ERROR")
}

_HG_Tick() {
    hosts := _HG_HostsFile()
    if !FileExist(hosts)
        return
    cur := Sha256Hex(FileRead(hosts))
    if cur == ""
        return
    Global _HG_Last
    if _HG_Changed(_HG_Last, cur) {
        Log("HostsGuard: hosts file changed (hash " . SubStr(_HG_Last, 1, 12) . " -> " . SubStr(cur, 1, 12) . ")", "WARN")
        Notify("Hosts file changed", "Something modified the hosts file. Restore the baseline?", "SECURITY")
        AuditLog("HostsGuard: hosts file changed - " . SubStr(_HG_Last, 1, 12) . " -> " . SubStr(cur, 1, 12))
        if ConfirmDlg("HostsGuard", "The hosts file differs from the baseline.`n`nRestore it from Config\baseline\hosts.bak?")
            _HG_Restore()
        _HG_Last := Sha256Hex(FileRead(hosts))
        _HG_WriteLast(_HG_Last)
    }
}

Global _HG_Last := _HG_ReadLast()
if _HG_Last == "" && !FileExist(_HG_BakFile())
    _HG_MakeBaseline(_HG_HostsFile(), _HG_BakFile(), _HG_HashFile())
if _HG_Last == ""
    _HG_Last := Sha256Hex(FileRead(_HG_HostsFile()))
SetTimer(_HG_Tick, 30000)
Log("HostsGuard started - baseline " . (FileExist(_HG_BakFile()) ? "present" : "MISSING"), "INFO")
