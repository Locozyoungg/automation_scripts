#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\USBGuard.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Watches for USB storage insertion (Win32_DiskDrive InterfaceType
;          USB, polled every 15 s). Unknown serials raise a SECURITY alert +
;          audit entry; serials listed in Config\ignorelist.ini
;          [usb_allow_serials] are logged quietly. An autorun.inf on any
;          removable volume triggers an immediate alert. Removals are logged.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : one read-only snapshot + helpers, no alerts (exit 0/1).
; SECURITY: Read-only monitoring. Does not eject or modify drives (documented
;          limit - physical port control belongs to policy/EDR).
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

; PS snapshot script. Defined BEFORE the selftest block (file-order execution).
_UG_PS := (
    "$disks=@(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue|Where-Object{$_.InterfaceType -eq 'USB'}|ForEach-Object{@{serial=$_.SerialNumber;model=$_.Model}})`n"
    . "$vols=@(Get-Volume -ErrorAction SilentlyContinue|Where-Object{$_.DriveType -eq 'Removable' -and $_.DriveLetter}|ForEach-Object{$_.DriveLetter + ':'})`n"
    . "@{disks=$disks;volumes=$vols}|ConvertTo-Json -Depth 4 -Compress"
)

if ArgHas("--selftest") {
    EnsureDirs()
    snap := _UG_Snapshot()
    Check("USB snapshot runs (disks+volumes)", IsObject(snap) && snap.Has("disks") && snap.Has("volumes"))
    Check("allow-list parses", IsObject(Cfg.IgnoreList("usb_allow_serials")))
    tmp := Env.DataDir . "\tmp\ug-state-test.json"
    _UG_SaveState(tmp, Map("A1", "Test Model"))
    Check("state file round-trip", _UG_LoadState(tmp).Has("A1"))
    try FileDelete(tmp)
    fx := Env.DataDir . "\tmp\ug-fixture"
    if DirExist(fx)
        DirDelete(fx, true)
    DirCreate(fx)
    FileAppend("[autorun]", fx . "\autorun.inf")
    Check("autorun.inf detection", _UG_HasAutorun(fx))
    DirDelete(fx, true)
    Check("empty dir has no autorun", !_UG_HasAutorun(Env.DataDir . "\tmp"))
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("USBGuard`nAlerts on USB storage insertion (15 s poll).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Snapshot + state
;------------------------------------------------------------------------------
_UG_Snapshot() {
    return RunPSJsonF(_UG_PS, 60, Map())
}

_UG_StateFile() => Env.DataDir . "\state\usbguard.json"

_UG_SaveState(path, stateMap) {
    try FileAppend(JSON.stringify(Map("serials", stateMap)), path)
    catch as e {
        Log("USBGuard: state write failed: " . ErrText(e), "ERROR")
    }
}

_UG_LoadState(path) {
    try {
        obj := JSON.parse(FileRead(path))
        if obj.Has("serials")
            return obj["serials"]
    } catch {
        ; first run or unreadable state
    }
    return Map()
}

_UG_HasAutorun(dir) {
    return FileExist(dir . "\autorun.inf")
}

_UG_Allowed(serial) {
    for s in Cfg.IgnoreList("usb_allow_serials")
        if StrLower(Trim(s)) == StrLower(serial)
            return true
    return false
}

_UG_Tick() {
    Global _UG_Seen
    snap := _UG_Snapshot()
    if !IsObject(snap) || !snap.Has("disks")
        return
    current := Map()
    for d in snap["disks"] {
        serial := Trim(String(d["serial"]))
        if serial == ""
            continue
        current[serial] := String(d["model"])
        if !_UG_Seen.Has(serial) {
            if _UG_Allowed(serial)
                Log("USBGuard: known USB storage attached - " . d["model"] . " (serial " . serial . ")", "INFO")
            else {
                Notify("USB storage inserted", d["model"] . " (serial " . serial . ")", "SECURITY")
                AuditLog("USBGuard: unknown USB storage inserted - " . d["model"] . " serial " . serial)
            }
            for vol in snap.Has("volumes") ? snap["volumes"] : []
                if _UG_HasAutorun(vol) {
                    Notify("autorun.inf on USB drive", vol . " contains autorun.inf - do not run files from it.", "SECURITY")
                    AuditLog("USBGuard: autorun.inf present on " . vol . " (serial " . serial . ")")
                }
        }
    }
    for serial in _UG_Seen
        if !current.Has(serial)
            Log("USBGuard: USB storage removed - " . _UG_Seen[serial] . " (serial " . serial . ")", "INFO")
    _UG_Seen := current
    _UG_SaveState(_UG_StateFile(), _UG_Seen)
}

Global _UG_Seen := _UG_LoadState(_UG_StateFile())
_UG_Tick()
SetTimer(_UG_Tick, 15000)
Log("USBGuard started - " . _UG_Seen.Count . " known device(s)", "INFO")
