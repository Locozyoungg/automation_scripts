#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\PersistenceMonitor.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Baseline diffs of autostart persistence: Run/RunOnce keys (HKLM+
;          HKCU), Startup folders (user + common) and scheduled task names.
;          Baseline lives in Config\baseline\persistence.json (rebuilt with
;          --baseline, or silently on first run). Every 15 minutes new
;          entries raise a SECURITY alert + audit entry; removals are logged.
; USAGE  : Launcher child (default) or standalone.
;          --baseline : rebuild the baseline and exit.
;          --selftest : one snapshot + diff logic, no alerts (exit 0/1).
; SECURITY: Read-only monitoring; never modifies autostarts.
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

; PS snapshot script. Defined BEFORE the selftest block: top-level assignments
; execute in file order and the selftest calls _PM_Snapshot().
_PM_PS := (
    "$out=@{run=@();startup=@();tasks=@()}`n"
    . "foreach($h in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'){`n"
    . "  $p=Get-ItemProperty -Path $h -ErrorAction SilentlyContinue`n"
    . "  if($p){$p.PSObject.Properties|Where-Object{$_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')}|ForEach-Object{$out.run+=($h + '|' + $_.Name + '|' + [string]$_.Value)}}`n"
    . "}`n"
    . "foreach($d in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){`n"
    . "  Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue|ForEach-Object{$out.startup+=($d + '|' + $_.Name)}`n"
    . "}`n"
    . "Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskPath -notlike '\Microsoft\*'}|ForEach-Object{$out.tasks+=($_.TaskPath + $_.TaskName)}`n"
    . "$out|ConvertTo-Json -Depth 4 -Compress"
)

if ArgHas("--selftest") {
    EnsureDirs()
    snap := _PM_Snapshot()
    Check("snapshot runs (run+startup+tasks keys)", IsObject(snap) && snap.Has("run") && snap.Has("startup") && snap.Has("tasks"))
    base := Map()
    base["run|HKLM|X"] := "cmd"
    base["startup|dir|old.exe"] := "file"
    cur := Map()
    cur["run|HKLM|X"] := "cmd"
    cur["run|HKCU|NewApp"] := "new.exe"
    d := _PM_Diff(base, cur)
    Check("diff detects new entries", d["new"].Length == 1 && InStr(d["new"][1], "NewApp") > 0)
    Check("diff detects removals", d["removed"].Length == 1)
    tmp := Env.DataDir . "\tmp\pm-test.json"
    _PM_WriteBaseline(tmp, cur)
    Check("baseline JSON round-trip", _PM_ReadBaseline(tmp).Count == 2)
    try FileDelete(tmp)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("PersistenceMonitor`nWatches autostarts for new entries (15 min).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Snapshot + diff
;------------------------------------------------------------------------------
_PM_Snapshot() {
    return RunPSJsonF(_PM_PS, 60, Map())
}

_PM_Map(snap) {
    m := Map()
    if !IsObject(snap)
        return m
    for v in snap.Has("run") ? snap["run"] : []
        m["run|" . v] := true
    for v in snap.Has("startup") ? snap["startup"] : []
        m["startup|" . v] := true
    for v in snap.Has("tasks") ? snap["tasks"] : []
        m["task|" . v] := true
    return m
}

_PM_Diff(base, cur) {
    new := [], removed := []
    for k in cur
        if !base.Has(k)
            new.Push(k)
    for k in base
        if !cur.Has(k)
            removed.Push(k)
    return Map("new", new, "removed", removed)
}

_PM_BaselineFile() => Env.ConfigDir . "\baseline\persistence.json"

_PM_WriteBaseline(path, stateMap) {
    EnsureDirs()
    try FileAppend(JSON.stringify(Map("generated", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"), "items", stateMap)), path)
    catch as e {
        Log("PersistenceMonitor: baseline write failed: " . ErrText(e), "ERROR")
        return false
    }
    return true
}

_PM_ReadBaseline(path) {
    try {
        obj := JSON.parse(FileRead(path))
        if obj.Has("items")
            return obj["items"]
    } catch {
        ; fall through to empty
    }
    return Map()
}

_PM_Tick() {
    Global _PM_Base
    snap := _PM_Snapshot()
    cur := _PM_Map(snap)
    if !cur.Count
        return
    d := _PM_Diff(_PM_Base, cur)
    for k in d["new"] {
        Log("PersistenceMonitor: NEW autostart - " . k, "WARN")
        Notify("New autostart detected", k, "SECURITY")
        AuditLog("PersistenceMonitor: new autostart entry: " . k)
    }
    for k in d["removed"]
        Log("PersistenceMonitor: autostart removed - " . k, "INFO")
    _PM_Base := cur
}

;------------------------------------------------------------------------------
; Startup
;------------------------------------------------------------------------------
Global _PM_Base := _PM_ReadBaseline(_PM_BaselineFile())
if ArgHas("--baseline") {
    snap := _PM_Snapshot()
    _PM_Base := _PM_Map(snap)
    if _PM_WriteBaseline(_PM_BaselineFile(), _PM_Base)
        Notify("PersistenceMonitor", "Baseline rebuilt: " . _PM_Base.Count . " entries.", "INFO")
    ExitApp(0)
}
if !_PM_Base.Count {
    snap := _PM_Snapshot()
    _PM_Base := _PM_Map(snap)
    _PM_WriteBaseline(_PM_BaselineFile(), _PM_Base)
    Log("PersistenceMonitor: first run - baseline created (" . _PM_Base.Count . " entries)", "INFO")
}
_PM_Tick()
SetTimer(_PM_Tick, 900000)
Log("PersistenceMonitor started - baseline " . _PM_Base.Count . " entries", "INFO")
