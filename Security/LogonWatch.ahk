#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\LogonWatch.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Watches the Security event log (30 s poll) for logon activity:
;          4624 (logon), 4625 (failed), 4648 (explicit credential use) and
;          1102 (log cleared). 3+ failures in 10 minutes, RDP logons
;          (type 10) and log-clearing raise SECURITY alerts + audit entries.
;          Unprivileged runs degrade to a one-time WARN (the Security log
;          needs admin) and keep retrying.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : classification logic + state file only (exit 0/1).
; SECURITY: Event data stays local; usernames/IDs are logged as metadata.
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

_LW_PS_TMPL := (
    "$evs=@()`n"
    . "try{`n"
    . "  $e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4648} -MaxEvents 300 -ErrorAction Stop|Where-Object{$_.RecordId -gt $LastId}`n"
    . "  foreach($x in $e){`n"
    . "    $user='';$lt='';$ip=''`n"
    . "    $mu=[regex]::Match($x.Message,'Account Name:\s+(\S+)')`n"
    . "    $ml=[regex]::Match($x.Message,'Logon Type:\s+(\d+)')`n"
    . "    $mi=[regex]::Match($x.Message,'Source Network Address:\s+(\S+)')`n"
    . "    if($mu.Success){$user=$mu.Groups[1].Value};if($ml.Success){$lt=$ml.Groups[1].Value};if($mi.Success){$ip=$mi.Groups[1].Value}`n"
    . "    $evs+=@{id=$x.Id;rec=$x.RecordId;time=$x.TimeCreated.ToString('s');user=$user;type=$lt;ip=$ip}`n"
    . "  }`n"
    . "  $cl=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 20 -ErrorAction Stop|Where-Object{$_.RecordId -gt $LastId}|ForEach-Object{$_.RecordId})`n"
    . "  $nl=$LastId`n"
    . "  if($evs.Count -gt 0){$nl=($evs|Measure-Object rec -Maximum).Maximum}`n"
    . "  if($cl.Count -gt 0){$m=($cl|Measure-Object -Maximum).Maximum;if($m -gt $nl){$nl=$m}}`n"
    . "  @{events=$evs;clears=$cl;newLast=$nl;degraded=$false}|ConvertTo-Json -Depth 5 -Compress`n"
    . "}catch{@{events=@();clears=@();newLast=$LastId;degraded=$true}|ConvertTo-Json -Depth 5 -Compress}`n"
)

if ArgHas("--selftest") {
    EnsureDirs()
    ; Pure classification on synthetic events.
    now := A_TickCount
    evs := [Map("id", 4625, "rec", 1, "time", "", "user", "ADMIN", "type", "3", "ip", "10.0.0.9")
        , Map("id", 4625, "rec", 2, "time", "", "user", "ADMIN", "type", "3", "ip", "10.0.0.9")
        , Map("id", 4625, "rec", 3, "time", "", "user", "ADMIN", "type", "3", "ip", "10.0.0.9")]
    c := _LW_Classify(evs, [], now)
    Check("3 failures in window alert", c["failAlert"])
    evs2 := [Map("id", 4624, "rec", 1, "time", "", "user", "bob", "type", "10", "ip", "203.0.113.5")]
    c2 := _LW_Classify(evs2, [], now)
    Check("RDP logon alert (type 10)", c2["rdpAlert"])
    Check("cleared-log alert", _LW_Classify([], [99], now)["clearAlert"])
    Check("quiet events no alerts", !_LW_Classify([], [], now)["failAlert"] && !_LW_Classify([], [], now)["rdpAlert"])
    tmp := Env.DataDir . "\tmp\lw-state-test.json"
    try FileAppend(JSON.stringify(Map("lastId", 42, "degraded", 0)), tmp)
    Check("state file round-trip", _LW_ReadState(tmp)["lastId"] == 42)
    try FileDelete(tmp)
    Check("lastId embeds as integer", RegExMatch(_LW_Embed(42), "^\$LastId=42;") > 0)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("LogonWatch`nWatches Security-log logon events (30 s).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Classification (pure, testable)
;------------------------------------------------------------------------------
_LW_Classify(events, clears, nowTick) {
    fails := 0
    rdp := false
    for e in events {
        if Integer(e["id"]) == 4625
            fails++
        if Integer(e["id"]) == 4624 && e["type"] == "10"
            rdp := true
    }
    return Map("failAlert", fails >= 3, "rdpAlert", rdp, "clearAlert", clears.Length > 0, "fails", fails)
}

_LW_StateFile() => Env.DataDir . "\state\logonwatch.json"

_LW_ReadState(path) {
    try {
        obj := JSON.parse(FileRead(path))
        if obj.Has("lastId")
            return Map("lastId", Integer(obj["lastId"]), "degraded", obj.Has("degraded") && obj["degraded"] ? 1 : 0)
    } catch {
        ; first run
    }
    return Map("lastId", 0, "degraded", 0)
}

_LW_WriteState(path, state) {
    try FileAppend(JSON.stringify(Map("lastId", state["lastId"], "degraded", state["degraded"])), path)
}

_LW_Embed(lastId) {
    ; The id comes from our own state file - validated integer, safe to embed.
    return "$LastId=" . Integer(lastId) . ";"
}

_LW_Tick() {
    Global _LW_State
    ps := _LW_Embed(_LW_State["lastId"]) . _LW_PS_TMPL
    r := RunPSJsonF(ps, 45, Map())
    if !IsObject(r) || !r.Has("degraded")
        return
    if r["degraded"] {
        if !_LW_State["degraded"] {
            _LW_State["degraded"] := 1
            _LW_WriteState(_LW_StateFile(), _LW_State)
            Log("LogonWatch: Security log not readable without admin - degraded (retrying)", "WARN")
            Notify("LogonWatch degraded", "Run elevated for Security-log monitoring.", "WARN")
        }
        return
    }
    _LW_State["degraded"] := 0
    now := A_TickCount
    c := _LW_Classify(r.Has("events") ? r["events"] : [], r.Has("clears") ? r["clears"] : [], now)
    if c["clearAlert"] {
        Notify("SECURITY LOG CLEARED", "Event 1102: the Security log was cleared. Investigate.", "SECURITY")
        AuditLog("LogonWatch: Security log was CLEARED")
    }
    if c["failAlert"] {
        Notify("Failed logons", c["fails"] . " failed logons in the last batch.", "SECURITY")
        AuditLog("LogonWatch: " . c["fails"] . " failed logon events")
    }
    if c["rdpAlert"] {
        Notify("RDP logon", "Remote Desktop logon detected.", "SECURITY")
        AuditLog("LogonWatch: RDP logon (type 10)")
    }
    for e in r.Has("events") ? r["events"] : []
        Log("LogonWatch: event " . e["id"] . " user=" . e["user"] . " type=" . e["type"] . " ip=" . e["ip"], "INFO")
    if r.Has("newLast") && Integer(r["newLast"]) > _LW_State["lastId"] {
        _LW_State["lastId"] := Integer(r["newLast"])
        _LW_WriteState(_LW_StateFile(), _LW_State)
    }
}

Global _LW_State := _LW_ReadState(_LW_StateFile())
_LW_Tick()
SetTimer(_LW_Tick, 30000)
Log("LogonWatch started - lastId " . _LW_State["lastId"] . (IsAdmin() ? " (elevated)" : " (unprivileged)"), "INFO")
