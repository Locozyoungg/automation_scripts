#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\PrivacyMonitor.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Win+Alt+Q toggles the microphone privacy switch (Windows Consent
;          Store; documented limit: Microsoft Store apps honor it, Win32
;          apps are covered by Settings > Privacy). Every 15 s it reports
;          apps that used the camera (WARN) or microphone (INFO) within the
;          last 2 minutes, with dedupe.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : toggle math + registry structure read (exit 0/1).
; SECURITY: App names come from ConsentStore registry keys - metadata only.
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

_PV_PS := (
    "$res=@()`n"
    . "foreach($dev in 'webcam','microphone'){`n"
    . "  $base='HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\' + $dev`n"
    . "  Get-ChildItem -Path $base -Recurse -ErrorAction SilentlyContinue|ForEach-Object{`n"
    . "    $p=Get-ItemProperty -Path $_.PSPath -Name LastUsedTimeStart -ErrorAction SilentlyContinue`n"
    . "    if($p -and $p.LastUsedTimeStart){`n"
    . "      $t=0; $v=$p.LastUsedTimeStart`n"
    . "      if($v -is [long]){$t=[long]$v}elseif($v -is [byte[]]){$t=[BitConverter]::ToInt64($v,0)}`n"
    . "      if($t -gt 0){`n"
    . "        $dt=[DateTime]::FromFileTime($t)`n"
    . "        if(((Get-Date)-$dt).TotalSeconds -lt 120){$res+=@{dev=$dev;app=$_.PSChildName;start=$dt.ToString('s')}}`n"
    . "      }`n"
    . "    }`n"
    . "  }`n"
    . "}`n"
    . "$res|ConvertTo-Json -Depth 4 -Compress"
)

if ArgHas("--selftest") {
    EnsureDirs()
    Check("toggle math: Deny -> Allow", _PV_Next("Deny") == "Allow")
    Check("toggle math: Allow -> Deny", _PV_Next("Allow") == "Deny")
    Check("toggle math: unknown -> Deny", _PV_Next("Weird") == "Deny")
    cur := _PV_Current()
    Check("mic consent value readable", cur == "Allow" || cur == "Deny" || cur == "?", "cur=" . cur)
    r := RunPS("Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' 2>&1|Out-String", 15)
    Check("ConsentStore webcam key exists", r["ok"] && InStr(r["stdout"], "True") == 1)
    proc := _PV_Process([Map("dev", "webcam", "app", "C:\x\evil.exe", "start", "now")
        , Map("dev", "webcam", "app", "C:\x\evil.exe", "start", "now")], Map())
    Check("camera use dedupes", proc.Length == 1)
    Check("privacy hotkey config readable", Cfg.Read("hotkeys", "privacy_mute", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("PrivacyMonitor`nMic mute: Win+Alt+Q`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Toggle + monitor
;------------------------------------------------------------------------------
_PV_Key() => "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"

_PV_Next(cur) {
    return cur == "Deny" ? "Allow" : "Deny"
}

_PV_Current() {
    v := RegReadVal(_PV_Key(), "Value")
    v := StrLower(Trim(v))
    return v == "deny" || v == "allow" ? _PV_Title(v) : "?"
}

_PV_Title(v) => v == "deny" ? "Deny" : "Allow"

ToggleMute() {
    cur := _PV_Current()
    next := _PV_Next(cur)
    r := RunPS("Set-ItemProperty -Path " . _PsLit(_PV_Key()) . " -Name Value -Value " . _PsLit(next) . " -Force 2>&1|Out-String", 15)
    if !r["ok"] {
        Notify("Mic toggle", "Could not write the microphone privacy switch.", "ERROR")
        return
    }
    state := next == "Deny" ? "muted" : "unmuted"
    Log("PrivacyMonitor: microphone " . state . " (Store apps; see Settings > Privacy for Win32 apps)", "INFO")
    Notify("Microphone " . state, "Store-app access " . (next == "Deny" ? "blocked" : "allowed")
        . ". Win32 apps: Settings > Privacy > Microphone.", "INFO")
}

_PV_Process(events, seen) {
    ; Dedupe: one alert per app per session while it stays recently-active.
    out := []
    for e in events {
        key := e["dev"] . "|" . e["app"]
        if seen.Has(key)
            continue
        seen[key] := true
        out.Push(e)
    }
    return out
}

_PV_Tick() {
    Global _PV_Seen
    r := RunPSJsonF(_PV_PS, 30, Map())
    if !IsObject(r)
        return
    fresh := _PV_Process(r, _PV_Seen)
    for e in fresh {
        if e["dev"] == "webcam" {
            Notify("Camera in use", e["app"] . " used the camera recently.", "WARN")
            Log("PrivacyMonitor: camera used by " . e["app"], "WARN")
        } else {
            Log("PrivacyMonitor: microphone used by " . e["app"], "INFO")
        }
    }
}

Global _PV_Seen := Map()
BindHotkey(Cfg.Read("hotkeys", "privacy_mute", "Win+Alt+Q"), ToggleMute, "PrivacyMonitor: mic mute")
SetTimer(_PV_Tick, 15000)
Log("PrivacyMonitor started", "INFO")
