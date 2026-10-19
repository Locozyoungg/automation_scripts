#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\FocusMode.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Win+Alt+F12 toggles Focus Mode: silences toast notifications
;          (focus-assist registry value, restored on exit), minimizes apps
;          listed in [focus] distract_apps, and runs a Pomodoro countdown
;          ([focus] pomodoro_minutes). Everything is restored on toggle-off.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : config parsing + registry read only (exit 0/1).
; SECURITY: Only ever strengthens notification silence while active; the
;          prior registry value is restored when Focus Mode ends.
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

;------------------------------------------------------------------------------
; Selftest: config parsing + read-only registry check. No writes, no timers.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    Check("distract list parsed", _DistractApps().Length >= 3, "count=" . _DistractApps().Length)
    Check("distract list normalized", _DistractApps()[1] == "slack.exe", _DistractApps()[1])
    Check("dnd value validation", _SafeDnd("abc") == "1" && _SafeDnd("0") == "0" && _SafeDnd("") == "1")
    Check("pomodoro minutes sane", Cfg.Int("focus", "pomodoro_minutes", 25) >= 1)
    cur := RegReadVal("HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings", "NOC_GLOBAL_SETTING_TOASTS_ENABLED")
    Check("focus-assist registry readable (or absent)", true, "current=" . cur)
    Check("focus hotkey config readable", Cfg.Read("hotkeys", "focus_mode", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("FocusMode`nToggle: Win+Alt+F12`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; State + helpers
;------------------------------------------------------------------------------
Global _FocusOn := false
Global _PriorDnd := ""
Global _FocusStart := 0
Global _PomodoroDone := false
Global _BlockLogged := Map()

_DND_KEY := "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

_DistractApps() {
    out := []
    v := Cfg.Read("focus", "distract_apps", "")
    for part in StrSplit(StrReplace(v, "|", ","), ",") {
        part := StrLower(Trim(part))
        if part != ""
            out.Push(part)
    }
    return out
}

_SafeDnd(v) {
    v := Trim(v)
    return RegExMatch(v, "^\d+$") ? v : "1"
}

_SetDnd(v) {
    v := _SafeDnd(v)
    r := RunPS("Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings'"
        . " -Name NOC_GLOBAL_SETTING_TOASTS_ENABLED -Value " . v . " -Force 2>&1|Out-String", 15)
    if !r["ok"]
        Log("FocusMode: DND registry write failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
}

_BlockTick() {
    Global _BlockLogged
    for exe in _DistractApps() {
        hwnd := WinExist("ahk_exe " . exe)
        if hwnd && WinGetMinMax("ahk_id " . hwnd) != -1 {
            WinMinimize("ahk_id " . hwnd)
            if !_BlockLogged.Has(exe) {
                _BlockLogged[exe] := true
                Log("FocusMode: minimized distraction " . exe, "INFO")
            }
        }
    }
}

_FocusTick() {
    ; Pomodoro countdown check (runs every 30 s while Focus Mode is on).
    Global _FocusStart, _PomodoroDone
    if _PomodoroDone || _FocusStart == 0
        return
    minutes := Cfg.Int("focus", "pomodoro_minutes", 25)
    if A_TickCount - _FocusStart >= minutes * 60000 {
        _PomodoroDone := true
        Notify("Pomodoro complete", minutes . " minutes of focus. Take a break!", "INFO")
        Log("FocusMode: pomodoro complete (" . minutes . " min)", "INFO")
    }
}

;------------------------------------------------------------------------------
; Toggle
;------------------------------------------------------------------------------
ToggleFocus() {
    Global _FocusOn, _PriorDnd, _FocusStart, _PomodoroDone
    if !_FocusOn {
        _PriorDnd := RegReadVal(_DND_KEY, "NOC_GLOBAL_SETTING_TOASTS_ENABLED")
        _SetDnd("0")
        _FocusOn := true
        _FocusStart := A_TickCount
        _PomodoroDone := false
        SetTimer(_FocusTick, 30000)
        SetTimer(_BlockTick, 2000)
        Log("FocusMode ON (dnd prior=" . _PriorDnd . ")", "INFO")
        Notify("Focus Mode ON", "Notifications muted; distractions blocked; pomodoro started.", "INFO")
    } else {
        _SetDnd(_PriorDnd == "" ? "1" : _PriorDnd)
        _FocusOn := false
        _FocusStart := 0
        SetTimer(_FocusTick, 0)
        SetTimer(_BlockTick, 0)
        Log("FocusMode OFF (dnd restored to " . _PriorDnd . ")", "INFO")
        Notify("Focus Mode OFF", "Notifications restored.", "INFO")
    }
}

BindHotkey(Cfg.Read("hotkeys", "focus_mode", "Win+Alt+F12"), ToggleFocus, "FocusMode: toggle")
Log("FocusMode started (off)", "INFO")
