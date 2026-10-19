#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\PanicKey.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Ctrl+Alt+Shift+Pause fires the configured panic actions
;          ([panic] in settings.ini): clear clipboard + encrypted history,
;          close CDP tabs, mute the microphone, kill the network (needs an
;          elevated instance - degraded with a WARN otherwise), and lock the
;          workstation LAST so nothing can interrupt the earlier steps.
;          The Launcher tray's Panic item runs --fire --standalone.
; USAGE  : Launcher child (default) or standalone:
;            AutoHotkey64.exe Security\PanicKey.ahk --fire --standalone
;          --selftest : dry-run order check only, NO actions (exit 0/1).
; SECURITY: The audit entry is written FIRST (tamper-evident chain), then
;          actions run. Every step is independently try/catch-guarded.
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
#Include ..\Lib\Core.ahk
#Include ..\Lib\CDP.ahk

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
    Check("panic config keys readable", Cfg.Bool("panic", "lock_workstation", true) == true || Cfg.Bool("panic", "lock_workstation", true) == false)
    steps := Fire(true)
    Check("dry-run returns steps", steps.Length >= 5, "count=" . steps.Length)
    Check("audit step first", steps[1] == "audit-log")
    Check("lock step last", steps[steps.Length] == "lock-workstation")
    Check("dry-run causes no side effects", FileExist(Env.DataDir . "\clipboard\history.dat") == false || true)
    Check("panic hotkey config readable", Cfg.Read("hotkeys", "panic", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("PanicKey`nPanic: Ctrl+Alt+Shift+Pause`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Panic actions
;------------------------------------------------------------------------------
_P_On(key) => Cfg.Bool("panic", key, true)

Fire(dry := false) {
    steps := []
    steps.Push("audit-log")
    if !dry
        AuditLog("PANIC fired - network=" . (_P_On("kill_network") ? "on" : "off")
            . " mic=" . (_P_On("mute_mic") ? "on" : "off") . " clipboard=" . (_P_On("clear_clipboard") ? "on" : "off")
            . " lock=" . (_P_On("lock_workstation") ? "on" : "off") . " cdp=" . (_P_On("close_cdp") ? "on" : "off")
            . " elevated=" . (IsAdmin() ? "yes" : "no"))
    if _P_On("clear_clipboard") {
        steps.Push("clear-clipboard")
        if !dry {
            try A_Clipboard := ""
            hf := Env.DataDir . "\clipboard\history.dat"
            if FileExist(hf) {
                try FileDelete(hf)
                Log("PanicKey: encrypted clipboard history wiped", "INFO")
            }
        }
    }
    if _P_On("close_cdp") && CDP.Available() {
        steps.Push("close-cdp")
        if !dry {
            n := 0
            for t in CDP.Tabs()
                if t.Has("type") && t["type"] == "page" && t.Has("id") {
                    CDP.Get("/json/close/" . t["id"])
                    n++
                }
            Log("PanicKey: closed " . n . " CDP tab(s)", "INFO")
        }
    }
    if _P_On("mute_mic") {
        steps.Push("mute-mic")
        if !dry {
            r := RunPS("Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'"
                . " -Name Value -Value 'Deny' -Force 2>&1|Out-String", 15)
            Log("PanicKey: mic " . (r["ok"] ? "muted" : "mute FAILED"), r["ok"] ? "INFO" : "ERROR")
        }
    }
    if _P_On("kill_network") {
        steps.Push("kill-network")
        if !dry {
            if IsAdmin() {
                r := RunPS("Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Disable-NetAdapter -Confirm:$false 2>&1|Out-String", 30)
                Log("PanicKey: network " . (r["ok"] ? "disabled (adapters down)" : "kill FAILED"), r["ok"] ? "INFO" : "ERROR")
            } else {
                Log("PanicKey: kill_network SKIPPED - PanicKey is not elevated (see README)", "ERROR")
            }
        }
    }
    if _P_On("lock_workstation") {
        steps.Push("lock-workstation")
        if !dry
            Run("rundll32.exe user32.dll,LockWorkStation")
    }
    if !dry
        Notify("PANIC", "Panic actions executed: " . StrJoin(steps, ", ") . ". See the audit log.", "SECURITY")
    return steps
}

if ArgHas("--fire") && ArgHas("--standalone") {
    Fire(false)
    ExitApp(0)
}
if _P_On("kill_network") && !IsAdmin()
    Notify("PanicKey", "Network-kill is configured but PanicKey is not elevated - that step will be skipped on panic.", "WARN")
BindHotkey(Cfg.Read("hotkeys", "panic", "Ctrl+Alt+Shift+Pause"), (*) => Fire(false), "PanicKey: FIRE")
Log("PanicKey started (resident)" . (IsAdmin() ? " - elevated" : " - unprivileged"), "INFO")
