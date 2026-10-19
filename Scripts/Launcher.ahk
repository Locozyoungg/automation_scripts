#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\Launcher.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Tray host that starts/stops every registered tool (children run
;          tray-less via --child), restarts crashed children with backoff,
;          and exposes quick actions (logs, README, elevated Security Check,
;          Panic). Started at logon by Install\LaunchToolkit.xml.
; USAGE  : "C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe" Scripts\Launcher.ahk
;          Flags: --safe-mode (security tools only), --debug-tray (children
;          keep their own tray icons).
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
#Include ..\Lib\Core.ahk

InstallKillSwitch("Toolkit Launcher`nLeft-click the tray icon for the tool menu.`nKill-switch: Esc+Pause")

SafeMode := ArgHas("--safe-mode")
DebugTray := ArgHas("--debug-tray")

;------------------------------------------------------------------------------
; Child process table: name -> {pid, attempts}
;------------------------------------------------------------------------------
Child := Map()

StartTool(rec) {
    Global Child, DebugTray
    if Child.Has(rec.name) && ProcessExist(Child[rec.name].pid)
        return true
    args := "--child" . (DebugTray ? " --debug-tray" : "")
    try {
        pid := Run(_Q(A_AhkPath) . " " . _Q(ToolPath(rec.script)) . " " . args)
        ; v2.0.30 Run returns "" even on success - discover the real PID.
        if pid == ""
            pid := _FindNewPid(rec.name)
        Child[rec.name] := {pid: pid, attempts: 0}
        Log("Launcher: started " . rec.name . " (pid " . pid . ")", "INFO")
        return true
    } catch as e {
        Log("Launcher: StartTool failed for " . rec.name . ": " . ErrText(e), "ERROR")
        return false
    }
}

_FindNewPid(toolName) {
    ; WMI lookup: the AutoHotkey64 process running this tool's script.
    ; (#SingleInstance guarantees at most one per script.)
    try {
        wmi := ComObject("WbemScripting.SWbemLocator").ConnectServer(".", "root\cimv2")
        for proc in wmi.ExecQuery("SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name='AutoHotkey64.exe'") {
            if InStr(String(proc.CommandLine), "\" . toolName . ".ahk")
                return Integer(proc.ProcessId)
        }
    } catch as e {
        Log("Launcher: PID discovery failed: " . ErrText(e), "ERROR")
    }
    return 0
}

StopTool(name) {
    ; Graceful: per-tool stop flag first (the child's OnExit logs a clean
    ; shutdown line), then terminate if it lingers.
    Global Child
    if !Child.Has(name)
        return
    c := Child[name]
    Child.Delete(name)
    try FileAppend("stop", Env.DataDir . "\tmp\stop-" . name . ".flag")
    deadline := A_TickCount + 3000
    while A_TickCount < deadline {
        if !ProcessExist(c.pid)
            break
        Sleep 100
    }
    if ProcessExist(c.pid)
        ProcessClose(c.pid)
    Log("Launcher: stopped " . name, "INFO")
}

Watchdog() {
    ; Restart crashed children with backoff (max 3 attempts, then disable).
    Global Child
    toDelete := []
    for name, c in Child {
        if !ProcessExist(c.pid) {
            c.attempts++
            if c.attempts > 3 {
                Log("Launcher: " . name . " crashed " . c.attempts . " times — disabled", "ERROR")
                Notify(name . " disabled", "Crashed repeatedly; disabled. Re-enable from the tray menu.", "ERROR")
                Cfg.Write("tools", name, "0")
                toDelete.Push(name)
                continue
            }
            Log("Launcher: " . name . " exited unexpectedly — restart " . c.attempts . "/3", "WARN")
            Notify(name . " restarted", "Unexpected exit — restarting (" . c.attempts . "/3).", "WARN")
            Child.Delete(name)
            StartTool(Tools.ByName(name))
        }
    }
    for name in toDelete
        Child.Delete(name)
}

;------------------------------------------------------------------------------
; Tray menu
;------------------------------------------------------------------------------
BuildMenu() {
    Global SafeMode, TOOLKIT_VERSION
    try A_TrayMenu.Delete()
    catch {
        ; fresh menu — nothing to remove (empty block: a bare catch would
        ; swallow the next statement as its body)
    }
    head := "Toolkit v" . TOOLKIT_VERSION . (SafeMode ? " — SAFE MODE" : "")
    A_TrayMenu.Add(head, (*) => 0)
    A_TrayMenu.Disable(head)
    A_TrayMenu.Add()
    for rec in Tools.List() {
        if SafeMode && rec.category != "Security"
            continue
        A_TrayMenu.Add(rec.name, ToolMenuClick)
    }
    A_TrayMenu.Add()
    A_TrayMenu.Add("Open Logs folder", (*) => Run(Env.LogDir))
    A_TrayMenu.Add("Open README", (*) => Run(ToolPath("README.md")))
    A_TrayMenu.Add("Run Security Check (elevated)", (*) => RunSecurityCheck())
    A_TrayMenu.Add("Run Secrets Scan", (*) => RunSecretsScan())
    A_TrayMenu.Add()
    A_TrayMenu.Add("Panic — FIRE NOW", (*) => FirePanic())
    A_TrayMenu.Add()
    A_TrayMenu.Add("Exit All", (*) => ExitAll())
    A_TrayMenu.Add("Exit Launcher only", (*) => ExitApp(0))
    ApplyChecks()
}

ApplyChecks() {
    Global SafeMode
    for rec in Tools.List() {
        if SafeMode && rec.category != "Security"
            continue
        if Cfg.Bool("tools", rec.name, rec.enabled)
            A_TrayMenu.Check(rec.name)
        else
            A_TrayMenu.Uncheck(rec.name)
    }
}

ToolMenuClick(name, pos, menu) {
    enabled := Cfg.Bool("tools", name, true)
    rec := Tools.ByName(name)
    if rec == ""
        return
    if enabled {
        Cfg.Write("tools", name, "0")
        StopTool(name)
        menu.Uncheck(name)
    } else {
        Cfg.Write("tools", name, "1")
        if StartTool(rec)
            menu.Check(name)
    }
    Notify("Toolkit", name . (enabled ? " stopped" : " started"), "INFO")
}

RunSecurityCheck() {
    try Run("*RunAs " . _Q(A_AhkPath) . " " . _Q(ToolPath("Security\SecurityCheck.ahk")) . " --standalone")
    catch as e
        Notify("Security Check", "Could not launch the elevated audit: " . e.Message, "ERROR")
}

RunSecretsScan() {
    try Run(_Q(A_AhkPath) . " " . _Q(ToolPath("Security\SecretsScanner.ahk")) . " --scan-now --standalone")
    catch as e
        Notify("Secrets Scan", "Could not launch: " . e.Message, "ERROR")
}

FirePanic() {
    if !ConfirmDlg("Panic Mode", "Trigger the full panic action NOW?`n(lock workstation, mute mic, clear clipboard, disable network if configured)")
        return
    try Run(_Q(A_AhkPath) . " " . _Q(ToolPath("Security\PanicKey.ahk")) . " --fire --standalone")
    catch as e
        Notify("Panic", "Could not launch PanicKey: " . e.Message, "ERROR")
}

ExitAll() {
    Global Child
    if !ConfirmDlg("Exit toolkit", "Stop ALL tools and exit the launcher?")
        return
    try FileAppend("stop", Env.DataDir . "\tmp\launcher-stop.flag")
    deadline := A_TickCount + 3000
    while A_TickCount < deadline {
        alive := false
        for _, c in Child
            if ProcessExist(c.pid)
                alive := true
        if !alive
            break
        Sleep 100
    }
    for _, c in Child
        if ProcessExist(c.pid)
            ProcessClose(c.pid)
    try FileDelete(Env.DataDir . "\tmp\launcher-stop.flag")
    Log("Launcher: Exit All", "INFO")
    ExitApp(0)
}

LauncherExit(ExitReason?, ExitCode?) {
    MutexRelease("launcher")
}

_CountRunning() {
    Global Child
    n := 0
    for _, c in Child
        if ProcessExist(c.pid)
            n++
    return n
}

;------------------------------------------------------------------------------
; Startup
;------------------------------------------------------------------------------
; --selftest: validate load + registry without side effects (no children).
if ArgHas("--selftest") {
    Log("Launcher selftest OK — " . Tools.List().Length . " tools registered", "TEST")
    ExitApp(0)
}
if !MutexAcquire("launcher") {
    MsgBox("The toolkit Launcher is already running.", "Toolkit Launcher", "Iconi")
    ExitApp(1)
}
OnExit(LauncherExit, 1)
Log("Launcher start (v" . TOOLKIT_VERSION . ")" . (SafeMode ? " — SAFE MODE: security tools only" : ""), "INFO")
BuildMenu()
for rec in Tools.List() {
    if SafeMode && rec.category != "Security"
        continue
    if Cfg.Bool("tools", rec.name, rec.enabled)
        StartTool(rec)
}
SetTimer(Watchdog, 10000)
Notify("Toolkit ready", "Launcher running — " . _CountRunning() . " tools active. Tray menu for control.", "INFO")
