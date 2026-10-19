#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\DevHotkeys.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Developer hotkeys — run the active project's tests in Windows
;          Terminal, open a terminal in the project root, copy the current
;          file path (plain / relative / path:line), kill or print the
;          process listening on a port, open the project's .env.example.
; USAGE  : Launcher child (default) or standalone:
;            "C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe" Scripts\DevHotkeys.ahk
;          --selftest : dependency checks only, no side effects (exit 0/1).
; SECURITY: Never opens .env, only .env.example. Port kills always confirm
;          and are recorded in the audit chain.
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
; Selftest: pure logic + read-only system checks. No hotkeys, no kills.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    fx := Env.DataDir . "\tmp\dh-fixture"
    if DirExist(fx)
        DirDelete(fx, true)
    DirCreate(fx)
    FileAppend("{}", fx . "\package.json")
    Check("test command: npm default", _TestCommand(fx) == "npm test", _TestCommand(fx))
    FileAppend("", fx . "\pnpm-lock.yaml")
    Check("test command: pnpm preferred", _TestCommand(fx) == "pnpm test")
    FileDelete(fx . "\pnpm-lock.yaml")
    FileDelete(fx . "\package.json")
    FileAppend("", fx . "\Cargo.toml")
    Check("test command: cargo", _TestCommand(fx) == "cargo test")
    FileDelete(fx . "\Cargo.toml")
    FileAppend("", fx . "\go.mod")
    Check("test command: go", _TestCommand(fx) == "go test ./...")
    FileDelete(fx . "\go.mod")
    FileAppend("", fx . "\pyproject.toml")
    Check("test command: python", _TestCommand(fx) == "python -m pytest")
    FileDelete(fx . "\pyproject.toml")
    Check("test command: unknown project", _TestCommand(fx) == "")
    DirDelete(fx, true)
    Check("port lookup: nothing on port 1", _PortInfo(1) == "")
    Check("hotkey config readable", Cfg.Read("hotkeys", "run_tests", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("DevHotkeys`nRun tests, Git GUI, paths, ports.`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Helpers
;------------------------------------------------------------------------------
_FirstMatch(dir, pattern) {
    first := ""
    try Loop Files dir . "\" . pattern, "F" {
        first := A_LoopFilePath
        break
    }
    return first
}

_TestCommand(root) {
    ; Map the project to its test command. Order matters (lockfiles first).
    if FileExist(root . "\package.json") {
        if FileExist(root . "\pnpm-lock.yaml")
            return "pnpm test"
        if FileExist(root . "\yarn.lock")
            return "yarn test"
        return "npm test"
    }
    if FileExist(root . "\Cargo.toml")
        return "cargo test"
    if FileExist(root . "\go.mod")
        return "go test ./..."
    if FileExist(root . "\pyproject.toml") || FileExist(root . "\pytest.ini")
        return "python -m pytest"
    if _FirstMatch(root, "*.csproj") != "" || _FirstMatch(root, "*.sln") != ""
        return "dotnet test"
    if FileExist(root . "\foundry.toml")
        return "forge test"
    if _FirstMatch(root, "hardhat.config.*") != ""
        return "npx hardhat test"
    return ""
}

_PortInfo(port) {
    ; Map(pid, name, port) for the listener on this port, or "" when none.
    if !RegExMatch(String(port), "^\d{1,5}$")
        return ""
    ps := "$Port=" . Integer(port) . "`n"
        . "$c=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue|Select-Object -First 1`n"
        . "if(-not $c){''}else{$p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue;"
        . "@{pid=$c.OwningProcess;name=$(if($p){$p.ProcessName}else{'unknown'});port=$c.LocalPort}|ConvertTo-Json -Compress}"
    r := RunPSJson(ps, 15)
    if IsObject(r) && r.Has("pid")
        return r
    return ""
}

;------------------------------------------------------------------------------
; Actions
;------------------------------------------------------------------------------
RunTests() {
    root := ActiveProject()
    if root == "" {
        Notify("Run tests", "No VS Code project detected. Open the project in VS Code first.", "WARN")
        return
    }
    cmd := _TestCommand(root)
    if cmd == "" {
        Notify("Run tests", "No known test setup found in " . root, "WARN")
        return
    }
    Log("DevHotkeys: running '" . cmd . "' in " . root, "INFO")
    OpenInTerminal(cmd, root)
    Notify("Tests started", cmd . "  (Windows Terminal)", "INFO")
}

GitGui() {
    root := ActiveProject()
    if root == "" {
        Notify("Project terminal", "No VS Code project detected.", "WARN")
        return
    }
    OpenInTerminal("", root)
    Log("DevHotkeys: opened terminal in " . root, "INFO")
}

CopyPath(mode := "abs") {
    info := ActiveEditorInfo()
    if !IsObject(info) || info["file"] == "" {
        Notify("Copy path", "Active window is not a VS Code editor with a file.", "WARN")
        return
    }
    text := info["file"]
    if mode == "rel" && info.Has("rel") && info["rel"] != ""
        text := info["rel"]
    if mode == "line" {
        title := ""
        try title := WinGetTitle("A")
        m := ""
        if RegExMatch(title, ":(\d+)\D*$", &m)
            text .= ":" . m[1]
    }
    A_Clipboard := text
    Log("DevHotkeys: copied path (len " . StrLen(text) . ")", "INFO")
    Notify("Path copied", text, "INFO")
}

KillPort() {
    port := InputText("Port number whose listener to kill (1-65535):", "Kill port")
    if port == ""
        return
    info := _PortInfo(port)
    if info == "" {
        Notify("Kill port", "Nothing is listening on port " . port, "INFO")
        return
    }
    pid := info["pid"], name := info["name"]
    if !ConfirmDlg("Kill process", "Kill " . name . " (PID " . pid . ") listening on port " . port . "?")
        return
    ps := "$r=taskkill /PID " . Integer(pid) . " /F 2>&1|Out-String;if($LASTEXITCODE -eq 0){'KILLED ' . $r}else{'FAILED ' . $r}"
    r := RunPS(ps, 20)
    tail := Trim(StrReplace(r["stdout"], "`r`n", " "))
    ok := r["ok"] && InStr(tail, "KILLED") == 1
    AuditLog("DevHotkeys: killed process " . name . " (pid " . pid . ") on port " . port . " - " . (ok ? "ok" : "failed"))
    Notify("Kill port", ok ? ("Killed " . name . " on port " . port) : ("Failed: " . tail), ok ? "INFO" : "ERROR")
    Log("KillPort: " . tail, "INFO")
}

PrintPort() {
    port := InputText("Port number to look up (1-65535):", "Print port")
    if port == ""
        return
    info := _PortInfo(port)
    if info == "" {
        Notify("Print port", "Nothing is listening on port " . port, "INFO")
        return
    }
    Log("PrintPort: pid " . info["pid"] . " (" . info["name"] . ") on " . port, "INFO")
    Notify("Port " . port, "PID " . info["pid"] . " - " . info["name"], "INFO")
}

OpenEnvExample() {
    root := ActiveProject()
    if root == "" {
        Notify("Open .env.example", "No VS Code project detected.", "WARN")
        return
    }
    p := root . "\.env.example"
    if !FileExist(p) {
        Notify("Open .env.example", "No .env.example in " . root, "WARN")
        return
    }
    ; Deliberately .env.example only - never .env itself.
    try Run(EnvGet("ComSpec") . " /c code " . _Q(p), , "Hide")
    catch
        Run(_Q(p))
    Log("DevHotkeys: opened " . p, "INFO")
}

;------------------------------------------------------------------------------
; Bindings
;------------------------------------------------------------------------------
BindHotkey(Cfg.Read("hotkeys", "run_tests", "Win+Alt+T"), RunTests, "DevHotkeys: run tests")
BindHotkey(Cfg.Read("hotkeys", "git_gui", "Win+Alt+B"), GitGui, "DevHotkeys: project terminal")
BindHotkey(Cfg.Read("hotkeys", "copy_path", "Win+Alt+C"), (*) => CopyPath("abs"), "DevHotkeys: copy path")
BindHotkey(Cfg.Read("hotkeys", "copy_path_rel", "Win+Alt+Shift+C"), (*) => CopyPath("rel"), "DevHotkeys: copy relative path")
BindHotkey(Cfg.Read("hotkeys", "copy_path_line", "Win+Alt+Ctrl+C"), (*) => CopyPath("line"), "DevHotkeys: copy path:line")
BindHotkey(Cfg.Read("hotkeys", "kill_port", "Win+Alt+K"), KillPort, "DevHotkeys: kill port")
BindHotkey(Cfg.Read("hotkeys", "print_port", "Win+Alt+P"), PrintPort, "DevHotkeys: print port")
BindHotkey(Cfg.Read("hotkeys", "open_env_example", "Win+Alt+E"), OpenEnvExample, "DevHotkeys: open .env.example")
Log("DevHotkeys started", "INFO")
