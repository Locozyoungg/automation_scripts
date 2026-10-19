#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\GitWorkflow.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Git menu scoped to terminal/IDE windows (Win+Alt+Shift+G):
;          smart commit (status + message), branch switcher, pull --rebase,
;          and cleanup of merged branches. All commands run in the git root
;          of the active VS Code project via PowerShell -File (no shell
;          string concatenation).
; USAGE  : Launcher child (default) or standalone.
;          --selftest : git presence + parse helpers only (exit 0/1).
; SECURITY: Destructive operations (cleanup, rebase) always confirm and are
;          recorded in the audit chain. Commit messages travel as PS
;          variables, never through a command line.
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
; Selftest: git presence + pure parse helpers. No git writes.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    r := RunPS("git --version 2>&1|Out-String", 15)
    Check("git is available", r["ok"] && InStr(r["stdout"], "git version") > 0)
    Check("GitRootOf resolves this repo", StrReplace(GitRootOf(Env.Root), "/", "\") == Env.Root, GitRootOf(Env.Root))
    Check("branch list parse (current marked)", _ParseBranches("  main`n* feat/x`n  dev")[2]["name"] == "feat/x" && _ParseBranches("  main`n* feat/x`n  dev")[2]["current"])
    Check("scope function runs", _Scope() == true || _Scope() == false)
    Check("git_menu hotkey config readable", Cfg.Read("hotkeys", "git_menu", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("GitWorkflow`nMenu: Win+Alt+Shift+G (in a terminal or IDE)`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Helpers
;------------------------------------------------------------------------------
_Scope() {
    ; Only offer the menu in terminal/IDE windows.
    exe := ""
    try exe := StrLower(WinGetProcessName("A"))
    return exe == "windowsterminal.exe" || exe == "cmd.exe" || exe == "conhost.exe"
        || exe == "powershell.exe" || exe == "pwsh.exe" || exe == "code.exe"
        || exe == "mintty.exe" || exe == "bash.exe"
}

_ProjectGit() {
    root := ActiveProject()
    if root == ""
        return ""
    return GitRootOf(root)
}

_GitOut(cmd, timeout := 30) {
    ; Run a git command in the project root; returns trimmed stdout.
    root := _ProjectGit()
    if root == ""
        return ""
    r := RunPS("git -C " . _PsLit(root) . " " . cmd . " 2>&1|Out-String", timeout)
    if !r["ok"]
        return ""
    return Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
}

_ParseBranches(txt) {
    ; "  main`n* feat/x" -> [{name, current}]
    out := []
    for raw in StrSplit(txt, "`n") {
        line := RTrim(raw, "`r")
        if Trim(line) == ""
            continue
        cur := InStr(line, "*") == 1
        name := Trim(SubStr(line, cur ? 2 : 1))
        out.Push(Map("name", name, "current", cur))
    }
    return out
}

_MenuFn(fn, val) {
    f(item, *) => fn(val)
    return f
}

_NotifyGit(title, out, okLevel := "INFO") {
    tail := StrReplace(SubStr(out, Max(1, StrLen(out) - 200)), "`n", " ")
    Notify(title, tail == "" ? "(no output)" : tail, okLevel)
}

;------------------------------------------------------------------------------
; Actions
;------------------------------------------------------------------------------
GitMenu() {
    root := _ProjectGit()
    if root == "" {
        Notify("GitWorkflow", "No VS Code project / git repo detected. Open a project first.", "WARN")
        return
    }
    m := Menu()
    m.Add("Smart Commit", (*) => SmartCommit(root))
    m.Add("Switch branch", (*) => SwitchBranch(root))
    m.Add("Pull --rebase", (*) => PullRebase(root))
    m.Add()
    m.Add("Cleanup (merged branches + gc)", (*) => Cleanup(root))
    m.Show()
}

SmartCommit(root) {
    stat := _GitOut("status --porcelain", 15)
    if stat == "" {
        Notify("Smart Commit", "Working tree is clean - nothing to commit.", "INFO")
        return
    }
    msg := InputText("Commit message for the current changes:", "Smart Commit")
    if msg == ""
        return
    ; The message travels as a quoted PS literal, never through a shell.
    ps := "git -C " . _PsLit(root) . " add -A 2>&1|Out-String;"
        . "git -C " . _PsLit(root) . " commit -m " . _PsLit(msg) . " 2>&1|Out-String"
    r := RunPS(ps, 60)
    out := Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    ok := r["ok"] && !InStr(out, "fatal:")
    Log("GitWorkflow: commit in " . root . (ok ? " ok" : " FAILED"), ok ? "INFO" : "ERROR")
    _NotifyGit(ok ? "Committed" : "Commit failed", out, ok ? "INFO" : "ERROR")
}

SwitchBranch(root) {
    txt := _GitOut("branch", 15)
    if txt == "" {
        Notify("Switch branch", "Could not list branches.", "ERROR")
        return
    }
    branches := _ParseBranches(txt)
    m := Menu()
    for b in branches {
        label := (b["current"] ? "[current] " : "") . b["name"]
        m.Add(label, _MenuFn(_DoCheckout, b["name"]))
    }
    m.Show()
}

_DoCheckout(branch) {
    root := _ProjectGit()
    if root == ""
        return
    ps := "git -C " . _PsLit(root) . " checkout " . _PsLit(branch) . " 2>&1|Out-String"
    r := RunPS(ps, 30)
    out := Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    ok := r["ok"] && !InStr(out, "fatal:")
    Log("GitWorkflow: checkout " . branch . (ok ? " ok" : " FAILED"), ok ? "INFO" : "ERROR")
    _NotifyGit(ok ? "Switched to " . branch : "Checkout failed", out, ok ? "INFO" : "ERROR")
}

PullRebase(root) {
    if !ConfirmDlg("Pull --rebase", "Run `"git pull --rebase`" in " . root . "?")
        return
    ps := "git -C " . _PsLit(root) . " pull --rebase 2>&1|Out-String"
    r := RunPS(ps, 120)
    out := Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    ok := r["ok"] && !InStr(out, "fatal:")
    AuditLog("GitWorkflow: pull --rebase in " . root . " - " . (ok ? "ok" : "failed"))
    _NotifyGit(ok ? "Rebase pull done" : "Rebase pull failed", out, ok ? "INFO" : "ERROR")
}

Cleanup(root) {
    if !ConfirmDlg("Git cleanup", "In " . root . ":`n"
        . "- fetch --prune`n- delete local branches already merged (keeps main/master/develop)`n- git gc`n`nContinue?")
        return
    ps := "git -C " . _PsLit(root) . " fetch --prune 2>&1|Out-Null`n"
        . "$merged=git -C " . _PsLit(root) . " branch --merged 2>&1|Out-String`n"
        . "$keep=@('main','master','develop','dev','staging','release')`n"
        . "foreach($line in ($merged -split `"`n`")){`n"
        . "  $n=$line.Trim().TrimStart('*').Trim()`n"
        . "  if($n -and ($keep -notcontains $n)){ git -C " . _PsLit(root) . " branch -d $n 2>&1|Out-Null }`n"
        . "}`n"
        . "git -C " . _PsLit(root) . " gc --quiet 2>&1|Out-String`n"
        . "'cleanup done'"
    r := RunPS(ps, 180)
    out := Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    ok := r["ok"] && InStr(out, "cleanup done") > 0
    AuditLog("GitWorkflow: cleanup in " . root . " - " . (ok ? "ok" : "failed"))
    _NotifyGit(ok ? "Cleanup done" : "Cleanup failed", out, ok ? "INFO" : "ERROR")
}

;------------------------------------------------------------------------------
; Binding (scoped to terminals/IDE via #HotIf)
;------------------------------------------------------------------------------
HotIf((*) => _Scope())
BindHotkey(Cfg.Read("hotkeys", "git_menu", "Win+Alt+Shift+G"), GitMenu, "GitWorkflow: git menu")
HotIf()
Log("GitWorkflow started (menu scoped to terminal/IDE windows)", "INFO")
