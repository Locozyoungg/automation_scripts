#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\DevEnvDoctor.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Win+Alt+D collects a toolchain report (node, npm, pnpm, yarn,
;          python, git, docker, dotnet, cargo, go, java, VS Code + disk
;          free + elevation state) into Logs\DevEnvDoctor-<ts>.md, shows a
;          toast summary, and offers to open it. An npm audit of the active
;          project can be appended on explicit confirmation (it is the only
;          network call this tool can make).
; USAGE  : Launcher child (default) or standalone.
;          --selftest : one collection run + report write to temp (exit 0/1).
; SECURITY: No secrets collected. npm audit runs only after confirmation.
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
; Collection engine. Defined BEFORE the selftest block: top-level assignments
; execute in file order and the selftest needs this value.
;------------------------------------------------------------------------------
_DOC_PS := (
    "$tools='node','npm','pnpm','yarn','python','git','docker','dotnet','cargo','go','java','code'`n"
    . "$out=@()`n"
    . "foreach($t in $tools){`n"
    . "  $cmd=Get-Command $t -ErrorAction SilentlyContinue`n"
    . "  if(-not $cmd){$out+=@{name=$t;found=$false;version=''};continue}`n"
    . "  $v=''`n"
    . "  if($t -eq 'code'){ $v='installed (VS Code)' }`n"
    . "  else { try { $v=((& $t --version 2>&1 | Select-Object -First 1) -join ' ') } catch { $v='(error querying)' } }`n"
    . "  $out+=@{name=$t;found=$true;version=$v}`n"
    . "}`n"
    . "$free=(Get-CimInstance Win32_LogicalDisk | Where-Object DeviceID -eq 'C:' | Select-Object -First 1)`n"
    . "$diskFree=0;if($free){$diskFree=[math]::Round($free.FreeSpace/1GB,1)}`n"
    . "@{tools=$out;diskFreeGB=$diskFree;user=$env:USERNAME;elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json -Depth 5 -Compress"
)

;------------------------------------------------------------------------------
; Selftest: one collection run + temp report write. No network (no audit).
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    r := RunPSJson(_DOC_PS, 90)
    if IsObject(r) && r.Has("tools")
        Check("toolchain collection: >= 8 tools", r["tools"].Length >= 8, "count=" . r["tools"].Length)
    else
        Check("toolchain collection: >= 8 tools", false)
    tmp := Env.DataDir . "\tmp\ded-test.md"
    _WriteReport(tmp, r, "")
    Check("report write + read back", FileExist(tmp) && InStr(FileRead(tmp), "# Dev Environment Doctor") > 0)
    try FileDelete(tmp)
    Check("doctor hotkey config readable", Cfg.Read("hotkeys", "dev_doctor", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("DevEnvDoctor`nReport: Win+Alt+D`nKill-switch: Esc+Pause")

_WriteReport(path, data, auditSection) {
    lines := []
    lines.Push("# Dev Environment Doctor - " . FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"))
    lines.Push("")
    lines.Push("Host: " . EnvGet("COMPUTERNAME") . " | User: " . data["user"]
        . " | Elevated: " . (data["elevated"] ? "yes" : "no") . " | Disk C: free: " . data["diskFreeGB"] . " GB")
    lines.Push("")
    lines.Push("| Tool | Found | Version |")
    lines.Push("|---|---|---|")
    for t in data["tools"]
        lines.Push("| " . t["name"] . " | " . (t["found"] ? "yes" : "NO") . " | " . _MdEsc(t["version"]) . " |")
    if auditSection != "" {
        lines.Push("")
        lines.Push(auditSection)
    }
    try FileAppend(StrJoin(lines, "`n") . "`n", path)
    catch as e {
        Log("DevEnvDoctor: report write failed: " . ErrText(e), "ERROR")
        return ""
    }
    return path
}

_MdEsc(s) => StrReplace(StrReplace(String(s), "|", "\|"), "`n", " ")

;------------------------------------------------------------------------------
; Action
;------------------------------------------------------------------------------
RunDoctor() {
    data := RunPSJson(_DOC_PS, 90)
    if !IsObject(data) || !data.Has("tools") {
        Notify("DevEnvDoctor", "Toolchain collection failed. See Logs\DevEnvDoctor.log.", "ERROR")
        return
    }
    found := 0
    for t in data["tools"]
        if t["found"]
            found++
    audit := ""
    root := ActiveProject()
    if root != "" && FileExist(root . "\package-lock.json")
        if ConfirmDlg("DevEnvDoctor", "Run `"npm audit`" on " . root . "? (network call - checks known vulnerabilities)")
            audit := _NpmAudit(root)
    path := Env.LogDir . "\DevEnvDoctor-" . FormatTime(A_Now, "yyyyMMdd-HHmmss") . ".md"
    _WriteReport(path, data, audit)
    Log("DevEnvDoctor: " . found . "/" . data["tools"].Length . " tools found; report " . path, "INFO")
    Notify("DevEnvDoctor", found . "/" . data["tools"].Length . " tools found; disk free " . data["diskFreeGB"] . " GB"
        . (audit != "" ? "; npm audit appended" : ""), "INFO")
    if ConfirmDlg("DevEnvDoctor", "Open the report?")
        Run(_Q(path))
}

_NpmAudit(root) {
    ; Metadata summary only: severity counts, never dependency details.
    ps := "Set-Location " . _PsLit(root) . "; npm audit --json 2>&1|Out-String"
    r := RunPS(ps, 120)
    out := Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n")
    section := "## npm audit (" . root . ")" . "`n`n"
    if r["ok"] {
        try {
            obj := JSON.parse(out)
            if obj.Has("metadata") && obj["metadata"].Has("vulnerabilities") {
                v := obj["metadata"]["vulnerabilities"]
                section .= "Known vulnerabilities: low " . v["low"] . ", moderate " . v["moderate"]
                    . ", high " . v["high"] . ", critical " . v["critical"] . "."
            } else {
                section .= "No known vulnerabilities."
            }
        } catch {
            section .= "Audit output unparseable - see the terminal output."
        }
    } else {
        section .= "npm audit failed (exit " . r["exit"] . ") or timed out."
    }
    return section
}

BindHotkey(Cfg.Read("hotkeys", "dev_doctor", "Win+Alt+D"), RunDoctor, "DevEnvDoctor: run report")
Log("DevEnvDoctor started", "INFO")
