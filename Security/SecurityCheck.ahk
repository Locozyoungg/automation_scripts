#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\SecurityCheck.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Security posture audit (Lib\SecurityChecks.ahk): Defender,
;          firewall, UAC, updates, autologon, SMBv1, RDP, guest, PS policy,
;          BitLocker, hosts integrity, shares, Defender exclusions, Run keys.
;          Writes Logs\SecurityReport.json + .html and records the summary in
;          the tamper-evident audit chain. Run elevated for full coverage;
;          unprivileged runs degrade to UNKNOWN, never fail.
; USAGE  : Launcher tray "Run Security Check (elevated)" or scheduled task:
;            AutoHotkey64.exe Security\SecurityCheck.ahk --standalone
;          --selftest : read-only subset + report serialization (exit 0/1).
; SECURITY: Read-only. No changes, no network, no secrets in reports.
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
#Include ..\Lib\Core.ahk
#Include ..\Lib\SecurityChecks.ahk

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
    ; Read-only subset: registry, policy, hotfix history, Run keys.
    _SC_Findings := []
    _SC_Uac()
    _SC_PsPolicy()
    _SC_Updates()
    _SC_Autostarts()
    _SC_Autologon()
    _SC_Rdp()
    Check("read-only checks produced findings", _SC_Findings.Length >= 6, "count=" . _SC_Findings.Length)
    Check("findings carry required fields", _SC_Findings[1].Has("status") && _SC_Findings[1].Has("evidence"))
    jsStr := JSON.stringify(_SC_Findings)
    back := JSON.parse(jsStr)
    Check("findings JSON round-trip", back.Length == _SC_Findings.Length)
    html := _SC_ReportHtml(Map("generated", _SC_Now(), "host", "TEST", "user", "TEST", "elevated", 0
        , "summary", Map("pass", 1, "warn", 0, "fail", 0, "unknown", 0), "findings", _SC_Findings))
    Check("HTML report renders a table", InStr(html, "<table>") > 0 && InStr(html, "</html>") > 0)
    Check("HTML escapes evidence", !InStr(_SC_ReportHtml(Map("generated", "", "host", "", "user", "", "elevated", 0
        , "summary", Map("pass", 0, "warn", 0, "fail", 0, "unknown", 0)
        , "findings", [Map("id", "x", "title", "t", "status", "FAIL", "severity", "high"
            , "evidence", "<script>&", "remediation_id", "", "safe_to_autofix", 0)])), "<script>"))
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("Security Check`nRun via the Launcher tray menu or the weekly scheduled task.`nKill-switch: Esc+Pause")

report := _SC_RunAll(true)
s := report["summary"]
if !IsAdmin()
    Log("SecurityCheck ran unprivileged - some checks report UNKNOWN (run elevated for full coverage)", "WARN")
if ArgHas("--standalone") {
    ExitApp(0)
}
; Child/resident mode: audit once at start, then idle (Launcher stop-flag watches).
Notify("Security Check", s["pass"] . " PASS / " . s["warn"] . " WARN / " . s["fail"] . " FAIL - "
    . "see Logs\SecurityReport.html", s["fail"] > 0 ? "WARN" : "INFO")
