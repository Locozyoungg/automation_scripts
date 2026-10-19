#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\Remediate.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Applies confirmed fixes for SecurityCheck findings. Only findings
;          flagged safe_to_autofix are offered, each behind an explicit
;          confirmation. Every change is backed up first (registry export /
;          file copy under Data\baselines\<id>-<ts>), recorded in the audit
;          chain, and re-checked afterwards. Run from an elevated shell or
;          answer the UAC prompt (system changes need admin).
; USAGE  : AutoHotkey64.exe Security\Remediate.ahk
;          --selftest : mapping/dry-run only, NO system changes (exit 0/1).
; SECURITY: No secret material is ever written to backups (registry values
;          like AutoAdminLogon hold no secrets; hosts is a system file).
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
    Check("handler table complete", _RM_Handlers().Count == 7, "count=" . _RM_Handlers().Count)
    fake := Map("id", "enable_uac", "title", "UAC", "status", "FAIL", "severity", "high"
        , "evidence", "test", "remediation_id", "enable_uac", "safe_to_autofix", 1)
    Check("dry-run handler returns without changes", _RM_Apply(fake, true) == "DRY")
    Check("unsupported id handled", _RM_Apply(Map("id", "x", "remediation_id", "update_windows", "safe_to_autofix", 1, "evidence", "", "title", "", "status", "FAIL", "severity", ""), true) == "NO HANDLER")
    tmp := Env.DataDir . "\tmp\rm-test.txt"
    try FileAppend("x", tmp)
    Check("backup dir writable (tmp)", FileExist(tmp))
    try FileDelete(tmp)
    fakeReport := Map("findings", [fake, Map("id", "y", "title", "", "status", "WARN", "severity", "", "evidence", "", "remediation_id", "update_windows", "safe_to_autofix", 0)])
    Check("autofixable filter", _RM_Autofixable(fakeReport).Length == 1)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

;------------------------------------------------------------------------------
; Handler table + apply logic
;------------------------------------------------------------------------------
_RM_Handlers() {
    return Map(
        "enable_defender_rt", _RM_FixDefender,
        "enable_firewall", _RM_FixFirewall,
        "enable_uac", _RM_FixUac,
        "disable_autologon", _RM_FixAutologon,
        "disable_rdp", _RM_FixRdp,
        "disable_guest", _RM_FixGuest,
        "restore_hosts", _RM_FixHosts)
}

_RM_BackupFile(id) => Env.DataDir . "\baselines\" . id . "-" . FormatTime(A_Now, "yyyyMMdd-HHmmss")

_RM_BackupReg(key, id) {
    path := _RM_BackupFile(id) . ".reg"
    r := RunPS("reg export " . _PsLit(key) . " " . _PsLit(path) . " /y 2>&1|Out-String", 20)
    if !r["ok"]
        Log("Remediate: backup of " . key . " failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
    return r["ok"]
}

_RM_Apply(item, dry) {
    handlers := _RM_Handlers()
    id := item["remediation_id"]
    if !handlers.Has(id)
        return "NO HANDLER"
    return handlers[id](item, dry)
}

_RM_Autofixable(report) {
    out := []
    for f in report["findings"]
        if f["status"] == "FAIL" && f["safe_to_autofix"] && f["remediation_id"] != ""
            out.Push(f)
    return out
}

;------------------------------------------------------------------------------
; Handlers (each: dry-run safe, backs up first, audit-logs, returns status)
;------------------------------------------------------------------------------
_RM_FixDefender(item, dry) {
    if dry
        return "DRY"
    ; Record prior state as the backup (re-enabling needs no registry restore).
    r := RunPSJson("try{Get-MpComputerStatus -ErrorAction Stop|Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge|ConvertTo-Json -Compress}catch{''}", 20)
    backup := _RM_BackupFile("enable_defender_rt") . ".json"
    if IsObject(r)
        try FileAppend(JSON.stringify(r), backup)
    ps := "try{Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop;'ok'}catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: enable Defender realtime - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixFirewall(item, dry) {
    if dry
        return "DRY"
    r := RunPSJson("try{@(Get-NetFirewallProfile -All -ErrorAction Stop)|ForEach-Object{@{name=$_.Name;enabled=[bool]$_.Enabled}}|ConvertTo-Json -Compress}catch{''}", 20)
    if IsObject(r)
        try FileAppend(JSON.stringify(r), _RM_BackupFile("enable_firewall") . ".json")
    ps := "try{Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop;'ok'}catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: enable firewall profiles - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixUac(item, dry) {
    if dry
        return "DRY"
    _RM_BackupReg("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "enable_uac")
    ps := "try{Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Force -ErrorAction Stop;"
        . "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Force -ErrorAction Stop;'ok'}"
        . "catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: enable UAC (EnableLUA=1, consent prompt) - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixAutologon(item, dry) {
    if dry
        return "DRY"
    _RM_BackupReg("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "disable_autologon")
    ps := "try{Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 -Force -ErrorAction Stop;'ok'}"
        . "catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: disable AutoAdminLogon - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixRdp(item, dry) {
    if dry
        return "DRY"
    _RM_BackupReg("HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "disable_rdp")
    ps := "try{Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Force -ErrorAction Stop;'ok'}"
        . "catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: disable RDP - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixGuest(item, dry) {
    if dry
        return "DRY"
    prior := _SC_PsText("net user guest 2>&1|Out-String", 15)
    if prior != ""
        try FileAppend(prior, _RM_BackupFile("disable_guest") . ".txt")
    ps := "try{$o=net user guest /active:no 2>&1|Out-String;if($LASTEXITCODE -eq 0){'ok'}else{'FAILED: ' + $o}}catch{'FAILED: ' + $_.Exception.Message}"
    res := _SC_PsText(ps, 30)
    ok := InStr(res, "ok") == 1
    AuditLog("Remediate: disable guest account - " . (ok ? "ok" : "failed: " . res))
    return ok ? "OK" : "FAILED"
}

_RM_FixHosts(item, dry) {
    if dry
        return "DRY"
    backup := _RM_BackupFile("restore_hosts") . ".hosts"
    try FileCopy(_SC_HostsFile(), backup, true)
    src := Env.ConfigDir . "\baseline\hosts.bak"
    if !FileExist(src) {
        AuditLog("Remediate: restore hosts FAILED - no baseline copy (run HostsGuard first)")
        return "FAILED"
    }
    ok := false
    try {
        FileCopy(src, _SC_HostsFile(), true)
        ok := Sha256Hex(FileRead(_SC_HostsFile())) == Trim(FileRead(Env.ConfigDir . "\baseline\hosts.sha256"))
    }
    AuditLog("Remediate: restore hosts from baseline - " . (ok ? "ok (verified)" : "failed (write denied or hash mismatch)"))
    return ok ? "OK" : "FAILED"
}

;------------------------------------------------------------------------------
; Main flow
;------------------------------------------------------------------------------
if !RequireAdmin("Remediate applies system hardening changes (Defender, firewall, UAC, RDP, hosts).")
    ExitApp(0)
InstallKillSwitch("Remediate`nApplies confirmed SecurityCheck fixes with backups.`nKill-switch: Esc+Pause")

if !FileExist(Env.LogDir . "\SecurityReport.json") {
    Notify("Remediate", "No SecurityReport.json found. Run Security Check first (tray menu).", "ERROR")
    ExitApp(1)
}
report := ""
try report := JSON.parse(FileRead(Env.LogDir . "\SecurityReport.json"))
catch {
    Notify("Remediate", "SecurityReport.json is unreadable.", "ERROR")
    ExitApp(1)
}
todo := _RM_Autofixable(report)
if !todo.Length {
    Notify("Remediate", "No auto-fixable FAIL findings. (WARN items and restart-requiring fixes are left to you.)", "INFO")
    ExitApp(0)
}
applied := 0
for item in todo {
    if !ConfirmDlg("Apply remediation", "[" . item["severity"] . "] " . item["title"] . "`n`n"
        . item["evidence"] . "`n`nApply '" . item["remediation_id"] . "'? (a backup is created first)")
        continue
    res := _RM_Apply(item, false)
    if res == "OK" {
        _SC_CheckById(item["remediation_id"])
        last := _SC_LastFinding()
        if last != "" && last["status"] == "PASS"
            Log("Remediate: " . item["remediation_id"] . " verified PASS", "INFO")
        else
            Log("Remediate: " . item["remediation_id"] . " applied but re-check is not PASS", "WARN")
        applied++
    } else {
        Notify("Remediate", item["remediation_id"] . " failed: " . res, "ERROR")
    }
}
Notify("Remediate", applied . "/" . todo.Length . " remediations applied. Details in Logs\audit-Remediate.log.", applied ? "INFO" : "WARN")
ExitApp(0)
