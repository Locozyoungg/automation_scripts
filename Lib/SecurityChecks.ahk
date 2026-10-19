;==============================================================================
; FILE   : <ROOT>\Lib\SecurityChecks.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Shared security-posture checks + report builder. Included by
;          Security\SecurityCheck.ahk (audit) and Security\Remediate.ahk
;          (fixes). One function per check, each appending a finding:
;          {id, title, status: PASS|WARN|FAIL|UNKNOWN, severity, evidence,
;           remediation_id, safe_to_autofix}.
; SECURITY: Read-only queries. Nothing is changed by this library. Evidence
;          never contains secrets. Failures degrade to UNKNOWN, never crash.
; NOTE   : Include AFTER Core.ahk (uses RunPS/RegReadVal/Sha256Hex/JSON/Audit).
;==============================================================================
#Requires AutoHotkey v2.0
#Warn All, StdOut

Global _SC_Findings := []

_SC_Add(id, title, status, severity, evidence, remediation_id := "", autofix := false) {
    Global _SC_Findings
    _SC_Findings.Push(Map("id", id, "title", title, "status", status, "severity", severity
        , "evidence", evidence, "remediation_id", remediation_id, "safe_to_autofix", autofix))
}

_SC_PsJson(script, timeout := 20) {
    r := RunPSJson(script, timeout)
    return IsObject(r) ? r : ""
}

_SC_PsText(script, timeout := 20) {
    r := RunPS(script, timeout)
    return r["ok"] ? Trim(StrReplace(r["stdout"], "`r`n", "`n"), "`r`n") : ""
}

_SC_HostsFile() => EnvGet("SystemRoot") . "\System32\drivers\etc\hosts"

;------------------------------------------------------------------------------
; Checks
;------------------------------------------------------------------------------
_SC_Defender() {
    r := _SC_PsJson("try{$c=Get-MpComputerStatus -ErrorAction Stop;@{rt=$c.RealTimeProtectionEnabled;age=[int]$c.AntivirusSignatureAge}}|ConvertTo-Json -Compress)catch{''}", 20)
    if r == "" || !r.Has("rt") {
        _SC_Add("defender_rt", "Defender real-time protection", "UNKNOWN", "med"
            , "Could not query Defender status (elevation or service state)", "enable_defender_rt", true)
        return
    }
    if r["rt"] {
        if r.Has("age") && Integer(r["age"]) > 7
            _SC_Add("defender_sigs", "Defender signatures fresh", "WARN", "med"
                , "Signature age " . r["age"] . " days (older than 7)", "update_windows", false)
        else
            _SC_Add("defender_rt", "Defender real-time protection", "PASS", "info"
                , "Real-time protection on; signatures " . r["age"] . " day(s) old")
    } else {
        _SC_Add("defender_rt", "Defender real-time protection", "FAIL", "high"
            , "Real-time protection is OFF", "enable_defender_rt", true)
    }
}

_SC_Firewall() {
    r := _SC_PsJson("try{@(Get-NetFirewallProfile -All -ErrorAction Stop)|ForEach-Object{@{name=$_.Name;enabled=[bool]$_.Enabled}}|ConvertTo-Json -Compress}catch{''}", 20)
    if r == "" || !(r is Array) || !r.Length {
        _SC_Add("firewall", "Windows Firewall", "UNKNOWN", "med"
            , "Could not read firewall profiles (elevation required)", "enable_firewall", true)
        return
    }
    off := ""
    for p in r
        if !p["enabled"]
            off .= (off == "" ? "" : ", ") . p["name"]
    if off != ""
        _SC_Add("firewall", "Windows Firewall", "FAIL", "high"
            , "Disabled profile(s): " . off, "enable_firewall", true)
    else
        _SC_Add("firewall", "Windows Firewall", "PASS", "info", "All profiles enabled")
}

_SC_Uac() {
    lua := RegReadVal("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    consent := RegReadVal("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    if lua == "" {
        _SC_Add("uac", "User Account Control", "UNKNOWN", "med"
            , "Could not read UAC policy keys", "enable_uac", true)
        return
    }
    if lua != "1"
        _SC_Add("uac", "User Account Control", "FAIL", "high"
            , "EnableLUA is " . lua . " (UAC disabled)", "enable_uac", true)
    else if consent == "0"
        _SC_Add("uac", "User Account Control", "WARN", "med"
            , "Elevated actions never prompt (ConsentPromptBehaviorAdmin=0)", "enable_uac", true)
    else
        _SC_Add("uac", "User Account Control", "PASS", "info"
            , "EnableLUA=1, ConsentPromptBehaviorAdmin=" . consent)
}

_SC_Updates() {
    r := _SC_PsJson("try{$h=Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 1;@{days=[int]((Get-Date)-$h.InstalledOn).TotalDays;date=$h.InstalledOn.ToString('yyyy-MM-dd')}}|ConvertTo-Json -Compress}catch{''}", 25)
    if r == "" || !r.Has("days") {
        _SC_Add("updates", "Windows updates", "UNKNOWN", "low", "Could not read update history")
        return
    }
    days := Integer(r["days"])
    if days > 90
        _SC_Add("updates", "Windows updates", "FAIL", "med"
            , "Last update installed " . days . " days ago (" . r["date"] . ")", "update_windows", false)
    else if days > 30
        _SC_Add("updates", "Windows updates", "WARN", "low"
            , "Last update installed " . days . " days ago (" . r["date"] . ")", "update_windows", false)
    else
        _SC_Add("updates", "Windows updates", "PASS", "info", "Last update " . days . " day(s) ago (" . r["date"] . ")")
}

_SC_Autologon() {
    v := RegReadVal("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    if v == "" {
        _SC_Add("autologon", "Automatic logon", "UNKNOWN", "low", "Could not read Winlogon keys", "disable_autologon", true)
        return
    }
    if v == "1"
        _SC_Add("autologon", "Automatic logon", "FAIL", "high"
            , "AutoAdminLogon=1 - the machine logs in without a password prompt", "disable_autologon", true)
    else
        _SC_Add("autologon", "Automatic logon", "PASS", "info", "AutoAdminLogon is off")
}

_SC_Smb1() {
    r := _SC_PsJson("try{@{s1=[bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol}|ConvertTo-Json -Compress}catch{''}", 20)
    if r == "" || !r.Has("s1") {
        _SC_Add("smb1", "SMBv1 protocol", "UNKNOWN", "med", "Could not query SMB configuration (elevation required)", "disable_smb1", false)
        return
    }
    if r["s1"]
        _SC_Add("smb1", "SMBv1 protocol", "FAIL", "high"
            , "SMBv1 is enabled (EternalBlue-class attacks). Disabling needs a restart.", "disable_smb1", false)
    else
        _SC_Add("smb1", "SMBv1 protocol", "PASS", "info", "SMBv1 disabled")
}

_SC_Rdp() {
    v := RegReadVal("HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if v == "" {
        _SC_Add("rdp", "Remote Desktop", "UNKNOWN", "low", "Could not read Terminal Server keys", "disable_rdp", true)
        return
    }
    if v == "0"
        _SC_Add("rdp", "Remote Desktop", "FAIL", "med"
            , "RDP is enabled (fDenyTSConnections=0). Disable unless you use it.", "disable_rdp", true)
    else
        _SC_Add("rdp", "Remote Desktop", "PASS", "info", "RDP disabled")
}

_SC_Guest() {
    out := _SC_PsText("net user guest 2>&1|Out-String", 15)
    if out == "" {
        _SC_Add("guest", "Guest account", "UNKNOWN", "low", "Could not query the guest account", "disable_guest", true)
        return
    }
    if RegExMatch(out, "i)Account active\s+Yes")
        _SC_Add("guest", "Guest account", "FAIL", "high"
            , "The Guest account is ACTIVE", "disable_guest", true)
    else
        _SC_Add("guest", "Guest account", "PASS", "info", "Guest account disabled")
}

_SC_PsPolicy() {
    out := _SC_PsText("Get-ExecutionPolicy 2>&1|Out-String", 15)
    pol := StrLower(Trim(out))
    if pol == "" {
        _SC_Add("ps_policy", "PowerShell execution policy", "UNKNOWN", "low", "Could not read the policy")
        return
    }
    if pol == "unrestricted" || pol == "bypass"
        _SC_Add("ps_policy", "PowerShell execution policy", "WARN", "med"
            , "Execution policy is " . pol . " (any script can run). Consider RemoteSigned.")
    else
        _SC_Add("ps_policy", "PowerShell execution policy", "PASS", "info", "Policy: " . pol)
}

_SC_Bitlocker() {
    r := _SC_PsJson("try{$b=Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop;@{status=[int]$b.ProtectionStatus}}|ConvertTo-Json -Compress}catch{''}", 25)
    if r == "" || !r.Has("status") {
        _SC_Add("bitlocker", "BitLocker (C:)", "UNKNOWN", "low"
            , "Could not query BitLocker (elevation required)", "enable_bitlocker", false)
        return
    }
    if r["status"] == 1
        _SC_Add("bitlocker", "BitLocker (C:)", "PASS", "info", "Drive encryption protection is ON")
    else
        _SC_Add("bitlocker", "BitLocker (C:)", "WARN", "low"
            , "ProtectionStatus=" . r["status"] . " (off or suspended)", "enable_bitlocker", false)
}

_SC_Hosts() {
    baseline := Env.ConfigDir . "\baseline\hosts.sha256"
    if !FileExist(baseline) {
        _SC_Add("hosts_integrity", "Hosts file integrity", "WARN", "low"
            , "No baseline yet - run HostsGuard once to create one (Config\baseline)", "restore_hosts", true)
        return
    }
    expect := Trim(FileRead(baseline))
    cur := Sha256Hex(FileRead(_SC_HostsFile()))
    if cur == "" {
        _SC_Add("hosts_integrity", "Hosts file integrity", "UNKNOWN", "med", "Could not hash the hosts file", "restore_hosts", true)
        return
    }
    if cur == expect
        _SC_Add("hosts_integrity", "Hosts file integrity", "PASS", "info", "Hosts file matches the baseline")
    else
        _SC_Add("hosts_integrity", "Hosts file integrity", "FAIL", "med"
            , "Hosts file differs from the baseline (DNS hijack check!)", "restore_hosts", true)
}

_SC_Shares() {
    r := _SC_PsJson("try{@(Get-SmbShare -ErrorAction Stop)|ForEach-Object{$_.Name}|ConvertTo-Json -Compress}catch{''}", 20)
    if r == "" || !(r is Array) {
        _SC_Add("smb_shares", "SMB shares", "UNKNOWN", "low", "Could not enumerate shares (elevation required)")
        return
    }
    extra := []
    for n in r
        if !(n == "ADMIN$" || n == "C$" || n == "IPC$" || n == "print$")
            extra.Push(n)
    if extra.Length
        _SC_Add("smb_shares", "SMB shares", "WARN", "low"
            , extra.Length . " non-default share(s): " . StrJoin(extra, ", ") . " - review them")
    else
        _SC_Add("smb_shares", "SMB shares", "PASS", "info", "No non-default SMB shares")
}

_SC_MpExclusions() {
    r := _SC_PsJson("try{$m=Get-MpPreference -ErrorAction Stop;@{paths=@($m.ExclusionPath).Count;procs=@($m.ExclusionProcess).Count}}|ConvertTo-Json -Compress}catch{''}", 20)
    if r == "" || !r.Has("paths") {
        _SC_Add("def_exclusions", "Defender exclusions", "UNKNOWN", "low", "Could not read Defender exclusions (elevation required)")
        return
    }
    total := Integer(r["paths"]) + Integer(r["procs"])
    if total > 0
        _SC_Add("def_exclusions", "Defender exclusions", "WARN", "med"
            , total . " exclusion(s) configured - malware often hides there. Review: Settings > Defender > Exclusions")
    else
        _SC_Add("def_exclusions", "Defender exclusions", "PASS", "info", "No Defender exclusions")
}

_SC_Autostarts() {
    r := _SC_PsJson("$n=0;foreach($h in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'){$p=Get-ItemProperty -Path $h -ErrorAction SilentlyContinue;if($p){$n+=($p.PSObject.Properties|Where-Object{$_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')}).Count}};@{count=$n}|ConvertTo-Json -Compress", 20)
    if r == "" || !r.Has("count") {
        _SC_Add("autostarts", "Autostart entries", "UNKNOWN", "low", "Could not enumerate Run keys")
        return
    }
    n := Integer(r["count"])
    if n > 15
        _SC_Add("autostarts", "Autostart entries", "WARN", "low"
            , n . " Run-key entries - PersistenceMonitor keeps a full baseline")
    else
        _SC_Add("autostarts", "Autostart entries", "PASS", "info", n . " Run-key entr(ies)")
}

;------------------------------------------------------------------------------
; Report building
;------------------------------------------------------------------------------
_SC_AllChecks() {
    return [
        _SC_Defender, _SC_Firewall, _SC_Uac, _SC_Updates, _SC_Autologon,
        _SC_Smb1, _SC_Rdp, _SC_Guest, _SC_PsPolicy, _SC_Bitlocker,
        _SC_Hosts, _SC_Shares, _SC_MpExclusions, _SC_Autostarts]
}

_SC_CheckById(remediationId) {
    ; Re-run the check responsible for a remediation id (post-fix verification).
    switch remediationId {
    case "enable_defender_rt": _SC_Defender()
    case "enable_firewall": _SC_Firewall()
    case "enable_uac": _SC_Uac()
    case "disable_autologon": _SC_Autologon()
    case "disable_rdp": _SC_Rdp()
    case "disable_guest": _SC_Guest()
    case "restore_hosts": _SC_Hosts()
    default:
        Log("SecurityChecks: no check for remediation id '" . remediationId . "'", "WARN")
    }
}

_SC_LastFinding() {
    Global _SC_Findings
    return _SC_Findings.Length ? _SC_Findings[_SC_Findings.Length] : ""
}

_SC_RunAll(writeReport := true) {
    Global _SC_Findings
    _SC_Findings := []
    for fn in _SC_AllChecks()
        fn()
    pass := 0, warn := 0, fail := 0, unknown := 0
    for f in _SC_Findings {
        switch f["status"] {
        case "PASS": pass++
        case "WARN": warn++
        case "FAIL": fail++
        default: unknown++
        }
    }
    report := Map(
        "generated", _SC_Now(), "host", EnvGet("COMPUTERNAME"), "user", EnvGet("USERNAME"),
        "elevated", IsAdmin(), "toolkit_version", TOOLKIT_VERSION,
        "summary", Map("pass", pass, "warn", warn, "fail", fail, "unknown", unknown),
        "findings", _SC_Findings)
    if writeReport {
        try FileAppend(JSON.stringify(report), Env.LogDir . "\SecurityReport.json")
        catch as e {
            Log("SecurityChecks: report write failed: " . ErrText(e), "ERROR")
        }
        try FileAppend(_SC_ReportHtml(report), Env.LogDir . "\SecurityReport.html")
        AuditLog("SecurityCheck complete: " . pass . " PASS / " . warn . " WARN / " . fail . " FAIL / "
            . unknown . " UNKNOWN (elevated=" . (IsAdmin() ? "yes" : "no") . ")")
    }
    return report
}

_SC_Now() {
    return Format("{1}.{2}", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"), SubStr("00" . A_MSec, -2))
}

_SC_HtmlEsc(s) => StrReplace(StrReplace(StrReplace(String(s), "&", "&amp;"), "<", "&lt;"), ">", "&gt;")

_SC_ReportHtml(report) {
    lines := []
    lines.Push("<!DOCTYPE html><html><head><meta charset=`"utf-8`"><title>Security Report</title>")
    lines.Push("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111}")
    lines.Push("table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left}")
    lines.Push(".PASS{background:#e6f4ea}.WARN{background:#fef7e0}.FAIL{background:#fce8e6}.UNKNOWN{background:#f1f3f4}")
    lines.Push(".s{font-weight:bold}</style></head><body>")
    lines.Push("<h2>Security Posture Report</h2>")
    lines.Push("<p>" . _SC_HtmlEsc(report["host"]) . " / " . _SC_HtmlEsc(report["user"]) . " / generated "
        . _SC_HtmlEsc(report["generated"]) . " / elevated: " . (report["elevated"] ? "yes" : "no") . "</p>")
    lines.Push("<p>Summary: <b>" . report["summary"]["pass"] . " PASS</b>, " . report["summary"]["warn"] . " WARN, "
        . report["summary"]["fail"] . " FAIL, " . report["summary"]["unknown"] . " UNKNOWN</p>")
    lines.Push("<table><tr><th>Status</th><th>Severity</th><th>Check</th><th>Evidence</th><th>Auto-fixable</th></tr>")
    for f in report["findings"] {
        lines.Push("<tr class=`"" . f["status"] . "`"><td class=`"s`">" . f["status"] . "</td><td>"
            . _SC_HtmlEsc(f["severity"]) . "</td><td>" . _SC_HtmlEsc(f["title"]) . "</td><td>"
            . _SC_HtmlEsc(f["evidence"]) . "</td><td>"
            . (f["safe_to_autofix"] ? ("yes (" . _SC_HtmlEsc(f["remediation_id"]) . ")") : "-") . "</td></tr>")
    }
    lines.Push("</table><p><i>Run Security\Remediate.ahk to apply confirmed auto-fixes. Every fix is backed up and audit-logged.</i></p>")
    lines.Push("</body></html>")
    return StrJoin(lines, "`n")
}
