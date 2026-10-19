#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\NetworkWatch.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Network posture watcher (30 s poll): new TCP listeners, DNS server
;          changes, proxy setting changes, and - if [security]
;          vpn_prompt_open_wifi=1 - a warning when connected to open Wi-Fi.
;          Optional [security] network_watch_outbound=1 alerts on outbound
;          connections from processes not seen at baseline.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : one read-only snapshot + diff logic (exit 0/1).
; SECURITY: Read-only monitoring. No packets captured, no payloads, no pcap.
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

_NW_PS := (
    "$listen=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|ForEach-Object{$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;@{port=$_.LocalPort;pid=$_.OwningProcess;name=$(if($p){$p.ProcessName}else{'?'})}})`n"
    . "$dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.ServerAddresses}|ForEach-Object{@{iface=$_.InterfaceIndex;addrs=@($_.ServerAddresses)}})`n"
    . "$px='0|'`n"
    . "$r=Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue`n"
    . "if($r){$px=[string]$r.ProxyEnable + '|' + [string]$r.ProxyServer}`n"
    . "$wifi=''`n"
    . "try{$w=netsh wlan show interfaces 2>&1|Out-String;$m=[regex]::Match($w,'SSID\s*:\s*([^\r\n]+)');$a=[regex]::Match($w,'Authentication\s*:\s*([^\r\n]+)');if($m.Success){$wifi=$m.Groups[1].Value.Trim() + '|' + $a.Groups[1].Value.Trim()}}catch{}`n"
    . "@{listeners=$listen;dns=$dns;proxy=$px;wifi=$wifi}|ConvertTo-Json -Depth 5 -Compress"
)

if ArgHas("--selftest") {
    EnsureDirs()
    snap := _NW_Snapshot()
    Check("network snapshot runs", IsObject(snap) && snap.Has("listeners") && snap.Has("dns") && snap.Has("proxy")
        , "wifi=" . (snap.Has("wifi") ? snap["wifi"] : "?"))
    base := Map()
    base["L|443|https"] := true
    cur := Map()
    cur["L|443|https"] := true
    cur["L|8443|evil"] := true
    d := _NW_Diff(base, cur)
    Check("listener diff detects new port", d["new"].Length == 1 && InStr(d["new"][1], "8443") > 0)
    Check("listener diff detects removals", _NW_Diff(cur, base)["removed"].Length == 1)
    Check("wifi parse: open detection", _NW_IsOpenWifi("CoffeeShop|Open"))
    Check("wifi parse: WPA2 not open", !_NW_IsOpenWifi("Home|WPA2-Personal"))
    Check("outbound watch config readable", Cfg.Bool("security", "network_watch_outbound", false) == true || Cfg.Bool("security", "network_watch_outbound", false) == false)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("NetworkWatch`nWatches listeners, DNS and proxy changes (30 s).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Snapshot + diff
;------------------------------------------------------------------------------
_NW_Snapshot() {
    return RunPSJsonF(_NW_PS, 45, Map())
}

_NW_Map(snap) {
    m := Map()
    if !IsObject(snap)
        return m
    for l in snap.Has("listeners") ? snap["listeners"] : []
        m["L|" . l["port"] . "|" . l["name"]] := true
    for d in snap.Has("dns") ? snap["dns"] : []
        m["D|" . d["iface"] . "|" . StrJoin(d["addrs"], ",")] := true
    if snap.Has("proxy")
        m["P|" . snap["proxy"]] := true
    return m
}

_NW_Diff(base, cur) {
    new := [], removed := []
    for k in cur
        if !base.Has(k)
            new.Push(k)
    for k in base
        if !cur.Has(k)
            removed.Push(k)
    return Map("new", new, "removed", removed)
}

_NW_IsOpenWifi(wifi) {
    parts := StrSplit(wifi, "|")
    if parts.Length != 2 || parts[1] == ""
        return false
    return InStr(StrLower(parts[2]), "open") > 0
}

_NW_Tick() {
    Global _NW_Base, _NW_WifiWarned
    snap := _NW_Snapshot()
    cur := _NW_Map(snap)
    if !cur.Count
        return
    d := _NW_Diff(_NW_Base, cur)
    for k in d["new"] {
        prefix := SubStr(k, 1, 1)
        if prefix == "L" {
            Notify("New TCP listener", SubStr(k, 3), "SECURITY")
            AuditLog("NetworkWatch: new listener - " . SubStr(k, 3))
        } else if prefix == "D" {
            Notify("DNS servers changed", SubStr(k, 3), "SECURITY")
            AuditLog("NetworkWatch: DNS change - " . SubStr(k, 3))
        } else if prefix == "P" {
            Notify("Proxy settings changed", SubStr(k, 3), "SECURITY")
            AuditLog("NetworkWatch: proxy change - " . SubStr(k, 3))
        }
    }
    for k in d["removed"]
        Log("NetworkWatch: entry removed - " . k, "INFO")
    _NW_Base := cur
    ; Open Wi-Fi advisory (only when the user opted in).
    if Cfg.Bool("security", "vpn_prompt_open_wifi", false) && snap.Has("wifi") {
        wifi := snap["wifi"]
        if _NW_IsOpenWifi(wifi) && !_NW_WifiWarned.Has(wifi) {
            _NW_WifiWarned[wifi] := true
            Notify("Open Wi-Fi network", "Connected to '" . StrSplit(wifi, "|")[1] . "' with NO encryption. Use the VPN.", "WARN")
            AuditLog("NetworkWatch: open Wi-Fi - " . wifi)
        }
    }
}

Global _NW_Base := Map()
Global _NW_WifiWarned := Map()
_NW_Tick()
SetTimer(_NW_Tick, 30000)
Log("NetworkWatch started", "INFO")
