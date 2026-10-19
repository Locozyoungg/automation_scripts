#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\HealthHUD.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Win+Alt+H toggles a small always-on-top overlay with CPU, RAM,
;          disk C:, network throughput (3 s delta) and VPN status, refreshed
;          every 3 s via a single PowerShell -File call. Esc (while focused)
;          or the hotkey again hides it.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : one metric fetch, no GUI (exit 0/1).
; SECURITY: Read-only system queries. Nothing is logged except errors.
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
; Metrics engine. Defined BEFORE the selftest block: top-level assignments
; execute in file order and the selftest needs this value.
;------------------------------------------------------------------------------
_HUD_PS := (
    "$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`n"
    . "$os=Get-CimInstance Win32_OperatingSystem`n"
    . "$ram=100*($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize`n"
    . "$d=Get-CimInstance Win32_LogicalDisk | Where-Object DeviceID -eq 'C:' | Select-Object -First 1`n"
    . "$disk=0;if($d){$disk=100*($d.Size-$d.FreeSpace)/$d.Size}`n"
    . "$adapters=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')`n"
    . "$vpn=@($adapters | Where-Object { $_.Name -match 'VPN|WireGuard|wg|tap|tun|ZeroTier|Tailscale' -or $_.InterfaceDescription -match 'VPN|WireGuard|TAP|TUN|ZeroTier|Tailscale' }).Count -gt 0`n"
    . "$rx=0;$tx=0`n"
    . "if($adapters.Count -gt 0){$s=@(Get-NetAdapterStatistics -Name $adapters.Name -ErrorAction SilentlyContinue);if($s){$rx=($s|Measure-Object ReceivedBytes -Sum).Sum;$tx=($s|Measure-Object TransmittedBytes -Sum).Sum}}`n"
    . "@{cpu=[int]$cpu;ram=[int]$ram;disk=[int]$disk;vpn=$vpn;rx=$rx;tx=$tx}|ConvertTo-Json -Compress"
)

;------------------------------------------------------------------------------
; Selftest: single metric fetch. No GUI, no timers.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    r := RunPSJson(_HUD_PS, 40)
    if IsObject(r) && r.Has("cpu")
        Check("metrics fetch: fields present", r.Has("ram") && r.Has("disk") && r.Has("vpn"), "cpu=" . r["cpu"])
    else
        Check("metrics fetch: fields present", false)
    Check("HumanBytes sanity", HumanBytes(1024) == "1.0 KB", HumanBytes(1024))
    Check("hud hotkey config readable", Cfg.Read("hotkeys", "health_hud", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("HealthHUD`nToggle overlay: Win+Alt+H`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; GUI
;------------------------------------------------------------------------------
Global _HudGui := 0
Global _LastRx := 0
Global _LastTx := 0

ToggleHud() {
    Global _HudGui
    if _HudGui is Gui {
        _HudGui.Destroy()
        _HudGui := 0
        SetTimer(_HudTick, 0)
        Log("HealthHUD hidden", "INFO")
        return
    }
    _OpenHud()
}

_OpenHud() {
    Global _HudGui
    g := Gui("+AlwaysOnTop -Caption +ToolWindow", "Health HUD")
    g.SetFont("s10", "Consolas")
    g.AddText("vHud", "CPU --  RAM --  C: --`nnet --  VPN --")
    g.OnEvent("Escape", (*) => ToggleHud())
    g.Show("NoActivate AutoSize")
    _HudGui := g
    _HudTick()
    SetTimer(_HudTick, 3000)
    Log("HealthHUD shown", "INFO")
}

_HudTick() {
    Global _HudGui, _LastRx, _LastTx
    if !(_HudGui is Gui)
        return
    r := RunPSJson(_HUD_PS, 40)
    if !IsObject(r) || !r.Has("cpu") {
        _HudGui["Hud"].Value := "metrics unavailable`n(see Logs\HealthHUD.log)"
        return
    }
    ; Delta between consecutive totals gives the 3 s interval throughput.
    dRx := 0, dTx := 0
    if _LastRx > 0 {
        dRx := r["rx"] - _LastRx
        dTx := r["tx"] - _LastTx
    }
    _LastRx := r["rx"], _LastTx := r["tx"]
    vpnTag := r["vpn"] ? "  VPN ON" : ""
    text := Format("CPU {1}%   RAM {2}%   C: {3}%{4}`nD {5}/s   U {6}/s", r["cpu"], r["ram"], r["disk"], vpnTag
        , HumanBytes(Integer(dRx) // 3), HumanBytes(Integer(dTx) // 3))
    _HudGui["Hud"].Value := text
    ; Keep the overlay docked to the bottom-right of the primary monitor.
    g := _HudGui
    g.GetPos(&gx, &gy, &gw, &gh)
    MonitorGetWorkArea(1, &l, &t, &rt, &b)
    WinMove(rt - gw - 16, b - gh - 16, , , "ahk_id " . g.Hwnd)
}

BindHotkey(Cfg.Read("hotkeys", "health_hud", "Win+Alt+H"), ToggleHud, "HealthHUD: toggle overlay")
Log("HealthHUD started", "INFO")
