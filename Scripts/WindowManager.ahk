#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\WindowManager.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Per-monitor window layouts (Config\windowlayout.ini): save the
;          current arrangement (Win+Numpad1), restore it (Win+Numpad0),
;          half/quarter snapping (Win+Alt+Arrows, +Shift for quarters),
;          move a window to the next monitor (Win+Alt+M). Auto-restores the
;          default layout when the display configuration changes.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : layout parsing + geometry math only, no window moves.
; SECURITY: Window geometry is local-only; nothing leaves the machine.
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
; Selftest: layout parsing + geometry math. No window moves.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    rules := _LayoutRules()
    Check("layout rules parsed (3 shipped)", rules.Length == 3, "count=" . rules.Length)
    Check("ide rule matches code.exe", rules[1]["exe"] == "code.exe" && rules[1]["monitor"] == 1)
    MonitorGetWorkArea(1, &l, &t, &r, &b)
    rect := _SnapRect("Left", false, l, t, r, b)
    Check("half rect: left", rect["x"] == l && rect["w"] == (r - l) // 2 && rect["h"] == b - t)
    q := _SnapRect("Left", true, l, t, r, b)
    Check("quarter rect: shift+left", q["y"] == t + (b - t) // 2 && q["w"] == (r - l) // 2)
    hwnd := WinExist("A")
    Check("monitor detection returns >= 1", _MonitorOf(hwnd) >= 1)
    tmp := Env.DataDir . "\tmp\wm-test.json"
    data := Map("ide", Map("mon", 1, "x", 0, "y", 0, "w", 800, "h", 600))
    try FileAppend(JSON.stringify(data), tmp)
    back := JSON.parse(FileRead(tmp))
    Check("layout JSON round-trip", back["ide"]["w"] == 800)
    try FileDelete(tmp)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("WindowManager`nSave layout: Win+Numpad1  Restore: Win+Numpad0`nSnap: Win+Alt+Arrows  Next monitor: Win+Alt+M`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Layout engine
;------------------------------------------------------------------------------
_LayoutName() => Cfg.Read("windowmanager", "default_layout", "default")

_LayoutFile() => Env.DataDir . "\windowlayout\" . _LayoutName() . ".json"

_LayoutRules() {
    rules := []
    for rname in StrSplit(Cfg.Read("default", "rules", "", "windowlayout.ini"), ",") {
        rname := Trim(rname)
        if rname == ""
            continue
        rules.Push(Map(
            "name", rname,
            "exe", StrLower(Cfg.Read("rule." . rname, "match_exe", "", "windowlayout.ini")),
            "cls", Cfg.Read("rule." . rname, "match_class", "", "windowlayout.ini"),
            "title", Cfg.Read("rule." . rname, "match_title", "", "windowlayout.ini"),
            "monitor", Cfg.Int("rule." . rname, "monitor", 1, "windowlayout.ini"),
            "action", StrLower(Cfg.Read("rule." . rname, "action", "left", "windowlayout.ini"))))
    }
    return rules
}

_InList(exe, list) {
    for cand in StrSplit(list, "|") {
        cand := StrLower(Trim(cand))
        if !InStr(cand, ".")
            cand .= ".exe"
        if exe == cand
            return true
    }
    return false
}

_FindByRule(rec) {
    for hwnd in WinGetList() {
        try {
            if WinGetMinMax("ahk_id " . hwnd) == -1 || WinGetTitle("ahk_id " . hwnd) == ""
                continue
            exe := StrLower(WinGetProcessName("ahk_id " . hwnd))
            if !_InList(exe, rec["exe"])
                continue
            if rec["title"] != "" && !InStr(WinGetTitle("ahk_id " . hwnd), rec["title"])
                continue
            if rec["cls"] != "" && !InStr(WinGetClass("ahk_id " . hwnd), rec["cls"])
                continue
            return hwnd
        } catch
            continue
    }
    return 0
}

_MonitorOf(hwnd) {
    if !hwnd
        return 1
    WinGetPos(&x, &y, &w, &h, "ahk_id " . hwnd)
    cx := x + w // 2, cy := y + h // 2
    Loop MonitorGetCount() {
        MonitorGet(A_Index, &ml, &mt, &mr, &mb)
        if cx >= ml && cx < mr && cy >= mt && cy < mb
            return A_Index
    }
    return 1
}

_WorkAreaFor(rec) {
    m := rec["monitor"]
    if m > MonitorGetCount() || m < 1
        m := 1
    MonitorGetWorkArea(m, &l, &t, &r, &b)
    return Map("l", l, "t", t, "r", r, "b", b)
}

SaveLayout() {
    EnsureDirs()
    data := Map()
    for rec in _LayoutRules() {
        hwnd := _FindByRule(rec)
        if !hwnd {
            Log("WindowManager: no window for rule '" . rec["name"] . "' - skipped", "WARN")
            continue
        }
        WinGetPos(&x, &y, &w, &h, "ahk_id " . hwnd)
        data[rec["name"]] := Map("mon", _MonitorOf(hwnd), "x", x, "y", y, "w", w, "h", h)
    }
    if !data.Count {
        Notify("WindowManager", "No matching windows found to save.", "WARN")
        return
    }
    try FileAppend(JSON.stringify(data), _LayoutFile())
    catch as e {
        Notify("WindowManager", "Save failed: " . e.Message, "ERROR")
        return
    }
    Log("WindowManager: saved " . data.Count . " windows to " . _LayoutFile(), "INFO")
    Notify("WindowManager", "Layout saved (" . data.Count . " windows).", "INFO")
}

RestoreLayout() {
    if !FileExist(_LayoutFile()) {
        Notify("WindowManager", "No saved layout. Press Win+Numpad1 first.", "WARN")
        return
    }
    try data := JSON.parse(FileRead(_LayoutFile()))
    catch as e {
        Notify("WindowManager", "Layout file unreadable: " . e.Message, "ERROR")
        return
    }
    rules := Map()
    for rec in _LayoutRules()
        rules[rec["name"]] := rec
    restored := 0
    for name, geo in data {
        if !rules.Has(name)
            continue
        hwnd := _FindByRule(rules[name])
        if !hwnd {
            Log("WindowManager: window for '" . name . "' not open - skipped", "WARN")
            continue
        }
        x := Integer(geo["x"]), y := Integer(geo["y"])
        w := Integer(geo["w"]), h := Integer(geo["h"])
        ; If the monitor is gone, drag the window back into the primary area.
        if _MonitorOf(hwnd) < 1 || !_OnAnyMonitor(x + w // 2, y + h // 2) {
            MonitorGetWorkArea(1, &l, &t, &r, &b)
            x := l + 40, y := t + 40
            w := Min(w, r - l - 80), h := Min(h, b - t - 80)
        }
        try WinMove(x, y, w, h, "ahk_id " . hwnd)
        restored++
    }
    Log("WindowManager: restored " . restored . " windows", "INFO")
    Notify("WindowManager", "Layout restored (" . restored . " windows).", "INFO")
}

_OnAnyMonitor(cx, cy) {
    Loop MonitorGetCount() {
        MonitorGet(A_Index, &ml, &mt, &mr, &mb)
        if cx >= ml && cx < mr && cy >= mt && cy < mb
            return true
    }
    return false
}

;------------------------------------------------------------------------------
; Snapping
;------------------------------------------------------------------------------
_SnapRect(dir, quarter, l, t, r, b) {
    w := r - l, h := b - t
    hw := w // 2, hh := h // 2
    if quarter {
        switch dir {
        case "Left":  return Map("x", l, "y", t + hh, "w", hw, "h", hh) ; bottom-left
        case "Right": return Map("x", l + hw, "y", t + hh, "w", hw, "h", hh) ; bottom-right
        case "Up":    return Map("x", l, "y", t, "w", hw, "h", hh) ; top-left
        case "Down":  return Map("x", l + hw, "y", t, "w", hw, "h", hh) ; top-right
        }
    }
    switch dir {
    case "Left":  return Map("x", l, "y", t, "w", hw, "h", h)
    case "Right": return Map("x", l + hw, "y", t, "w", hw, "h", h)
    case "Up":    return Map("x", l, "y", t, "w", w, "h", hh)
    case "Down":  return Map("x", l, "y", t + hh, "w", w, "h", hh)
    }
    return Map("x", l, "y", t, "w", w, "h", h)
}

_Snap(dir) {
    hwnd := WinExist("A")
    if !hwnd {
        Notify("WindowManager", "No active window to snap.", "WARN")
        return
    }
    m := _MonitorOf(hwnd)
    MonitorGetWorkArea(m, &l, &t, &r, &b)
    rect := _SnapRect(dir, GetKeyState("Shift", "P"), l, t, r, b)
    WinMove(rect["x"], rect["y"], rect["w"], rect["h"], "A")
}

NextMonitor() {
    hwnd := WinExist("A")
    if !hwnd
        return
    m := _MonitorOf(hwnd)
    n := MonitorGetCount()
    next := m == n ? 1 : m + 1
    MonitorGetWorkArea(next, &l, &t, &r, &b)
    WinGetPos(&x, &y, &w, &h, "A")
    nw := Min(w, r - l), nh := Min(h, b - t)
    WinMove(l + (r - l - nw) // 2, t + (b - t - nh) // 2, nw, nh, "A")
}

_OnDisplayChange(wParam, lParam, msg, hwnd) {
    ; WM_DISPLAYCHANGE can fire repeatedly - debounce with a one-shot timer.
    if !Cfg.Bool("windowmanager", "auto_apply_on_display_change", true)
        return
    if FileExist(_LayoutFile())
        SetTimer(RestoreLayout, -2000)
}

;------------------------------------------------------------------------------
; Bindings
;------------------------------------------------------------------------------
BindHotkey("Win+Numpad0", RestoreLayout, "WindowManager: restore layout")
BindHotkey("Win+Numpad1", SaveLayout, "WindowManager: save layout")
BindHotkey("Win+Alt+Left", (*) => _Snap("Left"), "WindowManager: snap left")
BindHotkey("Win+Alt+Right", (*) => _Snap("Right"), "WindowManager: snap right")
BindHotkey("Win+Alt+Up", (*) => _Snap("Up"), "WindowManager: snap up")
BindHotkey("Win+Alt+Down", (*) => _Snap("Down"), "WindowManager: snap down")
BindHotkey("Win+Alt+Shift+Left", (*) => _Snap("Left"), "WindowManager: snap quarter")
BindHotkey("Win+Alt+Shift+Right", (*) => _Snap("Right"), "WindowManager: snap quarter")
BindHotkey("Win+Alt+Shift+Up", (*) => _Snap("Up"), "WindowManager: snap quarter")
BindHotkey("Win+Alt+Shift+Down", (*) => _Snap("Down"), "WindowManager: snap quarter")
BindHotkey("Win+Alt+M", NextMonitor, "WindowManager: next monitor")
OnMessage(0x007E, _OnDisplayChange)
Log("WindowManager started", "INFO")
