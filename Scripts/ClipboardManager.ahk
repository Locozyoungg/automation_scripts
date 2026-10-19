#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\ClipboardManager.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : DPAPI-encrypted clipboard history (Data\clipboard\history.dat,
;          CurrentUser scope). Win+Shift+C history menu (copy/pin/delete),
;          Win+Shift+V cycle-paste, Win+Shift+X clear all. Password managers
;          and other exclusions in Config\ignorelist.ini are never recorded.
;          Images are not stored (documented limit).
; USAGE  : Launcher child (default) or standalone.
;          --selftest : history logic + DPAPI round-trip only (exit 0/1).
; SECURITY: Only metadata (length + FNV prefix) is ever logged - never
;          clipboard content. History file is DPAPI-encrypted per-user.
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
; Selftest: pure history logic + DPAPI round-trip on a temp file. No global
; clipboard writes, no menus.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    now := A_TickCount
    h := [Map("t", now - 1000, "txt", "old", "pinned", 0), Map("t", now, "txt", "new", "pinned", 0)]
    Check("trim keeps within cap", _TrimHist(h, 2, now, 999999).Length == 2)
    t2 := _TrimHist(h, 1, now, 999999)
    Check("trim drops oldest unpinned", t2.Length == 1 && t2[1]["txt"] == "new")
    h2 := [Map("t", now - 5000, "txt", "old-unpinned", "pinned", 0), Map("t", now, "txt", "p", "pinned", 1)]
    t3 := _TrimHist(h2, 1, now, 999999)
    Check("trim keeps pinned over newer", t3.Length == 1 && t3[1]["txt"] == "p")
    t4 := _TrimHist(h2, 5, now, 1000)
    Check("expire drops old unpinned", t4.Length == 1 && t4[1]["txt"] == "p")
    tmp := Env.DataDir . "\tmp\cm-test.dat"
    _SaveHist(tmp, [Map("t", now, "txt", "hello", "pinned", 0)])
    back := _LoadHist(tmp)
    Check("history DPAPI round-trip", back.Length == 1 && back[1]["txt"] == "hello")
    try FileDelete(tmp)
    Check("exclusion: password manager", _Excluded("Bitwarden.exe"))
    Check("exclusion: editor not excluded", !_Excluded("Code.exe"))
    Check("preview truncates + strips newlines", StrLen(_Preview("a`nb")) < 5 && !InStr(_Preview("a`nb"), "`n"))
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("ClipboardManager`nMenu: Win+Shift+C  Cycle: Win+Shift+V  Clear: Win+Shift+X`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; History engine (pure helpers, testable)
;------------------------------------------------------------------------------
_HistFile() => Env.DataDir . "\clipboard\history.dat"

_LoadHist(path) {
    try {
        txt := DpapiUnprotectStr(Trim(FileRead(path), "`r`n"))
        if txt == ""
            return []
        obj := JSON.parse(txt)
        if obj is Array
            return obj
    } catch {
        ; Corrupted or unreadable history: start fresh, never fatal.
    }
    return []
}

_SaveHist(path, hist) {
    enc := DpapiProtectStr(JSON.stringify(hist))
    if enc == "" {
        Log("ClipboardManager: encryption failed, history not saved", "ERROR")
        return
    }
    try FileAppend(enc, path)
    catch as e {
        Log("ClipboardManager: history save failed: " . ErrText(e), "ERROR")
    }
}

_TrimHist(hist, max, now, expireMs) {
    ; Newest at the end. Pinned entries survive expiry and the cap.
    out := []
    for e in hist {
        if !e["pinned"] && now - e["t"] > expireMs
            continue
        out.Push(e)
    }
    while out.Length > max {
        dropped := false
        for i, e in out {
            if !e["pinned"] {
                out.RemoveAt(i)
                dropped := true
                break
            }
        }
        if !dropped
            break
    }
    return out
}

_Excluded(exe) {
    if exe == ""
        return true
    for bad in Cfg.IgnoreList("clipboard_exclude")
        if StrLower(exe) == StrLower(bad)
            return true
    return false
}

_Preview(txt) {
    t := StrReplace(StrReplace(txt, "`r`n", " "), "`n", " ")
    return StrLen(t) > 48 ? SubStr(t, 1, 48) . "..." : t
}

_MenuFn(fn, val) {
    ; Per-item closure binding - a bare loop variable would be shared.
    f(item, *) => fn(val)
    return f
}

;------------------------------------------------------------------------------
; Clipboard watcher
;------------------------------------------------------------------------------
_OnClip(ClipType) {
    Global Hist
    if ClipType != 0 {
        if ClipType == 2
            Log("ClipboardManager: image change ignored (images not stored)", "DEBUG")
        return
    }
    if _Excluded(WinGetProcessName("A"))
        return
    txt := A_Clipboard
    if Trim(txt) == "" || StrLen(txt) > 20000
        return
    if Hist.Length && Hist[Hist.Length]["txt"] == txt {
        Hist[Hist.Length]["t"] := A_TickCount ; refresh the newest entry
        _SaveHist(_HistFile(), Hist)
        return
    }
    Hist.Push(Map("t", A_TickCount, "txt", txt, "pinned", 0))
    Hist := _TrimHist(Hist, Cfg.Int("clipboard", "max_items", 10), A_TickCount
        , Cfg.Int("clipboard", "expire_minutes", 30) * 60000)
    _SaveHist(_HistFile(), Hist)
    Log("ClipboardManager: recorded " . ClipMeta(txt), "DEBUG")
}

_ExpireTick() {
    Global Hist
    Hist := _TrimHist(Hist, Cfg.Int("clipboard", "max_items", 10), A_TickCount
        , Cfg.Int("clipboard", "expire_minutes", 30) * 60000)
    _SaveHist(_HistFile(), Hist)
}

;------------------------------------------------------------------------------
; Actions
;------------------------------------------------------------------------------
ShowMenu() {
    Global Hist
    entries := []
    i := Hist.Length
    while i >= 1 {
        entries.Push(Map("idx", i, "e", Hist[i]))
        i -= 1
    }
    m := Menu()
    if !entries.Length
        m.Add("(history is empty)", (*) => 0)
    for en in entries {
        sub := Menu()
        sub.Add("Copy", _MenuFn(_CopyEntry, en["idx"]))
        sub.Add(en["e"]["pinned"] ? "Unpin" : "Pin", _MenuFn(_PinEntry, en["idx"]))
        sub.Add("Delete", _MenuFn(_DelEntry, en["idx"]))
        m.Add(_Preview(en["e"]["txt"]), sub)
    }
    m.Add()
    m.Add("Clear all history", (*) => ClearHist())
    m.Show()
}

_CopyEntry(idx) {
    Global Hist
    if idx < 1 || idx > Hist.Length
        return
    A_Clipboard := Hist[idx]["txt"]
    Log("ClipboardManager: menu copy (" . ClipMeta(Hist[idx]["txt"]) . ")", "DEBUG")
    Notify("Clipboard", "Copied: " . _Preview(Hist[idx]["txt"]), "INFO")
}

_PinEntry(idx) {
    Global Hist
    if idx < 1 || idx > Hist.Length
        return
    Hist[idx]["pinned"] := Hist[idx]["pinned"] ? 0 : 1
    _SaveHist(_HistFile(), Hist)
    Notify("Clipboard", Hist[idx]["pinned"] ? "Pinned." : "Unpinned.", "INFO")
}

_DelEntry(idx) {
    Global Hist
    if idx < 1 || idx > Hist.Length
        return
    Hist.RemoveAt(idx)
    _SaveHist(_HistFile(), Hist)
}

CyclePaste() {
    Global Hist, _CyclePos
    if !Hist.Length {
        Notify("Clipboard cycle", "History is empty.", "WARN")
        return
    }
    if _CyclePos < 1 || _CyclePos > Hist.Length
        _CyclePos := Hist.Length
    e := Hist[_CyclePos]
    A_Clipboard := e["txt"]
    Send "^v"
    Log("ClipboardManager: cycle-paste #" . (Hist.Length - _CyclePos + 1), "DEBUG")
    Notify("Clipboard cycle", "#" . (Hist.Length - _CyclePos + 1) . " of " . Hist.Length . " pasted", "INFO")
    _CyclePos--
}

ClearHist() {
    Global Hist, _CyclePos
    if !ConfirmDlg("Clear clipboard history", "Delete all " . Hist.Length . " history entries?")
        return
    Hist := []
    _CyclePos := 0
    _SaveHist(_HistFile(), Hist)
    Log("ClipboardManager: history cleared", "INFO")
    Notify("Clipboard", "History cleared.", "INFO")
}

;------------------------------------------------------------------------------
; Startup
;------------------------------------------------------------------------------
Global Hist := _LoadHist(_HistFile())
Global _CyclePos := 0
Hist := _TrimHist(Hist, Cfg.Int("clipboard", "max_items", 10), A_TickCount
    , Cfg.Int("clipboard", "expire_minutes", 30) * 60000)
OnClipboardChange(_OnClip)
SetTimer(_ExpireTick, 600000)
BindHotkey(Cfg.Read("hotkeys", "clip_menu", "Win+Shift+C"), ShowMenu, "ClipboardManager: history menu")
BindHotkey(Cfg.Read("hotkeys", "clip_cycle", "Win+Shift+V"), CyclePaste, "ClipboardManager: cycle paste")
BindHotkey(Cfg.Read("hotkeys", "clip_clear", "Win+Shift+X"), ClearHist, "ClipboardManager: clear history")
Log("ClipboardManager started - " . Hist.Length . " history items", "INFO")
