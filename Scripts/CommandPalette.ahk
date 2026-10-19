#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\CommandPalette.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Ctrl+Alt+Space fuzzy launcher over every registered tool action
;          and every snippet. Typing filters by subsequence match; Enter
;          triggers the selected item (tool actions are fired by sending the
;          tool's own hotkey, so only tools already running respond;
;          snippets expand into the focused app). Esc closes.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : fuzzy matching + action list only, no GUI (exit 0/1).
; SECURITY: Pure launcher - no network, no secrets, nothing leaves the box.
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
; Selftest: fuzzy matching + action inventory. No GUI.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    Check("fuzzy: exact match scores", _Fuzzy("dev", "DevHotkeys") > 0)
    Check("fuzzy: subsequence match", _Fuzzy("dvhk", "DevHotkeys") > 0)
    Check("fuzzy: case-insensitive", _Fuzzy("DEV", "DevHotkeys") > 0)
    Check("fuzzy: no match is negative", _Fuzzy("xyz", "DevHotkeys") < 0)
    Check("fuzzy: prefix bonus beats inner match", _Fuzzy("git", "GitWorkflow") > _Fuzzy("git", "WindowManager"))
    acts := _BuildActions()
    Check("actions include all tools + snippets", acts.Length >= Tools.List().Length + 5, "count=" . acts.Length)
    Check("first hotkey extraction", _FirstHotkey(["Win+Alt+T", "(menu)"]) == "Win+Alt+T")
    Check("first hotkey skips parens", _FirstHotkey(["(menu)"]) == "")
    Check("palette hotkey config readable", Cfg.Read("hotkeys", "palette", "") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("CommandPalette`nOpen: Ctrl+Alt+Space`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Fuzzy matching + action inventory
;------------------------------------------------------------------------------
_Fuzzy(q, s) {
    ; Subsequence match with a density/prefix score. -1 = no match.
    q := StrLower(q), s := StrLower(s)
    if q == ""
        return 0
    pos := 1, first := 0, last := 0
    for ch in StrSplit(q) {
        pos := InStr(s, ch, true, pos)
        if !pos
            return -1
        if first == 0
            first := pos
        last := pos
        pos += 1
    }
    span := last - first + 1
    score := StrLen(q) * 100 - span
    if InStr(s, q, true) == 1
        score += 500 ; prefix bonus
    return score
}

_SnippetSections() {
    sections := []
    try {
        for sec in StrSplit(IniRead(Cfg.File("snippets.ini")), "`n")
            if Trim(sec) != ""
                sections.Push(Trim(sec))
    } catch as e {
        Log("CommandPalette: snippets read failed: " . ErrText(e), "ERROR")
    }
    return sections
}

_FirstHotkey(list) {
    for h in list
        if SubStr(h, 1, 1) != "("
            return h
    return ""
}

_BuildActions() {
    acts := []
    for rec in Tools.List() {
        hot := _FirstHotkey(rec.hotkeys)
        acts.Push(Map("label", rec.name . " - " . rec.desc . (hot != "" ? "  [" . hot . "]" : "")
            , "kind", "tool", "rec", rec))
    }
    for sec in _SnippetSections() {
        exp := IniRead(Cfg.File("snippets.ini"), sec, "expansion", "")
        exp := StrReplace(StrReplace(exp, "\n", " "), "\t", " ")
        exp := StrLen(exp) > 40 ? SubStr(exp, 1, 40) . "..." : exp
        acts.Push(Map("label", "Snippet " . sec . " -> " . exp, "kind", "snippet", "sec", sec))
    }
    return acts
}

;------------------------------------------------------------------------------
; GUI
;------------------------------------------------------------------------------
Global _PalGui := 0
Global _PalActions := []

_IsPalActive() {
    Global _PalGui
    return _PalGui is Gui && WinActive("ahk_id " . _PalGui.Hwnd)
}

_UpdatePal() {
    Global _PalGui, _PalActions
    if !(_PalGui is Gui)
        return
    q := _PalGui["Query"].Value
    scored := []
    for i, act in _PalActions {
        s := _Fuzzy(q, act["label"])
        if s >= 0
            scored.Push(Map("s", s, "i", i))
    }
    ; insertion sort by score desc (lists are short)
    j := 2
    while j <= scored.Length {
        cur := scored[j], k := j - 1
        while k >= 1 && scored[k]["s"] < cur["s"] {
            scored[k + 1] := scored[k]
            k -= 1
        }
        scored[k + 1] := cur
        j += 1
    }
    items := []
    for e in scored
        items.Push(_PalActions[e["i"]]["label"])
    lb := _PalGui["List"]
    lb.Delete()
    lb.Add(items)
    if items.Length
        lb.Choose(1)
    _PalGui["Status"].Value := Format("{1} match{2} - Enter to run, Esc to close", items.Length, items.Length == 1 ? "" : "es")
}

OpenPalette() {
    Global _PalGui, _PalActions
    if _PalGui is Gui {
        _PalGui.Destroy()
        _PalGui := 0
    }
    _PalActions := _BuildActions()
    g := Gui("+AlwaysOnTop -MinimizeBox", "Command Palette")
    g.SetFont("s10")
    g.AddEdit("w520 vQuery")
    g.AddListBox("w520 r14 vList", [])
    g.AddText("w520 vStatus", "Type to filter...")
    g["Query"].OnEvent("Change", (*) => _UpdatePal())
    g["List"].OnEvent("DoubleClick", (*) => _ActivateSel())
    g.OnEvent("Escape", (*) => _ClosePal())
    g.OnEvent("Close", (*) => _ClosePal())
    _PalGui := g
    _UpdatePal()
    g["Query"].Focus()
    g.Show()
}

_ClosePal() {
    Global _PalGui
    if _PalGui is Gui {
        _PalGui.Destroy()
        _PalGui := 0
    }
}

_ActivateSel() {
    Global _PalGui, _PalActions
    if !(_PalGui is Gui)
        return
    label := _PalGui["List"].Text
    if label == ""
        return
    act := ""
    for a in _PalActions
        if a["label"] == label
            act := a
    _ClosePal()
    if act == ""
        return
    if act["kind"] == "tool" {
        rec := act["rec"]
        if !Cfg.Bool("tools", rec.name, rec.enabled) {
            Notify("Command Palette", rec.name . " is disabled. Enable it in the Launcher tray menu.", "WARN")
            return
        }
        hk := _FirstHotkey(rec.hotkeys)
        if hk == "" {
            Notify("Command Palette", rec.name . " has no hotkey - use the tray menu.", "WARN")
            return
        }
        Send(hk)
    } else if act["kind"] == "snippet" {
        raw := IniRead(Cfg.File("snippets.ini"), act["sec"], "expansion", "")
        raw := StrReplace(StrReplace(raw, "\n", "`n"), "\t", "`t")
        raw := StrReplace(raw, "{date}", FormatTime(A_Now, "yyyy-MM-dd"))
        raw := StrReplace(raw, "{time}", FormatTime(A_Now, "HH:mm:ss"))
        raw := StrReplace(raw, "{username}", EnvGet("USERNAME"))
        old := A_Clipboard
        A_Clipboard := raw
        Send "^v"
        Sleep 300
        try A_Clipboard := old
    }
    Log("CommandPalette: ran '" . label . "'", "INFO")
}

;------------------------------------------------------------------------------
; Binding (Enter is context-scoped to the palette window)
;------------------------------------------------------------------------------
HotIf((*) => _IsPalActive())
Hotkey("Enter", (*) => _ActivateSel())
HotIf()
BindHotkey(Cfg.Read("hotkeys", "palette", "Ctrl+Alt+Space"), OpenPalette, "CommandPalette: open")
Log("CommandPalette started", "INFO")
