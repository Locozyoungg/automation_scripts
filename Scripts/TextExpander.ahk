#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\TextExpander.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : INI-driven text snippets (Config\snippets.ini). Type a trigger and
;          press Space/Enter/Tab to expand. Placeholders: {date} {time} {iso}
;          {branch} {clipboard} {cursor} {uuid} {username}. Modes: raw
;          (SendText) or clipboard (paste; the previous clipboard is saved and
;          restored). Live-edited snippets.ini is picked up after each match.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : expansion logic only, no input hooks (exit 0/1).
; SECURITY: Expansions are the user's own text; triggers only (never content)
;          are logged.
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

; Assigned before the selftest block below (top-level assignments execute
; in file order, and _CurrentBranch reads this during selftest).
Global _BranchCache := Map("t", 0, "v", "")

;------------------------------------------------------------------------------
; Selftest: pure expansion logic. No input hooks, no key sends.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    Check("snippet sections loaded", _SnippetSections().Length >= 5, "count=" . _SnippetSections().Length)
    Check("triggers include gitpush", _TriggersNow().Length >= 1 && _Has(_TriggersNow(), ";gitpush"))
    Check("unescape \\n and \\t", _Unescape("a\nb\tc") == "a`nb`tc")
    d := _Expand("date")
    Check("placeholder {date} resolves", d["mode"] == "raw" && d["parts"].Length == 1 && d["parts"][1] == FormatTime(A_Now, "yyyy-MM-dd"), d["parts"][1])
    p := _Expand("pr")
    Check("placeholder {cursor} splits parts", p["parts"].Length == 2 && p["mode"] == "clipboard")
    Check("placeholder {branch} resolves", _CurrentBranch() == "main", _CurrentBranch())
    u := _NewUuid()
    Check("placeholder {uuid} format", RegExMatch(u, "i)^[0-9a-f-]{36}$"), u)
    Check("snippet expansion end-to-end", _Expand("thankyou")["parts"][1] == "Thank you!")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("TextExpander`nType a snippet trigger, then Space/Enter/Tab.`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Snippet engine (pure helpers)
;------------------------------------------------------------------------------
_Has(arr, val) {
    for v in arr
        if v == val
            return true
    return false
}

_SnippetSections() {
    sections := []
    try {
        txt := IniRead(Cfg.File("snippets.ini"))
        for sec in StrSplit(txt, "`n")
            if Trim(sec) != ""
                sections.Push(Trim(sec))
    } catch as e {
        Log("TextExpander: snippets read failed: " . ErrText(e), "ERROR")
    }
    return sections
}

_TriggerOf(sec) => Trim(IniRead(Cfg.File("snippets.ini"), sec, "trigger", ""))

_Unescape(s) {
    ; INI stores \n and \t literally; AHK has no backslash escapes.
    s := StrReplace(s, "\n", "`n")
    s := StrReplace(s, "\t", "`t")
    s := StrReplace(s, "\\", "\")
    return s
}

_CurrentBranch() {
    Global _BranchCache
    if A_TickCount - _BranchCache["t"] < 20000
        return _BranchCache["v"]
    root := ActiveProject()
    if root == ""
        root := Env.Root
    r := RunPS("git -C " . _PsLit(root) . " rev-parse --abbrev-ref HEAD 2>&1|Out-String", 15)
    v := Trim(StrReplace(r["stdout"], "`r`n", ""))
    if InStr(v, "fatal") || InStr(v, "not a git")
        v := ""
    _BranchCache := Map("t", A_TickCount, "v", v)
    return v
}

_NewUuid() {
    r := RunPS("[guid]::NewGuid().ToString()", 10)
    return Trim(StrReplace(r["stdout"], "`r`n", ""))
}

_Expand(sec) {
    raw := _Unescape(IniRead(Cfg.File("snippets.ini"), sec, "expansion", ""))
    mode := StrLower(IniRead(Cfg.File("snippets.ini"), sec, "mode", "raw"))
    if mode == "script"
        mode := "clipboard" ; built-in scripted snippets ship as clipboard templates
    if raw == ""
        return Map("parts", [""], "mode", "raw")
    raw := StrReplace(raw, "{date}", FormatTime(A_Now, "yyyy-MM-dd"))
    raw := StrReplace(raw, "{time}", FormatTime(A_Now, "HH:mm:ss"))
    raw := StrReplace(raw, "{iso}", Format("{1}T{2}", FormatTime(A_Now, "yyyy-MM-dd"), FormatTime(A_Now, "HH:mm:ss")))
    raw := StrReplace(raw, "{clipboard}", A_Clipboard)
    raw := StrReplace(raw, "{username}", EnvGet("USERNAME"))
    if InStr(raw, "{uuid}")
        raw := StrReplace(raw, "{uuid}", _NewUuid())
    if InStr(raw, "{branch}")
        raw := StrReplace(raw, "{branch}", _CurrentBranch())
    return Map("parts", StrSplit(raw, "{cursor}"), "mode", mode == "clipboard" ? "clipboard" : "raw")
}

;------------------------------------------------------------------------------
; InputHook plumbing
;------------------------------------------------------------------------------
Global _Hook := 0
Global _Expanding := false

_TriggersNow() {
    out := []
    for sec in _SnippetSections() {
        t := _TriggerOf(sec)
        if t != ""
            out.Push(t)
    }
    return out
}

_EnsureHook() {
    Global _Hook
    try {
        if _Hook is InputHook
            _Hook.Stop()
    }
    _Hook := InputHook("I1", " `t`n", _TriggersNow())
    _Hook.OnMatch := _OnMatch
    _Hook.Start()
}

_OnMatch(ih, *) {
    ; The re-entrancy guard stops our own expansion text from re-triggering.
    Global _Expanding
    if _Expanding
        return
    trig := ih.Input
    sec := ""
    for s in _SnippetSections()
        if _TriggerOf(s) == trig
            sec := s
    if sec == "" {
        _EnsureHook()
        return
    }
    e := _Expand(sec)
    _Expanding := true
    ; Erase the typed trigger + end character, then emit the expansion.
    Send("{Backspace " . (StrLen(trig) + 1) . "}")
    after := 0
    if e["parts"].Length > 1 {
        for i, part in e["parts"]
            if i > 1
                after += StrLen(part)
    }
    if e["mode"] == "clipboard" {
        old := A_Clipboard
        for i, part in e["parts"] {
            if part == "" && e["parts"].Length > 1
                continue ; the {cursor} slot
            A_Clipboard := part
            Send "^v"
            Sleep 120
        }
        Sleep 300
        try A_Clipboard := old ; restore what the user had copied
    } else {
        for i, part in e["parts"] {
            if part == "" && e["parts"].Length > 1
                continue
            SendText(part)
        }
    }
    if after > 0
        Send("{Left " . after . "}") ; land the caret at the {cursor} slot
    _Expanding := false
    Log("TextExpander: '" . trig . "' -> section '" . sec . "' (mode " . e["mode"] . ")", "INFO")
    _EnsureHook() ; pick up live edits to snippets.ini
}

_EnsureHook()
Log("TextExpander started - " . _TriggersNow().Length . " triggers", "INFO")
