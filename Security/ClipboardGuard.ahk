#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\ClipboardGuard.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Wallet-address clipboard hijack defense. HEURISTIC (documented
;          limit): if the clipboard is replaced within 3 s of a copy AND the
;          old or new content looks like a crypto address, raise a SECURITY
;          alert + audit entry. Password managers (Config\ignorelist.ini
;          [clipboard_exclude]) are ignored.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : pure detection logic on synthetic events (exit 0/1).
; SECURITY: Only metadata (length + FNV prefix) is ever logged - never the
;          clipboard content itself.
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

if ArgHas("--selftest") {
    EnsureDirs()
    Check("address: ETH 0x40hex", _CG_LooksAddress("0x52908400098527886E0F7030069857D2E4169EE7"))
    Check("address: BTC legacy", _CG_LooksAddress("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"))
    Check("address: bech32", _CG_LooksAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))
    Check("address: TRON", _CG_LooksAddress("TUpHUgDVBQ7KUWCwBq9EErV6F7cZQ2S6Qn"))
    Check("address: short text is not", !_CG_LooksAddress("hello world"))
    Check("address: empty is not", !_CG_LooksAddress(""))
    prev := Map("t", 1000, "fnv", "aaaa", "addr", 1)
    cur := Map("t", 2500, "fnv", "bbbb", "addr", 1)
    Check("detect: 1.5 s rapid replacement", _CG_Detect(prev, cur))
    Check("detect: same content not flagged", !_CG_Detect(Map("t", 1000, "fnv", "aaaa", "addr", 1), Map("t", 2500, "fnv", "aaaa", "addr", 1)))
    Check("detect: 10 s gap not flagged", !_CG_Detect(prev, Map("t", 11000, "fnv", "bbbb", "addr", 1)))
    Check("detect: non-address pair not flagged", !_CG_Detect(Map("t", 1000, "fnv", "a", "addr", 0), Map("t", 2500, "fnv", "b", "addr", 0)))
    Check("exclusion: password managers", _CG_Excluded("Bitwarden.exe") && _CG_Excluded("keepassxc.exe"))
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("ClipboardGuard`nClipboard hijack heuristic (3 s window).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Detection logic (pure, testable)
;------------------------------------------------------------------------------
_CG_LooksAddress(txt) {
    return RegExMatch(txt, "^(0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,39}|bc1[0-9a-zA-Z]{25,59}|T[1-9A-HJ-NP-Za-km-z]{33})$")
}

_CG_Excluded(exe) {
    if exe == ""
        return true
    for bad in Cfg.IgnoreList("clipboard_exclude")
        if StrLower(exe) == StrLower(bad)
            return true
    return false
}

_CG_Detect(prev, cur) {
    ; Heuristic: a second, different text change within 3 s where either side
    ; looks like a crypto address - the classic copy-then-swap hijack.
    return prev["t"] > 0 && cur["t"] - prev["t"] < 3000
        && prev["fnv"] != cur["fnv"] && (prev["addr"] || cur["addr"])
}

;------------------------------------------------------------------------------
; Live hook
;------------------------------------------------------------------------------
Global _CG_Prev := Map("t", 0, "fnv", "", "addr", 0)

_CG_OnClip(ClipType) {
    Global _CG_Prev
    if ClipType != 0
        return
    exe := ""
    try exe := WinGetProcessName("A")
    if _CG_Excluded(exe)
        return
    txt := A_Clipboard
    if Trim(txt) == "" || StrLen(txt) < 10 || StrLen(txt) > 200
        return
    cur := Map("t", A_TickCount, "fnv", Fnv1a(txt), "addr", _CG_LooksAddress(txt) ? 1 : 0)
    if _CG_Detect(_CG_Prev, cur) {
        Notify("Possible clipboard hijack", "Clipboard was replaced within 3 s of a copy. Check it before pasting.", "SECURITY")
        AuditLog("ClipboardGuard: rapid replacement - prev fnv=" . SubStr(_CG_Prev["fnv"], 1, 4)
            . " new len=" . StrLen(txt) . " fnv=" . SubStr(cur["fnv"], 1, 4))
    }
    _CG_Prev := cur
}

OnClipboardChange(_CG_OnClip)
Log("ClipboardGuard started (heuristic, 3 s window)", "INFO")
