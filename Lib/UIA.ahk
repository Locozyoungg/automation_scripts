#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\UIA.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Optional extension point over thqby's UIA-v2 library
;          (https://github.com/thqby/ahk2_lib/tree/master/UIA, MIT license).
; WHY    : The toolkit's anti-fragility order is (1) COM/CLI/API, (2) UIA,
;          (3) Acc, (4) window title/class matching, (5) coordinates.
;          Every built-in tool does its job with COM/CLI and window matching,
;          so UIA is never REQUIRED — this file just tells callers whether it
;          is available and how to enable it.
; ENABLE : 1) Copy the UIA folder from ahk2_lib into <ROOT>\Lib\UIA\
;          2) Add  #Include UIA\UIA.ahk  to the tool that needs it
;          3) Guard every use with UIAv2Available()
; NOTE   : AHK has no conditional #Include, which is why this is an adapter
;          and not a wrapper. Include Core.ahk before this file.
;==============================================================================

UIAv2Available() {
    ; True when the vendored UIA-v2 library exists (cached after first check).
    static have := ""
    if have == ""
        have := FileExist(Env.LibDir . "\UIA\UIA.ahk")
    return have
}
