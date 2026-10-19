#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\Toast.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Thin toast layer over TrayTip. Core.Notify is the primary path;
;          these are convenience aliases with fixed levels.
; NOTE   : Function definitions only — no top-level side effects.
;==============================================================================

ToastInfo(title, msg) {
    Notify(title, msg, "INFO")
}

ToastWarn(title, msg) {
    Notify(title, msg, "WARN")
}

ToastError(title, msg) {
    Notify(title, msg, "ERROR")
}

ToastSecurity(title, msg) {
    ; Security alerts skip the duplicate rate-limit — they always show.
    Notify(title, msg, "SECURITY", false)
}
