#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\SecretsScanner.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Scans configured roots ([security] secrets_roots, semicolon-
;          separated) for hardcoded secrets: AWS/Google/GitHub/Slack tokens,
;          private-key blocks, 0x64-hex keys, generic assignment patterns and
;          .env assignments. Win+Alt+9 runs an interactive scan; the Launcher
;          tray runs --scan-now --standalone. Reports go to
;          Logs\SecretsScan-<ts>.json/.html with file, line, pattern and an
;          FNV fingerprint prefix - NEVER the secret content.
; USAGE  : AutoHotkey64.exe Security\SecretsScanner.ahk [--scan-now --standalone]
;          --selftest : fixture scan, no real roots (exit 0/1).
; SECURITY: Content never leaves the machine and never appears in reports or
;          logs. Fingerprints in [secrets_allow] mark known-false positives.
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

_SS_Patterns := [
    Map("name", "aws-access-key", "re", "AKIA[0-9A-Z]{16}"),
    Map("name", "google-api-key", "re", "AIza[0-9A-Za-z_-]{35}"),
    Map("name", "github-token", "re", "gh[pousr]_[0-9A-Za-z]{36}"),
    Map("name", "slack-token", "re", "xox[baprs]-[0-9A-Za-z-]{10,}"),
    Map("name", "private-key-block", "re", "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    Map("name", "hex-private-key", "re", "0x[0-9a-fA-F]{64}"),
    Map("name", "generic-assignment", "re", "(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|client[_-]?secret)\s*[:=]\s*['`"][^'`"]{6,}['`"]"),
    Map("name", "env-assignment", "re", "(?i)^\s*[A-Z0-9_]{3,}=(?!\s*$)[^\s]{4,}$", "envOnly", true)]

if ArgHas("--selftest") {
    EnsureDirs()
    fx := Env.DataDir . "\tmp\ss-fixture"
    if DirExist(fx)
        DirDelete(fx, true)
    DirCreate(fx)
    FileAppend("var x = 1;`nvar key = `"AKIA1234567890ABCDEF`";`n", fx . "\a.js")
    FileAppend("password='hunter2secret'`n# comment`n", fx . "\b.py")
    FileAppend("just a normal file`nwith nothing`n", fx . "\c.txt")
    FileAppend("API_KEY=realvalue123`n", fx . "\.env")
    results := _SS_ScanDirSync(fx)
    Check("fixture scan finds >= 3", results.Length >= 3, "count=" . results.Length)
    foundAws := false, foundPwd := false, foundEnv := false
    for r in results {
        if r["pattern"] == "aws-access-key" && InStr(r["file"], "a.js")
            foundAws := true
        if r["pattern"] == "generic-assignment"
            foundPwd := true
        if r["pattern"] == "env-assignment"
            foundEnv := true
    }
    Check("aws key found", foundAws)
    Check("generic assignment found", foundPwd)
    Check("env assignment found", foundEnv)
    jsStr := JSON.stringify(results)
    Check("report contains NO secret content", !InStr(jsStr, "AKIA1234567890ABCDEF") && !InStr(jsStr, "hunter2secret") && !InStr(jsStr, "realvalue123"))
    Check("report contains fingerprint", results.Length == 0 || StrLen(String(results[1]["fp"])) == 8)
    DirDelete(fx, true)
    Check("roots config readable", Cfg.Read("security", "secrets_roots", "C:\dev") != "")
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("SecretsScanner`nScan roots: Win+Alt+9`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Scan engine
;------------------------------------------------------------------------------
_SS_SkipDirs() {
    return StrSplit(Cfg.Read("security", "scan_skip_dirs"
        , "node_modules,.git,build,dist,out,vendor,.venv,venv,__pycache__,target,obj"), ",")
}

_SS_ExtOk(ext) {
    ext := StrLower(ext)
    for ok in [".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rs", ".java", ".c", ".h", ".cpp", ".cs", ".php", ".rb", ".sh", ".ps1", ".bat", ".cmd", ".yaml", ".yml", ".json", ".ini", ".env", ".txt", ".md", ".sol", ".toml", ".key", ".pem"]
        if ext == ok
            return true
    return false
}

_SS_EnvOnly(name, pattern) {
    return pattern.Has("envOnly") && pattern["envOnly"] && !RegExMatch(StrLower(name), "^\.env")
}

_SS_ScanFile(path, findings) {
    if FileGetSize(path) > 2 * 1024 * 1024
        return
    txt := ""
    try txt := FileRead(path)
    catch
        return
    name := _SS_Leaf(path)
    line := 1
    for raw in StrSplit(txt, "`n") {
        if findings.Length >= 500
            return
        for p in _SS_Patterns {
            if _SS_EnvOnly(name, p)
                continue
            if RegExMatch(RTrim(raw, "`r"), p["re"]) {
                findings.Push(Map("file", path, "line", line, "pattern", p["name"]
                    , "len", StrLen(raw), "fp", SubStr(Fnv1a(raw), 1, 8)))
            }
        }
        line++
    }
}

_SS_Leaf(path) => SubStr(path, InStr(path, "\", false, -1) + 1)

_SS_ScanDirSync(dir) {
    findings := []
    if !DirExist(dir)
        return findings
    skips := _SS_SkipDirs()
    _SS_Walk(dir, skips, findings)
    return findings
}

_SS_Walk(dir, skips, findings) {
    try Loop Files dir . "\*", "FR" {
        if findings.Length >= 500
            break
        if InStr(A_LoopFileAttrib, "D") {
            skip := false
            for s in skips
                if A_LoopFileName == Trim(s) {
                    skip := true
                    break
                }
            if !skip
                _SS_Walk(A_LoopFilePath, skips, findings)
            continue
        }
        if _SS_ExtOk(SubStr(A_LoopFileName, InStr(A_LoopFileName, ".", false, -1)))
            _SS_ScanFile(A_LoopFilePath, findings)
    }
}

_SS_Allowed(fp) {
    for a in Cfg.IgnoreList("secrets_allow")
        if StrLower(Trim(a)) == StrLower(fp)
            return true
    return false
}

_SS_HtmlEsc(s) => StrReplace(StrReplace(StrReplace(String(s), "&", "&amp;"), "<", "&lt;"), ">", "&gt;")

_SS_Report(findings, filesScanned) {
    ts := FormatTime(A_Now, "yyyyMMdd-HHmmss")
    jsStr := JSON.stringify(Map("generated", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
        , "files_scanned", filesScanned, "truncated", findings.Length >= 500, "findings", findings))
    try FileAppend(jsStr, Env.LogDir . "\SecretsScan-" . ts . ".json")
    lines := []
    lines.Push("<!DOCTYPE html><html><head><meta charset=`"utf-8`"><title>Secrets Scan</title>")
    lines.Push("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ccc;padding:5px 8px;text-align:left}</style></head><body>")
    lines.Push("<h2>Secrets Scan - " . _SS_HtmlEsc(FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")) . "</h2>")
    lines.Push("<p>" . filesScanned . " files scanned, " . findings.Length . " finding(s). Only locations and fingerprints are shown - never content.</p>")
    lines.Push("<table><tr><th>File</th><th>Line</th><th>Pattern</th><th>Fingerprint</th><th>Allowed</th></tr>")
    for f in findings
        lines.Push("<tr><td>" . _SS_HtmlEsc(f["file"]) . "</td><td>" . f["line"] . "</td><td>"
            . _SS_HtmlEsc(f["pattern"]) . "</td><td>" . f["fp"] . "</td><td>"
            . (_SS_Allowed(f["fp"]) ? "yes" : "") . "</td></tr>")
    lines.Push("</table></body></html>")
    try FileAppend(StrJoin(lines, "`n"), Env.LogDir . "\SecretsScan-" . ts . ".html")
    return ts
}

_SS_Roots() {
    roots := []
    for part in StrSplit(Cfg.Read("security", "secrets_roots", "C:\dev"), ";") {
        part := Trim(part)
        if part != "" && DirExist(part)
            roots.Push(part)
    }
    return roots
}

;------------------------------------------------------------------------------
; Scan flow (chunked: 60 files per tick keeps the UI responsive)
;------------------------------------------------------------------------------
Global _SS_Queue := []
Global _SS_Idx := 1
Global _SS_Findings := []
Global _SS_FilesScanned := 0
Global _SS_Scanning := false

_SS_Collect() {
    Global _SS_Queue
    _SS_Queue := []
    skips := _SS_SkipDirs()
    for root in _SS_Roots()
        _SS_CollectWalk(root, skips)
    _SS_Idx := 1
}

_SS_CollectWalk(dir, skips) {
    Global _SS_Queue
    try Loop Files dir . "\*", "FR" {
        if InStr(A_LoopFileAttrib, "D") {
            skip := false
            for s in skips
                if A_LoopFileName == Trim(s) {
                    skip := true
                    break
                }
            if !skip
                _SS_CollectWalk(A_LoopFilePath, skips)
            continue
        }
        if _SS_ExtOk(SubStr(A_LoopFileName, InStr(A_LoopFileName, ".", false, -1)))
            _SS_Queue.Push(A_LoopFilePath)
    }
}

_SS_Tick() {
    Global _SS_Queue, _SS_Idx, _SS_Findings, _SS_FilesScanned, _SS_Scanning
    budget := 60
    while _SS_Idx <= _SS_Queue.Length && budget > 0 {
        _SS_ScanFile(_SS_Queue[_SS_Idx], _SS_Findings)
        _SS_Idx++
        _SS_FilesScanned++
        budget--
    }
    if _SS_Idx > _SS_Queue.Length
        _SS_Finish()
}

_SS_Finish() {
    Global _SS_Queue, _SS_Findings, _SS_FilesScanned, _SS_Scanning
    SetTimer(_SS_Tick, 0)
    _SS_Scanning := false
    n := _SS_Findings.Length
    _SS_Report(_SS_Findings, _SS_FilesScanned)
    AuditLog("SecretsScanner: " . n . " finding(s) across " . _SS_FilesScanned . " files (truncated=" . (n >= 500 ? "yes" : "no") . ")")
    Notify("Secrets scan done", n . " finding(s) in " . _SS_FilesScanned . " files - see Logs\SecretsScan-*.html", n > 0 ? "SECURITY" : "INFO")
    if ArgHas("--standalone")
        ExitApp(0)
}

_SS_Start() {
    Global _SS_Findings, _SS_FilesScanned, _SS_Scanning
    if _SS_Scanning {
        Notify("Secrets scan", "A scan is already running.", "WARN")
        return
    }
    _SS_Findings := []
    _SS_FilesScanned := 0
    _SS_Scanning := true
    _SS_Collect()
    Notify("Secrets scan", "Scanning " . _SS_Queue.Length . " files...", "INFO")
    SetTimer(_SS_Tick, 50)
}

if ArgHas("--scan-now") && ArgHas("--standalone") {
    _SS_Start()
    ; _SS_Finish exits when the queue drains.
} else {
    BindHotkey(Cfg.Read("hotkeys", "secrets_scan", "Win+Alt+9"), _SS_Start, "SecretsScanner: scan now")
    Log("SecretsScanner started (resident; roots: " . StrJoin(_SS_Roots(), ", ") . ")", "INFO")
}
