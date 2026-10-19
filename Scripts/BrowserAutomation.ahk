#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Scripts\BrowserAutomation.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Chrome DevTools Protocol (CDP) automation over 127.0.0.1:9222:
;          Win+Alt+J open Jira ticket / GitHub PR for the current branch,
;          Win+Alt+F fill a form (Config\formfill.json), Win+Alt+S scrape the
;          first table to TSV on the clipboard. Requires Chrome/Edge started
;          with --remote-debugging-port=9222 and a DEDICATED user-data-dir
;          (the tool offers to launch it). Disabled by default ([tools]).
; USAGE  : Launcher child (default) or standalone.
;          --selftest : allowlist/URL helpers + formfill parse only (exit 0/1).
; SECURITY: CDP actions are refused outside Config\ignorelist.ini
;          [browser_allow_domains]. Secret field values come from Credential
;          Manager (cred:<target>) and are NEVER logged or stored.
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
; Selftest: URL/allowlist helpers + formfill schema. No browser interaction.
;------------------------------------------------------------------------------
if ArgHas("--selftest") {
    EnsureDirs()
    Check("allowlist: github.com ok", _DomainAllowed("https://github.com/Locozyoungg/automation_scripts"))
    Check("allowlist: atlassian ok", _DomainAllowed("https://team.atlassian.net/browse/PROJ-1"))
    Check("allowlist: localhost ok", _DomainAllowed("http://localhost:3000/x"))
    Check("allowlist: evil.com refused", !_DomainAllowed("https://evil.com/x"))
    Check("allowlist: subdomain spoof refused", !_DomainAllowed("https://github.com.evil.com/x"))
    Check("remote url -> https (git@ form)", _ToHttps("git@github.com:Locozyoungg/automation_scripts.git") == "https://github.com/Locozyoungg/automation_scripts")
    Check("remote url -> https (https form)", _ToHttps("https://github.com/o/r.git") == "https://github.com/o/r")
    Check("jira key regex", RegExMatch("PROJ-123", "i)^[A-Z]{2,}-\d+$"))
    try {
        forms := JSON.parse(FileRead(Cfg.File("formfill.json")))
        Check("formfill.json parses with fields", forms.Has("forms") && forms["forms"].Length >= 1)
        Check("formfill secret field uses cred: prefix", forms["forms"][1]["fields"][3]["value"] == "cred:AHK-web-example")
    } catch as e {
        Check("formfill.json parses with fields", false, e.Message)
    }
    js := _FillJS("https://example.com", Map("fields", [Map("selector", "#x", "value", "hi", "secret", false)]), false, false)
    Check("fill JS escapes and selects", InStr(js, "querySelector") > 0 && InStr(js, "#x") > 0)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("BrowserAutomation`nJira/PR: Win+Alt+J  Form fill: Win+Alt+F  Scrape: Win+Alt+S`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; URL / domain safety
;------------------------------------------------------------------------------
_HostOf(url) {
    m := ""
    if !RegExMatch(StrLower(url), "i)^[a-z]+://([^/:?#]+)", &m)
        return ""
    return m[1]
}

_DomainAllowed(url) {
    host := _HostOf(url)
    if host == ""
        return false
    for d in Cfg.IgnoreList("browser_allow_domains") {
        d := StrLower(Trim(d))
        if d == ""
            continue
        if host == d
            return true
        ; suffix match: host ends with ".d" (github.com ok, github.com.evil.com no)
        if InStr(host, "." . d) == StrLen(host) - StrLen("." . d) + 1
            return true
    }
    return false
}

_ToHttps(remote) {
    remote := Trim(remote)
    if remote == ""
        return ""
    if InStr(remote, "https://") == 1 || InStr(remote, "http://") == 1 {
        if SubStr(remote, StrLen(remote) - 3) == ".git"
            remote := SubStr(remote, 1, StrLen(remote) - 4)
        return remote
    }
    if InStr(remote, "git@") == 1 {
        rest := SubStr(remote, 5)
        parts := StrSplit(rest, ":")
        if parts.Length != 2
            return ""
        path := parts[2]
        if SubStr(path, StrLen(path) - 3) == ".git"
            path := SubStr(path, 1, StrLen(path) - 4)
        return "https://" . parts[1] . "/" . path
    }
    return ""
}

_RemoteUrl(root) {
    r := RunPS("git -C " . _PsLit(root) . " config --get remote.origin.url 2>&1|Out-String", 15)
    if !r["ok"]
        return ""
    return Trim(StrReplace(r["stdout"], "`r`n", ""))
}

_BranchOf(root) {
    r := RunPS("git -C " . _PsLit(root) . " rev-parse --abbrev-ref HEAD 2>&1|Out-String", 15)
    v := Trim(StrReplace(r["stdout"], "`r`n", ""))
    if InStr(v, "fatal")
        return ""
    return v
}

;------------------------------------------------------------------------------
; Browser lifecycle
;------------------------------------------------------------------------------
_EnsureBrowser() {
    if CDP.Available()
        return true
    if !ConfirmDlg("Browser automation"
        , "No browser exposes the CDP debug port (127.0.0.1:9222).`n`n"
        . "Launch Chrome with a dedicated debug profile now?`n"
        . "(A fresh, separate user-data-dir is created under Data\ - your main profile is never touched.)")
        return false
    exe := ""
    for cand in [EnvGet("ProgramFiles") . "\Google\Chrome\Application\chrome.exe"
               , EnvGet("ProgramFiles(x86)") . "\Google\Chrome\Application\chrome.exe"
               , EnvGet("ProgramFiles") . "\Microsoft\Edge\Application\msedge.exe"
               , EnvGet("ProgramFiles(x86)") . "\Microsoft\Edge\Application\msedge.exe"]
        if FileExist(cand) {
            exe := cand
            break
        }
    if exe == "" {
        Notify("Browser automation", "Chrome/Edge not found. Start a browser manually with --remote-debugging-port=9222.", "ERROR")
        return false
    }
    EnsureDirs()
    try Run(_Q(exe) . " --remote-debugging-port=9222 --user-data-dir=" . _Q(Env.DataDir . "\chrome-cdp") . " about:blank")
    catch as e {
        Notify("Browser automation", "Launch failed: " . e.Message, "ERROR")
        return false
    }
    deadline := A_TickCount + 8000
    while A_TickCount < deadline {
        if CDP.Available()
            return true
        Sleep 250
    }
    Notify("Browser automation", "Browser started but the debug port did not answer.", "ERROR")
    return false
}

_ActiveTab() {
    for t in CDP.Tabs() {
        if t.Has("type") && t["type"] == "page" && t.Has("webSocketDebuggerUrl")
            return t
    }
    return ""
}

;------------------------------------------------------------------------------
; Actions
;------------------------------------------------------------------------------
JiraPr() {
    if !_EnsureBrowser()
        return
    root := ActiveProject()
    if root == "" {
        Notify("Jira/PR", "No VS Code project detected.", "WARN")
        return
    }
    root := GitRootOf(root)
    if root == "" {
        Notify("Jira/PR", "Active project is not a git repo.", "WARN")
        return
    }
    branch := _BranchOf(root)
    if branch == "" {
        Notify("Jira/PR", "Could not determine the current branch (detached HEAD?).", "WARN")
        return
    }
    url := ""
    if RegExMatch(branch, "i)^[A-Z]{2,}-\d+$") {
        base := Cfg.Read("browser", "jira_base", "")
        if base != ""
            url := RTrim(base, "/") . "/browse/" . branch
        else
            Notify("Jira/PR", "Branch looks like a Jira ticket, but [browser] jira_base is unset. Falling back to GitHub.", "WARN")
    }
    if url == "" {
        https := _ToHttps(_RemoteUrl(root))
        if https == ""
            https := "https://github.com"
        url := https . "/compare/" . branch
    }
    if !_DomainAllowed(url) {
        Log("BrowserAutomation: refused URL outside allowlist: " . url, "WARN")
        Notify("Jira/PR", "Target domain is not in [browser_allow_domains]. Refused.", "SECURITY")
        return
    }
    tab := CDP.NewTab(url)
    if tab == ""
        Notify("Jira/PR", "Could not open a new tab.", "ERROR")
    else
        Notify("Jira/PR", "Opened: " . url, "INFO")
}

_FillJS(url, form, dryRun, submit) {
    ; Build one JS expression that fills every field and returns per-field
    ; status codes (1 = filled/highlighted, 0 = selector missing). Values are
    ; embedded as JSON literals - no string concatenation into JS.
    blocks := []
    for f in form["fields"] {
        sel := String(f["selector"])
        val := String(f["value"])
        if f.Has("secret") && f["secret"] == true && SubStr(val, 1, 5) == "cred:" {
            val := Cred.Get(SubStr(val, 6))
            if val == "" {
                Notify("Form fill", "Credential '" . SubStr(String(f["value"]), 6) . "' not found in Credential Manager.", "ERROR")
                val := ""
            }
        }
        if dryRun
            body := "var el=document.querySelector(" . JSON.stringify(sel) . ");if(!el){return 0}el.style.outline='3px solid red';el.scrollIntoView();return 1"
        else
            body := "var el=document.querySelector(" . JSON.stringify(sel) . ");if(!el){return 0}el.focus();el.value="
                . JSON.stringify(val)
                . ";el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));return 1"
        blocks.Push("(function(){" . body . "})()")
    }
    expr := "JSON.stringify([" . StrJoin(blocks, ",") . "])"
    if submit && !dryRun
        expr := "(function(){var r=" . expr . ";var el=document.querySelector("
            . JSON.stringify(String(form["fields"][1]["selector"])) . ");"
            . "var f=el?el.closest('form'):null;if(f){f.submit();r.push('submitted')}else{r.push('noform')}return JSON.stringify(r)})()"
    return expr
}

FormFill() {
    if !_EnsureBrowser()
        return
    tab := _ActiveTab()
    if tab == "" {
        Notify("Form fill", "No page tab found via CDP.", "ERROR")
        return
    }
    url := tab["url"]
    forms := JSON.parse(FileRead(Cfg.File("formfill.json")))
    form := ""
    for f in forms["forms"]
        if InStr(url, String(f["url_pattern"])) > 0
            form := f
    if form == "" {
        Notify("Form fill", "No formfill.json entry matches " . url, "WARN")
        return
    }
    if !_DomainAllowed(url) {
        Log("BrowserAutomation: form fill refused for " . url, "WARN")
        Notify("Form fill", "Domain not in [browser_allow_domains]. Refused.", "SECURITY")
        return
    }
    dry := form.Has("dry_run") && form["dry_run"] == true
    doSubmit := form.Has("submit") && form["submit"] == true
    res := CDP.EvalString(tab, _FillJS(url, form, dry, doSubmit))
    ok := 0
    if res != "" {
        try {
            arr := JSON.parse(res)
            for v in arr
                if v == 1
                    ok++
        }
    }
    Log("BrowserAutomation: form fill on " . url . " - " . ok . "/" . form["fields"].Length
        . (dry ? " (dry-run)" : "") . (doSubmit ? " (submitted)" : ""), "INFO")
    Notify("Form fill", ok . "/" . form["fields"].Length . " fields " . (dry ? "highlighted (dry-run)" : "filled")
        . (doSubmit ? " - form submitted" : ""), "INFO")
}

ScrapeTable() {
    if !_EnsureBrowser()
        return
    tab := _ActiveTab()
    if tab == "" {
        Notify("Table scrape", "No page tab found via CDP.", "ERROR")
        return
    }
    if !_DomainAllowed(tab["url"]) {
        Notify("Table scrape", "Domain not in [browser_allow_domains]. Refused.", "SECURITY")
        return
    }
    js := "(function(){var t=document.querySelector('table');if(!t){return ''}"
        . "var rows=[];var trs=t.querySelectorAll('tr');"
        . "for(var i=0;i<trs.length;i++){var cells=[];var tds=trs[i].querySelectorAll('th,td');"
        . "for(var j=0;j<tds.length;j++){var c=tds[j].innerText.replace(/\t/g,' ').replace(/\r?\n/g,' ');cells.push(c)}"
        . "rows.push(cells.join('\t'))}return rows.join('\n')})()"
    tsv := CDP.EvalString(tab, js)
    if tsv == "" {
        Notify("Table scrape", "No table found on this page.", "WARN")
        return
    }
    A_Clipboard := tsv
    rows := 0
    Loop Parse tsv, "`n"
        rows++
    Log("BrowserAutomation: scraped table - " . rows . " rows to clipboard", "INFO")
    Notify("Table scrape", rows . " rows copied to the clipboard as TSV.", "INFO")
}

;------------------------------------------------------------------------------
; Bindings
;------------------------------------------------------------------------------
BindHotkey(Cfg.Read("hotkeys", "browser_jira", "Win+Alt+J"), JiraPr, "BrowserAutomation: Jira/PR")
BindHotkey(Cfg.Read("hotkeys", "browser_fill", "Win+Alt+F"), FormFill, "BrowserAutomation: form fill")
BindHotkey(Cfg.Read("hotkeys", "browser_scrape", "Win+Alt+S"), ScrapeTable, "BrowserAutomation: table scrape")
Log("BrowserAutomation started (CDP " . (CDP.Available() ? "available" : "offline") . ")", "INFO")
