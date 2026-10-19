#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\CDP.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Minimal Chrome DevTools Protocol client. HTTP endpoints via
;          WinHttpRequest COM; WebSocket (Runtime.evaluate) via .NET
;          ClientWebSocket through Core.RunPS. Zero third-party libraries —
;          both engines ship with Windows.
; SECURITY: The debug port MUST stay bound to 127.0.0.1 (Chrome/Edge refuse
;          non-local connections for --remote-debugging-port without
;          --remote-debugging-address anyway). Never expose port 9222 to a
;          network, and never point this at a shared profile (see README).
; NOTE   : Include Core.ahk before this file (uses Env/Log/RunPS/JSON).
;==============================================================================

class CDP {
    static Port := 9222

    static Base() => "http://127.0.0.1:" . CDP.Port

    static Get(path) {
        ; HTTP GET against the debug endpoint. Map(ok, body); body "" on any
        ; failure (including timeouts) — never throws.
        try {
            http := ComObject("WinHttp.WinHttpRequest.5.1")
            http.SetTimeouts(1500, 1500, 3000, 3000)
            http.Open("GET", CDP.Base() . path, false)
            http.Send()
            return Map("ok", http.Status == 200, "body", http.ResponseText)
        } catch {
            return Map("ok", false, "body", "")
        }
    }

    static Available() {
        ; True when a browser exposes the debug endpoint on 127.0.0.1.
        return CDP.Get("/json/version")["ok"]
    }

    static Version() {
        r := CDP.Get("/json/version")
        if !r["ok"]
            return ""
        try return JSON.parse(r["body"])
        catch
            return ""
    }

    static Tabs() {
        ; Array of tab maps: {id, title, url, webSocketDebuggerUrl, ...}.
        r := CDP.Get("/json/list")
        if !r["ok"]
            return []
        try return JSON.parse(r["body"])
        catch
            return []
    }

    static NewTab(url := "about:blank") {
        ; Create a fresh tab via HTTP. Returns the tab map or "".
        r := CDP.Get("/json/new?url=" . _UriEncode(url))
        if !r["ok"]
            return ""
        try return JSON.parse(r["body"])
        catch
            return ""
    }

    static ActivateTab(tab) {
        return CDP.Get("/json/activate/" . tab["id"])["ok"]
    }

    static Eval(tab, expr) {
        ; Runtime.evaluate over WebSocket. Returns the JSON 'result' object
        ; (has value/type) or "" on failure. The expression travels via a
        ; temp file — never through a command line.
        Global _CDP_WS_PS
        ws := tab["webSocketDebuggerUrl"]
        if !ws
            return ""
        EnsureDirs()
        tmp := Env.DataDir . "\tmp\cdp-" . A_TickCount . ".js"
        try FileAppend(expr, tmp, "UTF-8-RAW")
        catch {
            Log("CDP.Eval: cannot write expression file", "ERROR")
            return ""
        }
        r := RunPS(_CDP_WS_PS, 25, ["-WsUrl", ws, "-ExprFile", tmp])
        try FileDelete(tmp)
        out := Trim(StrReplace(r["stdout"], "`r`n", ""))
        if !r["ok"] || out == "" {
            Log("CDP.Eval failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
            return ""
        }
        try {
            msg := JSON.parse(out)
            if msg.Has("result") && !msg.Has("error")
                return msg["result"]
            Log("CDP.Eval protocol error: " . SubStr(out, 1, 200), "WARN")
            return ""
        } catch as e {
            Log("CDP.Eval parse error: " . ErrText(e), "WARN")
            return ""
        }
    }

    static EvalString(tab, expr) {
        ; Convenience: the evaluated value as a string ("" when not a string).
        res := CDP.Eval(tab, expr)
        if !IsObject(res) || !res.Has("value")
            return ""
        return String(res["value"])
    }
}

_UriEncode(s) {
    ; Minimal RFC 3986 encoding for URLs we build (safe chars kept as-is).
    out := ""
    Loop Parse s {
        c := A_LoopField
        if RegExMatch(c, "i)[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]")
            out .= c
        else
            out .= Format("%{:02X}", Ord(c))
    }
    return out
}

_CDP_WS_PS := (
    "param([string]$WsUrl, [string]$ExprFile)`n"
    . "$expr = [IO.File]::ReadAllText($ExprFile)`n"
    . "$ws = [Net.WebSockets.ClientWebSocket]::new()`n"
    . "$ws.ConnectAsync([Uri]$WsUrl, [Threading.CancellationToken]::None).GetAwaiter().GetResult()`n"
    . "$payload = @{ id = 1; method = 'Runtime.evaluate'; params = @{ expression = $expr; returnByValue = $true; awaitPromise = $true } } | ConvertTo-Json -Depth 6 -Compress`n"
    . "$bytes = [Text.Encoding]::UTF8.GetBytes($payload)`n"
    . "$ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()`n"
    . "$ms = New-Object IO.MemoryStream`n"
    . "$buffer = New-Object byte[] 65536`n"
    . "$done = $false`n"
    . "while (-not $done) {`n"
    . "  $res = $ws.ReceiveAsync([ArraySegment[byte]]::new($buffer), [Threading.CancellationToken]::None).GetAwaiter().GetResult()`n"
    . "  $ms.Write($buffer, 0, $res.Count)`n"
    . "  if ($res.EndOfMessage) { $done = $true }`n"
    . "}`n"
    . "$ws.Dispose()`n"
    . "[Text.Encoding]::UTF8.GetString($ms.ToArray())`n"
)
