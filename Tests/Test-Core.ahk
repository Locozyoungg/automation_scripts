#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Tests\Test-Core.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Smoke tests for the Core library: root resolution, tool registry,
;          JSON round-trip + escapes, SHA-256 NIST test vector, FNV
;          determinism, RunPS (stdout, exit codes, param-arg binding, JSON,
;          timeout), logger rotation, tamper-evident hash-chain verification,
;          config defaults/validation, DPAPI + AES round-trips, Cred.Get
;          failure path. No hotkeys, no tray, no side effects.
; RUN    : "C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe" Tests\Test-Core.ahk
;          Exit code 0 = all passed; 1 = at least one failure.
;==============================================================================
#Warn All, StdOut
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
#Include ..\Lib\Core.ahk

Pass := 0
Fail := 0

Out(msg) {
    ; Print to console AND to the log — a selftest must leave a trail.
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

; --- 1. Root / directory resolution -------------------------------------------
EnsureDirs()
Check("Env.Root exists and contains toolkit folders"
    , DirExist(Env.Root) && DirExist(Env.LogDir) && DirExist(Env.ConfigDir) && DirExist(Env.DataDir)
    , Env.Root)

Check("Tool registry populated", Tools.List().Length >= 20, "count=" . Tools.List().Length)

; --- 2. JSON round-trip --------------------------------------------------------
jObj := Map("a", [1, 2, Map("b", "x`ny")], "c", 3.5, "d", true, "e", false)
jStr := JSON.stringify(jObj)
jBack := JSON.parse(jStr)
Check("JSON round-trip Map/Array nesting"
    , jBack["a"][3]["b"] == "x`ny" && jBack["c"] == 3.5 && jBack["d"] == 1 && jBack["e"] == 0
    , jStr)

Check("JSON unicode escape decode", JSON.parse("`"A\u0042C`"") == "ABC")

jQ := Map("k", "q`"t")
Check("JSON survives embedded quotes", JSON.parse(JSON.stringify(jQ))["k"] == "q`"t")

badCaught := false
try JSON.parse("{this is not json")
catch
    badCaught := true
Check("JSON malformed input throws", badCaught)

; --- 3. Hashing -----------------------------------------------------------------
fnv1 := Fnv1a("hello world")
fnv2 := Fnv1a("hello world")
fnv3 := Fnv1a("hello worle")
Check("FNV-1a deterministic", fnv1 == fnv2 && StrLen(fnv1) <= 8, "fnv1=" . fnv1 . " fnv2=" . fnv2)
Check("FNV-1a changes with input", fnv1 != fnv3)

; SHA-256("abc") — well-known NIST test vector.
Check("SHA-256 test vector (abc)"
    , Sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

; --- 4. RunPS -------------------------------------------------------------------
r1 := RunPS("'hello'")
Check("RunPS captures stdout", r1["ok"] && InStr(Trim(r1["stdout"]), "hello") > 0, r1["stderr"])

r2 := RunPS("exit 3")
Check("RunPS reports exit codes", !r2["ok"] && r2["exit"] == 3)

r3 := RunPS("param([string]$A) $A", 15, ["-A", "hello-arg"])
Check("RunPS binds param args", r3["ok"] && InStr(Trim(r3["stdout"]), "hello-arg") > 0, r3["stderr"])

r4 := RunPSJson("@{a=1;b='x'}|ConvertTo-Json -Compress")
Check("RunPSJson parses ConvertTo-Json", IsObject(r4) && r4.Has("a") && r4["a"] == 1 && r4["b"] == "x")

t0 := A_TickCount
r5 := RunPS("Start-Sleep 60", 2)
elapsed := A_TickCount - t0
Check("RunPS enforces timeout", !r5["ok"] && elapsed < 15000, "elapsed " . elapsed . "ms")

; --- 5. Logger rotation ----------------------------------------------------------
rotLog := Env.LogDir . "\Test-Core.log"
try FileDelete(rotLog)
try FileDelete(rotLog . ".1")
; 100 KB chunk appended 21 times (~2.1 MB total) — avoids O(n^2) concat.
chunk := ""
Loop 1000
    chunk .= "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789`n"
Loop 21
    try FileAppend(chunk, rotLog, "UTF-8-RAW")
Log("rotation trigger line", "TEST")
Check("Log rotates at 2 MB (keeps .1)", FileExist(rotLog . ".1") && FileGetSize(rotLog) < 1024 * 1024
    , "cur=" . FileGetSize(rotLog) . " rotated=" . (FileExist(rotLog . ".1") ? FileGetSize(rotLog . ".1") : "none"))

; --- 6. Tamper-evident audit chain ----------------------------------------------
audLog := Env.LogDir . "\audit-Test-Core.log"
audState := Env.DataDir . "\state\audit-Test-Core.chain"
try FileDelete(audLog)
try FileDelete(audState)
AuditLog("test entry one")
AuditLog("test entry two")
AuditLog("test entry three")
v1 := VerifyLogChain(audLog)
Check("VerifyLogChain passes on clean chain", v1 == "OK", v1)
try FileAppend("2020-01-01 00:00:00.000 | AUDIT | injected line`r`n", audLog)
v2 := VerifyLogChain(audLog)
Check("VerifyLogChain detects tampering", InStr(v2, "BROKEN") == 1, v2)
try FileDelete(audLog)
try FileDelete(audState)
Check("VerifyLogChain on missing file", VerifyLogChain(Env.LogDir . "\audit-does-not-exist.log") == "NO FILE")

; --- 7. Config defaults + validation --------------------------------------------
cfgTmp := Cfg.File("test-tmp.ini")
try FileDelete(cfgTmp)
Check("Cfg.Read falls back to default", Cfg.Read("s", "k", "fallback", "test-tmp.ini") == "fallback")
Cfg.Write("s", "k", "stored", "test-tmp.ini")
Check("Cfg.Write/Read round-trip", Cfg.Read("s", "k", "fallback", "test-tmp.ini") == "stored")
Cfg.Write("ints", "bad", "notanumber", "test-tmp.ini")
Check("Cfg.Int validates and falls back", Cfg.Int("ints", "bad", 7, "test-tmp.ini") == 7)
try FileDelete(cfgTmp)

; --- 8. DPAPI round-trip (validates the PS ProtectedData path) ------------------
dp := DpapiProtectStr("toolkit-dpapi-marker")
dpBack := dp != "" ? DpapiUnprotectStr(dp) : ""
Check("DPAPI string round-trip (CurrentUser)", dp != "" && dpBack == "toolkit-dpapi-marker")

; --- 9. AES round-trip + tamper detection ----------------------------------------
aesKey := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
aesCt := AesEncryptStr("toolkit-aes-marker", aesKey)
aesBack := aesCt != "" ? AesDecryptStr(aesCt, aesKey) : ""
Check("AES-256-CBC+HMAC round-trip", aesBack == "toolkit-aes-marker")
aesKey2 := StrReplace(Format("{:064}", 0), "0", "f")
aesWrong := aesCt != "" ? AesDecryptStr(aesCt, aesKey2) : "unexpected"
Check("AES detects wrong key (MAC mismatch)", aesWrong == "")
aesBad := AesEncryptStr("x", "not-a-key")
Check("AES rejects invalid key format", aesBad == "")

; --- 10. Credential Manager failure path ------------------------------------------
cMissing := Cred.Get("AHK-toolkit-does-not-exist")
Check("Cred.Get missing target returns empty", cMissing == "")

; --- Summary ----------------------------------------------------------------------
Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
ExitApp(Fail == 0 ? 0 : 1)
