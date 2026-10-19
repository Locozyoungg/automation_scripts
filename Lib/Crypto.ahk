#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\Crypto.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : DPAPI (CurrentUser scope) and AES-256-CBC + HMAC-SHA256 helpers,
;          implemented through .NET via Core.RunPS. Used by ClipboardManager
;          (encrypted history), SecretsScanner allow-lists, PanicKey.
; SECURITY: DPAPI binds ciphertext to this Windows user — files copied to
;           another machine or account cannot be decrypted. AES uses
;           encrypt-then-MAC (CBC + HMAC) because .NET Framework 4.8 (PS 5.1)
;           has no AES-GCM. Keys are 64 hex chars (32 bytes).
; NOTE   : Function definitions only — no top-level side effects.
;==============================================================================

; --- DPAPI engine. Ops: encs/decs (string <-> base64) and encf/decf (files). ---
_DPAPI_PS := (
    "param([string]$Op, [string]$In, [string]$Out = '')`n"
    . "Add-Type -AssemblyName System.Security`n"
    . "if ($Op -eq 'encs') {`n"
    . "  $b = [IO.File]::ReadAllBytes($In)`n"
    . "  $p = [Security.Cryptography.ProtectedData]::Protect($b, $null, 'CurrentUser')`n"
    . "  [Convert]::ToBase64String($p)`n"
    . "} elseif ($Op -eq 'decs') {`n"
    . "  $b = [Convert]::FromBase64String(([IO.File]::ReadAllText($In)).Trim())`n"
    . "  $p = [Security.Cryptography.ProtectedData]::Unprotect($b, $null, 'CurrentUser')`n"
    . "  [Text.Encoding]::UTF8.GetString($p)`n"
    . "} elseif ($Op -eq 'encf') {`n"
    . "  $b = [IO.File]::ReadAllBytes($In)`n"
    . "  $p = [Security.Cryptography.ProtectedData]::Protect($b, $null, 'CurrentUser')`n"
    . "  [IO.File]::WriteAllBytes($Out, $p)`n"
    . "} else {`n"
    . "  $b = [IO.File]::ReadAllBytes($In)`n"
    . "  $p = [Security.Cryptography.ProtectedData]::Unprotect($b, $null, 'CurrentUser')`n"
    . "  [IO.File]::WriteAllBytes($Out, $p)`n"
    . "}"
)

; --- AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) engine. Ops: enc / dec. -----
_AES_PS := (
    "param([string]$Op, [string]$In, [string]$KeyHex)`n"
    . "$key = New-Object byte[] 32`n"
    . "for ($i = 0; $i -lt 32; $i++) { $key[$i] = [Convert]::ToByte($KeyHex.Substring($i * 2, 2), 16) }`n"
    . "if ($Op -eq 'enc') {`n"
    . "  $plain = [IO.File]::ReadAllBytes($In)`n"
    . "  $aes = [Security.Cryptography.Aes]::Create()`n"
    . "  $aes.Key = $key; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.GenerateIV()`n"
    . "  $enc = $aes.CreateEncryptor()`n"
    . "  $ct = $enc.TransformFinalBlock($plain, 0, $plain.Length)`n"
    . "  $hmac = New-Object Security.Cryptography.HMACSHA256(,$key)`n"
    . "  $mac = $hmac.ComputeHash($ct)`n"
    . "  $out = New-Object byte[] (16 + $ct.Length + 32)`n"
    . "  [Array]::Copy($aes.IV, 0, $out, 0, 16)`n"
    . "  [Array]::Copy($ct, 0, $out, 16, $ct.Length)`n"
    . "  [Array]::Copy($mac, 0, $out, 16 + $ct.Length, 32)`n"
    . "  [Convert]::ToBase64String($out)`n"
    . "} else {`n"
    . "  $blob = [Convert]::FromBase64String(([IO.File]::ReadAllText($In)).Trim())`n"
    . "  if ($blob.Length -lt 49) { throw 'blob too small' }`n"
    . "  $iv = New-Object byte[] 16; [Array]::Copy($blob, 0, $iv, 0, 16)`n"
    . "  $ctLen = $blob.Length - 48`n"
    . "  $ct = New-Object byte[] $ctLen; [Array]::Copy($blob, 16, $ct, 0, $ctLen)`n"
    . "  $mac = New-Object byte[] 32; [Array]::Copy($blob, 16 + $ctLen, $mac, 0, 32)`n"
    . "  $hmac = New-Object Security.Cryptography.HMACSHA256(,$key)`n"
    . "  $expect = $hmac.ComputeHash($ct)`n"
    . "  for ($i = 0; $i -lt 32; $i++) { if ($mac[$i] -ne $expect[$i]) { throw 'MAC mismatch' } }`n"
    . "  $aes = [Security.Cryptography.Aes]::Create()`n"
    . "  $aes.Key = $key; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.IV = $iv`n"
    . "  $dec = $aes.CreateDecryptor()`n"
    . "  $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)`n"
    . "  [Text.Encoding]::UTF8.GetString($pt)`n"
    . "}"
)

_CryptoStrOp(op, payload, psBody) {
    ; Shared temp-file plumbing for string-based crypto ops.
    EnsureDirs()
    inFile := Env.DataDir . "\tmp\crypto-" . _OwnPID() . "-" . A_TickCount . "-" . Random(1000, 9999) . ".txt"
    try FileAppend(payload, inFile, "UTF-8-RAW")
    catch {
        Log("Crypto: cannot write temp payload", "ERROR")
        return ""
    }
    r := RunPS(psBody, 20, ["-Op", op, "-In", inFile])
    try FileDelete(inFile)
    out := Trim(StrReplace(r["stdout"], "`r`n", ""))
    if !r["ok"] || out == "" {
        Log("Crypto " . op . " failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
        return ""
    }
    return out
}

; --- DPAPI public API ---------------------------------------------------------
DpapiProtectStr(plain) {
    ; plaintext -> base64 DPAPI blob (CurrentUser). "" on failure.
    Global _DPAPI_PS
    return _CryptoStrOp("encs", plain, _DPAPI_PS)
}

DpapiUnprotectStr(b64) {
    ; base64 DPAPI blob -> plaintext. "" on failure or wrong user.
    Global _DPAPI_PS
    return _CryptoStrOp("decs", b64, _DPAPI_PS)
}

DpapiProtectFile(plainPath, outPath) {
    Global _DPAPI_PS
    EnsureDirs()
    r := RunPS(_DPAPI_PS, 30, ["-Op", "encf", "-In", plainPath, "-Out", outPath])
    if !r["ok"]
        Log("DpapiProtectFile failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
    return r["ok"]
}

DpapiUnprotectFile(inPath, outPath) {
    Global _DPAPI_PS
    EnsureDirs()
    r := RunPS(_DPAPI_PS, 30, ["-Op", "decf", "-In", inPath, "-Out", outPath])
    if !r["ok"]
        Log("DpapiUnprotectFile failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
    return r["ok"]
}

; --- AES public API -----------------------------------------------------------
AesEncryptStr(plain, keyHex) {
    ; AES-256-CBC + HMAC-SHA256, output base64(iv || ct || mac). "" on failure.
    if !RegExMatch(keyHex, "i)^[0-9a-f]{64}$") {
        Log("AesEncryptStr: key must be 64 hex chars (32 bytes)", "ERROR")
        return ""
    }
    return _AesStrOp("enc", plain, keyHex)
}

AesDecryptStr(b64, keyHex) {
    if !RegExMatch(keyHex, "i)^[0-9a-f]{64}$") {
        Log("AesDecryptStr: key must be 64 hex chars (32 bytes)", "ERROR")
        return ""
    }
    return _AesStrOp("dec", b64, keyHex)
}

_AesStrOp(op, payload, keyHex) {
    ; Shared temp-file plumbing. KeyHex travels as a bound param so it never
    ; appears on a command line.
    Global _AES_PS
    EnsureDirs()
    inFile := Env.DataDir . "\tmp\crypto-" . _OwnPID() . "-" . A_TickCount . "-" . Random(1000, 9999) . ".txt"
    try FileAppend(payload, inFile, "UTF-8-RAW")
    catch {
        Log("Crypto: cannot write temp payload", "ERROR")
        return ""
    }
    r := RunPS(_AES_PS, 20, ["-Op", op, "-In", inFile, "-KeyHex", keyHex])
    try FileDelete(inFile)
    out := Trim(StrReplace(r["stdout"], "`r`n", ""))
    if !r["ok"] || out == "" {
        Log("Crypto " . op . " failed: " . StrReplace(Trim(r["stderr"]), "`r`n", " "), "ERROR")
        return ""
    }
    return out
}
