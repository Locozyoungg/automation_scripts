#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Security\BackupGuardian.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Mirrors [security] backup_source to
;          [security]\backup_dest\AHKToolkitBackup\<ts>\ with robocopy /MIR,
;          records a SHA-256 manifest of the source, verifies every copied
;          file against it, and prunes old backup sets to [security]
;          backup_retention (default 7). Runs at start and every 24 h.
;          Disabled by default; requires backup_dest to be set.
; USAGE  : Launcher child (default) or standalone.
;          --selftest : manifest + verify + prune logic on temp fixtures,
;          no robocopy (exit 0/1).
; SECURITY: Backups are local copies of YOUR data. Never sends anything
;          anywhere. Verify failures raise SECURITY alerts.
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
    fx := Env.DataDir . "\tmp\bg-fixture"
    if DirExist(fx)
        DirDelete(fx, true)
    DirCreate(fx . "\src")
    DirCreate(fx . "\dst")
    FileAppend("alpha content", fx . "\src\a.txt")
    FileAppend("beta content", fx . "\src\b.txt")
    FileAppend("gamma", fx . "\src\c.txt")
    man := _BG_Manifest(fx . "\src")
    Check("manifest hashes all files", man["count"] == 3, "count=" . man["count"])
    ; Simulate the robocopy result with plain copies.
    FileCopy(fx . "\src\a.txt", fx . "\dst\a.txt", true)
    FileCopy(fx . "\src\b.txt", fx . "\dst\b.txt", true)
    FileCopy(fx . "\src\c.txt", fx . "\dst\c.txt", true)
    v1 := _BG_Verify(fx . "\dst", man)
    Check("verify: clean copy passes", v1.Length == 0)
    FileAppend("tampered!", fx . "\dst\b.txt")
    v2 := _BG_Verify(fx . "\dst", man)
    Check("verify: tampered file detected", v2.Length == 1 && InStr(v2[1], "b.txt") > 0)
    Check("verify: missing file detected", (_BG_Verify(fx . "\dst", _BG_Manifest(fx . "\src"))).Length == 1)
    ; Prune logic on fake set names.
    Check("prune keeps newest N", _BG_PruneList(["20261001-000000", "20261002-000000", "20261003-000000"], 2).Length == 1
        && _BG_PruneList(["20261001-000000", "20261002-000000", "20261003-000000"], 2)[1] == "20261001-000000")
    Check("prune keeps all under retention", _BG_PruneList(["a", "b"], 5).Length == 0)
    DirDelete(fx, true)
    Out(Format("RESULT: {1} passed, {2} failed", Pass, Fail))
    ExitApp(Fail == 0 ? 0 : 1)
}

InstallKillSwitch("BackupGuardian`nMirrors backup_source to backup_dest (24 h).`nKill-switch: Esc+Pause")

;------------------------------------------------------------------------------
; Manifest + verify (pure helpers)
;------------------------------------------------------------------------------
_BG_Src() => Cfg.Read("security", "backup_source", "C:\dev")
_BG_Dest() => Cfg.Read("security", "backup_dest", "")

_BG_ManifestPS(src) {
    ; Pure .NET SHA-256 (no Get-FileHash: some PS environments cannot
    ; autoload Microsoft.PowerShell.Utility when spawned via Exec).
    return "$src=" . _PsLit(src) . "`n"
        . "$files=@(Get-ChildItem -Path $src -Recurse -File -ErrorAction SilentlyContinue|Where-Object{$_.Length -lt 52428800 -and $_.FullName -notmatch '\\(node_modules|\\.git|\\.venv|venv|dist|build|target|obj|__pycache__|\\.next|\\.cache)(\\\\|$)'})`n"
        . "$m=@{}`n"
        . "$sha=[Security.Cryptography.SHA256]::Create()`n"
        . "foreach($f in $files){`n"
        . "  try{$b=[IO.File]::ReadAllBytes($f.FullName);$rel=$f.FullName.Substring($src.Length+1);$m[$rel]=(($sha.ComputeHash($b)|ForEach-Object{$_.ToString('x2')}) -join '')}catch{}`n"
        . "}`n"
        . "@{count=$files.Count;files=$m}|ConvertTo-Json -Depth 3 -Compress"
}

_BG_Manifest(src) {
    return RunPSJsonF(_BG_ManifestPS(src), 600, Map())
}

_BG_Verify(dst, manifest) {
    ; Hash the copy and compare against the manifest. Returns mismatch relpaths.
    if !IsObject(manifest) || !manifest.Has("files")
        return ["(manifest unavailable)"]
    dm := RunPSJsonF(_BG_ManifestPS(dst), 600, Map())
    bad := []
    if !IsObject(dm) || !dm.Has("files") {
        bad.Push("(could not read backup copy)")
        return bad
    }
    for rel, hash in manifest["files"]
        if !dm["files"].Has(rel) || dm["files"][rel] != hash
            bad.Push(rel)
    return bad
}

_BG_PruneList(names, retention) {
    ; names: yyyyMMdd-HHmmss set names (sortable). Returns the ones to DELETE.
    out := []
    if names.Length <= retention
        return out
    ; newest first
    sorted := names.Clone()
    for i in sorted
        i := String(i)
    ; bubble desc (lists are tiny)
    j := 1
    while j < sorted.Length {
        k := j + 1
        while k <= sorted.Length {
            if StrCompare(sorted[j], sorted[k]) < 0 {
                t := sorted[j]
                sorted[j] := sorted[k]
                sorted[k] := t
            }
            k += 1
        }
        j += 1
    }
    idx := retention + 1
    while idx <= sorted.Length {
        out.Push(sorted[idx])
        idx += 1
    }
    return out
}

;------------------------------------------------------------------------------
; Backup run
;------------------------------------------------------------------------------
_BG_Run() {
    src := _BG_Src(), dest := _BG_Dest()
    if dest == "" {
        Log("BackupGuardian: backup_dest is empty - set [security] backup_dest in settings.ini", "WARN")
        return
    }
    if !DirExist(src) {
        Log("BackupGuardian: backup_source '" . src . "' does not exist", "ERROR")
        Notify("BackupGuardian", "backup_source not found: " . src, "ERROR")
        return
    }
    ts := FormatTime(A_Now, "yyyyMMdd-HHmmss")
    dst := dest . "\AHKToolkitBackup\" . ts
    AuditLog("BackupGuardian: backup started - " . src . " -> " . dst)
    man := _BG_Manifest(src)
    if !IsObject(man) || !man.Has("count") {
        Notify("BackupGuardian", "Manifest build failed - backup aborted.", "ERROR")
        return
    }
    r := RunPS("& robocopy " . _PsLit(src) . " " . _PsLit(dst)
        . " /MIR /R:1 /W:1 /NFL /NDL /NJH /NP /XD node_modules .git .venv venv dist build target obj __pycache__ .next .cache 2>&1|Out-String`n"
        . "if($LASTEXITCODE -lt 8){exit 0}else{exit $LASTEXITCODE}", 3600)
    if !r["ok"] {
        Notify("BackupGuardian", "robocopy failed (exit " . r["exit"] . ").", "ERROR")
        AuditLog("BackupGuardian: robocopy FAILED (exit " . r["exit"] . ")")
        return
    }
    bad := _BG_Verify(dst, man)
    if bad.Length {
        Notify("Backup verify FAILED", bad.Length . " file(s) differ from the source manifest.", "SECURITY")
        AuditLog("BackupGuardian: verify failed - " . bad.Length . " mismatched file(s): " . StrJoin(_BG_FirstN(bad, 5), ", "))
    } else {
        Notify("Backup complete", man["count"] . " files mirrored and verified to " . dst, "INFO")
        AuditLog("BackupGuardian: backup verified - " . man["count"] . " files -> " . dst)
    }
    ; Prune old sets beyond retention.
    if DirExist(dest . "\AHKToolkitBackup") {
        names := []
        try Loop Files dest . "\AHKToolkitBackup\*", "D"
            names.Push(A_LoopFileName)
        for old in _BG_PruneList(names, Cfg.Int("security", "backup_retention", 7)) {
            p := dest . "\AHKToolkitBackup\" . old
            if DirExist(p) {
                try DirDelete(p, true)
                Log("BackupGuardian: pruned old backup set " . old, "INFO")
            }
        }
    }
}

_BG_FirstN(arr, n) {
    out := []
    i := 1
    while i <= Min(n, arr.Length) {
        out.Push(arr[i])
        i += 1
    }
    return out
}

;------------------------------------------------------------------------------
; Resident loop (Launcher watchdog restarts exiting children, so this stays
; resident: backup at start, then every 24 h).
;------------------------------------------------------------------------------
_BG_Run()
SetTimer(_BG_Run, 86400000)
Log("BackupGuardian started (source=" . _BG_Src() . " dest=" . (_BG_Dest() == "" ? "(unset)" : _BG_Dest()) . ")", "INFO")
