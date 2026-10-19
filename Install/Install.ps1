#Requires -Version 5.1
<#
.SYNOPSIS
    One-time installer for the Automation & Protection Toolkit.

.DESCRIPTION
    Verifies the AutoHotkey v2 install, creates the runtime folders,
    unblocks downloaded files, runs the test suite + launcher selftest,
    and registers the two documented Task Scheduler entries:

      * AHK-Toolkit-Launcher    - starts the tray host 30 s after logon,
                                  restarts it up to 3 times on failure
      * AHK-Toolkit-WeeklyAudit - elevated weekly security audit
                                  (registered only once Security\SecurityCheck.ahk exists)

    Re-running is safe (idempotent). See Install\Uninstall.ps1 to remove.
    These tasks are the ONLY autostart persistence the toolkit uses.

.PARAMETER SkipTasks
    Skip Task Scheduler registration (folders/unblock/selftest only).

.PARAMETER ProtectData
    Also tighten ACLs on Data\ so only you, SYSTEM and Administrators can
    read it. Requires an elevated shell and runs only when explicitly given.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Install\Install.ps1
    powershell -ExecutionPolicy Bypass -File Install\Install.ps1 -ProtectData
#>
[CmdletBinding()]
param(
    [switch]$SkipTasks,
    [switch]$ProtectData
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

function Write-Step([string]$Text) {
    Write-Host "[INSTALL] $Text" -ForegroundColor Cyan
}

Write-Step "Toolkit root: $Root"

# Task registration (logon task + elevated weekly audit) requires
# administrator rights: importing a task XML with a principal fails with
# "Access is denied" otherwise. Re-launch elevated with the same switches.
# Selftests still run inside the elevated copy, so nothing unverified
# gets registered. -SkipTasks needs no elevation.
if (-not $SkipTasks) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host '[INSTALL] Task registration needs administrator rights (Task Scheduler import). Requesting elevation...' -ForegroundColor Yellow
        $elevArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($ProtectData) { $elevArgs += '-ProtectData' }
        $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $elevArgs -Wait -PassThru
        exit $p.ExitCode
    }
}

# --- 1. Locate AutoHotkey v2 ---------------------------------------------------
$AhkExe = @(
    (Join-Path $env:ProgramFiles 'AutoHotkey\v2\AutoHotkey64.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'AutoHotkey\v2\AutoHotkey64.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $AhkExe) {
    throw 'AutoHotkey v2 was not found in Program Files. Install it from https://www.autohotkey.com (choose v2), then re-run this script.'
}
Write-Step "AutoHotkey: $AhkExe"

# --- 2. Runtime folders ----------------------------------------------------------
$Dirs = @(
    'Logs',
    'Data', 'Data\state', 'Data\clipboard', 'Data\baselines', 'Data\install',
    'Config\baseline',
    'Security'
)
foreach ($d in $Dirs) {
    $p = Join-Path $Root $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
Write-Step 'Runtime folders present'

# --- 3. Unblock downloaded files ---------------------------------------------------
Get-ChildItem -Path $Root -Recurse -File |
    Where-Object { $_.Extension -in '.ahk', '.ps1', '.ini', '.json', '.xml', '.md' } |
    ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }
Write-Step 'Files unblocked (zone identifiers cleared where present)'

# --- 4. Selftests (always run - never install over a broken foundation) ------------
Write-Step 'Running selftests (takes ~1-2 min)...'
# AHK is a GUI-subsystem exe: the call operator would NOT wait for it.
# Start-Process -Wait is required to read the real exit code.
$p = Start-Process -FilePath $AhkExe -ArgumentList @((Join-Path $Root 'Tests\Test-Core.ahk')) -Wait -PassThru -WindowStyle Hidden
if ($p.ExitCode -ne 0) { throw "Test-Core failed with exit $($p.ExitCode) - fix before installing." }
Write-Step 'Test-Core: PASS'
$p = Start-Process -FilePath $AhkExe -ArgumentList @((Join-Path $Root 'Scripts\Launcher.ahk'), '--selftest') -Wait -PassThru -WindowStyle Hidden
if ($p.ExitCode -ne 0) { throw "Launcher --selftest failed with exit $($p.ExitCode) - fix before installing." }
Write-Step 'Launcher --selftest: PASS'

# --- 5. Task Scheduler -------------------------------------------------------------
if ($SkipTasks) {
    Write-Step 'Task registration skipped (-SkipTasks).'
}
else {
    $Sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $User = "$($env:USERDOMAIN)\$($env:USERNAME)"
    $InstantiatedDir = Join-Path $Root 'Data\install'

    # 5a. Logon launcher (always registered)
    $xml = Get-Content -Path (Join-Path $PSScriptRoot 'LaunchToolkit.xml') -Raw
    $xml = $xml.Replace('__AHK_EXE__', $AhkExe).Replace('__ROOT__', $Root).Replace('__USER_SID__', $Sid)
    Set-Content -Path (Join-Path $InstantiatedDir 'AHK-Toolkit-Launcher.xml') -Value $xml -Encoding Unicode
    Register-ScheduledTask -TaskName 'AHK-Toolkit-Launcher' -Xml $xml -Force -ErrorAction Stop | Out-Null
    Write-Step "Task registered: AHK-Toolkit-Launcher (logon + 30 s delay, restart up to 3x) -> $User"

    # 5b. Weekly audit (only once the security suite ships)
    if (Test-Path (Join-Path $Root 'Security\SecurityCheck.ahk')) {
        $auditTime = Get-Date '02:00'
        while ($auditTime.DayOfWeek -ne 'Sunday') { $auditTime = $auditTime.AddDays(1) }
        if ($auditTime -lt (Get-Date)) { $auditTime = $auditTime.AddDays(7) }
        $xml = Get-Content -Path (Join-Path $PSScriptRoot 'WeeklyAudit.xml') -Raw
        $xml = $xml.Replace('__AHK_EXE__', $AhkExe).Replace('__ROOT__', $Root).Replace('__USER_SID__', $Sid).Replace('__START_BOUNDARY__', $auditTime.ToString('yyyy-MM-ddTHH:mm:ss'))
        Set-Content -Path (Join-Path $InstantiatedDir 'AHK-Toolkit-WeeklyAudit.xml') -Value $xml -Encoding Unicode
        try {
            Register-ScheduledTask -TaskName 'AHK-Toolkit-WeeklyAudit' -Xml $xml -Force -ErrorAction Stop | Out-Null
            Write-Step "Task registered: AHK-Toolkit-WeeklyAudit (elevated, Sundays 02:00, next run $($auditTime.ToString('yyyy-MM-dd HH:mm'))) -> $User"
        }
        catch {
            Write-Warning "Could not register AHK-Toolkit-WeeklyAudit: $($_.Exception.Message)"
            Write-Warning 'The elevated weekly task usually needs an elevated shell. Re-run this script as Administrator.'
        }
    }
    else {
        Write-Warning 'Security\SecurityCheck.ahk not present yet - weekly audit task NOT registered. Re-run Install.ps1 after the security suite ships.'
    }

    Write-Step 'Instantiated task XML saved under Data\install\ (gitignored; records exactly what was registered)'
}

# --- 6. Optional ACL hardening on Data\ --------------------------------------------
if ($ProtectData) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw '-ProtectData requires an elevated shell.' }
    $data = Join-Path $Root 'Data'
    icacls $data /inheritance:r /grant:r "*${Sid}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'icacls failed while hardening Data\ ACLs.' }
    Write-Step "ACLs tightened on Data\ ($User + SYSTEM + Administrators only)"
}

Write-Host ''
Write-Host 'Done. The toolkit is installed and will start at your next logon.' -ForegroundColor Green
Write-Host '  Start it right now (no need to sign out): Start-ScheduledTask -TaskName AHK-Toolkit-Launcher'
Write-Host '  Tray menu: start/stop tools, logs, panic. Kill-switch: Esc+Pause.'
Write-Host '  Remove: powershell -ExecutionPolicy Bypass -File Install\Uninstall.ps1'
