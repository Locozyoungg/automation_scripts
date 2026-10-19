#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the toolkit's Task Scheduler entries.

.DESCRIPTION
    Unregisters AHK-Toolkit-Launcher (logon start) and AHK-Toolkit-WeeklyAudit.
    Leaves Data\ and Logs\ untouched - they are local-only by design.
    Running tools are not killed: exit the tray launcher first (Esc+Pause
    or Exit All in the tray menu).

.PARAMETER WhatIf
    Show which tasks would be removed without removing them.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Install\Uninstall.ps1
#>
[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

foreach ($name in @('AHK-Toolkit-Launcher', 'AHK-Toolkit-WeeklyAudit')) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        if ($WhatIf) {
            Write-Host "[UNINSTALL] would remove: $name"
        }
        else {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "[UNINSTALL] Removed task: $name"
        }
    }
    else {
        Write-Host "[UNINSTALL] Not present: $name"
    }
}

Write-Host ''
Write-Host 'Task Scheduler entries are gone. The toolkit will no longer start at logon.' -ForegroundColor Green
Write-Host "Your Data\ and Logs\ folders under $Root are untouched (local-only)."
Write-Host 'To remove everything: exit the tray launcher, then delete the toolkit folder.'
