param(
    [Parameter(Mandatory=$true)] [string]$InstallPath,
    [string]$Time = "09:00"
)
$ErrorActionPreference = "Stop"
$ExePath = Join-Path $InstallPath "WinSecLite.exe"
if (-not (Test-Path $ExePath)) { throw "WinSecLite.exe not found at $ExePath" }
$Action = New-ScheduledTaskAction -Execute $ExePath -Argument "scan quick --report html"
$Trigger = New-ScheduledTaskTrigger -Daily -At $Time
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
Register-ScheduledTask -TaskName "WinSecLite Daily Quick Scan" -Action $Action -Trigger $Trigger -Principal $Principal -Description "Daily WinSecLite defensive quick scan" -Force
Write-Host "Scheduled task created at $Time"
