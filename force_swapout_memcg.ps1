<#
用途:
- 根据输入的 PID，定位对应进程的进程名和 UID。
- 拼出 memcg 目录名后，执行一组内存回收/换出相关命令，触发目标进程的强制回收与换出。

原理:
- 通过 `ps -ef | grep <pid>` 找到目标进程行，并从中解析出 `uid`、`pid` 和进程名。
- 按 `{进程名}_{uid}` 的规则拼出 memcg 路径。
- 依次执行：
  - `memory.zswapd_single_memcg_param`
  - `memory.force_shrink_all`
  - `memory.force_swapout`
  - `/proc/<pid>/reclaim`
- 该脚本本身不做结果分析，定位目标是提供一个稳定、可复用的换出触发入口。
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [int]$TargetPid,

    [string]$Hdc = "hdc",
    [string]$Device
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[info] $Message"
}

function Invoke-HdcShell {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [string]$RemoteCommand
    )

    $args = @()
    if ($DeviceId) {
        $args += "-t"
        $args += $DeviceId
    }
    $args += "shell"
    $args += $RemoteCommand

    $result = & $HdcPath @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "hdc shell failed: $($result -join [Environment]::NewLine)"
    }
    return ($result -join [Environment]::NewLine)
}

function Get-ProcessInfo {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$QueryPid
    )

    $output = Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "ps -ef | grep $QueryPid"
    $lines = @($output -split "(`r`n|`n|`r)") | Where-Object { $_.Trim() }

    $targetLine = $lines | Where-Object {
        $_ -match "^\s*(\S+)\s+$QueryPid\s+" -and $_ -notmatch "\bgrep\s+$QueryPid\b"
    } | Select-Object -First 1

    if (-not $targetLine) {
        throw "Failed to find process info for pid $QueryPid from: $output"
    }

    $parts = @($targetLine -split '\s+') | Where-Object { $_ -ne "" }
    if ($parts.Count -lt 8) {
        throw "Unexpected ps output format: $targetLine"
    }

    return [pscustomobject]@{
        Uid = $parts[0]
        Pid = [int]$parts[1]
        ProcessName = $parts[-1]
    }
}

$proc = Get-ProcessInfo -HdcPath $Hdc -DeviceId $Device -QueryPid $TargetPid
$packageName = "{0}_{1}" -f $proc.ProcessName, $proc.Uid
$memcgDir = "/dev/memcg/100/$packageName"

Write-Host ""
Write-Host "Force swapout target"
Write-Host "--------------------"
Write-Host ("PID          : {0}" -f $proc.Pid)
Write-Host ("Process name : {0}" -f $proc.ProcessName)
Write-Host ("UID          : {0}" -f $proc.Uid)
Write-Host ("Package dir  : {0}" -f $memcgDir)
Write-Host ""

$commands = @(
    "echo 100 100 50 > $memcgDir/memory.zswapd_single_memcg_param",
    "echo 99 > $memcgDir/memory.force_shrink_all",
    "echo 0 > $memcgDir/memory.force_swapout",
    "echo 4 > /proc/$TargetPid/reclaim"
)

foreach ($cmd in $commands) {
    Write-Info $cmd
    Invoke-HdcShell -HdcPath $Hdc -DeviceId $Device -RemoteCommand $cmd | Out-Null
}

Write-Host "Done."
