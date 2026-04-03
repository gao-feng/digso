<#
用途:
- 以单个目标进程为起点，找出它使用到的库和文件页。
- 再从系统维度分析这些文件还被哪些进程使用，并统计每个文件在各进程中的物理内存占用情况。

原理:
- 先抓取目标进程的 `smaps`，提取所有 file-backed 映射。
- 使用 `lsof` 找到系统里也引用这些文件的进程。
- 再逐个抓取相关进程的 `smaps`，重新按文件聚合 `PSS/RSS`。
- 输出包含三层结果：文件汇总、进程汇总，以及“文件 x 进程”的细粒度明细。
- 该脚本适合分析某个进程所依赖文件在系统范围内的共享情况和实际物理内存分摊。
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [int]$TargetPid,

    [string]$Hdc = "hdc",
    [string]$Device,
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

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

function Invoke-HdcFileRecv {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [string]$RemotePath,
        [string]$LocalPath
    )

    $args = @()
    if ($DeviceId) {
        $args += "-t"
        $args += $DeviceId
    }
    $args += "file"
    $args += "recv"
    $args += $RemotePath
    $args += $LocalPath

    $result = & $HdcPath @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "hdc file recv failed: $($result -join [Environment]::NewLine)"
    }
}

function Get-SafePathName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return "unknown"
    }

    $safe = $Name.Trim()
    foreach ($char in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace($char, "_")
    }
    $safe = $safe -replace '\s+', '_'
    $safe = $safe -replace '[^\w\.-]', '_'
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "unknown"
    }
    return $safe
}

function Get-RemoteProcessName {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$ProcessId
    )

    try {
        $name = Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "cat /proc/$ProcessId/comm"
        return (Get-SafePathName -Name $name)
    } catch {
        return "unknown"
    }
}

function Save-RemoteTextFile {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [string]$RemotePath,
        [string]$LocalPath,
        [string]$RemoteTempPath
    )

    Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "cat $RemotePath > $RemoteTempPath" | Out-Null
    Invoke-HdcFileRecv -HdcPath $HdcPath -DeviceId $DeviceId -RemotePath $RemoteTempPath -LocalPath $LocalPath
    Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "rm -f $RemoteTempPath" | Out-Null
}

function Save-ProcSmaps {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$ProcessId,
        [string]$LocalPath
    )

    $remotePath = "/proc/$ProcessId/smaps"
    $tempPath = "/data/${ProcessId}_shared_usage_smaps"
    Save-RemoteTextFile -HdcPath $HdcPath -DeviceId $DeviceId -RemotePath $remotePath -LocalPath $LocalPath -RemoteTempPath $tempPath
}

function Parse-Smaps {
    param([string]$Path)

    $entries = New-Object System.Collections.Generic.List[object]
    $current = $null
    $metricKeys = @(
        "Size", "Rss", "Pss", "Shared_Clean", "Shared_Dirty",
        "Private_Clean", "Private_Dirty", "Anonymous", "Swap"
    )

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^[0-9a-fA-F]+-[0-9a-fA-F]+\s+') {
            if ($null -ne $current) {
                $entries.Add([pscustomobject]$current)
            }

            $parts = $line -split '\s+', 6
            $pathname = if ($parts.Length -ge 6) { $parts[5].Trim() } else { "" }
            $headerParts = @($line -split '\s+') | Where-Object { $_ -ne "" }
            $inode = 0
            if ($headerParts.Count -ge 5 -and $headerParts[4] -match '^\d+$') {
                $inode = [int64]$headerParts[4]
            }
            $current = [ordered]@{
                Path          = $pathname
                Inode         = $inode
                Size          = 0
                Rss           = 0
                Pss           = 0
                Shared_Clean  = 0
                Shared_Dirty  = 0
                Private_Clean = 0
                Private_Dirty = 0
                Anonymous     = 0
                Swap          = 0
            }
            continue
        }

        if ($null -ne $current -and $line -match '^([A-Za-z_]+):\s+(\d+)\s+kB') {
            $key = $matches[1]
            if ($metricKeys -contains $key) {
                $current[$key] = [int64]$matches[2]
            }
        }
    }

    if ($null -ne $current) {
        $entries.Add([pscustomobject]$current)
    }

    return $entries
}

function Get-FileIdentityKey {
    param(
        [string]$Path,
        [Int64]$Inode
    )

    if ($Inode -gt 0) {
        return "inode:$Inode"
    }
    return "path:$Path"
}

function Test-IsInterestingFilePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    if (-not $Path.StartsWith("/")) {
        return $false
    }

    if ($Path.StartsWith("/dev/") -or $Path.StartsWith("/proc/") -or $Path.StartsWith("/memfd:")) {
        return $false
    }

    return $true
}

function Test-IsLibraryFilePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    return (
        $Path -match '\.(so|dll|dylib)(\.\d+)*$' -or
        $Path -match '\.z\.so(\.\d+)*$'
    )
}

function Get-FileType {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "Unknown" }
    if ($Path.StartsWith("/dev/")) { return "DeviceFile" }
    if ($Path.StartsWith("/proc/")) { return "ProcFile" }
    if ($Path.StartsWith("/memfd:")) { return "Memfd" }
    if ($Path -match '^\[.*\]$') { return "SpecialMapping" }
    if (Test-IsLibraryFilePath -Path $Path) { return "DynamicLibrary" }
    $fileName = [System.IO.Path]::GetFileName($Path)
    $extension = [System.IO.Path]::GetExtension($fileName)
    if (-not [string]::IsNullOrWhiteSpace($extension)) { return $extension.TrimStart('.').ToLowerInvariant() }
    if ($Path -match '^/(system|vendor|product|system_ext|apex)/.*/bin(/|$)' -or $Path -match '^/(system|vendor|product|system_ext)/bin(/|$)' -or $Path -match '/bin/[^/]+$') {
        return "ExecutableBinary"
    }
    if ($Path.StartsWith("/")) { return "RegularFile" }
    return "Other"
}

function Group-FileMappings {
    param([object[]]$Entries)

    $map = @{}
    foreach ($entry in $Entries) {
        if (-not (Test-IsInterestingFilePath -Path $entry.Path)) {
            continue
        }

        $fileKey = Get-FileIdentityKey -Path $entry.Path -Inode $entry.Inode
        if (-not $map.ContainsKey($fileKey)) {
            $map[$fileKey] = [ordered]@{
                FileKey = $fileKey
                Inode = [int64]$entry.Inode
                FilePath = $entry.Path
                FileName = [System.IO.Path]::GetFileName($entry.Path)
                FileType = (Get-FileType -Path $entry.Path)
                SizeKB = 0
                RssKB = 0
                PssKB = 0
                SharedKB = 0
                PrivateKB = 0
                Segments = 0
            }
        }

        $item = $map[$fileKey]
        $item.SizeKB += $entry.Size
        $item.RssKB += $entry.Rss
        $item.PssKB += $entry.Pss
        $item.SharedKB += ($entry.Shared_Clean + $entry.Shared_Dirty)
        $item.PrivateKB += ($entry.Private_Clean + $entry.Private_Dirty)
        $item.Segments += 1
    }

    return $map.Values | Sort-Object PssKB -Descending, RssKB -Descending
}

function Parse-LsofOutput {
    param([string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]
    $lines = Get-Content -LiteralPath $Path

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -match '^\s*COMMAND\s+PID\s+') {
            continue
        }

        $parts = @($line -split '\s+') | Where-Object { $_ -ne "" }
        if ($parts.Count -lt 9) {
            continue
        }

        if ($parts[1] -notmatch '^\d+$') {
            continue
        }

        $rows.Add([pscustomobject]@{
            Command = $parts[0]
            ProcessId = [int]$parts[1]
            User = $parts[2]
            Node = if ($parts[-2] -match '^\d+$') { [int64]$parts[-2] } else { 0 }
            Name = $parts[-1]
        })
    }

    return $rows
}

function Read-ProcessFileUsage {
    param(
        [string]$SmapsPath,
        [hashtable]$InterestingFiles
    )

    $entries = Parse-Smaps -Path $SmapsPath
    $grouped = Group-FileMappings -Entries $entries
    $result = @{}
    foreach ($row in $grouped) {
        if ($InterestingFiles.ContainsKey($row.FileKey)) {
            $result[$row.FileKey] = $row
        }
    }
    return $result
}

$processName = Get-RemoteProcessName -HdcPath $Hdc -DeviceId $Device -ProcessId $TargetPid

if (-not $OutputDir) {
    $OutputDir = Join-Path (Get-Location) "shared_file_usage_${processName}_${TargetPid}_$RunTimestamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$rawDir = Join-Path $OutputDir "raw"
$smapsDir = Join-Path $OutputDir "proc_smaps"
New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
New-Item -ItemType Directory -Path $smapsDir -Force | Out-Null

$targetSmapsPath = Join-Path $rawDir "target_smaps.txt"
Write-Info "Capturing target smaps for pid $TargetPid"
Save-ProcSmaps -HdcPath $Hdc -DeviceId $Device -ProcessId $TargetPid -LocalPath $targetSmapsPath

$targetFiles = @(Group-FileMappings -Entries (Parse-Smaps -Path $targetSmapsPath))
if (-not $targetFiles -or $targetFiles.Count -eq 0) {
    throw "No file-backed mappings found for pid $TargetPid"
}

$interestingFiles = @{}
$interestingPathToKeyMap = @{}
$interestingInodeToKeyMap = @{}
foreach ($row in $targetFiles) {
    $interestingFiles[$row.FileKey] = $row
    $interestingPathToKeyMap[$row.FilePath] = $row.FileKey
    if ([int64]$row.Inode -gt 0) {
        $interestingInodeToKeyMap[[string]$row.Inode] = $row.FileKey
    }
}

$lsofPath = Join-Path $rawDir "lsof.txt"
Write-Info "Capturing system lsof"
$lsofOutput = Invoke-HdcShell -HdcPath $Hdc -DeviceId $Device -RemoteCommand "lsof"
Set-Content -LiteralPath $lsofPath -Value $lsofOutput -Encoding UTF8

$lsofRows = @(Parse-LsofOutput -Path $lsofPath)
$matchedLsofRows = $lsofRows | Where-Object {
    ($_.Node -gt 0 -and $interestingInodeToKeyMap.ContainsKey([string]$_.Node)) -or
    $interestingPathToKeyMap.ContainsKey($_.Name)
}

$processMap = @{}
foreach ($row in $matchedLsofRows) {
    $key = [string]$row.ProcessId
    if (-not $processMap.ContainsKey($key)) {
        $processMap[$key] = [ordered]@{
            ProcessId = $row.ProcessId
            ProcessName = $row.Command
            User = $row.User
        }
    }
}

if (-not $processMap.ContainsKey([string]$TargetPid)) {
    $processMap[[string]$TargetPid] = [ordered]@{
        ProcessId = $TargetPid
        ProcessName = $processName
        User = ""
    }
}

$processInfos = $processMap.Values | Sort-Object ProcessId
$usageRows = New-Object System.Collections.Generic.List[object]

foreach ($proc in $processInfos) {
    $procId = [int]$proc.ProcessId
    $procSmapsPath = Join-Path $smapsDir ("smaps_{0}_{1}.txt" -f $procId, (Get-SafePathName -Name $proc.ProcessName))

    try {
        Write-Info "Capturing smaps for pid $procId ($($proc.ProcessName))"
        Save-ProcSmaps -HdcPath $Hdc -DeviceId $Device -ProcessId $procId -LocalPath $procSmapsPath
        $procUsage = Read-ProcessFileUsage -SmapsPath $procSmapsPath -InterestingFiles $interestingFiles

        foreach ($fileKey in $procUsage.Keys) {
            $targetFile = $interestingFiles[$fileKey]
            $fileUsage = $procUsage[$fileKey]
            $usageRows.Add([pscustomobject]@{
                FileKey = $fileKey
                Inode = $targetFile.Inode
                FilePath = $targetFile.FilePath
                FileName = $targetFile.FileName
                FileType = $targetFile.FileType
                FileSizeKB = $targetFile.SizeKB
                TargetProcessPssKB = $targetFile.PssKB
                TargetProcessRssKB = $targetFile.RssKB
                ProcessId = $procId
                ProcessName = $proc.ProcessName
                User = $proc.User
                ProcessPssKB = $fileUsage.PssKB
                ProcessRssKB = $fileUsage.RssKB
                SharedKB = $fileUsage.SharedKB
                PrivateKB = $fileUsage.PrivateKB
                IsTargetProcess = ($procId -eq $TargetPid)
            })
        }
    } catch {
        Write-Warning ("Failed to analyze pid {0}: {1}" -f $procId, $_.Exception.Message)
    }
}

$usageRows = @($usageRows)

$summaryRows = foreach ($fileGroup in ($usageRows | Group-Object FileKey)) {
    $first = $fileGroup.Group | Select-Object -First 1
    [pscustomobject]@{
        FileKey = $fileGroup.Name
        Inode = $first.Inode
        FilePath = $first.FilePath
        FileName = $first.FileName
        FileType = $first.FileType
        FileSizeKB = $first.FileSizeKB
        TargetProcessPssKB = $first.TargetProcessPssKB
        TargetProcessRssKB = $first.TargetProcessRssKB
        SystemTotalPssKB = (($fileGroup.Group | Measure-Object -Property ProcessPssKB -Sum).Sum)
        SystemTotalRssKB = (($fileGroup.Group | Measure-Object -Property ProcessRssKB -Sum).Sum)
        ProcessCount = ($fileGroup.Group | Select-Object -ExpandProperty ProcessId -Unique | Measure-Object).Count
        TopProcesses = (($fileGroup.Group | Sort-Object ProcessPssKB -Descending | Select-Object -First 5 | ForEach-Object { "{0}:{1}kB" -f $_.ProcessName, $_.ProcessPssKB }) -join "; ")
    }
} | Sort-Object SystemTotalPssKB -Descending, TargetProcessPssKB -Descending

$processSummaryRows = foreach ($procGroup in ($usageRows | Group-Object ProcessId)) {
    $first = $procGroup.Group | Select-Object -First 1
    [pscustomobject]@{
        ProcessId = [int]$procGroup.Name
        ProcessName = $first.ProcessName
        User = $first.User
        SharedFileCount = ($procGroup.Group | Select-Object -ExpandProperty FileKey -Unique | Measure-Object).Count
        TotalPssKB = (($procGroup.Group | Measure-Object -Property ProcessPssKB -Sum).Sum)
        TotalRssKB = (($procGroup.Group | Measure-Object -Property ProcessRssKB -Sum).Sum)
        IsTargetProcess = $first.IsTargetProcess
    }
} | Sort-Object TotalPssKB -Descending, TotalRssKB -Descending

$baseName = "shared_file_usage_{0}_{1}_{2}" -f (Get-SafePathName -Name $processName), $TargetPid, $RunTimestamp
$detailCsvPath = Join-Path $OutputDir "$baseName.details.csv"
$fileSummaryCsvPath = Join-Path $OutputDir "$baseName.files.csv"
$processSummaryCsvPath = Join-Path $OutputDir "$baseName.processes.csv"
$jsonPath = Join-Path $OutputDir "$baseName.json"

$usageRows | Sort-Object ProcessPssKB -Descending, ProcessRssKB -Descending | Export-Csv -LiteralPath $detailCsvPath -NoTypeInformation -Encoding UTF8
$summaryRows | Export-Csv -LiteralPath $fileSummaryCsvPath -NoTypeInformation -Encoding UTF8
$processSummaryRows | Export-Csv -LiteralPath $processSummaryCsvPath -NoTypeInformation -Encoding UTF8

$report = [pscustomobject]@{
    TargetProcessName = $processName
    TargetProcessId = $TargetPid
    OutputDir = $OutputDir
    TargetFileCount = $targetFiles.Count
    RelatedProcessCount = $processSummaryRows.Count
    Files = $summaryRows
    Processes = $processSummaryRows
    Details = $usageRows
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "Shared file usage summary"
Write-Host "-------------------------"
Write-Host ("Target process   : {0} ({1})" -f $processName, $TargetPid)
Write-Host ("Target file count: {0}" -f $targetFiles.Count)
Write-Host ("Related processes: {0}" -f $processSummaryRows.Count)
Write-Host ("Detail CSV       : {0}" -f $detailCsvPath)
Write-Host ("File summary CSV : {0}" -f $fileSummaryCsvPath)
Write-Host ("Proc summary CSV : {0}" -f $processSummaryCsvPath)
Write-Host ("JSON report      : {0}" -f $jsonPath)
Write-Host ""

Write-Host "Top shared files by system PSS"
$summaryRows | Select-Object -First 20 FileName, FileType, FileSizeKB, SystemTotalPssKB, TargetProcessPssKB, ProcessCount, FilePath | Format-Table -AutoSize

Write-Host ""
Write-Host "Top related processes by shared-file PSS"
$processSummaryRows | Select-Object -First 20 ProcessId, ProcessName, User, TotalPssKB, SharedFileCount, IsTargetProcess | Format-Table -AutoSize
