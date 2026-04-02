<#
用途:
- 从一个“进程名列表文件(process_list.txt)”出发，找到这些进程当前使用到的动态链接库。
- 再从系统维度找出还有哪些进程也在使用这些库，并统计每个库的系统总物理内存占用，以及各进程占用的比例和值。

原理:
- 先通过 `ps -ef` 将输入的进程名解析成实际运行中的 PID。
- 再抓这些目标进程的 `maps/smaps`，从中提取感兴趣的动态库。
- 动态库身份优先按 `inode` 判定，`inode` 缺失时再回退到路径，避免同名同路径变更或路径差异带来的误判。
- 通过 `lsof` 找出系统里也打开了这些库的相关进程，再逐个抓取它们的 `smaps`。
- 最终按库汇总系统总 `PSS/RSS`，并在明细里记录每个进程对该库的占用值和比例。
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ProcessListFile,

    [string]$Hdc = "hdc",
    [string]$Device,
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

trap {
    Write-Host ""
    Write-Host "[error] $($_.Exception.Message)"
    if ($_.InvocationInfo) {
        Write-Host ("[error] Script line: {0}" -f $_.InvocationInfo.ScriptLineNumber)
        Write-Host ("[error] Position   : {0}" -f $_.InvocationInfo.PositionMessage.Trim())
    }
    if ($_.ScriptStackTrace) {
        Write-Host "[error] Stack trace:"
        Write-Host $_.ScriptStackTrace
    }
    exit 1
}

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
        $safe = $safe.Replace([string]$char, "_")
    }
    $safe = $safe -replace '\s+', '_'
    $safe = $safe -replace '[^\w\.-]', '_'
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "unknown"
    }
    return $safe
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

function Save-ProcMaps {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$ProcessId,
        [string]$LocalPath
    )

    Save-RemoteTextFile -HdcPath $HdcPath -DeviceId $DeviceId `
        -RemotePath "/proc/$ProcessId/maps" `
        -LocalPath $LocalPath `
        -RemoteTempPath "/data/${ProcessId}_proc_list_maps"
}

function Save-ProcSmaps {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$ProcessId,
        [string]$LocalPath
    )

    Save-RemoteTextFile -HdcPath $HdcPath -DeviceId $DeviceId `
        -RemotePath "/proc/$ProcessId/smaps" `
        -LocalPath $LocalPath `
        -RemoteTempPath "/data/${ProcessId}_proc_list_smaps"
}

function Parse-ProcessListFile {
    param([string]$Path)

    $names = foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith("#")) { continue }
        $trimmed
    }

    return @($names | Select-Object -Unique)
}

function Get-PsRows {
    param(
        [string]$HdcPath,
        [string]$DeviceId
    )

    $output = Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "ps -ef"
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($line in ($output -split "(`r`n|`n|`r)")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*UID\s+PID\s+') { continue }

        $parts = @($line -split '\s+') | Where-Object { $_ -ne "" }
        if ($parts.Count -lt 8) { continue }
        if ($parts[1] -notmatch '^\d+$') { continue }

        $rows.Add([pscustomobject]@{
            Uid = $parts[0]
            ProcessId = [int]$parts[1]
            Command = $parts[-1]
            RawLine = $line
        })
    }

    return $rows
}

function Resolve-TargetProcesses {
    param(
        [string[]]$ProcessNames,
        [object[]]$PsRows
    )

    $resolved = New-Object System.Collections.Generic.List[object]

    foreach ($name in $ProcessNames) {
        $matches = @($PsRows | Where-Object { $_.Command -eq $name })
        if (-not $matches -or $matches.Count -eq 0) {
            Write-Warning "No process found for name: $name"
            continue
        }

        foreach ($match in $matches) {
            $resolved.Add([pscustomobject]@{
                RequestedName = $name
                ProcessName = $match.Command
                ProcessId = $match.ProcessId
                Uid = $match.Uid
            })
        }
    }

    $uniqueMap = @{}
    foreach ($item in $resolved) {
        $key = "{0}|{1}" -f $item.ProcessName, $item.ProcessId
        if (-not $uniqueMap.ContainsKey($key)) {
            $uniqueMap[$key] = $item
        }
    }

    return @(
        $uniqueMap.Values |
            Sort-Object `
                @{ Expression = { [string]$_.ProcessName } ; Descending = $false }, `
                @{ Expression = { [int64]$_.ProcessId } ; Descending = $false }
    )
}

function Parse-MapsFile {
    param([string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch '^[0-9a-fA-F]+-[0-9a-fA-F]+\s+') {
            continue
        }

        $parts = $line -split '\s+', 6
        $pathname = if ($parts.Length -ge 6) { $parts[5].Trim() } else { "" }
        $headerParts = @($line -split '\s+') | Where-Object { $_ -ne "" }
        $inode = 0
        if ($headerParts.Count -ge 5 -and $headerParts[4] -match '^\d+$') {
            $inode = [int64]$headerParts[4]
        }
        $rows.Add([pscustomobject]@{
            Path = $pathname
            Inode = $inode
            Header = $line
        })
    }

    return $rows
}

function Test-IsInterestingLibraryPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not $Path.StartsWith("/")) { return $false }
    if ($Path.StartsWith("/dev/") -or $Path.StartsWith("/proc/") -or $Path.StartsWith("/memfd:")) { return $false }
    # if ($Path.StartsWith("/system/") -or $Path.StartsWith("/vendor/")) { return $false }
    if ($Path -match '\.(so|dll|dylib)(\.\d+)*$' -or $Path -match '\.z\.so(\.\d+)*$') {
        return $true
    }
    return $false
}

function Get-LibraryIdentityKey {
    param(
        [string]$Path,
        [Int64]$Inode
    )

    if ($Inode -gt 0) {
        return "inode:$Inode"
    }
    return "path:$Path"
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

function Group-FileMappingsFromSmaps {
    param([object[]]$Entries)

    $map = @{}
    foreach ($entry in $Entries) {
        if (-not (Test-IsInterestingLibraryPath -Path $entry.Path)) { continue }

        $fileKey = Get-LibraryIdentityKey -Path $entry.Path -Inode $entry.Inode

        if (-not $map.ContainsKey($fileKey)) {
            $map[$fileKey] = [ordered]@{
                FileKey = $fileKey
                Inode = [int64]$entry.Inode
                FilePath = $entry.Path
                FileName = [System.IO.Path]::GetFileName($entry.Path)
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

    return $map
}

function Parse-LsofOutput {
    param([string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*COMMAND\s+PID\s+') { continue }

        $parts = @($line -split '\s+') | Where-Object { $_ -ne "" }
        if ($parts.Count -lt 9) { continue }
        if ($parts[1] -notmatch '^\d+$') { continue }

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

$ProcessListFile = (Resolve-Path -LiteralPath $ProcessListFile).Path
$requestedProcessNames = Parse-ProcessListFile -Path $ProcessListFile
if (-not $requestedProcessNames -or $requestedProcessNames.Count -eq 0) {
    throw "No process names found in $ProcessListFile"
}

$outputLabel = Get-SafePathName -Name ([System.IO.Path]::GetFileNameWithoutExtension($ProcessListFile))
if (-not $OutputDir) {
    $OutputDir = Join-Path (Get-Location) "process_list_shared_files_${outputLabel}_$RunTimestamp"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$rawDir = Join-Path $OutputDir "raw"
$targetMapsDir = Join-Path $OutputDir "target_maps"
$targetSmapsDir = Join-Path $OutputDir "target_smaps"
$relatedSmapsDir = Join-Path $OutputDir "related_smaps"
foreach ($dir in @($rawDir, $targetMapsDir, $targetSmapsDir, $relatedSmapsDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

Write-Info "Capturing ps -ef"
$psPath = Join-Path $rawDir "ps_ef.txt"
$psOutput = Invoke-HdcShell -HdcPath $Hdc -DeviceId $Device -RemoteCommand "ps -ef"
Set-Content -LiteralPath $psPath -Value $psOutput -Encoding UTF8
$psRows = @(Get-PsRows -HdcPath $Hdc -DeviceId $Device)

$targetProcesses = @(Resolve-TargetProcesses -ProcessNames $requestedProcessNames -PsRows $psRows)
if (-not $targetProcesses -or $targetProcesses.Count -eq 0) {
    throw "No target processes matched from $ProcessListFile"
}

$targetFileMap = @{}
$targetPathToKeyMap = @{}
$targetInodeToKeyMap = @{}
$targetProcessFileRows = @()

foreach ($proc in $targetProcesses) {
    $safeProcName = Get-SafePathName -Name $proc.ProcessName
    $mapsPath = Join-Path $targetMapsDir ("maps_{0}_{1}.txt" -f $proc.ProcessId, $safeProcName)
    $smapsPath = Join-Path $targetSmapsDir ("smaps_{0}_{1}.txt" -f $proc.ProcessId, $safeProcName)

    Write-Info "Capturing maps for target pid $($proc.ProcessId) ($($proc.ProcessName))"
    Save-ProcMaps -HdcPath $Hdc -DeviceId $Device -ProcessId $proc.ProcessId -LocalPath $mapsPath
    Write-Info "Capturing smaps for target pid $($proc.ProcessId) ($($proc.ProcessName))"
    Save-ProcSmaps -HdcPath $Hdc -DeviceId $Device -ProcessId $proc.ProcessId -LocalPath $smapsPath

    $mapEntries = Parse-MapsFile -Path $mapsPath
    foreach ($entry in $mapEntries) {
        if (-not (Test-IsInterestingLibraryPath -Path $entry.Path)) { continue }
        $fileKey = Get-LibraryIdentityKey -Path $entry.Path -Inode $entry.Inode
        if (-not $targetFileMap.ContainsKey($fileKey)) {
            $targetFileMap[$fileKey] = [pscustomobject]@{
                FileKey = $fileKey
                Inode = [int64]$entry.Inode
                FilePath = $entry.Path
                FileName = [System.IO.Path]::GetFileName($entry.Path)
                IsLibrary = $true
            }
        }
        $targetPathToKeyMap[$entry.Path] = $fileKey
        if ($entry.Inode -gt 0) {
            $targetInodeToKeyMap[[string]$entry.Inode] = $fileKey
        }
    }

    $smapsEntries = Parse-Smaps -Path $smapsPath
    $fileUsageMap = Group-FileMappingsFromSmaps -Entries $smapsEntries
    foreach ($fileKey in $fileUsageMap.Keys) {
        $usage = $fileUsageMap[$fileKey]
        $targetProcessFileRows += [pscustomobject]@{
            TargetProcessId = $proc.ProcessId
            TargetProcessName = $proc.ProcessName
            FileKey = $fileKey
            Inode = $usage.Inode
            FilePath = $usage.FilePath
            FileName = $usage.FileName
            IsLibrary = $true
            TargetProcessPssKB = $usage.PssKB
            TargetProcessRssKB = $usage.RssKB
        }
    }
}

if ($targetFileMap.Count -eq 0) {
    throw "No interesting file-backed mappings found in target processes"
}

Write-Info "Capturing lsof"
$lsofPath = Join-Path $rawDir "lsof.txt"
$lsofOutput = Invoke-HdcShell -HdcPath $Hdc -DeviceId $Device -RemoteCommand "lsof"
Set-Content -LiteralPath $lsofPath -Value $lsofOutput -Encoding UTF8
$lsofRows = @(Parse-LsofOutput -Path $lsofPath)
$matchedLsof = @(
    $lsofRows | Where-Object {
        ($_.Node -gt 0 -and $targetInodeToKeyMap.ContainsKey([string]$_.Node)) -or
        $targetPathToKeyMap.ContainsKey($_.Name)
    }
)

$relatedProcessMap = @{}
foreach ($row in $matchedLsof) {
    $key = [string]$row.ProcessId
    if (-not $relatedProcessMap.ContainsKey($key)) {
        $relatedProcessMap[$key] = [pscustomobject]@{
            ProcessId = $row.ProcessId
            ProcessName = $row.Command
            User = $row.User
        }
    }
}

foreach ($proc in $targetProcesses) {
    $key = [string]$proc.ProcessId
    if (-not $relatedProcessMap.ContainsKey($key)) {
        $relatedProcessMap[$key] = [pscustomobject]@{
            ProcessId = $proc.ProcessId
            ProcessName = $proc.ProcessName
            User = $proc.Uid
        }
    }
}

$detailRows = @()
$relatedProcessSummaryRows = @()

foreach ($proc in ($relatedProcessMap.Values | Sort-Object @{ Expression = { [int64]$_.ProcessId } ; Descending = $false })) {
    $safeProcName = Get-SafePathName -Name $proc.ProcessName
    $smapsPath = Join-Path $relatedSmapsDir ("smaps_{0}_{1}.txt" -f $proc.ProcessId, $safeProcName)

    try {
        Write-Info "Capturing smaps for related pid $($proc.ProcessId) ($($proc.ProcessName))"
        Save-ProcSmaps -HdcPath $Hdc -DeviceId $Device -ProcessId $proc.ProcessId -LocalPath $smapsPath
        $usageMap = Group-FileMappingsFromSmaps -Entries (Parse-Smaps -Path $smapsPath)

        $procTotalPss = 0
        $procTotalRss = 0
        $sharedFileCount = 0

        foreach ($fileKey in $usageMap.Keys) {
            if (-not $targetFileMap.ContainsKey($fileKey)) { continue }

            $usage = $usageMap[$fileKey]
            $procTotalPss += $usage.PssKB
            $procTotalRss += $usage.RssKB
            $sharedFileCount += 1

            $detailRows += [pscustomobject]@{
                FileKey = $fileKey
                Inode = $usage.Inode
                FilePath = $usage.FilePath
                FileName = $usage.FileName
                IsLibrary = $targetFileMap[$fileKey].IsLibrary
                ProcessId = $proc.ProcessId
                ProcessName = $proc.ProcessName
                User = $proc.User
                ProcessPssKB = $usage.PssKB
                ProcessRssKB = $usage.RssKB
                SharedKB = $usage.SharedKB
                PrivateKB = $usage.PrivateKB
                IsRequestedProcess = [bool]($targetProcesses | Where-Object { $_.ProcessId -eq $proc.ProcessId })
            }
        }

        $relatedProcessSummaryRows += [pscustomobject]@{
            ProcessId = $proc.ProcessId
            ProcessName = $proc.ProcessName
            User = $proc.User
            SharedFileCount = $sharedFileCount
            TotalPssKB = $procTotalPss
            TotalRssKB = $procTotalRss
            IsRequestedProcess = [bool]($targetProcesses | Where-Object { $_.ProcessId -eq $proc.ProcessId })
        }
    } catch {
        Write-Warning ("Failed to analyze related pid {0}: {1}" -f $proc.ProcessId, $_.Exception.Message)
    }
}
$fileSummaryRows = @(
foreach ($group in ($detailRows | Group-Object FileKey)) {
    $first = $group.Group | Select-Object -First 1
    $systemTotalPss = (($group.Group | Measure-Object -Property ProcessPssKB -Sum).Sum)
    $systemTotalRss = (($group.Group | Measure-Object -Property ProcessRssKB -Sum).Sum)

    foreach ($row in $group.Group) {
        $row | Add-Member -NotePropertyName SystemTotalPssKB -NotePropertyValue $systemTotalPss -Force
        $row | Add-Member -NotePropertyName SystemTotalRssKB -NotePropertyValue $systemTotalRss -Force
        $row | Add-Member -NotePropertyName PssRatio -NotePropertyValue $(if ($systemTotalPss -gt 0) { [math]::Round(($row.ProcessPssKB / $systemTotalPss), 6) } else { 0 }) -Force
        $row | Add-Member -NotePropertyName RssRatio -NotePropertyValue $(if ($systemTotalRss -gt 0) { [math]::Round(($row.ProcessRssKB / $systemTotalRss), 6) } else { 0 }) -Force
    }

    [pscustomobject]@{
        FileKey = $group.Name
        Inode = $first.Inode
        FilePath = $first.FilePath
        FileName = $first.FileName
        IsLibrary = $first.IsLibrary
        SystemTotalPssKB = $systemTotalPss
        SystemTotalRssKB = $systemTotalRss
        ProcessCount = ($group.Group | Select-Object -ExpandProperty ProcessId -Unique | Measure-Object).Count
        RequestedProcessCount = (($group.Group | Where-Object { $_.IsRequestedProcess }) | Select-Object -ExpandProperty ProcessId -Unique | Measure-Object).Count
        TopProcessesByPss = (($group.Group | Sort-Object ProcessPssKB -Descending | Select-Object -First 5 | ForEach-Object { "{0}:{1}kB({2:P2})" -f $_.ProcessName, $_.ProcessPssKB, $_.PssRatio }) -join "; ")
    }
}
) | Sort-Object `
        @{ Expression = { [int64]$_.SystemTotalPssKB } ; Descending = $true }, `
        @{ Expression = { [int64]$_.ProcessCount } ; Descending = $true }, `
        @{ Expression = { [int64]$_.Inode } ; Descending = $false }, `
        @{ Expression = { [string]$_.FilePath } ; Descending = $false }

$relatedProcessSummaryRows = @(
    $relatedProcessSummaryRows |
        Sort-Object `
            @{ Expression = { [int64]$_.TotalPssKB } ; Descending = $true }, `
            @{ Expression = { [int64]$_.SharedFileCount } ; Descending = $true }, `
            @{ Expression = { [int64]$_.ProcessId } ; Descending = $false }
)
$requestedProcessRows = @(
    $targetProcesses |
        Sort-Object `
            @{ Expression = { [string]$_.ProcessName } ; Descending = $false }, `
            @{ Expression = { [int64]$_.ProcessId } ; Descending = $false }
)
$targetProcessFileRows = @(
    $targetProcessFileRows |
        Sort-Object `
            @{ Expression = { [int64]$_.TargetProcessPssKB } ; Descending = $true }, `
            @{ Expression = { [int64]$_.Inode } ; Descending = $false }, `
            @{ Expression = { [string]$_.FilePath } ; Descending = $false }, `
            @{ Expression = { [int64]$_.TargetProcessId } ; Descending = $false }
)
$detailRows = @(
    $detailRows |
        Sort-Object `
            @{ Expression = { [int64]$_.SystemTotalPssKB } ; Descending = $true }, `
            @{ Expression = { [int64]$_.ProcessPssKB } ; Descending = $true }, `
            @{ Expression = { [int64]$_.Inode } ; Descending = $false }, `
            @{ Expression = { [string]$_.FilePath } ; Descending = $false }, `
            @{ Expression = { [int64]$_.ProcessId } ; Descending = $false }
)

$baseName = "process_list_shared_files_{0}_{1}" -f $outputLabel, $RunTimestamp
$requestedCsv = Join-Path $OutputDir "$baseName.requested_processes.csv"
$targetFilesCsv = Join-Path $OutputDir "$baseName.target_process_files.csv"
$fileSummaryCsv = Join-Path $OutputDir "$baseName.file_summary.csv"
$processSummaryCsv = Join-Path $OutputDir "$baseName.process_summary.csv"
$detailCsv = Join-Path $OutputDir "$baseName.detail.csv"
$jsonPath = Join-Path $OutputDir "$baseName.json"

$requestedProcessRows | Export-Csv -LiteralPath $requestedCsv -NoTypeInformation -Encoding UTF8
$targetProcessFileRows | Export-Csv -LiteralPath $targetFilesCsv -NoTypeInformation -Encoding UTF8
$fileSummaryRows | Export-Csv -LiteralPath $fileSummaryCsv -NoTypeInformation -Encoding UTF8
$relatedProcessSummaryRows | Export-Csv -LiteralPath $processSummaryCsv -NoTypeInformation -Encoding UTF8
$detailRows | Export-Csv -LiteralPath $detailCsv -NoTypeInformation -Encoding UTF8

$report = [pscustomobject]@{
    ProcessListFile = $ProcessListFile
    RequestedProcessNames = $requestedProcessNames
    RequestedProcesses = $requestedProcessRows
    TargetFileCount = $targetFileMap.Count
    RelatedProcessCount = $relatedProcessSummaryRows.Count
    FileSummary = $fileSummaryRows
    ProcessSummary = $relatedProcessSummaryRows
    Detail = $detailRows
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "Process-list shared file summary"
Write-Host "--------------------------------"
Write-Host ("Process list file  : {0}" -f $ProcessListFile)
Write-Host ("Requested procs    : {0}" -f $requestedProcessRows.Count)
Write-Host ("Target file count  : {0}" -f $targetFileMap.Count)
Write-Host ("Related proc count : {0}" -f $relatedProcessSummaryRows.Count)
Write-Host ("Requested CSV      : {0}" -f $requestedCsv)
Write-Host ("Target files CSV   : {0}" -f $targetFilesCsv)
Write-Host ("File summary CSV   : {0}" -f $fileSummaryCsv)
Write-Host ("Process summary CSV: {0}" -f $processSummaryCsv)
Write-Host ("Detail CSV         : {0}" -f $detailCsv)
Write-Host ("JSON report        : {0}" -f $jsonPath)
Write-Host ""

Write-Host "Top files by system total PSS"
$fileSummaryRows | Select-Object -First 20 FileName, IsLibrary, SystemTotalPssKB, ProcessCount, FilePath | Format-Table -AutoSize

Write-Host ""
Write-Host "Top processes by shared-file PSS"
$relatedProcessSummaryRows | Select-Object -First 20 ProcessId, ProcessName, User, TotalPssKB, SharedFileCount, IsRequestedProcess | Format-Table -AutoSize
