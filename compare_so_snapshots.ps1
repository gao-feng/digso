<#
用途:
- 比较两个抓取目录中，同一个应用/同一个 PID 在两个时间点的动态链接库物理内存占用变化。
- 输出新增、减少和保持不变的库，并给出 `DeltaPssKB/DeltaRssKB`。

原理:
- 优先读取目录中现成的 `library_memory_*.json` 结果；如果不存在，则回退到直接解析 `smaps`。
- 比较单位为“完整库路径”，避免同名不同路径的库被错误合并。
- 对比时以 `TotalPssKB/TotalRssKB` 为主，其中 `PSS` 更适合表示进程对动态库的实际物理内存分摊。
- 会校验两个目录的进程名和 PID 是否一致，避免跨应用误比。
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$BeforeDir,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$AfterDir,

    [string]$OutputDir,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[info] $Message"
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

function Get-SnapshotMetaFromDir {
    param([string]$DirPath)

    $name = Split-Path -Leaf $DirPath
    if ($name -match '^proc_(.+)_(\d+)_(\d{8}_\d{6})$') {
        return [pscustomobject]@{
            ProcessName = $matches[1]
            Pid = [int]$matches[2]
            Timestamp = $matches[3]
            DirectoryName = $name
        }
    }

    return [pscustomobject]@{
        ProcessName = ""
        Pid = 0
        Timestamp = ""
        DirectoryName = $name
    }
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

    if (-not ($Path.StartsWith("/") -or $Path -match '^[A-Za-z]:\\')) {
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
        $Path -match '(^/|^[A-Za-z]:\\).+\.(so|dll|dylib)(\.\d+)*$' -or
        $Path -match '(^/|^[A-Za-z]:\\).+\.z\.so(\.\d+)*$'
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
    if ($Path.StartsWith("/") -or $Path -match '^[A-Za-z]:\\') { return "RegularFile" }
    return "Other"
}

function Get-BssLibraryName {
    param([string]$AnonPath)

    if ($AnonPath -match '^\[anon:(.+?)\.bss\]$') {
        return $matches[1]
    }
    return $null
}

function Add-FileMetrics {
    param(
        [hashtable]$Map,
        [string]$Key,
        [psobject]$Entry
    )

    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = [ordered]@{
            FilePath      = [string]$Entry.Path
            Inode         = [int64]$(if ($Entry.PSObject.Properties.Name -contains "Inode") { $Entry.Inode } else { 0 })
            Size          = 0
            Rss           = 0
            Pss           = 0
            Shared_Clean  = 0
            Shared_Dirty  = 0
            Private_Clean = 0
            Private_Dirty = 0
            Anonymous     = 0
            Swap          = 0
            Segments      = 0
        }
    }

    $item = $Map[$Key]
    $item.Size += $Entry.Size
    $item.Rss += $Entry.Rss
    $item.Pss += $Entry.Pss
    $item.Shared_Clean += $Entry.Shared_Clean
    $item.Shared_Dirty += $Entry.Shared_Dirty
    $item.Private_Clean += $Entry.Private_Clean
    $item.Private_Dirty += $Entry.Private_Dirty
    $item.Anonymous += $Entry.Anonymous
    $item.Swap += $Entry.Swap
    $item.Segments += 1
}

function Analyze-FilesFromSmaps {
    param([string]$SmapsPath)

    $entries = Parse-Smaps -Path $SmapsPath
    $fileRowsMap = @{}
    $bssRowsMap = @{}

    foreach ($entry in $entries) {
        if (Test-IsInterestingFilePath -Path $entry.Path) {
            $fileKey = Get-FileIdentityKey -Path $entry.Path -Inode $entry.Inode
            Add-FileMetrics -Map $fileRowsMap -Key $fileKey -Entry $entry
            continue
        }

        $bssName = Get-BssLibraryName -AnonPath $entry.Path
        if ($bssName) {
            $bssKey = Get-FileIdentityKey -Path $bssName -Inode 0
            Add-FileMetrics -Map $bssRowsMap -Key $bssKey -Entry $entry
        }
    }

    $rows = foreach ($fileKey in $fileRowsMap.Keys) {
        $fileRow = $fileRowsMap[$fileKey]
        $bssLookupKey = Get-FileIdentityKey -Path $fileRow.FilePath -Inode 0
        $bssRow = if ($bssRowsMap.ContainsKey($bssLookupKey)) { $bssRowsMap[$bssLookupKey] } else { $null }
        $filePath = [string]$fileRow.FilePath

        [pscustomobject]@{
            FileName = [System.IO.Path]::GetFileName($(if ($filePath) { $filePath } else { $fileKey }))
            FileType = (Get-FileType -Path $filePath)
            IsLibrary = (Test-IsLibraryFilePath -Path $filePath)
            Inode = [int64]$fileRow.Inode
            FileKey = $fileKey
            FilePath = $filePath
            FileSizeKB = $fileRow.Size
            TotalPssKB = $fileRow.Pss + $(if ($bssRow) { $bssRow.Pss } else { 0 })
            TotalRssKB = $fileRow.Rss + $(if ($bssRow) { $bssRow.Rss } else { 0 })
            FilePssKB = $fileRow.Pss
            FileRssKB = $fileRow.Rss
            BssPssKB = if ($bssRow) { $bssRow.Pss } else { 0 }
            BssRssKB = if ($bssRow) { $bssRow.Rss } else { 0 }
            Segments = $fileRow.Segments
        }
    }

    return $rows
}

function Get-FileRowsFromSnapshotDir {
    param([string]$DirPath)

    $jsonCandidate = Get-ChildItem -LiteralPath $DirPath -Filter "file_memory_*.json" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $jsonCandidate) {
        $jsonCandidate = Get-ChildItem -LiteralPath $DirPath -Filter "library_memory_*.json" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    }

    if ($jsonCandidate) {
        Write-Info "Using existing JSON report: $($jsonCandidate.FullName)"
        $raw = Get-Content -LiteralPath $jsonCandidate.FullName -Raw | ConvertFrom-Json
        $processName = if ($raw.ProcessName) { [string]$raw.ProcessName } else { "" }
        $rows = @()
        if ($raw.PSObject.Properties.Name -contains "Files") {
            $rows = @($raw.Files)
        } elseif ($raw.PSObject.Properties.Name -contains "Libraries") {
            $rows = @($raw.Libraries | ForEach-Object {
                [pscustomobject]@{
                    FileName = if ($_.PSObject.Properties.Name -contains "FileName") { [string]$_.FileName } else { [string]$_.Library }
                    FileType = if ($_.PSObject.Properties.Name -contains "FileType") { [string]$_.FileType } else { (Get-FileType -Path ([string]$_.FilePath)) }
                    IsLibrary = if ($_.PSObject.Properties.Name -contains "IsLibrary") { [bool]$_.IsLibrary } else { $true }
                    Inode = [int64]$_.Inode
                    FileKey = [string]$_.FileKey
                    FilePath = [string]$_.FilePath
                    FileSizeKB = if ($_.PSObject.Properties.Name -contains "FileSizeKB") { [int64]$_.FileSizeKB } elseif ($_.PSObject.Properties.Name -contains "SizeKB") { [int64]$_.SizeKB } else { 0 }
                    TotalPssKB = [int64]$_.TotalPssKB
                    TotalRssKB = [int64]$_.TotalRssKB
                    FilePssKB = [int64]$_.FilePssKB
                    FileRssKB = [int64]$_.FileRssKB
                    BssPssKB = if ($_.PSObject.Properties.Name -contains "BssPssKB") { [int64]$_.BssPssKB } else { 0 }
                    BssRssKB = if ($_.PSObject.Properties.Name -contains "BssRssKB") { [int64]$_.BssRssKB } else { 0 }
                    Segments = if ($_.PSObject.Properties.Name -contains "Segments") { [int64]$_.Segments } else { 0 }
                }
            })
        }

        return [pscustomobject]@{
            ProcessName = $processName
            Files = $rows
        }
    }

    $smapsPath = Join-Path $DirPath "smaps"
    if (-not (Test-Path -LiteralPath $smapsPath)) {
        throw "No file report or smaps found in $DirPath"
    }

    Write-Info "No JSON report found, parsing $smapsPath"
    return [pscustomobject]@{
        ProcessName = ""
        Files = @(Analyze-FilesFromSmaps -SmapsPath $smapsPath)
    }
}

function Compare-FileRows {
    param(
        [object[]]$BeforeRows,
        [object[]]$AfterRows
    )

    $beforeMap = @{}
    foreach ($row in $BeforeRows) {
        $identityKey = Get-FileIdentityKey -Path ([string]$row.FilePath) -Inode ([int64]$(if ($row.PSObject.Properties.Name -contains "Inode") { $row.Inode } else { 0 }))
        $beforeMap[$identityKey] = $row
    }

    $afterMap = @{}
    foreach ($row in $AfterRows) {
        $identityKey = Get-FileIdentityKey -Path ([string]$row.FilePath) -Inode ([int64]$(if ($row.PSObject.Properties.Name -contains "Inode") { $row.Inode } else { 0 }))
        $afterMap[$identityKey] = $row
    }

    $allKeys = @($beforeMap.Keys + $afterMap.Keys | Sort-Object -Unique)

    $diffRows = foreach ($key in $allKeys) {
        $before = if ($beforeMap.ContainsKey($key)) { $beforeMap[$key] } else { $null }
        $after = if ($afterMap.ContainsKey($key)) { $afterMap[$key] } else { $null }

        $beforePss = if ($before) { [int64]$before.TotalPssKB } else { 0 }
        $afterPss = if ($after) { [int64]$after.TotalPssKB } else { 0 }
        $beforeRss = if ($before) { [int64]$before.TotalRssKB } else { 0 }
        $afterRss = if ($after) { [int64]$after.TotalRssKB } else { 0 }
        $beforeSize = if ($before -and $before.PSObject.Properties.Name -contains "FileSizeKB") { [int64]$before.FileSizeKB } else { 0 }
        $afterSize = if ($after -and $after.PSObject.Properties.Name -contains "FileSizeKB") { [int64]$after.FileSizeKB } else { 0 }

        [pscustomobject]@{
            FileName = if ($after) { [string]$(if ($after.PSObject.Properties.Name -contains "FileName") { $after.FileName } else { $after.Library }) } elseif ($before) { [string]$(if ($before.PSObject.Properties.Name -contains "FileName") { $before.FileName } else { $before.Library }) } else { "" }
            FileType = if ($after -and $after.PSObject.Properties.Name -contains "FileType") { [string]$after.FileType } elseif ($before -and $before.PSObject.Properties.Name -contains "FileType") { [string]$before.FileType } else { (Get-FileType -Path ([string]$(if ($after) { $after.FilePath } elseif ($before) { $before.FilePath } else { "" }))) }
            IsLibrary = if ($after -and $after.PSObject.Properties.Name -contains "IsLibrary") { [bool]$after.IsLibrary } elseif ($before -and $before.PSObject.Properties.Name -contains "IsLibrary") { [bool]$before.IsLibrary } else { $true }
            Inode = [int64]$(if ($after -and $after.PSObject.Properties.Name -contains "Inode") { $after.Inode } elseif ($before -and $before.PSObject.Properties.Name -contains "Inode") { $before.Inode } else { 0 })
            FileKey = $key
            FilePath = [string]$(if ($after) { $after.FilePath } elseif ($before) { $before.FilePath } else { "" })
            BeforeFileSizeKB = $beforeSize
            AfterFileSizeKB = $afterSize
            BeforePssKB = $beforePss
            AfterPssKB = $afterPss
            DeltaPssKB = $afterPss - $beforePss
            BeforeRssKB = $beforeRss
            AfterRssKB = $afterRss
            DeltaRssKB = $afterRss - $beforeRss
            BeforeExists = [bool]($null -ne $before)
            AfterExists = [bool]($null -ne $after)
            ChangeType = if ($before -and $after) { "changed" } elseif ($after) { "added" } else { "removed" }
        }
    }

    return $diffRows | Sort-Object -Property DeltaPssKB, DeltaRssKB -Descending
}

$BeforeDir = (Resolve-Path -LiteralPath $BeforeDir).Path
$AfterDir = (Resolve-Path -LiteralPath $AfterDir).Path

$beforeMeta = Get-SnapshotMetaFromDir -DirPath $BeforeDir
$afterMeta = Get-SnapshotMetaFromDir -DirPath $AfterDir

if (-not $OutputDir) {
    $name = if ($beforeMeta.ProcessName) { Get-SafePathName $beforeMeta.ProcessName } else { "unknown" }
    $procIdLabel = if ($beforeMeta.Pid -gt 0) { $beforeMeta.Pid } else { "unknown" }
    $beforeTs = if ($beforeMeta.Timestamp) { $beforeMeta.Timestamp } else { "before" }
    $afterTs = if ($afterMeta.Timestamp) { $afterMeta.Timestamp } else { "after" }
    $OutputDir = Join-Path (Get-Location) "compare_files_${name}_${procIdLabel}_${beforeTs}_vs_${afterTs}"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$beforeSnapshot = Get-FileRowsFromSnapshotDir -DirPath $BeforeDir
$afterSnapshot = Get-FileRowsFromSnapshotDir -DirPath $AfterDir

$effectiveBeforeName = if ($beforeSnapshot.ProcessName) { $beforeSnapshot.ProcessName } else { $beforeMeta.ProcessName }
$effectiveAfterName = if ($afterSnapshot.ProcessName) { $afterSnapshot.ProcessName } else { $afterMeta.ProcessName }

if ($beforeMeta.Pid -gt 0 -and $afterMeta.Pid -gt 0 -and $beforeMeta.Pid -ne $afterMeta.Pid) {
    throw "PID mismatch: $($beforeMeta.Pid) vs $($afterMeta.Pid)"
}

if ($effectiveBeforeName -and $effectiveAfterName -and $effectiveBeforeName -ne $effectiveAfterName) {
    throw "Process name mismatch: $effectiveBeforeName vs $effectiveAfterName"
}

$diffRows = Compare-FileRows -BeforeRows $beforeSnapshot.Files -AfterRows $afterSnapshot.Files

$summary = [pscustomobject]@{
    ProcessName = if ($effectiveAfterName) { $effectiveAfterName } else { $effectiveBeforeName }
    ProcessId = if ($afterMeta.Pid -gt 0) { $afterMeta.Pid } else { $beforeMeta.Pid }
    BeforeDir = $BeforeDir
    AfterDir = $AfterDir
    BeforeTimestamp = $beforeMeta.Timestamp
    AfterTimestamp = $afterMeta.Timestamp
    AddedFiles = (($diffRows | Where-Object { $_.ChangeType -eq "added" }) | Measure-Object).Count
    RemovedFiles = (($diffRows | Where-Object { $_.ChangeType -eq "removed" }) | Measure-Object).Count
    ChangedFiles = (($diffRows | Where-Object { $_.ChangeType -eq "changed" -and $_.DeltaPssKB -ne 0 }) | Measure-Object).Count
    BeforeTotalPssKB = (($diffRows | Measure-Object -Property BeforePssKB -Sum).Sum)
    AfterTotalPssKB = (($diffRows | Measure-Object -Property AfterPssKB -Sum).Sum)
    DeltaTotalPssKB = (($diffRows | Measure-Object -Property DeltaPssKB -Sum).Sum)
    BeforeTotalRssKB = (($diffRows | Measure-Object -Property BeforeRssKB -Sum).Sum)
    AfterTotalRssKB = (($diffRows | Measure-Object -Property AfterRssKB -Sum).Sum)
    DeltaTotalRssKB = (($diffRows | Measure-Object -Property DeltaRssKB -Sum).Sum)
}

$reportBase = "compare_files_{0}_{1}_{2}_vs_{3}" -f `
    (Get-SafePathName -Name $(if ($summary.ProcessName) { $summary.ProcessName } else { "unknown" })), `
    $(if ($summary.ProcessId) { $summary.ProcessId } else { "unknown" }), `
    $(if ($summary.BeforeTimestamp) { $summary.BeforeTimestamp } else { "before" }), `
    $(if ($summary.AfterTimestamp) { $summary.AfterTimestamp } else { "after" })

$csvPath = Join-Path $OutputDir "$reportBase.csv"
$jsonPath = Join-Path $OutputDir "$reportBase.json"

$diffRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$report = [pscustomobject]@{
    Summary = $summary
    Diffs = $diffRows
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "File memory diff summary"
Write-Host "------------------------"
Write-Host ("Process name     : {0}" -f $summary.ProcessName)
Write-Host ("PID              : {0}" -f $summary.ProcessId)
Write-Host ("Before total PSS : {0} kB" -f $summary.BeforeTotalPssKB)
Write-Host ("After total PSS  : {0} kB" -f $summary.AfterTotalPssKB)
Write-Host ("Delta total PSS  : {0} kB" -f $summary.DeltaTotalPssKB)
Write-Host ("Before total RSS : {0} kB" -f $summary.BeforeTotalRssKB)
Write-Host ("After total RSS  : {0} kB" -f $summary.AfterTotalRssKB)
Write-Host ("Delta total RSS  : {0} kB" -f $summary.DeltaTotalRssKB)
Write-Host ("CSV report       : {0}" -f $csvPath)
Write-Host ("JSON report      : {0}" -f $jsonPath)
Write-Host ""

Write-Host "Top PSS increases"
$diffRows |
    Where-Object { $_.DeltaPssKB -gt 0 } |
    Select-Object -First 20 FileName, FileType, IsLibrary, AfterFileSizeKB, DeltaPssKB, AfterPssKB, BeforePssKB, ChangeType, FilePath |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Top PSS decreases"
$diffRows |
    Sort-Object DeltaPssKB |
    Where-Object { $_.DeltaPssKB -lt 0 } |
    Select-Object -First 20 FileName, FileType, IsLibrary, BeforeFileSizeKB, DeltaPssKB, AfterPssKB, BeforePssKB, ChangeType, FilePath |
    Format-Table -AutoSize

if ($Json) {
    $report | ConvertTo-Json -Depth 5
}
