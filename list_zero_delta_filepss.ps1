<#
用途:
- 从一个 SO 对比目录中筛出 `DeltaPssKB = 0` 的库。
- 再到一个普通内存分析目录中，查出这些库对应的 `FilePssKB` 等指标，并集中列出来。

原理:
- 读取对比目录中的 `compare_so_*.json`，筛出 `DeltaPssKB` 为 0 的库记录。
- 再读取普通内存目录中的 `library_memory_*.json`，按完整 `FilePath` 查找对应库。
- 最终输出一张交叉结果表，方便分析“对比不变的库，在某个普通内存快照里实际占了多少 file-backed 内存”。
- 输出字段同时保留 `DeltaPssKB`、`FilePssKB`、`TotalPssKB` 等信息，便于横向关联。
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$CompareDir,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$MemoryDir,

    [string]$OutputDir,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

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

function Get-LatestFileByPattern {
    param(
        [string]$DirPath,
        [string]$Pattern
    )

    return Get-ChildItem -LiteralPath $DirPath -Filter $Pattern -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
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

function Load-CompareDiffs {
    param([string]$DirPath)

    $jsonFile = Get-LatestFileByPattern -DirPath $DirPath -Pattern "compare_so_*.json"
    if (-not $jsonFile) {
        throw "No compare_so_*.json found in $DirPath"
    }

    Write-Info "Using compare JSON: $($jsonFile.FullName)"
    $data = Get-Content -LiteralPath $jsonFile.FullName -Raw | ConvertFrom-Json
    return [pscustomobject]@{
        SourceFile = $jsonFile.FullName
        Summary = $data.Summary
        Diffs = @($data.Diffs)
    }
}

function Load-LibraryRows {
    param([string]$DirPath)

    $jsonFile = Get-LatestFileByPattern -DirPath $DirPath -Pattern "library_memory_*.json"
    if (-not $jsonFile) {
        throw "No library_memory_*.json found in $DirPath"
    }

    Write-Info "Using memory JSON: $($jsonFile.FullName)"
    $data = Get-Content -LiteralPath $jsonFile.FullName -Raw | ConvertFrom-Json
    return [pscustomobject]@{
        SourceFile = $jsonFile.FullName
        ProcessName = $data.ProcessName
        Libraries = @($data.Libraries)
    }
}

$CompareDir = (Resolve-Path -LiteralPath $CompareDir).Path
$MemoryDir = (Resolve-Path -LiteralPath $MemoryDir).Path

if (-not $OutputDir) {
    $compareName = Get-SafePathName -Name (Split-Path -Leaf $CompareDir)
    $memoryName = Get-SafePathName -Name (Split-Path -Leaf $MemoryDir)
    $OutputDir = Join-Path (Get-Location) "zero_delta_lookup_${compareName}_vs_${memoryName}_$RunTimestamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$compareData = Load-CompareDiffs -DirPath $CompareDir
$memoryData = Load-LibraryRows -DirPath $MemoryDir

$memoryMap = @{}
foreach ($row in $memoryData.Libraries) {
    $inode = [int64]$(if ($row.PSObject.Properties.Name -contains "Inode") { $row.Inode } else { 0 })
    $filePath = [string]$row.FilePath
    $memoryMap[(Get-FileIdentityKey -Path $filePath -Inode $inode)] = $row
}

$rows = foreach ($diff in $compareData.Diffs) {
    if ([int64]$diff.DeltaPssKB -ne 0) {
        continue
    }

    $filePath = [string]$diff.FilePath
    $inode = [int64]$(if ($diff.PSObject.Properties.Name -contains "Inode") { $diff.Inode } else { 0 })
    $fileKey = Get-FileIdentityKey -Path $filePath -Inode $inode
    $memoryRow = if ($memoryMap.ContainsKey($fileKey)) { $memoryMap[$fileKey] } else { $null }

    [pscustomobject]@{
        Library = [string]$diff.Library
        Inode = $inode
        FileKey = $fileKey
        FilePath = $filePath
        DeltaPssKB = [int64]$diff.DeltaPssKB
        BeforePssKB = [int64]$diff.BeforePssKB
        AfterPssKB = [int64]$diff.AfterPssKB
        ChangeType = [string]$diff.ChangeType
        FilePssKB = if ($memoryRow) { [int64]$memoryRow.FilePssKB } else { $null }
        FileRssKB = if ($memoryRow) { [int64]$memoryRow.FileRssKB } else { $null }
        TotalPssKB = if ($memoryRow) { [int64]$memoryRow.TotalPssKB } else { $null }
        TotalRssKB = if ($memoryRow) { [int64]$memoryRow.TotalRssKB } else { $null }
        BssPssKB = if ($memoryRow) { [int64]$memoryRow.BssPssKB } else { $null }
        FoundInMemoryDir = [bool]($null -ne $memoryRow)
    }
}

$rows = @($rows | Sort-Object -Property FilePssKB, Library -Descending)

$baseName = "zero_delta_filepss_{0}_{1}" -f `
    (Get-SafePathName -Name (Split-Path -Leaf $CompareDir)), `
    $RunTimestamp

$csvPath = Join-Path $OutputDir "$baseName.csv"
$jsonPath = Join-Path $OutputDir "$baseName.json"

$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$report = [pscustomobject]@{
    CompareDir = $CompareDir
    MemoryDir = $MemoryDir
    CompareSourceFile = $compareData.SourceFile
    MemorySourceFile = $memoryData.SourceFile
    ProcessName = $memoryData.ProcessName
    ZeroDeltaLibraryCount = $rows.Count
    FoundInMemoryDirCount = (($rows | Where-Object { $_.FoundInMemoryDir }) | Measure-Object).Count
    Rows = $rows
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "Zero-delta library lookup summary"
Write-Host "---------------------------------"
Write-Host ("Compare dir      : {0}" -f $CompareDir)
Write-Host ("Memory dir       : {0}" -f $MemoryDir)
Write-Host ("Zero-delta count : {0}" -f $rows.Count)
Write-Host ("Matched count    : {0}" -f $report.FoundInMemoryDirCount)
Write-Host ("CSV report       : {0}" -f $csvPath)
Write-Host ("JSON report      : {0}" -f $jsonPath)
Write-Host ""

$rows | Select-Object -First 50 Library, FilePssKB, FileRssKB, TotalPssKB, DeltaPssKB, FoundInMemoryDir, FilePath | Format-Table -AutoSize

if ($Json) {
    $report | ConvertTo-Json -Depth 5
}
