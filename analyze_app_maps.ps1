<#
用途:
- 通过 hdc 抓取指定进程的 `maps`、`smaps`、`smaps_rollup` 和 `hidumper --mem` 输出。
- 基于 `smaps` 分析该进程各个动态链接库占用的物理内存，并导出 CSV/JSON 报告。

原理:
- `maps/smaps/smaps_rollup` 通过设备侧 `cat > /data/...` 再 `hdc file recv` 的方式拉回本地，避免直接 `hdc shell cat` 时大文件输出不完整。
- `hidumper --mem` 直接执行命令并把标准输出保存到本地文本文件。
- 解析 `smaps` 后，按完整库路径聚合 file-backed 段，并把 `[anon:xxx.so.bss]` 归并到对应库。
- 输出时同时给出 file 段和 bss 段的 `RSS/PSS`，其中 `TotalPssKB` 更接近该进程对动态库实际分摊的物理内存。
#>
param(
    [Parameter(ParameterSetName = "Capture", Mandatory = $true)]
    [int]$TargetPid,

    [Parameter(ParameterSetName = "AnalyzeOnly")]
    [string]$SourceDir,

    [string]$OutputDir,
    [string]$Hdc = "hdc",
    [string]$Device,
    [switch]$KeepRawFiles,
    [switch]$Json
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
        [int]$TargetPid
    )

    try {
        $name = Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "cat /proc/$TargetPid/comm"
        return (Get-SafePathName -Name $name)
    } catch {
        return "unknown"
    }
}

function Save-ProcFiles {
    param(
        [string]$HdcPath,
        [string]$DeviceId,
        [int]$TargetPid,
        [string]$TargetDir
    )

    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null

    foreach ($name in @("maps", "smaps", "smaps_rollup")) {
        $remote = "/proc/$TargetPid/$name"
        $tmpRemote = "/data/${TargetPid}_${name}"
        $localPath = Join-Path $TargetDir $name

        Write-Info "Capturing $remote"
        Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "cat $remote > $tmpRemote"
        Invoke-HdcFileRecv -HdcPath $HdcPath -DeviceId $DeviceId -RemotePath $tmpRemote -LocalPath $localPath
        Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "rm -f $tmpRemote" | Out-Null
    }

    $hidumperLocal = Join-Path $TargetDir "hidumper_mem.txt"

    Write-Info "Capturing hidumper --mem $TargetPid"
    $hidumperContent = Invoke-HdcShell -HdcPath $HdcPath -DeviceId $DeviceId -RemoteCommand "hidumper --mem $TargetPid"
    Set-Content -LiteralPath $hidumperLocal -Value $hidumperContent -Encoding UTF8
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
                Header        = $line
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

function Get-BssLibraryName {
    param([string]$AnonPath)

    if ($AnonPath -match '^\[anon:(.+?)\.bss\]$') {
        return $matches[1]
    }
    return $null
}

function Add-LibMetrics {
    param(
        [hashtable]$Map,
        [string]$Key,
        [string]$DisplayPath,
        [psobject]$Entry,
        [string]$Kind
    )

    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = [ordered]@{
            LibraryKey    = $Key
            DisplayPath   = $DisplayPath
            Kind          = $Kind
            Inode         = 0
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
    if ($Entry.PSObject.Properties.Name -contains "Inode" -and [int64]$Entry.Inode -gt 0 -and [int64]$item.Inode -eq 0) {
        $item.Inode = [int64]$Entry.Inode
    }
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

function Analyze-Libraries {
    param([object[]]$Entries)

    $fileLibs = @{}
    $bssLibs = @{}

    foreach ($entry in $Entries) {
        if (Test-IsLibraryFilePath -Path $entry.Path) {
            $fileKey = Get-FileIdentityKey -Path $entry.Path -Inode $entry.Inode
            Add-LibMetrics -Map $fileLibs -Key $fileKey -DisplayPath $entry.Path -Entry $entry -Kind "file"
            continue
        }

        $bssName = Get-BssLibraryName -AnonPath $entry.Path
        if ($bssName) {
            $bssKey = Get-FileIdentityKey -Path $bssName -Inode 0
            Add-LibMetrics -Map $bssLibs -Key $bssKey -DisplayPath $entry.Path -Entry $entry -Kind "bss"
        }
    }

    $libraryRows = foreach ($fileKey in $fileLibs.Keys) {
        $fileRow = $fileLibs[$fileKey]
        $bssRow = $null
        $bssLookupKey = Get-FileIdentityKey -Path $fileRow.DisplayPath -Inode 0
        if ($bssLibs.ContainsKey($bssLookupKey)) {
            $bssRow = $bssLibs[$bssLookupKey]
        }

        [pscustomobject]@{
            Library         = [System.IO.Path]::GetFileName($fileRow.DisplayPath)
            Inode           = [int64]$fileRow.Inode
            FileKey         = $fileKey
            FilePath        = $fileRow.DisplayPath
            FileSizeKB      = $fileRow.Size
            FileRssKB       = $fileRow.Rss
            FilePssKB       = $fileRow.Pss
            BssSizeKB       = if ($bssRow) { $bssRow.Size } else { 0 }
            BssRssKB        = if ($bssRow) { $bssRow.Rss } else { 0 }
            BssPssKB        = if ($bssRow) { $bssRow.Pss } else { 0 }
            TotalRssKB      = $fileRow.Rss + $(if ($bssRow) { $bssRow.Rss } else { 0 })
            TotalPssKB      = $fileRow.Pss + $(if ($bssRow) { $bssRow.Pss } else { 0 })
            PrivateKB       = $fileRow.Private_Clean + $fileRow.Private_Dirty
            SharedKB        = $fileRow.Shared_Clean + $fileRow.Shared_Dirty
            Segments        = $fileRow.Segments
        }
    }

    $sameNameCounts = @{}
    foreach ($group in ($libraryRows | Group-Object Library)) {
        $sameNameCounts[[string]$group.Name] = $group.Count
    }

    $libraryRows = foreach ($row in $libraryRows) {
        [pscustomobject]@{
            Library         = $row.Library
            SameNameCount   = $sameNameCounts[[string]$row.Library]
            Inode           = $row.Inode
            FileKey         = $row.FileKey
            FilePath        = $row.FilePath
            FileSizeKB      = $row.FileSizeKB
            FileRssKB       = $row.FileRssKB
            FilePssKB       = $row.FilePssKB
            BssSizeKB       = $row.BssSizeKB
            BssRssKB        = $row.BssRssKB
            BssPssKB        = $row.BssPssKB
            TotalRssKB      = $row.TotalRssKB
            TotalPssKB      = $row.TotalPssKB
            PrivateKB       = $row.PrivateKB
            SharedKB        = $row.SharedKB
            Segments        = $row.Segments
        }
    }

    $summary = [pscustomobject]@{
        FileLibraryCount = ($libraryRows | Measure-Object).Count
        BssLibraryCount  = (($libraryRows | Where-Object { $_.BssSizeKB -gt 0 }) | Measure-Object).Count
        FileRssKB        = (($libraryRows | Measure-Object -Property FileRssKB -Sum).Sum)
        FilePssKB        = (($libraryRows | Measure-Object -Property FilePssKB -Sum).Sum)
        BssRssKB         = (($libraryRows | Measure-Object -Property BssRssKB -Sum).Sum)
        BssPssKB         = (($libraryRows | Measure-Object -Property BssPssKB -Sum).Sum)
        TotalRssKB       = (($libraryRows | Measure-Object -Property TotalRssKB -Sum).Sum)
        TotalPssKB       = (($libraryRows | Measure-Object -Property TotalPssKB -Sum).Sum)
    }

    return [pscustomobject]@{
        Summary   = $summary
        Libraries = $libraryRows | Sort-Object -Property TotalPssKB, TotalRssKB -Descending
    }
}

function Read-Rollup {
    param([string]$Path)

    $data = [ordered]@{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([A-Za-z_]+):\s+(\d+)\s+kB') {
            $data[$matches[1]] = [int64]$matches[2]
        }
    }
    return [pscustomobject]$data
}

if ($PSCmdlet.ParameterSetName -eq "Capture") {
    $ProcessName = Get-RemoteProcessName -HdcPath $Hdc -DeviceId $Device -TargetPid $TargetPid
} else {
    $ProcessName = ""
}

if (-not $OutputDir) {
    if ($PSCmdlet.ParameterSetName -eq "Capture") {
        $OutputDir = Join-Path (Get-Location) "proc_${ProcessName}_${TargetPid}_$RunTimestamp"
    } elseif ($SourceDir) {
        $OutputDir = $SourceDir
    } else {
        $OutputDir = Get-Location
    }
}

if ($PSCmdlet.ParameterSetName -eq "Capture") {
    Save-ProcFiles -HdcPath $Hdc -DeviceId $Device -TargetPid $TargetPid -TargetDir $OutputDir
    $inputDir = $OutputDir
} else {
    if (-not $SourceDir) {
        throw "AnalyzeOnly mode requires -SourceDir."
    }
    $inputDir = $SourceDir
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$smapsPath = Join-Path $inputDir "smaps"
$rollupPath = Join-Path $inputDir "smaps_rollup"
$mapsPath = Join-Path $inputDir "maps"

foreach ($required in @($smapsPath, $rollupPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required file not found: $required"
    }
}

Write-Info "Parsing $smapsPath"
$entries = Parse-Smaps -Path $smapsPath
$analysis = Analyze-Libraries -Entries $entries
$rollup = Read-Rollup -Path $rollupPath

$reportName = if ([string]::IsNullOrWhiteSpace($ProcessName)) { "library_memory_$RunTimestamp" } else { "library_memory_${ProcessName}_$RunTimestamp" }
$csvPath = Join-Path $OutputDir "$reportName.csv"
$analysis.Libraries | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$jsonPath = Join-Path $OutputDir "$reportName.json"
$report = [pscustomobject]@{
    SourceDir = $inputDir
    ProcessName = $ProcessName
    Rollup    = $rollup
    Summary   = $analysis.Summary
    Libraries = $analysis.Libraries
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "Library memory summary"
Write-Host "----------------------"
Write-Host ("Process total RSS : {0} kB" -f $rollup.Rss)
Write-Host ("Process total PSS : {0} kB" -f $rollup.Pss)
Write-Host ("Library file RSS  : {0} kB" -f $analysis.Summary.FileRssKB)
Write-Host ("Library file PSS  : {0} kB" -f $analysis.Summary.FilePssKB)
Write-Host ("Library bss RSS   : {0} kB" -f $analysis.Summary.BssRssKB)
Write-Host ("Library bss PSS   : {0} kB" -f $analysis.Summary.BssPssKB)
Write-Host ("Library total RSS : {0} kB" -f $analysis.Summary.TotalRssKB)
Write-Host ("Library total PSS : {0} kB" -f $analysis.Summary.TotalPssKB)
Write-Host ("CSV report        : {0}" -f $csvPath)
Write-Host ("JSON report       : {0}" -f $jsonPath)
Write-Host ""

$analysis.Libraries |
    Select-Object -First 30 Library, TotalPssKB, TotalRssKB, FilePssKB, BssPssKB, Segments, FilePath |
    Format-Table -AutoSize

if (-not $KeepRawFiles -and $PSCmdlet.ParameterSetName -eq "Capture") {
    Write-Info "Raw proc files kept in $OutputDir"
}

if ($Json) {
    $report | ConvertTo-Json -Depth 4
}
