# digso Python CLI

`oh/digso/digso.py` is a cross-platform Python replacement for the existing PowerShell-based `digso` tools.

`oh/digso/digso.py` 是一组跨平台 Python 工具，用来替代原来的 PowerShell 版 `digso` 脚本。

It works on both Windows and Linux as long as:

- Python 3.10+ is available
- `hdc` is available in `PATH` when you use capture commands
- The target device exposes the same `/proc`, `ps`, `lsof`, and `hidumper` commands expected by the old scripts

只要满足下面条件，就可以在 Windows 和 Linux 上使用：

- 已安装 Python 3.10 或更高版本
- 抓取设备数据时，`hdc` 已经在 `PATH` 中
- 目标设备提供旧脚本依赖的 `/proc`、`ps`、`lsof`、`hidumper` 等命令

By default, commands that generate reports now write into:

- Windows: `D:/digso_logs`
- Linux: `/data/digso_logs`

默认报告输出目录：

- Windows: `D:/digso_logs`
- Linux: `/data/digso_logs`

You can still override the destination with `--output-dir` in Python or `-OutputDir` in the PowerShell scripts.

也可以通过 Python CLI 的 `--output-dir` 或 PowerShell 脚本的 `-OutputDir` 指定其它输出目录。

## Commands / 命令

Analyze one process and generate file-backed memory reports:

分析单个进程，生成 file-backed 内存报告：

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345
```

The file report also includes disk usage fields for mapped files. For a live `--target-pid`, the tool queries the target device with `stat`; for `--source-dir`, it only fills these fields when the same path exists on the local machine.

文件报告也会输出映射文件的磁盘文件大小字段。使用 live `--target-pid` 时，工具会在目标设备上通过 `stat` 查询；使用 `--source-dir` 离线分析时，只有同一路径在本机真实存在，才会填充该字段。

Relevant fields:

相关字段：

- `DiskFileSizeKB`: apparent file size from filesystem metadata
- `DiskFileSizeKB`：文件系统元数据里的文件逻辑大小

Pagemap analysis is disabled by default because it is expensive on processes
with large `maps` files. Enable it explicitly when needed:

`pagemap` 分析默认关闭。对于 `maps` 很大的进程，逐段读取 `/proc/<pid>/pagemap` 会很慢，所以只有显式加参数时才启用：

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345 --analyze-pagemap
```

When enabled, the command analyzes `/proc/<pid>/pagemap` by each
`/proc/<pid>/maps` range. It writes `map_pagemap_*.summary.csv` for per-map
present/swap/not-mapped counts and `map_pagemap_*.ranges.csv` for continuous VA
ranges. Remote pagemap reads merge nearby map ranges first to reduce
`dd + file recv` round trips. If the kernel masks PFNs for the current user, the
report can still show present/swap state, but `StartPA`/`EndPA` may be empty.

启用后，工具会按 `/proc/<pid>/maps` 的虚拟地址区间分析 `/proc/<pid>/pagemap`，输出：

- `map_pagemap_*.summary.csv`：每个 maps 区间的 present、swap、not-mapped 等统计
- `map_pagemap_*.ranges.csv`：连续 VA 区间明细
- `map_pagemap_*.json`：完整 pagemap 分析结果

远端 pagemap 读取会先合并相邻或距离较近的 maps 区间，减少 `dd + hdc file recv` 次数。默认合并距离是 16MB，可以用 `--pagemap-merge-gap-kb` 调整：

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345 --analyze-pagemap --pagemap-merge-gap-kb 65536
```

如果内核对当前用户屏蔽 PFN，报告仍然可以看到 present/swap 状态，但 `StartPA`、`EndPA` 可能为空。

Enable library import-source analysis for the same flow:

同时分析动态库 import 来源：

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345 -I
```

Use a specific local ELF cache/export directory:

指定本地 ELF 缓存或导出目录：

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345 -I --elf-dir D:/digso_logs/elf_exports
```

Analyze an already captured directory:

分析已经抓取好的目录：

```bash
python oh/digso/digso.py analyze-app-maps --source-dir ./proc_demo_12345_20260408_120000
```

Analyze system-wide sharing for a target process:

分析目标进程相关文件在系统范围内的共享情况：

```bash
python oh/digso/digso.py analyze-app-shared-file-usage 12345
```

Analyze shared files for a process list:

按进程列表分析共享文件：

```bash
python oh/digso/digso.py analyze-process-list-shared-files oh/digso/process_list.txt
```

Compare two snapshots:

对比两次快照：

```bash
python oh/digso/digso.py compare-so-snapshots before_dir after_dir
```

Look up zero-delta libraries in a memory snapshot:

在内存快照中查找 PSS 差异为 0 的库：

```bash
python oh/digso/digso.py list-zero-delta-filepss compare_dir memory_dir
```

Force memcg reclaim/swapout for a process:

对指定进程触发 memcg reclaim/swapout：

```bash
python oh/digso/digso.py force-swapout-memcg 12345
```

## Notes / 说明

- The old `.ps1` scripts are still present for reference, but the `.bat` entrypoints now call the Python CLI.
- Python cache files under `oh/digso/__pycache__/` are ignored by Git.
- For device selection, use `--device <serial>` on the capture commands.
- If you do not pass an output directory, each run creates a timestamped subdirectory under the platform default log root.
- The `.bat` wrappers also accept an optional trailing output-directory argument, for example `run_compare_so_snapshots.bat before after D:/custom_logs`.
- `analyze-app-maps -I` is the short form for import-source analysis. It first checks a local ELF cache directory, and only exports missing files from the device. The default cache/export root is `D:/digso_logs/elf_exports` on Windows and `/data/digso_logs/elf_exports` on Linux. You can override it with `--elf-dir`.
- The same `-I` flow also writes a Mermaid dependency graph as `file_memory_xxx.imports.mmd`.
- `run_analyze_app_maps.bat` also accepts `-I` or `--analyze-imports`, and can additionally pass an ELF cache directory via a later `--elf-dir` position.

中文补充：

- 旧的 `.ps1` 脚本还保留在目录里，方便参考；现在 `.bat` 入口默认调用 Python CLI。
- `oh/digso/__pycache__/` 下的 Python 缓存文件会被 Git 忽略。
- 多设备场景可以用 `--device <serial>` 指定设备。
- 不传输出目录时，每次运行都会在默认 log 根目录下创建带时间戳的子目录。
- `.bat` 包装脚本也支持在最后追加输出目录，例如 `run_compare_so_snapshots.bat before after D:/custom_logs`。
- `analyze-app-maps -I` 是 import 来源分析的简写。它会优先复用本地 ELF 缓存，只从设备导出缺失文件。默认 ELF 缓存目录是 Windows 的 `D:/digso_logs/elf_exports` 或 Linux 的 `/data/digso_logs/elf_exports`，也可以用 `--elf-dir` 覆盖。
- `-I` 流程还会额外输出 Mermaid 依赖图：`file_memory_xxx.imports.mmd`。
- `run_analyze_app_maps.bat` 支持 `-I`、`--analyze-imports`、`--analyze-library-imports` 和 `--analyze-pagemap`。
