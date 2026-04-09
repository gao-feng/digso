# digso Python CLI

`oh/digso/digso.py` is a cross-platform Python replacement for the existing PowerShell-based `digso` tools.

It works on both Windows and Linux as long as:

- Python 3.10+ is available
- `hdc` is available in `PATH` when you use capture commands
- The target device exposes the same `/proc`, `ps`, `lsof`, and `hidumper` commands expected by the old scripts

By default, commands that generate reports now write into:

- Windows: `D:/digso_logs`
- Linux: `/data/digso_logs`

You can still override the destination with `--output-dir` in Python or `-OutputDir` in the PowerShell scripts.

## Commands

Analyze one process and generate file-backed memory reports:

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345
```

Enable library import-source analysis for the same flow:

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345 -I
```

Analyze an already captured directory:

```bash
python oh/digso/digso.py analyze-app-maps --source-dir ./proc_demo_12345_20260408_120000
```

Analyze system-wide sharing for a target process:

```bash
python oh/digso/digso.py analyze-app-shared-file-usage 12345
```

Analyze shared files for a process list:

```bash
python oh/digso/digso.py analyze-process-list-shared-files oh/digso/process_list.txt
```

Compare two snapshots:

```bash
python oh/digso/digso.py compare-so-snapshots before_dir after_dir
```

Look up zero-delta libraries in a memory snapshot:

```bash
python oh/digso/digso.py list-zero-delta-filepss compare_dir memory_dir
```

Force memcg reclaim/swapout for a process:

```bash
python oh/digso/digso.py force-swapout-memcg 12345
```

## Notes

- The old `.ps1` scripts are still present for reference, but the `.bat` entrypoints now call the Python CLI.
- Python cache files under `oh/digso/__pycache__/` are ignored by Git.
- For device selection, use `--device <serial>` on the capture commands.
- If you do not pass an output directory, each run creates a timestamped subdirectory under the platform default log root.
- The `.bat` wrappers also accept an optional trailing output-directory argument, for example `run_compare_so_snapshots.bat before after D:/custom_logs`.
- `analyze-app-maps -I` is the short form for import-source analysis. It exports the loaded ELF files into `elf_exports/`, parses `DT_NEEDED`, and classifies loaded libraries as `needed_by_executable`, `needed_by_library`, `needed_by_dlopen_library`, `dlopen_or_runtime`, or `unknown`.
- `run_analyze_app_maps.bat` also accepts `-I` or `--analyze-imports` as the second or third argument.
