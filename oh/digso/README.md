# digso Python CLI

`oh/digso/digso.py` is a cross-platform Python replacement for the existing PowerShell-based `digso` tools.

It works on both Windows and Linux as long as:

- Python 3.10+ is available
- `hdc` is available in `PATH` when you use capture commands
- The target device exposes the same `/proc`, `ps`, `lsof`, and `hidumper` commands expected by the old scripts

## Commands

Analyze one process and generate file-backed memory reports:

```bash
python oh/digso/digso.py analyze-app-maps --target-pid 12345
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
