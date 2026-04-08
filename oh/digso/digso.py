#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


METRIC_KEYS = (
    "Size",
    "Rss",
    "Pss",
    "Shared_Clean",
    "Shared_Dirty",
    "Private_Clean",
    "Private_Dirty",
    "Anonymous",
    "Swap",
)


class DigsoError(RuntimeError):
    pass


def info(message: str) -> None:
    print(f"[info] {message}")


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_name(name: str | None) -> str:
    if not name:
        return "unknown"
    cleaned = re.sub(r"\s+", "_", name.strip())
    cleaned = re.sub(r"[^0-9A-Za-z_.-]", "_", cleaned)
    return cleaned or "unknown"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


@dataclass
class SmapsEntry:
    path: str
    inode: int
    size: int = 0
    rss: int = 0
    pss: int = 0
    shared_clean: int = 0
    shared_dirty: int = 0
    private_clean: int = 0
    private_dirty: int = 0
    anonymous: int = 0
    swap: int = 0


class HdcClient:
    def __init__(self, hdc: str = "hdc", device: str | None = None) -> None:
        self.hdc = hdc
        self.device = device

    def _base(self) -> list[str]:
        args = [self.hdc]
        if self.device:
            args.extend(["-t", self.device])
        return args

    def run(self, extra: list[str]) -> str:
        cmd = self._base() + extra
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise DigsoError(result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(cmd)}")
        return result.stdout

    def shell(self, remote_command: str) -> str:
        return self.run(["shell", remote_command])

    def recv(self, remote_path: str, local_path: Path) -> None:
        cmd = self._base() + ["file", "recv", remote_path, str(local_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise DigsoError(result.stderr.strip() or result.stdout.strip() or f"hdc file recv failed: {remote_path}")

    def save_remote_text_file(self, remote_path: str, local_path: Path, remote_temp_path: str) -> None:
        self.shell(f"cat {remote_path} > {remote_temp_path}")
        try:
            self.recv(remote_temp_path, local_path)
        finally:
            try:
                self.shell(f"rm -f {remote_temp_path}")
            except DigsoError:
                pass

    def get_process_name(self, pid: int) -> str:
        try:
            return safe_name(self.shell(f"cat /proc/{pid}/comm").strip())
        except DigsoError:
            return "unknown"


def split_lines(text: str) -> list[str]:
    return text.splitlines()


def parse_smaps(path: Path) -> list[SmapsEntry]:
    entries: list[SmapsEntry] = []
    current: SmapsEntry | None = None
    for line in split_lines(read_text(path)):
        if re.match(r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s+", line):
            if current is not None:
                entries.append(current)
            parts = re.split(r"\s+", line, maxsplit=5)
            pathname = parts[5].strip() if len(parts) >= 6 else ""
            header_parts = [part for part in re.split(r"\s+", line.strip()) if part]
            inode = int(header_parts[4]) if len(header_parts) >= 5 and header_parts[4].isdigit() else 0
            current = SmapsEntry(path=pathname, inode=inode)
            continue
        metric_match = re.match(r"^([A-Za-z_]+):\s+(\d+)\s+kB", line)
        if current is None or not metric_match:
            continue
        key, value = metric_match.group(1), int(metric_match.group(2))
        if key not in METRIC_KEYS:
            continue
        attr = {
            "Size": "size",
            "Rss": "rss",
            "Pss": "pss",
            "Shared_Clean": "shared_clean",
            "Shared_Dirty": "shared_dirty",
            "Private_Clean": "private_clean",
            "Private_Dirty": "private_dirty",
            "Anonymous": "anonymous",
            "Swap": "swap",
        }[key]
        setattr(current, attr, value)
    if current is not None:
        entries.append(current)
    return entries


def parse_rollup(path: Path) -> dict[str, int]:
    data: dict[str, int] = {}
    for line in split_lines(read_text(path)):
        metric_match = re.match(r"^([A-Za-z_]+):\s+(\d+)\s+kB", line)
        if metric_match:
            data[metric_match.group(1)] = int(metric_match.group(2))
    return data


def parse_maps(path: Path) -> list[dict]:
    rows = []
    for line in split_lines(read_text(path)):
        if not re.match(r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s+", line):
            continue
        parts = re.split(r"\s+", line, maxsplit=5)
        pathname = parts[5].strip() if len(parts) >= 6 else ""
        header_parts = [part for part in re.split(r"\s+", line.strip()) if part]
        inode = int(header_parts[4]) if len(header_parts) >= 5 and header_parts[4].isdigit() else 0
        rows.append({"path": pathname, "inode": inode, "header": line})
    return rows


def file_identity_key(path: str, inode: int) -> str:
    return f"inode:{inode}" if inode > 0 else f"path:{path}"


def is_interesting_file_path(path: str) -> bool:
    if not path:
        return False
    if not (path.startswith("/") or re.match(r"^[A-Za-z]:\\", path)):
        return False
    if path.startswith("/dev/") or path.startswith("/proc/") or path.startswith("/memfd:"):
        return False
    return True


def is_library_file_path(path: str) -> bool:
    if not path:
        return False
    return bool(
        re.search(r"(^/|^[A-Za-z]:\\).+\.(so|dll|dylib)(\.\d+)*$", path)
        or re.search(r"(^/|^[A-Za-z]:\\).+\.z\.so(\.\d+)*$", path)
    )


def file_type(path: str) -> str:
    if not path:
        return "Unknown"
    if path.startswith("/dev/"):
        return "DeviceFile"
    if path.startswith("/proc/"):
        return "ProcFile"
    if path.startswith("/memfd:"):
        return "Memfd"
    if re.match(r"^\[.*\]$", path):
        return "SpecialMapping"
    if is_library_file_path(path):
        return "DynamicLibrary"
    suffix = Path(path).suffix.lstrip(".")
    if suffix:
        return suffix.lower()
    if re.search(r"^/(system|vendor|product|system_ext|apex)/.*/bin(/|$)", path) or re.search(
        r"^/(system|vendor|product|system_ext)/bin(/|$)", path
    ) or re.search(r"/bin/[^/]+$", path):
        return "ExecutableBinary"
    if path.startswith("/") or re.match(r"^[A-Za-z]:\\", path):
        return "RegularFile"
    return "Other"


def bss_library_name(path: str) -> str | None:
    match = re.match(r"^\[anon:(.+?)\.bss\]$", path)
    return match.group(1) if match else None


def file_source_category(path: str) -> str:
    if not path:
        return "OtherFile"
    if path.startswith("/data/storage/el1/bundle/arkwebcore/libs/"):
        return "SystemLibrary"
    if path.startswith("/system/") or path.startswith("/vendor/"):
        return "SystemLibrary"
    if path.startswith("/data/"):
        return "AppBundledFile"
    return "OtherFile"


def group_file_mappings(entries: list[SmapsEntry]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for entry in entries:
        if not is_interesting_file_path(entry.path):
            continue
        key = file_identity_key(entry.path, entry.inode)
        row = grouped.setdefault(
            key,
            {
                "FileKey": key,
                "Inode": entry.inode,
                "FilePath": entry.path,
                "FileName": os.path.basename(entry.path),
                "FileType": file_type(entry.path),
                "SizeKB": 0,
                "RssKB": 0,
                "PssKB": 0,
                "SharedKB": 0,
                "PrivateKB": 0,
                "Segments": 0,
            },
        )
        row["SizeKB"] += entry.size
        row["RssKB"] += entry.rss
        row["PssKB"] += entry.pss
        row["SharedKB"] += entry.shared_clean + entry.shared_dirty
        row["PrivateKB"] += entry.private_clean + entry.private_dirty
        row["Segments"] += 1
    return sorted(grouped.values(), key=lambda row: (-row["PssKB"], -row["RssKB"], row["FilePath"]))


def analyze_file_mappings(entries: list[SmapsEntry]) -> dict:
    file_rows: dict[str, dict] = {}
    bss_rows: dict[str, dict] = {}

    def add_metrics(target: dict[str, dict], key: str, display_path: str, entry: SmapsEntry, kind: str) -> None:
        row = target.setdefault(
            key,
            {
                "LibraryKey": key,
                "DisplayPath": display_path,
                "Kind": kind,
                "Inode": 0,
                "Size": 0,
                "Rss": 0,
                "Pss": 0,
                "Shared_Clean": 0,
                "Shared_Dirty": 0,
                "Private_Clean": 0,
                "Private_Dirty": 0,
                "Anonymous": 0,
                "Swap": 0,
                "Segments": 0,
            },
        )
        if entry.inode > 0 and row["Inode"] == 0:
            row["Inode"] = entry.inode
        row["Size"] += entry.size
        row["Rss"] += entry.rss
        row["Pss"] += entry.pss
        row["Shared_Clean"] += entry.shared_clean
        row["Shared_Dirty"] += entry.shared_dirty
        row["Private_Clean"] += entry.private_clean
        row["Private_Dirty"] += entry.private_dirty
        row["Anonymous"] += entry.anonymous
        row["Swap"] += entry.swap
        row["Segments"] += 1

    for entry in entries:
        if is_interesting_file_path(entry.path):
            add_metrics(file_rows, file_identity_key(entry.path, entry.inode), entry.path, entry, "file")
            continue
        bss_name = bss_library_name(entry.path)
        if bss_name:
            add_metrics(bss_rows, file_identity_key(bss_name, 0), entry.path, entry, "bss")

    rows = []
    for key, file_row in file_rows.items():
        bss_key = file_identity_key(file_row["DisplayPath"], 0)
        bss_row = bss_rows.get(bss_key)
        rows.append(
            {
                "FileName": os.path.basename(file_row["DisplayPath"]),
                "FileType": file_type(file_row["DisplayPath"]),
                "IsLibrary": is_library_file_path(file_row["DisplayPath"]),
                "Inode": file_row["Inode"],
                "FileKey": key,
                "FilePath": file_row["DisplayPath"],
                "FileSizeKB": file_row["Size"],
                "FileRssKB": file_row["Rss"],
                "FilePssKB": file_row["Pss"],
                "BssSizeKB": 0 if bss_row is None else bss_row["Size"],
                "BssRssKB": 0 if bss_row is None else bss_row["Rss"],
                "BssPssKB": 0 if bss_row is None else bss_row["Pss"],
                "TotalRssKB": file_row["Rss"] + (0 if bss_row is None else bss_row["Rss"]),
                "TotalPssKB": file_row["Pss"] + (0 if bss_row is None else bss_row["Pss"]),
                "PrivateKB": file_row["Private_Clean"] + file_row["Private_Dirty"],
                "SharedKB": file_row["Shared_Clean"] + file_row["Shared_Dirty"],
                "Segments": file_row["Segments"],
            }
        )

    same_name_counts = defaultdict(int)
    for row in rows:
        same_name_counts[row["FileName"]] += 1
    for row in rows:
        row["SameNameCount"] = same_name_counts[row["FileName"]]

    rows.sort(key=lambda row: (-row["TotalPssKB"], -row["TotalRssKB"], row["FilePath"]))
    summary = {
        "FileCount": len(rows),
        "LibraryCount": sum(1 for row in rows if row["IsLibrary"]),
        "FilesWithBssCount": sum(1 for row in rows if row["BssSizeKB"] > 0),
        "FileRssKB": sum(row["FileRssKB"] for row in rows),
        "FilePssKB": sum(row["FilePssKB"] for row in rows),
        "BssRssKB": sum(row["BssRssKB"] for row in rows),
        "BssPssKB": sum(row["BssPssKB"] for row in rows),
        "TotalRssKB": sum(row["TotalRssKB"] for row in rows),
        "TotalPssKB": sum(row["TotalPssKB"] for row in rows),
    }
    return {"Summary": summary, "Files": rows}


def parse_lsof_output(path: Path) -> list[dict]:
    rows = []
    for line in split_lines(read_text(path)):
        if not line.strip() or re.match(r"^\s*COMMAND\s+PID\s+", line):
            continue
        parts = [part for part in re.split(r"\s+", line.strip()) if part]
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        rows.append(
            {
                "Command": parts[0],
                "ProcessId": int(parts[1]),
                "User": parts[2],
                "Node": int(parts[-2]) if parts[-2].isdigit() else 0,
                "Name": parts[-1],
            }
        )
    return rows


def parse_process_list_file(path: Path) -> list[str]:
    names = []
    for line in split_lines(read_text(path)):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        names.append(stripped)
    return sorted(set(names))


def parse_ps_rows(text: str) -> list[dict]:
    rows = []
    for line in split_lines(text):
        if not line.strip() or re.match(r"^\s*UID\s+PID\s+", line):
            continue
        parts = [part for part in re.split(r"\s+", line.strip()) if part]
        if len(parts) < 8 or not parts[1].isdigit():
            continue
        rows.append({"Uid": parts[0], "ProcessId": int(parts[1]), "Command": parts[-1], "RawLine": line})
    return rows


def resolve_target_processes(process_names: list[str], ps_rows: list[dict]) -> list[dict]:
    resolved = {}
    for name in process_names:
        matches = [row for row in ps_rows if row["Command"] == name]
        if not matches:
            print(f"[warn] No process found for name: {name}")
            continue
        for match in matches:
            resolved[(match["Command"], match["ProcessId"])] = {
                "RequestedName": name,
                "ProcessName": match["Command"],
                "ProcessId": match["ProcessId"],
                "Uid": match["Uid"],
            }
    return [resolved[key] for key in sorted(resolved.keys(), key=lambda item: (item[0], item[1]))]


def save_proc_files(client: HdcClient, pid: int, target_dir: Path) -> None:
    ensure_dir(target_dir)
    for name in ("maps", "smaps", "smaps_rollup"):
        info(f"Capturing /proc/{pid}/{name}")
        client.save_remote_text_file(f"/proc/{pid}/{name}", target_dir / name, f"/data/{pid}_{name}")
    info(f"Capturing hidumper --mem {pid}")
    write_text(target_dir / "hidumper_mem.txt", client.shell(f"hidumper --mem {pid}"))


def save_proc_smaps(client: HdcClient, pid: int, local_path: Path, suffix: str) -> None:
    client.save_remote_text_file(f"/proc/{pid}/smaps", local_path, f"/data/{pid}_{suffix}")


def save_proc_maps(client: HdcClient, pid: int, local_path: Path, suffix: str) -> None:
    client.save_remote_text_file(f"/proc/{pid}/maps", local_path, f"/data/{pid}_{suffix}")


def print_kv(title: str, rows: list[tuple[str, object]]) -> None:
    print()
    print(title)
    print("-" * len(title))
    for key, value in rows:
        print(f"{key:<18}: {value}")
    print()


def latest_file(dir_path: Path, pattern: str) -> Path | None:
    matches = sorted(dir_path.glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def snapshot_meta_from_dir(dir_path: Path) -> dict:
    match = re.match(r"^proc_(.+)_(\d+)_(\d{8}_\d{6})$", dir_path.name)
    if not match:
        return {"ProcessName": "", "Pid": 0, "Timestamp": "", "DirectoryName": dir_path.name}
    return {"ProcessName": match.group(1), "Pid": int(match.group(2)), "Timestamp": match.group(3), "DirectoryName": dir_path.name}


def rows_from_snapshot_dir(dir_path: Path) -> dict:
    json_candidate = latest_file(dir_path, "file_memory_*.json") or latest_file(dir_path, "library_memory_*.json")
    if json_candidate:
        info(f"Using existing JSON report: {json_candidate}")
        payload = json.loads(read_text(json_candidate))
        rows = payload.get("Files", payload.get("Libraries", []))
        normalized = []
        for row in rows:
            file_path = row.get("FilePath", "")
            normalized.append(
                {
                    "FileName": row.get("FileName") or row.get("Library") or os.path.basename(file_path),
                    "FileType": row.get("FileType") or file_type(file_path),
                    "IsLibrary": bool(row.get("IsLibrary", True)),
                    "Inode": int(row.get("Inode", 0) or 0),
                    "FileKey": row.get("FileKey", file_identity_key(file_path, int(row.get("Inode", 0) or 0))),
                    "FilePath": file_path,
                    "FileSizeKB": int(row.get("FileSizeKB", row.get("SizeKB", 0)) or 0),
                    "TotalPssKB": int(row.get("TotalPssKB", 0) or 0),
                    "TotalRssKB": int(row.get("TotalRssKB", 0) or 0),
                    "FilePssKB": int(row.get("FilePssKB", 0) or 0),
                    "FileRssKB": int(row.get("FileRssKB", 0) or 0),
                    "BssPssKB": int(row.get("BssPssKB", 0) or 0),
                    "BssRssKB": int(row.get("BssRssKB", 0) or 0),
                    "Segments": int(row.get("Segments", 0) or 0),
                }
            )
        return {"ProcessName": payload.get("ProcessName", ""), "Files": normalized}
    smaps_path = dir_path / "smaps"
    if not smaps_path.exists():
        raise DigsoError(f"No file report or smaps found in {dir_path}")
    info(f"No JSON report found, parsing {smaps_path}")
    analysis = analyze_file_mappings(parse_smaps(smaps_path))
    return {"ProcessName": "", "Files": analysis["Files"]}


def cmd_analyze_app_maps(args: argparse.Namespace) -> int:
    process_name = ""
    if args.target_pid is not None:
        client = HdcClient(args.hdc, args.device)
        process_name = client.get_process_name(args.target_pid)
    if args.output_dir:
        output_dir = Path(args.output_dir)
    elif args.target_pid is not None:
        output_dir = Path.cwd() / f"proc_{process_name}_{args.target_pid}_{now_stamp()}"
    elif args.source_dir:
        output_dir = Path(args.source_dir)
    else:
        output_dir = Path.cwd()
    input_dir = Path(args.source_dir) if args.source_dir else output_dir
    if args.target_pid is not None:
        save_proc_files(client, args.target_pid, output_dir)

    smaps_path = input_dir / "smaps"
    rollup_path = input_dir / "smaps_rollup"
    if not smaps_path.exists() or not rollup_path.exists():
        raise DigsoError(f"Required file not found in {input_dir}")

    ensure_dir(output_dir)
    info(f"Parsing {smaps_path}")
    analysis = analyze_file_mappings(parse_smaps(smaps_path))
    rollup = parse_rollup(rollup_path)
    report_name = f"file_memory_{process_name}_{now_stamp()}" if process_name else f"file_memory_{now_stamp()}"
    csv_path = output_dir / f"{report_name}.csv"
    json_path = output_dir / f"{report_name}.json"
    write_csv(csv_path, analysis["Files"])
    report = {"SourceDir": str(input_dir), "ProcessName": process_name, "Rollup": rollup, "Summary": analysis["Summary"], "Files": analysis["Files"]}
    write_json(json_path, report)

    print_kv(
        "File memory summary",
        [
            ("Process total RSS", f"{rollup.get('Rss', 0)} kB"),
            ("Process total PSS", f"{rollup.get('Pss', 0)} kB"),
            ("Tracked files", analysis["Summary"]["FileCount"]),
            ("Tracked libraries", analysis["Summary"]["LibraryCount"]),
            ("File-backed RSS", f"{analysis['Summary']['FileRssKB']} kB"),
            ("File-backed PSS", f"{analysis['Summary']['FilePssKB']} kB"),
            ("Bss RSS", f"{analysis['Summary']['BssRssKB']} kB"),
            ("Bss PSS", f"{analysis['Summary']['BssPssKB']} kB"),
            ("Tracked total RSS", f"{analysis['Summary']['TotalRssKB']} kB"),
            ("Tracked total PSS", f"{analysis['Summary']['TotalPssKB']} kB"),
            ("CSV report", csv_path),
            ("JSON report", json_path),
        ],
    )
    for row in analysis["Files"][:30]:
        print(f"{row['FileName']}\t{row['FileType']}\tlib={row['IsLibrary']}\tTotalPssKB={row['TotalPssKB']}\tTotalRssKB={row['TotalRssKB']}\t{row['FilePath']}")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def cmd_analyze_app_shared_file_usage(args: argparse.Namespace) -> int:
    client = HdcClient(args.hdc, args.device)
    run_timestamp = now_stamp()
    process_name = client.get_process_name(args.target_pid)
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd() / f"shared_file_usage_{process_name}_{args.target_pid}_{run_timestamp}"
    raw_dir = ensure_dir(output_dir / "raw")
    smaps_dir = ensure_dir(output_dir / "proc_smaps")

    target_smaps_path = raw_dir / "target_smaps.txt"
    info(f"Capturing target smaps for pid {args.target_pid}")
    save_proc_smaps(client, args.target_pid, target_smaps_path, "shared_usage_smaps")
    target_files = group_file_mappings(parse_smaps(target_smaps_path))
    if not target_files:
        raise DigsoError(f"No file-backed mappings found for pid {args.target_pid}")

    interesting_files = {row["FileKey"]: row for row in target_files}
    path_to_key = {row["FilePath"]: row["FileKey"] for row in target_files}
    inode_to_key = {str(row["Inode"]): row["FileKey"] for row in target_files if row["Inode"] > 0}

    lsof_path = raw_dir / "lsof.txt"
    info("Capturing system lsof")
    write_text(lsof_path, client.shell("lsof"))
    matched_lsof_rows = [row for row in parse_lsof_output(lsof_path) if (row["Node"] > 0 and str(row["Node"]) in inode_to_key) or row["Name"] in path_to_key]

    process_map = {row["ProcessId"]: {"ProcessId": row["ProcessId"], "ProcessName": row["Command"], "User": row["User"]} for row in matched_lsof_rows}
    process_map.setdefault(args.target_pid, {"ProcessId": args.target_pid, "ProcessName": process_name, "User": ""})

    usage_rows = []
    for proc in sorted(process_map.values(), key=lambda row: row["ProcessId"]):
        proc_smaps_path = smaps_dir / f"smaps_{proc['ProcessId']}_{safe_name(proc['ProcessName'])}.txt"
        try:
            info(f"Capturing smaps for pid {proc['ProcessId']} ({proc['ProcessName']})")
            save_proc_smaps(client, proc["ProcessId"], proc_smaps_path, "shared_usage_peer_smaps")
            proc_usage = {row["FileKey"]: row for row in group_file_mappings(parse_smaps(proc_smaps_path)) if row["FileKey"] in interesting_files}
            for file_key, file_usage in proc_usage.items():
                target_file = interesting_files[file_key]
                usage_rows.append(
                    {
                        "FileKey": file_key,
                        "Inode": target_file["Inode"],
                        "FilePath": target_file["FilePath"],
                        "FileName": target_file["FileName"],
                        "FileType": target_file["FileType"],
                        "FileSizeKB": target_file["SizeKB"],
                        "TargetProcessPssKB": target_file["PssKB"],
                        "TargetProcessRssKB": target_file["RssKB"],
                        "ProcessId": proc["ProcessId"],
                        "ProcessName": proc["ProcessName"],
                        "User": proc["User"],
                        "ProcessPssKB": file_usage["PssKB"],
                        "ProcessRssKB": file_usage["RssKB"],
                        "SharedKB": file_usage["SharedKB"],
                        "PrivateKB": file_usage["PrivateKB"],
                        "IsTargetProcess": proc["ProcessId"] == args.target_pid,
                    }
                )
        except DigsoError as exc:
            print(f"[warn] Failed to analyze pid {proc['ProcessId']}: {exc}")

    file_groups: dict[str, list[dict]] = defaultdict(list)
    process_groups: dict[int, list[dict]] = defaultdict(list)
    for row in usage_rows:
        file_groups[row["FileKey"]].append(row)
        process_groups[row["ProcessId"]].append(row)

    summary_rows = []
    for rows in file_groups.values():
        first = rows[0]
        summary_rows.append(
            {
                "FileKey": first["FileKey"],
                "Inode": first["Inode"],
                "FilePath": first["FilePath"],
                "FileName": first["FileName"],
                "FileType": first["FileType"],
                "FileSizeKB": first["FileSizeKB"],
                "TargetProcessPssKB": first["TargetProcessPssKB"],
                "TargetProcessRssKB": first["TargetProcessRssKB"],
                "SystemTotalPssKB": sum(row["ProcessPssKB"] for row in rows),
                "SystemTotalRssKB": sum(row["ProcessRssKB"] for row in rows),
                "ProcessCount": len({row["ProcessId"] for row in rows}),
                "TopProcesses": "; ".join(f"{row['ProcessName']}:{row['ProcessPssKB']}kB" for row in sorted(rows, key=lambda item: (-item["ProcessPssKB"], -item["ProcessRssKB"]))[:5]),
            }
        )
    summary_rows.sort(key=lambda row: (-row["SystemTotalPssKB"], -row["TargetProcessPssKB"], row["FilePath"]))

    process_summary_rows = []
    for rows in process_groups.values():
        first = rows[0]
        process_summary_rows.append(
            {
                "ProcessId": first["ProcessId"],
                "ProcessName": first["ProcessName"],
                "User": first["User"],
                "SharedFileCount": len({row["FileKey"] for row in rows}),
                "TotalPssKB": sum(row["ProcessPssKB"] for row in rows),
                "TotalRssKB": sum(row["ProcessRssKB"] for row in rows),
                "IsTargetProcess": first["IsTargetProcess"],
            }
        )
    process_summary_rows.sort(key=lambda row: (-row["TotalPssKB"], -row["TotalRssKB"], row["ProcessId"]))

    base_name = f"shared_file_usage_{safe_name(process_name)}_{args.target_pid}_{run_timestamp}"
    detail_csv = output_dir / f"{base_name}.details.csv"
    file_csv = output_dir / f"{base_name}.files.csv"
    proc_csv = output_dir / f"{base_name}.processes.csv"
    json_path = output_dir / f"{base_name}.json"
    write_csv(detail_csv, sorted(usage_rows, key=lambda row: (-row["ProcessPssKB"], -row["ProcessRssKB"], row["FilePath"], row["ProcessId"])))
    write_csv(file_csv, summary_rows)
    write_csv(proc_csv, process_summary_rows)
    report = {"TargetProcessName": process_name, "TargetProcessId": args.target_pid, "OutputDir": str(output_dir), "TargetFileCount": len(target_files), "RelatedProcessCount": len(process_summary_rows), "Files": summary_rows, "Processes": process_summary_rows, "Details": usage_rows}
    write_json(json_path, report)

    print_kv(
        "Shared file usage summary",
        [
            ("Target process", f"{process_name} ({args.target_pid})"),
            ("Target file count", len(target_files)),
            ("Related processes", len(process_summary_rows)),
            ("Detail CSV", detail_csv),
            ("File summary CSV", file_csv),
            ("Proc summary CSV", proc_csv),
            ("JSON report", json_path),
        ],
    )
    for row in summary_rows[:20]:
        print(f"{row['FileName']}\t{row['FileType']}\tFileSizeKB={row['FileSizeKB']}\tSystemTotalPssKB={row['SystemTotalPssKB']}\tTargetProcessPssKB={row['TargetProcessPssKB']}\t{row['FilePath']}")
    return 0


def cmd_analyze_process_list_shared_files(args: argparse.Namespace) -> int:
    client = HdcClient(args.hdc, args.device)
    process_list_file = Path(args.process_list_file).resolve()
    requested_names = parse_process_list_file(process_list_file)
    if not requested_names:
        raise DigsoError(f"No process names found in {process_list_file}")

    output_label = safe_name(process_list_file.stem)
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd() / f"process_list_shared_files_{output_label}_{now_stamp()}"
    raw_dir = ensure_dir(output_dir / "raw")
    target_maps_dir = ensure_dir(output_dir / "target_maps")
    target_smaps_dir = ensure_dir(output_dir / "target_smaps")
    related_smaps_dir = ensure_dir(output_dir / "related_smaps")

    info("Capturing ps -ef")
    ps_output = client.shell("ps -ef")
    write_text(raw_dir / "ps_ef.txt", ps_output)
    target_processes = resolve_target_processes(requested_names, parse_ps_rows(ps_output))
    if not target_processes:
        raise DigsoError(f"No target processes matched from {process_list_file}")

    target_file_map: dict[str, dict] = {}
    target_path_to_key: dict[str, str] = {}
    target_inode_to_key: dict[str, str] = {}
    target_process_file_rows: list[dict] = []

    for proc in target_processes:
        safe_proc = safe_name(proc["ProcessName"])
        maps_path = target_maps_dir / f"maps_{proc['ProcessId']}_{safe_proc}.txt"
        smaps_path = target_smaps_dir / f"smaps_{proc['ProcessId']}_{safe_proc}.txt"
        info(f"Capturing maps for target pid {proc['ProcessId']} ({proc['ProcessName']})")
        save_proc_maps(client, proc["ProcessId"], maps_path, "proc_list_maps")
        info(f"Capturing smaps for target pid {proc['ProcessId']} ({proc['ProcessName']})")
        save_proc_smaps(client, proc["ProcessId"], smaps_path, "proc_list_smaps")

        for entry in parse_maps(maps_path):
            if not is_interesting_file_path(entry["path"]):
                continue
            key = file_identity_key(entry["path"], entry["inode"])
            target_file_map.setdefault(
                key,
                {
                    "FileKey": key,
                    "Inode": entry["inode"],
                    "FilePath": entry["path"],
                    "FileName": os.path.basename(entry["path"]),
                    "FileType": file_type(entry["path"]),
                    "IsLibrary": is_library_file_path(entry["path"]),
                    "SourceCategory": file_source_category(entry["path"]),
                },
            )
            target_path_to_key[entry["path"]] = key
            if entry["inode"] > 0:
                target_inode_to_key[str(entry["inode"])] = key

        usage_map = {row["FileKey"]: row for row in group_file_mappings(parse_smaps(smaps_path))}
        for file_key, usage in usage_map.items():
            target_process_file_rows.append(
                {
                    "TargetProcessId": proc["ProcessId"],
                    "TargetProcessName": proc["ProcessName"],
                    "FileKey": file_key,
                    "Inode": usage["Inode"],
                    "FilePath": usage["FilePath"],
                    "FileName": usage["FileName"],
                    "FileType": file_type(usage["FilePath"]),
                    "IsLibrary": is_library_file_path(usage["FilePath"]),
                    "SourceCategory": file_source_category(usage["FilePath"]),
                    "FileSizeKB": usage["SizeKB"],
                    "TargetProcessPssKB": usage["PssKB"],
                    "TargetProcessRssKB": usage["RssKB"],
                }
            )

    if not target_file_map:
        raise DigsoError("No file-backed mappings found in target processes")

    info("Capturing lsof")
    lsof_path = raw_dir / "lsof.txt"
    write_text(lsof_path, client.shell("lsof"))
    matched_lsof = [row for row in parse_lsof_output(lsof_path) if (row["Node"] > 0 and str(row["Node"]) in target_inode_to_key) or row["Name"] in target_path_to_key]

    related_process_map = {row["ProcessId"]: {"ProcessId": row["ProcessId"], "ProcessName": row["Command"], "User": row["User"]} for row in matched_lsof}
    for proc in target_processes:
        related_process_map.setdefault(proc["ProcessId"], {"ProcessId": proc["ProcessId"], "ProcessName": proc["ProcessName"], "User": proc["Uid"]})

    target_pids = {proc["ProcessId"] for proc in target_processes}
    detail_rows = []
    related_process_summary_rows = []
    for proc in sorted(related_process_map.values(), key=lambda row: row["ProcessId"]):
        safe_proc = safe_name(proc["ProcessName"])
        smaps_path = related_smaps_dir / f"smaps_{proc['ProcessId']}_{safe_proc}.txt"
        try:
            info(f"Capturing smaps for related pid {proc['ProcessId']} ({proc['ProcessName']})")
            save_proc_smaps(client, proc["ProcessId"], smaps_path, "proc_list_related_smaps")
            usage_map = {row["FileKey"]: row for row in group_file_mappings(parse_smaps(smaps_path))}
            proc_total_pss = 0
            proc_total_rss = 0
            shared_file_count = 0
            for file_key, usage in usage_map.items():
                if file_key not in target_file_map:
                    continue
                proc_total_pss += usage["PssKB"]
                proc_total_rss += usage["RssKB"]
                shared_file_count += 1
                detail_rows.append(
                    {
                        "FileKey": file_key,
                        "Inode": usage["Inode"],
                        "FilePath": usage["FilePath"],
                        "FileName": usage["FileName"],
                        "FileType": file_type(usage["FilePath"]),
                        "IsLibrary": target_file_map[file_key]["IsLibrary"],
                        "SourceCategory": target_file_map[file_key]["SourceCategory"],
                        "FileSizeKB": usage["SizeKB"],
                        "ProcessId": proc["ProcessId"],
                        "ProcessName": proc["ProcessName"],
                        "User": proc["User"],
                        "ProcessPssKB": usage["PssKB"],
                        "ProcessRssKB": usage["RssKB"],
                        "SharedKB": usage["SharedKB"],
                        "PrivateKB": usage["PrivateKB"],
                        "IsRequestedProcess": proc["ProcessId"] in target_pids,
                    }
                )
            related_process_summary_rows.append(
                {
                    "ProcessId": proc["ProcessId"],
                    "ProcessName": proc["ProcessName"],
                    "User": proc["User"],
                    "SharedFileCount": shared_file_count,
                    "TotalPssKB": proc_total_pss,
                    "TotalRssKB": proc_total_rss,
                    "IsRequestedProcess": proc["ProcessId"] in target_pids,
                }
            )
        except DigsoError as exc:
            print(f"[warn] Failed to analyze related pid {proc['ProcessId']}: {exc}")

    detail_groups: dict[str, list[dict]] = defaultdict(list)
    for row in detail_rows:
        detail_groups[row["FileKey"]].append(row)

    file_summary_rows = []
    for rows in detail_groups.values():
        first = rows[0]
        system_total_pss = sum(row["ProcessPssKB"] for row in rows)
        system_total_rss = sum(row["ProcessRssKB"] for row in rows)
        for row in rows:
            row["SystemTotalPssKB"] = system_total_pss
            row["SystemTotalRssKB"] = system_total_rss
            row["PssRatio"] = round(row["ProcessPssKB"] / system_total_pss, 6) if system_total_pss else 0
            row["RssRatio"] = round(row["ProcessRssKB"] / system_total_rss, 6) if system_total_rss else 0
        file_summary_rows.append(
            {
                "FileKey": first["FileKey"],
                "Inode": first["Inode"],
                "FilePath": first["FilePath"],
                "FileName": first["FileName"],
                "FileType": first["FileType"],
                "IsLibrary": first["IsLibrary"],
                "SourceCategory": first["SourceCategory"],
                "FileSizeKB": first["FileSizeKB"],
                "SystemTotalPssKB": system_total_pss,
                "SystemTotalRssKB": system_total_rss,
                "ProcessCount": len({row["ProcessId"] for row in rows}),
                "RequestedProcessCount": len({row["ProcessId"] for row in rows if row["IsRequestedProcess"]}),
                "TopProcessesByPss": "; ".join(f"{row['ProcessName']}:{row['ProcessPssKB']}kB({row['PssRatio']:.2%})" for row in sorted(rows, key=lambda item: (-item["ProcessPssKB"], -item["ProcessRssKB"]))[:5]),
            }
        )

    file_summary_rows.sort(key=lambda row: (-row["SystemTotalPssKB"], -row["ProcessCount"], row["Inode"], row["FilePath"]))
    related_process_summary_rows.sort(key=lambda row: (-row["TotalPssKB"], -row["SharedFileCount"], row["ProcessId"]))
    target_process_file_rows.sort(key=lambda row: (-row["TargetProcessPssKB"], row["Inode"], row["FilePath"], row["TargetProcessId"]))
    detail_rows.sort(key=lambda row: (-row["SystemTotalPssKB"], -row["ProcessPssKB"], row["Inode"], row["FilePath"], row["ProcessId"]))

    base_name = f"process_list_shared_files_{output_label}_{now_stamp()}"
    requested_csv = output_dir / f"{base_name}.requested_processes.csv"
    target_files_csv = output_dir / f"{base_name}.target_process_files.csv"
    file_summary_csv = output_dir / f"{base_name}.file_summary.csv"
    process_summary_csv = output_dir / f"{base_name}.process_summary.csv"
    detail_csv = output_dir / f"{base_name}.detail.csv"
    json_path = output_dir / f"{base_name}.json"
    write_csv(requested_csv, target_processes)
    write_csv(target_files_csv, target_process_file_rows)
    write_csv(file_summary_csv, file_summary_rows)
    write_csv(process_summary_csv, related_process_summary_rows)
    write_csv(detail_csv, detail_rows)
    report = {"ProcessListFile": str(process_list_file), "RequestedProcessNames": requested_names, "RequestedProcesses": target_processes, "TargetFileCount": len(target_file_map), "RelatedProcessCount": len(related_process_summary_rows), "FileSummary": file_summary_rows, "ProcessSummary": related_process_summary_rows, "Detail": detail_rows}
    write_json(json_path, report)

    print_kv(
        "Process-list shared file summary",
        [
            ("Process list file", process_list_file),
            ("Requested procs", len(target_processes)),
            ("Target file count", len(target_file_map)),
            ("Related proc count", len(related_process_summary_rows)),
            ("Requested CSV", requested_csv),
            ("Target files CSV", target_files_csv),
            ("File summary CSV", file_summary_csv),
            ("Process summary CSV", process_summary_csv),
            ("Detail CSV", detail_csv),
            ("JSON report", json_path),
        ],
    )
    for row in file_summary_rows[:20]:
        print(f"{row['FileName']}\t{row['SourceCategory']}\t{row['FileType']}\tlib={row['IsLibrary']}\tSystemTotalPssKB={row['SystemTotalPssKB']}\tProcessCount={row['ProcessCount']}\t{row['FilePath']}")
    return 0


def compare_file_rows(before_rows: list[dict], after_rows: list[dict]) -> list[dict]:
    before_map = {file_identity_key(row.get("FilePath", ""), int(row.get("Inode", 0) or 0)): row for row in before_rows}
    after_map = {file_identity_key(row.get("FilePath", ""), int(row.get("Inode", 0) or 0)): row for row in after_rows}
    rows = []
    for key in sorted(set(before_map) | set(after_map)):
        before = before_map.get(key)
        after = after_map.get(key)
        before_pss = int(before.get("TotalPssKB", 0) if before else 0)
        after_pss = int(after.get("TotalPssKB", 0) if after else 0)
        before_rss = int(before.get("TotalRssKB", 0) if before else 0)
        after_rss = int(after.get("TotalRssKB", 0) if after else 0)
        before_size = int(before.get("FileSizeKB", 0) if before else 0)
        after_size = int(after.get("FileSizeKB", 0) if after else 0)
        path = after.get("FilePath", "") if after else before.get("FilePath", "")
        pivot = after or before
        rows.append(
            {
                "FileName": pivot.get("FileName") or os.path.basename(path),
                "FileType": pivot.get("FileType") or file_type(path),
                "IsLibrary": bool(pivot.get("IsLibrary", True)),
                "Inode": int(pivot.get("Inode", 0) or 0),
                "FileKey": key,
                "FilePath": path,
                "BeforeFileSizeKB": before_size,
                "AfterFileSizeKB": after_size,
                "BeforePssKB": before_pss,
                "AfterPssKB": after_pss,
                "DeltaPssKB": after_pss - before_pss,
                "BeforeRssKB": before_rss,
                "AfterRssKB": after_rss,
                "DeltaRssKB": after_rss - before_rss,
                "BeforeExists": before is not None,
                "AfterExists": after is not None,
                "ChangeType": "changed" if before and after else ("added" if after else "removed"),
            }
        )
    rows.sort(key=lambda row: (-row["DeltaPssKB"], -row["DeltaRssKB"], row["FilePath"]))
    return rows


def cmd_compare_so_snapshots(args: argparse.Namespace) -> int:
    before_dir = Path(args.before_dir).resolve()
    after_dir = Path(args.after_dir).resolve()
    before_meta = snapshot_meta_from_dir(before_dir)
    after_meta = snapshot_meta_from_dir(after_dir)
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path.cwd() / f"compare_files_{safe_name(before_meta['ProcessName'] or 'unknown')}_{before_meta['Pid'] or 'unknown'}_{before_meta['Timestamp'] or 'before'}_vs_{after_meta['Timestamp'] or 'after'}"
    ensure_dir(output_dir)

    before_snapshot = rows_from_snapshot_dir(before_dir)
    after_snapshot = rows_from_snapshot_dir(after_dir)
    effective_before_name = before_snapshot["ProcessName"] or before_meta["ProcessName"]
    effective_after_name = after_snapshot["ProcessName"] or after_meta["ProcessName"]
    if before_meta["Pid"] > 0 and after_meta["Pid"] > 0 and before_meta["Pid"] != after_meta["Pid"]:
        raise DigsoError(f"PID mismatch: {before_meta['Pid']} vs {after_meta['Pid']}")
    if effective_before_name and effective_after_name and effective_before_name != effective_after_name:
        raise DigsoError(f"Process name mismatch: {effective_before_name} vs {effective_after_name}")

    diff_rows = compare_file_rows(before_snapshot["Files"], after_snapshot["Files"])
    summary = {
        "ProcessName": effective_after_name or effective_before_name,
        "ProcessId": after_meta["Pid"] or before_meta["Pid"],
        "BeforeDir": str(before_dir),
        "AfterDir": str(after_dir),
        "BeforeTimestamp": before_meta["Timestamp"],
        "AfterTimestamp": after_meta["Timestamp"],
        "AddedFiles": sum(1 for row in diff_rows if row["ChangeType"] == "added"),
        "RemovedFiles": sum(1 for row in diff_rows if row["ChangeType"] == "removed"),
        "ChangedFiles": sum(1 for row in diff_rows if row["ChangeType"] == "changed" and row["DeltaPssKB"] != 0),
        "BeforeTotalPssKB": sum(row["BeforePssKB"] for row in diff_rows),
        "AfterTotalPssKB": sum(row["AfterPssKB"] for row in diff_rows),
        "DeltaTotalPssKB": sum(row["DeltaPssKB"] for row in diff_rows),
        "BeforeTotalRssKB": sum(row["BeforeRssKB"] for row in diff_rows),
        "AfterTotalRssKB": sum(row["AfterRssKB"] for row in diff_rows),
        "DeltaTotalRssKB": sum(row["DeltaRssKB"] for row in diff_rows),
    }
    report_base = f"compare_files_{safe_name(summary['ProcessName'] or 'unknown')}_{summary['ProcessId'] or 'unknown'}_{summary['BeforeTimestamp'] or 'before'}_vs_{summary['AfterTimestamp'] or 'after'}"
    csv_path = output_dir / f"{report_base}.csv"
    json_path = output_dir / f"{report_base}.json"
    write_csv(csv_path, diff_rows)
    report = {"Summary": summary, "Diffs": diff_rows}
    write_json(json_path, report)

    print_kv(
        "File memory diff summary",
        [
            ("Process name", summary["ProcessName"]),
            ("PID", summary["ProcessId"]),
            ("Before total PSS", f"{summary['BeforeTotalPssKB']} kB"),
            ("After total PSS", f"{summary['AfterTotalPssKB']} kB"),
            ("Delta total PSS", f"{summary['DeltaTotalPssKB']} kB"),
            ("Before total RSS", f"{summary['BeforeTotalRssKB']} kB"),
            ("After total RSS", f"{summary['AfterTotalRssKB']} kB"),
            ("Delta total RSS", f"{summary['DeltaTotalRssKB']} kB"),
            ("CSV report", csv_path),
            ("JSON report", json_path),
        ],
    )
    print("Top PSS increases")
    for row in [item for item in diff_rows if item["DeltaPssKB"] > 0][:20]:
        print(f"{row['FileName']}\tDeltaPssKB={row['DeltaPssKB']}\tAfterPssKB={row['AfterPssKB']}\t{row['FilePath']}")
    print()
    print("Top PSS decreases")
    for row in sorted([item for item in diff_rows if item["DeltaPssKB"] < 0], key=lambda item: item["DeltaPssKB"])[:20]:
        print(f"{row['FileName']}\tDeltaPssKB={row['DeltaPssKB']}\tBeforePssKB={row['BeforePssKB']}\t{row['FilePath']}")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def cmd_list_zero_delta_filepss(args: argparse.Namespace) -> int:
    compare_dir = Path(args.compare_dir).resolve()
    memory_dir = Path(args.memory_dir).resolve()
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd() / f"zero_delta_filepss_{safe_name(compare_dir.name)}_vs_{safe_name(memory_dir.name)}_{now_stamp()}"
    ensure_dir(output_dir)

    compare_json = latest_file(compare_dir, "compare_so_*.json") or latest_file(compare_dir, "compare_files_*.json")
    if compare_json is None:
        raise DigsoError(f"No compare_so_*.json or compare_files_*.json found in {compare_dir}")
    info(f"Using compare JSON: {compare_json}")
    compare_data = json.loads(read_text(compare_json))

    memory_json = latest_file(memory_dir, "library_memory_*.json") or latest_file(memory_dir, "file_memory_*.json")
    if memory_json is None:
        raise DigsoError(f"No library_memory_*.json or file_memory_*.json found in {memory_dir}")
    info(f"Using memory JSON: {memory_json}")
    memory_data = json.loads(read_text(memory_json))
    memory_rows = memory_data.get("Libraries", memory_data.get("Files", []))
    memory_map = {file_identity_key(str(row.get("FilePath", "")), int(row.get("Inode", 0) or 0)): row for row in memory_rows}

    rows = []
    for diff in compare_data.get("Diffs", []):
        if int(diff.get("DeltaPssKB", 0) or 0) != 0:
            continue
        file_path = str(diff.get("FilePath", ""))
        inode = int(diff.get("Inode", 0) or 0)
        file_key = file_identity_key(file_path, inode)
        memory_row = memory_map.get(file_key)
        rows.append(
            {
                "Library": diff.get("Library") or diff.get("FileName") or os.path.basename(file_path),
                "Inode": inode,
                "FileKey": file_key,
                "FilePath": file_path,
                "DeltaPssKB": int(diff.get("DeltaPssKB", 0) or 0),
                "BeforePssKB": int(diff.get("BeforePssKB", 0) or 0),
                "AfterPssKB": int(diff.get("AfterPssKB", 0) or 0),
                "ChangeType": str(diff.get("ChangeType", "")),
                "FilePssKB": None if memory_row is None else int(memory_row.get("FilePssKB", 0) or 0),
                "FileRssKB": None if memory_row is None else int(memory_row.get("FileRssKB", 0) or 0),
                "TotalPssKB": None if memory_row is None else int(memory_row.get("TotalPssKB", 0) or 0),
                "TotalRssKB": None if memory_row is None else int(memory_row.get("TotalRssKB", 0) or 0),
                "BssPssKB": None if memory_row is None else int(memory_row.get("BssPssKB", 0) or 0),
                "FoundInMemoryDir": memory_row is not None,
            }
        )
    rows.sort(key=lambda row: (-(row["FilePssKB"] if row["FilePssKB"] is not None else -1), row["Library"]))

    base_name = f"zero_delta_filepss_{safe_name(compare_dir.name)}_{now_stamp()}"
    csv_path = output_dir / f"{base_name}.csv"
    json_path = output_dir / f"{base_name}.json"
    write_csv(csv_path, rows)
    report = {"CompareDir": str(compare_dir), "MemoryDir": str(memory_dir), "CompareSourceFile": str(compare_json), "MemorySourceFile": str(memory_json), "ProcessName": memory_data.get("ProcessName", ""), "ZeroDeltaLibraryCount": len(rows), "FoundInMemoryDirCount": sum(1 for row in rows if row["FoundInMemoryDir"]), "Rows": rows}
    write_json(json_path, report)

    print_kv(
        "Zero-delta library lookup summary",
        [
            ("Compare dir", compare_dir),
            ("Memory dir", memory_dir),
            ("Zero-delta count", len(rows)),
            ("Matched count", report["FoundInMemoryDirCount"]),
            ("CSV report", csv_path),
            ("JSON report", json_path),
        ],
    )
    for row in rows[:50]:
        print(f"{row['Library']}\tFilePssKB={row['FilePssKB']}\tFileRssKB={row['FileRssKB']}\tTotalPssKB={row['TotalPssKB']}\tFound={row['FoundInMemoryDir']}\t{row['FilePath']}")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def get_process_info_for_swapout(client: HdcClient, pid: int) -> dict:
    output = client.shell(f"ps -ef | grep {pid}")
    for line in split_lines(output):
        if not line.strip() or re.search(rf"\bgrep\s+{pid}\b", line):
            continue
        match = re.match(rf"^\s*(\S+)\s+{pid}\s+", line)
        if not match:
            continue
        parts = [part for part in re.split(r"\s+", line.strip()) if part]
        if len(parts) >= 8:
            return {"Uid": parts[0], "Pid": int(parts[1]), "ProcessName": parts[-1]}
    raise DigsoError(f"Failed to find process info for pid {pid} from ps output")


def cmd_force_swapout_memcg(args: argparse.Namespace) -> int:
    client = HdcClient(args.hdc, args.device)
    proc = get_process_info_for_swapout(client, args.target_pid)
    memcg_dir = f"/dev/memcg/100/{proc['ProcessName']}_{proc['Uid']}"
    print_kv("Force swapout target", [("PID", proc["Pid"]), ("Process name", proc["ProcessName"]), ("UID", proc["Uid"]), ("Package dir", memcg_dir)])
    commands = [
        f"echo 100 100 50 > {memcg_dir}/memory.zswapd_single_memcg_param",
        f"echo 99 > {memcg_dir}/memory.force_shrink_all",
        f"echo 0 > {memcg_dir}/memory.force_swapout",
        f"echo 4 > /proc/{args.target_pid}/reclaim",
    ]
    for command in commands:
        info(command)
        client.shell(command)
    print("Done.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cross-platform digso tools for HarmonyOS memory analysis.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    common_capture = argparse.ArgumentParser(add_help=False)
    common_capture.add_argument("--hdc", default="hdc")
    common_capture.add_argument("--device")

    app_maps = subparsers.add_parser("analyze-app-maps", parents=[common_capture])
    source_group = app_maps.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--target-pid", type=int)
    source_group.add_argument("--source-dir")
    app_maps.add_argument("--output-dir")
    app_maps.add_argument("--keep-raw-files", action="store_true")
    app_maps.add_argument("--json", action="store_true")
    app_maps.set_defaults(func=cmd_analyze_app_maps)

    shared_usage = subparsers.add_parser("analyze-app-shared-file-usage", parents=[common_capture])
    shared_usage.add_argument("target_pid", type=int)
    shared_usage.add_argument("--output-dir")
    shared_usage.set_defaults(func=cmd_analyze_app_shared_file_usage)

    proc_list = subparsers.add_parser("analyze-process-list-shared-files", parents=[common_capture])
    proc_list.add_argument("process_list_file")
    proc_list.add_argument("--output-dir")
    proc_list.set_defaults(func=cmd_analyze_process_list_shared_files)

    compare = subparsers.add_parser("compare-so-snapshots")
    compare.add_argument("before_dir")
    compare.add_argument("after_dir")
    compare.add_argument("--output-dir")
    compare.add_argument("--json", action="store_true")
    compare.set_defaults(func=cmd_compare_so_snapshots)

    zero_delta = subparsers.add_parser("list-zero-delta-filepss")
    zero_delta.add_argument("compare_dir")
    zero_delta.add_argument("memory_dir")
    zero_delta.add_argument("--output-dir")
    zero_delta.add_argument("--json", action="store_true")
    zero_delta.set_defaults(func=cmd_list_zero_delta_filepss)

    swapout = subparsers.add_parser("force-swapout-memcg", parents=[common_capture])
    swapout.add_argument("target_pid", type=int)
    swapout.set_defaults(func=cmd_force_swapout_memcg)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DigsoError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[error] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
