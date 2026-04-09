#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
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


def default_output_root() -> Path:
    if os.name == "nt":
        return ensure_dir(Path("D:/digso_logs"))
    return ensure_dir(Path("/data/digso_logs"))


def default_elf_cache_root() -> Path:
    if os.name == "nt":
        return ensure_dir(Path("D:/digso_logs/elf_exports"))
    return ensure_dir(Path("/data/digso_logs/elf_exports"))


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


def read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def normalize_remote_device_path(path: str) -> str:
    return re.sub(r"/+", "/", path.strip())


def remote_path_to_local_export_path(remote_path: str, export_root: Path) -> Path:
    parts = [part for part in normalize_remote_device_path(remote_path).split("/") if part]
    safe_parts = [part.replace(":", "_") for part in parts]
    return export_root.joinpath(*safe_parts)


def remote_path_suffix_key(remote_path: str) -> str:
    return "/".join(part for part in normalize_remote_device_path(remote_path).split("/") if part)


def find_existing_exported_elf(remote_path: str, search_root: Path) -> Path | None:
    expected = remote_path_to_local_export_path(remote_path, search_root)
    if expected.exists():
        return expected

    basename = os.path.basename(remote_path)
    if not basename or not search_root.exists():
        return None

    suffix_key = remote_path_suffix_key(remote_path).lower()
    candidates = [path for path in search_root.rglob(basename) if path.is_file()]
    if not candidates:
        return None

    ranked = []
    for candidate in candidates:
        candidate_key = candidate.as_posix().lower()
        score = 0
        if candidate_key.endswith(suffix_key):
            score += 1000
        score += len(os.path.commonprefix([candidate_key, suffix_key]))
        ranked.append((score, len(candidate.parts), candidate))

    ranked.sort(key=lambda item: (-item[0], item[1], str(item[2])))
    return ranked[0][2]


def vaddr_to_file_offset(vaddr: int, load_segments: list[dict]) -> int | None:
    for segment in load_segments:
        start = segment["vaddr"]
        end = start + max(segment["filesz"], segment["memsz"])
        if start <= vaddr < end:
            return segment["offset"] + (vaddr - start)
    return None


def parse_elf_dynamic_info(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise DigsoError(f"Not an ELF file: {path}")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise DigsoError(f"Unsupported ELF class in {path}")
    if ei_data not in (1, 2):
        raise DigsoError(f"Unsupported ELF endian in {path}")

    endian = "<" if ei_data == 1 else ">"
    if ei_class == 1:
        header_fmt = endian + "16sHHIIIIIHHHHHH"
        ph_fmt = endian + "IIIIIIII"
        dyn_fmt = endian + "II"
        phoff_index = 5
        phentsize_index = 9
        phnum_index = 10
        pt_type_idx = 0
        pt_offset_idx = 1
        pt_vaddr_idx = 2
        pt_filesz_idx = 4
        pt_memsz_idx = 5
    else:
        header_fmt = endian + "16sHHIQQQIHHHHHH"
        ph_fmt = endian + "IIQQQQQQ"
        dyn_fmt = endian + "QQ"
        phoff_index = 5
        phentsize_index = 9
        phnum_index = 10
        pt_type_idx = 0
        pt_offset_idx = 2
        pt_vaddr_idx = 3
        pt_filesz_idx = 5
        pt_memsz_idx = 6

    header = struct.unpack_from(header_fmt, data, 0)
    phoff = header[phoff_index]
    phentsize = header[phentsize_index]
    phnum = header[phnum_index]

    load_segments = []
    dynamic_segment = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        ph = struct.unpack_from(ph_fmt, data, offset)
        segment = {
            "type": ph[pt_type_idx],
            "offset": ph[pt_offset_idx],
            "vaddr": ph[pt_vaddr_idx],
            "filesz": ph[pt_filesz_idx],
            "memsz": ph[pt_memsz_idx],
        }
        if segment["type"] == 1:
            load_segments.append(segment)
        elif segment["type"] == 2:
            dynamic_segment = segment

    if dynamic_segment is None:
        return {"Soname": "", "Needed": [], "ParseStatus": "no_dynamic_segment"}

    dyn_entry_size = struct.calcsize(dyn_fmt)
    dyn_entries = []
    dyn_offset = dynamic_segment["offset"]
    dyn_limit = dyn_offset + dynamic_segment["filesz"]
    while dyn_offset + dyn_entry_size <= dyn_limit:
        tag, value = struct.unpack_from(dyn_fmt, data, dyn_offset)
        dyn_entries.append((tag, value))
        dyn_offset += dyn_entry_size
        if tag == 0:
            break

    strtab_vaddr = next((value for tag, value in dyn_entries if tag == 5), None)
    strtab_size = next((value for tag, value in dyn_entries if tag == 10), 0)
    if strtab_vaddr is None:
        return {"Soname": "", "Needed": [], "ParseStatus": "missing_strtab"}

    strtab_offset = vaddr_to_file_offset(strtab_vaddr, load_segments)
    if strtab_offset is None:
        return {"Soname": "", "Needed": [], "ParseStatus": "unmapped_strtab"}

    strtab_blob = data[strtab_offset : strtab_offset + strtab_size]
    needed = [read_c_string(strtab_blob, value) for tag, value in dyn_entries if tag == 1]
    soname_offsets = [value for tag, value in dyn_entries if tag == 14]
    return {
        "Soname": read_c_string(strtab_blob, soname_offsets[0]) if soname_offsets else "",
        "Needed": [name for name in needed if name],
        "ParseStatus": "ok",
    }


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

    def get_process_exe(self, pid: int) -> str:
        try:
            return normalize_remote_device_path(self.shell(f"readlink -f /proc/{pid}/exe").strip())
        except DigsoError:
            return ""


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


def export_remote_elfs(client: HdcClient, remote_paths: list[str], export_root: Path) -> dict[str, dict]:
    ensure_dir(export_root)
    manifest: dict[str, dict] = {}
    for remote_path in sorted({normalize_remote_device_path(item) for item in remote_paths if item}):
        existing_local_path = find_existing_exported_elf(remote_path, export_root)
        if existing_local_path is not None:
            manifest[remote_path] = {
                "RemotePath": remote_path,
                "LocalPath": str(existing_local_path),
                "Exported": False,
                "ReusedLocal": True,
                "Error": "",
            }
            continue

        local_path = remote_path_to_local_export_path(remote_path, export_root)
        ensure_dir(local_path.parent)
        try:
            info(f"Exporting ELF: {remote_path}")
            client.recv(remote_path, local_path)
            manifest[remote_path] = {
                "RemotePath": remote_path,
                "LocalPath": str(local_path),
                "Exported": True,
                "ReusedLocal": False,
                "Error": "",
            }
        except DigsoError as exc:
            manifest[remote_path] = {
                "RemotePath": remote_path,
                "LocalPath": str(local_path),
                "Exported": False,
                "ReusedLocal": False,
                "Error": str(exc),
            }
    return manifest


def analyze_library_import_sources(files: list[dict], process_exe: str, export_root: Path, export_manifest: dict[str, dict] | None = None) -> dict:
    libraries = [row for row in files if row.get("IsLibrary") and row.get("FilePath")]
    loaded_paths = sorted({normalize_remote_device_path(row["FilePath"]) for row in libraries})
    parsed_map: dict[str, dict] = {}
    manifest = export_manifest or {}

    candidate_paths = list(loaded_paths)
    if process_exe:
        candidate_paths.append(normalize_remote_device_path(process_exe))

    for remote_path in sorted(set(candidate_paths)):
        local_path = find_existing_exported_elf(remote_path, export_root) or remote_path_to_local_export_path(remote_path, export_root)
        export_info = manifest.get(
            remote_path,
            {
                "Exported": False,
                "ReusedLocal": local_path.exists(),
                "Error": "",
                "LocalPath": str(local_path),
            },
        )
        parsed = {
            "RemotePath": remote_path,
            "LocalPath": str(local_path),
            "Exported": bool(export_info.get("Exported", local_path.exists())),
            "ReusedLocal": bool(export_info.get("ReusedLocal", local_path.exists())),
            "ParseStatus": "missing_local_copy",
            "Error": export_info.get("Error", ""),
            "Soname": "",
            "Needed": [],
        }
        if local_path.exists():
            try:
                elf_info = parse_elf_dynamic_info(local_path)
                parsed.update(elf_info)
            except Exception as exc:  # keep import analysis best-effort
                parsed["ParseStatus"] = "parse_failed"
                parsed["Error"] = str(exc)
        parsed_map[remote_path] = parsed

    by_basename: dict[str, set[str]] = defaultdict(set)
    by_soname: dict[str, set[str]] = defaultdict(set)
    for lib_path in loaded_paths:
        by_basename[os.path.basename(lib_path)].add(lib_path)
        soname = parsed_map.get(lib_path, {}).get("Soname", "")
        if soname:
            by_soname[soname].add(lib_path)

    edges = []
    incoming_by_target: dict[str, list[dict]] = defaultdict(list)
    outgoing_by_importer: dict[str, list[str]] = defaultdict(list)
    for importer_path in sorted(set(candidate_paths)):
        importer_info = parsed_map.get(importer_path)
        if not importer_info or importer_info.get("ParseStatus") != "ok":
            continue
        for needed_name in importer_info.get("Needed", []):
            matches = sorted(by_soname.get(needed_name, set()) | by_basename.get(needed_name, set()))
            for target_path in matches:
                edge = {
                    "ImporterPath": importer_path,
                    "ImporterType": "main_executable" if importer_path == process_exe else "library",
                    "TargetPath": target_path,
                    "NeededName": needed_name,
                }
                edges.append(edge)
                incoming_by_target[target_path].append(edge)
                outgoing_by_importer[importer_path].append(target_path)

    reachable_from_exe: set[str] = set()
    if process_exe and process_exe in parsed_map:
        queue = list(outgoing_by_importer.get(process_exe, []))
        while queue:
            current = queue.pop(0)
            if current in reachable_from_exe:
                continue
            reachable_from_exe.add(current)
            queue.extend(outgoing_by_importer.get(current, []))

    rows = []
    summary = defaultdict(int)
    for row in files:
        row.setdefault("ImportKind", "")
        row.setdefault("ImportedBy", "")
        row.setdefault("NeededNames", "")
        row.setdefault("ImportParseStatus", "")
        row.setdefault("ImportAnalysisNote", "")

    for lib_row in libraries:
        lib_path = normalize_remote_device_path(lib_row["FilePath"])
        parsed = parsed_map.get(lib_path, {})
        incoming = incoming_by_target.get(lib_path, [])
        importers = sorted({edge["ImporterPath"] for edge in incoming})
        needed_names = sorted({edge["NeededName"] for edge in incoming})
        if any(edge["ImporterPath"] == process_exe for edge in incoming):
            import_kind = "needed_by_executable"
        elif lib_path in reachable_from_exe:
            import_kind = "needed_by_library"
        elif incoming:
            import_kind = "needed_by_dlopen_library"
        elif parsed.get("ParseStatus") == "ok":
            import_kind = "dlopen_or_runtime"
        else:
            import_kind = "unknown"

        note = ""
        if parsed.get("ParseStatus") not in ("", "ok"):
            note = parsed.get("Error") or parsed.get("ParseStatus", "")

        lib_row["ImportKind"] = import_kind
        lib_row["ImportedBy"] = "; ".join(importers)
        lib_row["NeededNames"] = "; ".join(needed_names)
        lib_row["ImportParseStatus"] = parsed.get("ParseStatus", "")
        lib_row["ImportAnalysisNote"] = note
        summary[import_kind] += 1
        rows.append(
            {
                "FileName": lib_row["FileName"],
                "FilePath": lib_path,
                "Inode": lib_row["Inode"],
                "ImportKind": import_kind,
                "ImportedBy": lib_row["ImportedBy"],
                "NeededNames": lib_row["NeededNames"],
                "Soname": parsed.get("Soname", ""),
                "SelfNeeded": "; ".join(parsed.get("Needed", [])),
                "LocalPath": parsed.get("LocalPath", ""),
                "Exported": parsed.get("Exported", False),
                "ReusedLocal": parsed.get("ReusedLocal", False),
                "ParseStatus": parsed.get("ParseStatus", ""),
                "Note": note,
            }
        )

    return {
        "ProcessExe": process_exe,
        "ExportRoot": str(export_root),
        "Summary": dict(summary),
        "Libraries": rows,
        "Edges": edges,
        "Manifest": manifest,
    }


def mermaid_node_id(prefix: str, value: str, used_ids: set[str]) -> str:
    base = re.sub(r"[^0-9A-Za-z_]", "_", f"{prefix}_{value}")
    if not base:
        base = prefix
    candidate = base
    index = 2
    while candidate in used_ids:
        candidate = f"{base}_{index}"
        index += 1
    used_ids.add(candidate)
    return candidate


def mermaid_label_for_path(path: str) -> str:
    base = os.path.basename(path) or path or "unknown"
    return base.replace('"', "'")


def build_import_mermaid_flowchart(import_analysis: dict, process_name: str) -> str:
    edges = import_analysis.get("Edges", [])
    libraries = import_analysis.get("Libraries", [])
    process_exe = import_analysis.get("ProcessExe", "")
    used_ids: set[str] = set()
    path_to_node: dict[str, str] = {}
    lines = ["flowchart LR"]

    if process_exe:
        exe_node = mermaid_node_id("exe", process_exe, used_ids)
        path_to_node[process_exe] = exe_node
        exe_label = mermaid_label_for_path(process_exe)
        if process_name:
            exe_label = f"{process_name}\\n{exe_label}"
        lines.append(f'    {exe_node}["{exe_label}"]')

    for row in libraries:
        lib_path = row.get("FilePath", "")
        if not lib_path:
            continue
        node_id = mermaid_node_id("lib", lib_path, used_ids)
        path_to_node[lib_path] = node_id
        label = mermaid_label_for_path(lib_path)
        import_kind = row.get("ImportKind", "")
        if import_kind:
            label = f"{label}\\n({import_kind})"
        lines.append(f'    {node_id}["{label}"]')

    seen_edges: set[tuple[str, str, str]] = set()
    for edge in edges:
        importer = edge.get("ImporterPath", "")
        target = edge.get("TargetPath", "")
        needed_name = (edge.get("NeededName", "") or "").replace('"', "'")
        importer_id = path_to_node.get(importer)
        target_id = path_to_node.get(target)
        if not importer_id or not target_id:
            continue
        edge_key = (importer_id, target_id, needed_name)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        if needed_name:
            lines.append(f'    {importer_id} -->|"{needed_name}"| {target_id}')
        else:
            lines.append(f"    {importer_id} --> {target_id}")

    if len(lines) == 1:
        lines.append('    empty["No dependency edges found"]')

    return "\n".join(lines) + "\n"


def cmd_analyze_app_maps(args: argparse.Namespace) -> int:
    process_name = ""
    process_exe = ""
    import_analysis = None
    if args.target_pid is not None:
        client = HdcClient(args.hdc, args.device)
        process_name = client.get_process_name(args.target_pid)
        process_exe = client.get_process_exe(args.target_pid)
    if args.output_dir:
        output_dir = Path(args.output_dir)
    elif args.target_pid is not None:
        output_dir = default_output_root() / f"proc_{process_name}_{args.target_pid}_{now_stamp()}"
    elif args.source_dir:
        output_dir = default_output_root() / f"analyze_app_maps_{safe_name(Path(args.source_dir).name)}_{now_stamp()}"
    else:
        output_dir = default_output_root() / f"analyze_app_maps_{now_stamp()}"
    input_dir = Path(args.source_dir) if args.source_dir else output_dir
    if args.target_pid is not None:
        save_proc_files(client, args.target_pid, output_dir)
        write_json(
            output_dir / "process_info.json",
            {
                "ProcessName": process_name,
                "TargetPid": args.target_pid,
                "ProcessExe": process_exe,
            },
        )
    else:
        process_info_path = input_dir / "process_info.json"
        if process_info_path.exists():
            process_info = json.loads(read_text(process_info_path))
            process_name = process_info.get("ProcessName", process_name)
            process_exe = process_info.get("ProcessExe", "")

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

    if args.analyze_library_imports:
        export_root = Path(args.elf_dir) if args.elf_dir else default_elf_cache_root()
        ensure_dir(export_root)
        manifest = {}
        if args.target_pid is not None:
            remote_paths = [row["FilePath"] for row in analysis["Files"] if row.get("IsLibrary") and row.get("FilePath")]
            if process_exe:
                remote_paths.append(process_exe)
            manifest = export_remote_elfs(client, remote_paths, export_root)
            write_json(export_root / "manifest.json", {"Files": list(manifest.values())})
        else:
            manifest_path = export_root / "manifest.json"
            if manifest_path.exists():
                payload = json.loads(read_text(manifest_path))
                manifest = {item["RemotePath"]: item for item in payload.get("Files", []) if item.get("RemotePath")}
        import_analysis = analyze_library_import_sources(analysis["Files"], process_exe, export_root, manifest)
        import_csv_path = output_dir / f"{report_name}.imports.csv"
        import_json_path = output_dir / f"{report_name}.imports.json"
        import_mermaid_path = output_dir / f"{report_name}.imports.mmd"
        write_csv(import_csv_path, import_analysis["Libraries"])
        write_json(import_json_path, import_analysis)
        write_text(import_mermaid_path, build_import_mermaid_flowchart(import_analysis, process_name))

    write_csv(csv_path, analysis["Files"])
    report = {
        "SourceDir": str(input_dir),
        "ProcessName": process_name,
        "ProcessExe": process_exe,
        "Rollup": rollup,
        "Summary": analysis["Summary"],
        "Files": analysis["Files"],
    }
    if import_analysis is not None:
        report["ImportAnalysis"] = import_analysis
    write_json(json_path, report)

    summary_rows = [
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
        ("Import analysis", "enabled" if import_analysis is not None else "disabled"),
    ]
    if import_analysis is not None:
        summary_rows.append(("Import kinds", json.dumps(import_analysis["Summary"], ensure_ascii=False)))
        summary_rows.append(("ELF export root", import_analysis["ExportRoot"]))
        summary_rows.append(("Import CSV", import_csv_path))
        summary_rows.append(("Import JSON", import_json_path))
        summary_rows.append(("Import Mermaid", import_mermaid_path))
    print_kv("File memory summary", summary_rows)
    for row in analysis["Files"][:30]:
        print(f"{row['FileName']}\t{row['FileType']}\tlib={row['IsLibrary']}\tTotalPssKB={row['TotalPssKB']}\tTotalRssKB={row['TotalRssKB']}\t{row['FilePath']}")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def cmd_analyze_app_shared_file_usage(args: argparse.Namespace) -> int:
    client = HdcClient(args.hdc, args.device)
    run_timestamp = now_stamp()
    process_name = client.get_process_name(args.target_pid)
    output_dir = Path(args.output_dir) if args.output_dir else default_output_root() / f"shared_file_usage_{process_name}_{args.target_pid}_{run_timestamp}"
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
    output_dir = Path(args.output_dir) if args.output_dir else default_output_root() / f"process_list_shared_files_{output_label}_{now_stamp()}"
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
        output_dir = default_output_root() / f"compare_files_{safe_name(before_meta['ProcessName'] or 'unknown')}_{before_meta['Pid'] or 'unknown'}_{before_meta['Timestamp'] or 'before'}_vs_{after_meta['Timestamp'] or 'after'}"
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
    output_dir = Path(args.output_dir) if args.output_dir else default_output_root() / f"zero_delta_filepss_{safe_name(compare_dir.name)}_vs_{safe_name(memory_dir.name)}_{now_stamp()}"
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
    app_maps.add_argument("-I", "--analyze-imports", "--analyze-library-imports", dest="analyze_library_imports", action="store_true")
    app_maps.add_argument("--elf-dir")
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
