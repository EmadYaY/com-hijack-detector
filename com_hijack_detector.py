#!/usr/bin/env python3
"""
COM Hijack Detector & Analyzer
================================
MITRE ATT&CK: T1546.015 - Component Object Model Hijacking

Analyzes COM object registrations in the Windows Registry to identify
potential COM hijacking by comparing CLSIDs in HKCU vs HKLM.

Supports two modes:
  - live   : Scans the local machine registry directly (Windows only)
  - analyze: Parses a JSON export file produced by the PowerShell script
             for offline / cross-machine analysis

Author  : github.com/EmadYaY - COM Hijack Detector Project
Version : 1.0.1

Changelog v1.0.1:
  - FIX:     Phantom COM detection — HKCU-only CLSIDs without a DLL path
             are now flagged as LOW risk instead of silently skipped
  - FIX:     KNOWN_BENIGN_PREFIXES logic was inverted; AppData/Users paths
             are now correctly treated as SUSPICIOUS, not benign
  - FEATURE: SUSPICIOUS_PATHS — DLL paths in user-writable locations
             (AppData, ProgramData, Temp, Users) now raise risk level
  - FEATURE: CLSID Whitelist — known-legitimate CLSIDs are skipped to
             reduce false positives
  - FEATURE: Task Correlation — scans C:\\Windows\\System32\\Tasks for
             ComHandler tasks referencing HKCU CLSIDs (Windows only)
  - FEATURE: --no-low flag to suppress LOW risk findings
  - FEATURE: SuspiciousPath and TaskCorrelated columns in CSV/JSON output
"""

from __future__ import annotations

import sys
import os
import json
import csv
import argparse
import platform
import datetime
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set

# -- Rich for terminal output --------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# -- winreg (Windows only for live mode) --------------------------------------
if platform.system() == "Windows":
    import winreg
    WINDOWS = True
else:
    WINDOWS = False

# -----------------------------------------------------------------------------
# CONSTANTS
# -----------------------------------------------------------------------------

VERSION      = "1.0.1"
MITRE_ID     = "T1546.015"
CLSID_SUBKEY = r"SOFTWARE\Classes\CLSID"
TASKS_PATH   = r"C:\Windows\System32\Tasks"

RISK_HIGH    = "HIGH"
RISK_MEDIUM  = "MEDIUM"
RISK_LOW     = "LOW"
RISK_INFO    = "INFO"

STATUS_HIJACK  = "POSSIBLE COM HIJACK"
STATUS_HKCU    = "HKCU ONLY (No HKLM counterpart)"
STATUS_PHANTOM = "PHANTOM COM (HKCU key, no DLL)"
STATUS_SAME    = "MATCH"

# v1.0.1 FIX: These paths are SUSPICIOUS (user-writable), not benign
SUSPICIOUS_PATHS = [
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\",
    "%appdata%",
    "%localappdata%",
    "%temp%",
    "%programdata%",
]

# v1.0.1 FEATURE: Known-legitimate CLSID whitelist
# CLSIDs commonly registered in HKCU by legitimate software.
# Extend this list to reduce false positives in your environment.
CLSID_WHITELIST: Set[str] = {
    # Microsoft Office / Click-to-Run
    "{000C101C-0000-0000-C000-000000000046}",
    "{00020900-0000-0000-C000-000000000046}",
    # Windows Shell / Explorer
    "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
    "{289AF617-1CC3-42A6-926C-E6A863F0E3BA}",
    # OneDrive
    "{CDD7975E-60F8-41D5-8149-19E51A6DF6DB}",
    "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}",
    # Windows Search
    "{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}",
    # Google Chrome / Updater
    "{2F0E2680-9FF5-43C0-B76E-114A56E93598}",
    # Skype
    "{E08E69B8-37DA-11D2-8185-00104B2E7DBC}",
}


# -----------------------------------------------------------------------------
# CONSOLE SETUP
# -----------------------------------------------------------------------------

console = Console() if HAS_RICH else None


def cprint(msg: str, style: str = ""):
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def banner():
    if HAS_RICH:
        title = Text()
        title.append("  COM Hijack Detector  ", style="bold white")
        title.append(f"v{VERSION}", style="dim white")

        subtitle = Text()
        subtitle.append("  MITRE ATT&CK: ", style="dim")
        subtitle.append(MITRE_ID, style="bold yellow")
        subtitle.append("  -  Component Object Model Hijacking", style="dim")

        github = Text()
        github.append("  github.com/EmadYaY", style="dim cyan")

        console.print()
        console.print(Panel.fit(
            f"{title}\n{subtitle}\n{github}",
            border_style="cyan",
            padding=(0, 2),
        ))
        console.print()
    else:
        print("\n" + "=" * 60)
        print(f"  COM Hijack Detector  v{VERSION}")
        print(f"  MITRE ATT&CK: {MITRE_ID}")
        print("=" * 60 + "\n")


# -----------------------------------------------------------------------------
# DATA STRUCTURES
# -----------------------------------------------------------------------------

class CLSIDEntry:
    def __init__(self, clsid: str, dll_path: Optional[str], friendly_name: str = ""):
        self.clsid         = clsid
        self.dll_path      = dll_path
        self.friendly_name = friendly_name

    def __repr__(self):
        return f"CLSIDEntry(clsid={self.clsid!r}, dll={self.dll_path!r})"


class Finding:
    def __init__(
        self,
        clsid: str,
        friendly_name: str,
        hkcu_dll: Optional[str],
        hklm_dll: Optional[str],
        status: str,
        risk: str,
        notes: str = "",
        suspicious_path: bool = False,
        task_correlated: bool = False,
    ):
        self.clsid           = clsid
        self.friendly_name   = friendly_name
        self.hkcu_dll        = hkcu_dll
        self.hklm_dll        = hklm_dll
        self.status          = status
        self.risk            = risk
        self.notes           = notes
        self.suspicious_path = suspicious_path
        self.task_correlated = task_correlated

    def to_dict(self) -> dict:
        return {
            "clsid":           self.clsid,
            "friendly_name":   self.friendly_name,
            "hkcu_dll":        self.hkcu_dll or "",
            "hklm_dll":        self.hklm_dll or "",
            "status":          self.status,
            "risk":            self.risk,
            "notes":           self.notes,
            "suspicious_path": self.suspicious_path,
            "task_correlated": self.task_correlated,
        }


# -----------------------------------------------------------------------------
# v1.0.1 FEATURE: TASK CORRELATOR
# Scans C:\Windows\System32\Tasks for ComHandler tasks that reference
# CLSIDs present in HKCU — these are high-value persistence targets.
# -----------------------------------------------------------------------------

class TaskCorrelator:
    """
    Parses Windows Task Scheduler XML files and extracts ComHandler CLSIDs.
    Also detects LogonTrigger tasks — the most common COM hijack persistence
    mechanism used by attackers (and by Turla specifically).
    """

    TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

    def __init__(self, tasks_path: str = TASKS_PATH):
        self.tasks_path           = Path(tasks_path)
        self.com_handler_clsids  : Set[str] = set()
        self.logon_trigger_clsids: Set[str] = set()

    def scan(self) -> Tuple[Set[str], Set[str]]:
        """
        Walk task XML files and extract ComHandler CLSIDs.
        Returns: (all_com_handler_clsids, logon_trigger_clsids)
        """
        if not self.tasks_path.exists():
            return set(), set()

        for task_file in self.tasks_path.rglob("*"):
            if not task_file.is_file():
                continue
            try:
                tree = ET.parse(task_file)
                root = tree.getroot()
                self._parse_task(root)
            except ET.ParseError:
                continue
            except PermissionError:
                continue

        return self.com_handler_clsids, self.logon_trigger_clsids

    def _parse_task(self, root: ET.Element):
        ns = self.TASK_NS
        clsid_in_task: Optional[str] = None

        for action in root.iter(f"{ns}ComHandler"):
            clsid_elem = action.find(f"{ns}ClassId")
            if clsid_elem is not None and clsid_elem.text:
                clsid = clsid_elem.text.strip()
                self.com_handler_clsids.add(clsid)
                clsid_in_task = clsid

        # If this task has a ComHandler AND a LogonTrigger — very high value target
        if clsid_in_task:
            for _ in root.iter(f"{ns}LogonTrigger"):
                self.logon_trigger_clsids.add(clsid_in_task)
                break


# -----------------------------------------------------------------------------
# LIVE SCANNER (Windows only)
# -----------------------------------------------------------------------------

class LiveScanner:

    def _open_hive(self, hive_const, subkey: str):
        try:
            return winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except (FileNotFoundError, PermissionError):
            return None

    def _get_inproc_dll(self, parent_key, clsid_name: str) -> Optional[str]:
        try:
            clsid_key  = winreg.OpenKey(parent_key, clsid_name)
            inproc_key = winreg.OpenKey(clsid_key, "InprocServer32")
            value, _   = winreg.QueryValueEx(inproc_key, "")
            return value.strip() if value else None
        except (FileNotFoundError, OSError):
            return None

    def _get_friendly_name(self, parent_key, clsid_name: str) -> str:
        try:
            clsid_key = winreg.OpenKey(parent_key, clsid_name)
            value, _  = winreg.QueryValueEx(clsid_key, "")
            return str(value).strip() if value else ""
        except (FileNotFoundError, OSError):
            return ""

    def _collect_clsids(self, hive_const, hive_label: str) -> Dict[str, CLSIDEntry]:
        entries  = {}
        root_key = self._open_hive(hive_const, CLSID_SUBKEY)
        if root_key is None:
            return entries

        idx = 0
        while True:
            try:
                clsid_name    = winreg.EnumKey(root_key, idx)
                dll_path      = self._get_inproc_dll(root_key, clsid_name)
                friendly_name = self._get_friendly_name(root_key, clsid_name)
                entries[clsid_name] = CLSIDEntry(clsid_name, dll_path, friendly_name)
                idx += 1
            except OSError:
                break

        return entries

    def scan(self) -> Tuple[dict, dict]:
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                t1   = progress.add_task("[cyan]Collecting HKLM CLSIDs...", total=None)
                hklm = self._collect_clsids(winreg.HKEY_LOCAL_MACHINE, "HKLM")
                progress.update(t1, description=f"[green]HKLM: {len(hklm)} CLSIDs collected")

                t2   = progress.add_task("[cyan]Collecting HKCU CLSIDs...", total=None)
                hkcu = self._collect_clsids(winreg.HKEY_CURRENT_USER, "HKCU")
                progress.update(t2, description=f"[green]HKCU: {len(hkcu)} CLSIDs collected")
        else:
            print("[*] Collecting HKLM CLSIDs...")
            hklm = self._collect_clsids(winreg.HKEY_LOCAL_MACHINE, "HKLM")
            print(f"    Found {len(hklm)} entries")
            print("[*] Collecting HKCU CLSIDs...")
            hkcu = self._collect_clsids(winreg.HKEY_CURRENT_USER, "HKCU")
            print(f"    Found {len(hkcu)} entries")

        return hklm, hkcu


# -----------------------------------------------------------------------------
# EXTERNAL FILE ANALYZER
# -----------------------------------------------------------------------------

class ExternalAnalyzer:

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.metadata: dict = {}

    def load(self) -> Tuple[dict, dict]:
        path = Path(self.filepath)
        if not path.exists():
            raise FileNotFoundError(f"Export file not found: {self.filepath}")
        if path.suffix.lower() != ".json":
            raise ValueError(f"Expected a .json file, got: {path.suffix}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.metadata = {
            "exported_at": data.get("ExportedAt", "Unknown"),
            "hostname":    data.get("Hostname",   "Unknown"),
            "username":    data.get("Username",   "Unknown"),
            "os":          data.get("OS",         "Unknown"),
        }

        hklm_map = self._parse_list(data.get("HKLM_CLSIDs", []))
        hkcu_map = self._parse_list(data.get("HKCU_CLSIDs", []))

        return hklm_map, hkcu_map

    def _parse_list(self, entries: list) -> Dict[str, CLSIDEntry]:
        result = {}
        for item in entries:
            clsid         = item.get("CLSID", "")
            dll_path      = item.get("DLLPath") or None
            friendly_name = item.get("FriendlyName", "")
            if clsid:
                result[clsid] = CLSIDEntry(clsid, dll_path, friendly_name)
        return result


# -----------------------------------------------------------------------------
# COMPARISON ENGINE  (v1.0.1 - fully revised)
# -----------------------------------------------------------------------------

class ComparisonEngine:
    """
    Core detection logic. Risk tiers:

      HIGH   - CLSID in both hives, DLL paths differ (classic hijack).
               Risk is further elevated if the HKCU DLL path is in a
               user-writable location (AppData, ProgramData, Temp, Users).

      MEDIUM - CLSID only in HKCU, has a DLL path but no HKLM counterpart.
               v1.0.1 FIX: no longer suppressed just because it lives under
               AppData. That was the old inverted logic.

      LOW    - v1.0.1 NEW: Phantom COM. CLSID key exists in HKCU but has
               no InprocServer32 DLL registered at all. Could be a stub
               left by an attacker after cleanup, or a partial hijack setup.

    Whitelist : CLSIDs in CLSID_WHITELIST are skipped to reduce FP noise.
    Task corr : If a CLSID is referenced by a ComHandler task (especially
                with LogonTrigger), the finding is annotated accordingly.
    """

    def __init__(
        self,
        hklm_map: dict,
        hkcu_map: dict,
        task_clsids:  Optional[Set[str]] = None,
        logon_clsids: Optional[Set[str]] = None,
    ):
        self.hklm_map    = hklm_map
        self.hkcu_map    = hkcu_map
        self.task_clsids  = task_clsids  or set()
        self.logon_clsids = logon_clsids or set()
        self.findings: List[Finding] = []

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _is_suspicious_path(dll_path: Optional[str]) -> bool:
        """v1.0.1 FIX: user-writable locations are suspicious, not benign."""
        if not dll_path:
            return False
        lower = dll_path.lower()
        return any(p in lower for p in SUSPICIOUS_PATHS)

    @staticmethod
    def _is_whitelisted(clsid: str) -> bool:
        return clsid.upper() in {c.upper() for c in CLSID_WHITELIST}

    def _build_notes(
        self,
        suspicious: bool,
        task_corr:  bool,
        logon_corr: bool,
        extra: str = "",
    ) -> str:
        parts = []
        if suspicious:
            parts.append("DLL in user-writable path")
        if logon_corr:
            parts.append("ComHandler task with LogonTrigger — high-value target")
        elif task_corr:
            parts.append("Referenced by a ComHandler scheduled task")
        if extra:
            parts.append(extra)
        return " | ".join(parts)

    # -- Main comparison -------------------------------------------------------

    def compare(self) -> List[Finding]:
        self.findings = []

        for clsid, hkcu_entry in self.hkcu_map.items():

            # Skip whitelisted CLSIDs
            if self._is_whitelisted(clsid):
                continue

            task_corr  = clsid in self.task_clsids
            logon_corr = clsid in self.logon_clsids

            if clsid in self.hklm_map:
                hklm_entry = self.hklm_map[clsid]
                hkcu_dll   = hkcu_entry.dll_path
                hklm_dll   = hklm_entry.dll_path

                if hkcu_dll and hklm_dll:
                    if hkcu_dll.lower() != hklm_dll.lower():
                        # HIGH: classic COM hijack
                        suspicious = self._is_suspicious_path(hkcu_dll)
                        notes      = self._build_notes(suspicious, task_corr, logon_corr)
                        self.findings.append(Finding(
                            clsid           = clsid,
                            friendly_name   = hkcu_entry.friendly_name,
                            hkcu_dll        = hkcu_dll,
                            hklm_dll        = hklm_dll,
                            status          = STATUS_HIJACK,
                            risk            = RISK_HIGH,
                            notes           = notes,
                            suspicious_path = suspicious,
                            task_correlated = task_corr,
                        ))

            else:
                # CLSID in HKCU but not in HKLM
                hkcu_dll = hkcu_entry.dll_path

                if hkcu_dll:
                    # MEDIUM: HKCU-only with a DLL
                    # v1.0.1 FIX: suspicious path no longer suppresses this
                    suspicious = self._is_suspicious_path(hkcu_dll)
                    notes      = self._build_notes(
                        suspicious, task_corr, logon_corr,
                        extra="No HKLM counterpart found",
                    )
                    self.findings.append(Finding(
                        clsid           = clsid,
                        friendly_name   = hkcu_entry.friendly_name,
                        hkcu_dll        = hkcu_dll,
                        hklm_dll        = None,
                        status          = STATUS_HKCU,
                        risk            = RISK_MEDIUM,
                        notes           = notes,
                        suspicious_path = suspicious,
                        task_correlated = task_corr,
                    ))
                else:
                    # LOW: v1.0.1 NEW - Phantom COM
                    # Key exists in HKCU, but no InprocServer32 DLL at all
                    notes = self._build_notes(
                        False, task_corr, logon_corr,
                        extra="HKCU key exists but no InprocServer32 DLL found",
                    )
                    self.findings.append(Finding(
                        clsid           = clsid,
                        friendly_name   = hkcu_entry.friendly_name,
                        hkcu_dll        = None,
                        hklm_dll        = None,
                        status          = STATUS_PHANTOM,
                        risk            = RISK_LOW,
                        notes           = notes,
                        suspicious_path = False,
                        task_correlated = task_corr,
                    ))

        # Sort: HIGH -> MEDIUM -> LOW, task-correlated first within each tier
        risk_order = {RISK_HIGH: 0, RISK_MEDIUM: 1, RISK_LOW: 2}
        self.findings.sort(
            key=lambda f: (risk_order.get(f.risk, 9), not f.task_correlated)
        )
        return self.findings

    # -- Counts ----------------------------------------------------------------

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RISK_HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RISK_MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RISK_LOW)


# -----------------------------------------------------------------------------
# REPORTER
# -----------------------------------------------------------------------------

class Reporter:

    RISK_STYLES = {
        RISK_HIGH:   "bold red",
        RISK_MEDIUM: "bold yellow",
        RISK_LOW:    "bold blue",
        RISK_INFO:   "dim",
    }

    def __init__(
        self,
        findings:   List[Finding],
        hklm_count: int,
        hkcu_count: int,
        metadata:   Optional[dict] = None,
        task_count: int = 0,
    ):
        self.findings   = findings
        self.hklm_count = hklm_count
        self.hkcu_count = hkcu_count
        self.metadata   = metadata or {}
        self.task_count = task_count
        self.scan_time  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -- Terminal Output -------------------------------------------------------

    def print_metadata(self, mode: str, source: str = "local"):
        if HAS_RICH:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="dim")
            grid.add_column()

            grid.add_row("Mode",        mode)
            grid.add_row("Source",      source)
            grid.add_row("Scan Time",   self.scan_time)
            grid.add_row("HKLM CLSIDs", str(self.hklm_count))
            grid.add_row("HKCU CLSIDs", str(self.hkcu_count))
            if self.task_count > 0:
                grid.add_row("ComHandler Tasks", str(self.task_count))

            if self.metadata:
                grid.add_row("Remote Host", self.metadata.get("hostname", ""))
                grid.add_row("Remote User", self.metadata.get("username", ""))
                grid.add_row("Remote OS",   self.metadata.get("os", ""))
                grid.add_row("Exported At", self.metadata.get("exported_at", ""))

            console.print(Panel(
                grid,
                title="[bold cyan]Scan Information",
                border_style="cyan",
                padding=(0, 1),
            ))
            console.print()
        else:
            print(f"[*] Mode       : {mode}")
            print(f"[*] Source     : {source}")
            print(f"[*] Scan Time  : {self.scan_time}")
            print(f"[*] HKLM CLSIDs: {self.hklm_count}")
            print(f"[*] HKCU CLSIDs: {self.hkcu_count}")
            if self.task_count > 0:
                print(f"[*] ComHandler Tasks: {self.task_count}")
            if self.metadata:
                for k, v in self.metadata.items():
                    print(f"[*] {k:16}: {v}")
            print()

    def print_summary(self, high: int, medium: int, low: int):
        if HAS_RICH:
            total = high + medium + low
            if total == 0:
                style = "bold green"
                msg   = "[bold green]No COM Hijacking indicators detected.[/]"
            elif high > 0:
                style = "bold red"
                msg   = f"[bold red]  {high} HIGH risk indicator(s) found![/]"
                if medium > 0:
                    msg += f"\n[yellow]   {medium} MEDIUM risk indicator(s) found.[/]"
                if low > 0:
                    msg += f"\n[blue]   {low} LOW risk (Phantom COM) indicator(s) found.[/]"
            elif medium > 0:
                style = "bold yellow"
                msg   = f"[yellow]~  {medium} MEDIUM risk indicator(s) found (review recommended).[/]"
                if low > 0:
                    msg += f"\n[blue]   {low} LOW risk (Phantom COM) indicator(s) found.[/]"
            else:
                style = "bold blue"
                msg   = f"[blue]  {low} LOW risk (Phantom COM) indicator(s) — review recommended.[/]"

            console.print(Panel(msg, title="[bold]Summary", border_style=style, padding=(0, 2)))
            console.print()
        else:
            total = high + medium + low
            if total == 0:
                print("[+] No COM Hijacking indicators detected.")
            else:
                print(f"[!] HIGH: {high}  MEDIUM: {medium}  LOW: {low}")
            print()

    def print_findings_table(self):
        if not self.findings:
            return

        high_findings   = [f for f in self.findings if f.risk == RISK_HIGH]
        medium_findings = [f for f in self.findings if f.risk == RISK_MEDIUM]
        low_findings    = [f for f in self.findings if f.risk == RISK_LOW]

        if HAS_RICH:
            # -- HIGH ---------------------------------------------------------
            if high_findings:
                console.print(Rule(
                    "[bold red]HIGH Risk Findings - Possible COM Hijacking",
                    style="red",
                ))
                console.print()
                tbl = Table(
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold white on red",
                    border_style="red",
                    show_lines=True,
                    expand=True,
                )
                tbl.add_column("CLSID",    style="bold white", min_width=36, max_width=40)
                tbl.add_column("Name",     style="cyan",       max_width=24)
                tbl.add_column("HKCU DLL", style="red",        max_width=46)
                tbl.add_column("HKLM DLL", style="green",      max_width=46)
                tbl.add_column("Flags",    style="yellow",     max_width=7)
                tbl.add_column("Notes",    style="dim",        max_width=36)

                for f in high_findings:
                    flags = ""
                    if f.suspicious_path: flags += "[P]"
                    if f.task_correlated: flags += "[T]"
                    tbl.add_row(
                        f.clsid,
                        f.friendly_name or "[dim]-[/]",
                        f.hkcu_dll      or "[dim]-[/]",
                        f.hklm_dll      or "[dim]-[/]",
                        flags,
                        f.notes         or "",
                    )
                console.print(tbl)
                console.print()

            # -- MEDIUM -------------------------------------------------------
            if medium_findings:
                console.print(Rule(
                    "[bold yellow]MEDIUM Risk Findings - HKCU-only DLL Entries",
                    style="yellow",
                ))
                console.print()
                tbl2 = Table(
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold black on yellow",
                    border_style="yellow",
                    show_lines=True,
                    expand=True,
                )
                tbl2.add_column("CLSID",    style="bold white", min_width=36, max_width=40)
                tbl2.add_column("Name",     style="cyan",       max_width=26)
                tbl2.add_column("HKCU DLL", style="yellow",     max_width=56)
                tbl2.add_column("Flags",    style="yellow",     max_width=7)
                tbl2.add_column("Notes",    style="dim",        max_width=36)

                for f in medium_findings:
                    flags = ""
                    if f.suspicious_path: flags += "[P]"
                    if f.task_correlated: flags += "[T]"
                    tbl2.add_row(
                        f.clsid,
                        f.friendly_name or "[dim]-[/]",
                        f.hkcu_dll      or "[dim]-[/]",
                        flags,
                        f.notes         or "",
                    )
                console.print(tbl2)
                console.print()

            # -- LOW (Phantom COM) --------------------------------------------
            if low_findings:
                console.print(Rule(
                    "[bold blue]LOW Risk Findings - Phantom COM (No DLL Registered)",
                    style="blue",
                ))
                console.print()
                tbl3 = Table(
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold white on blue",
                    border_style="blue",
                    show_lines=True,
                    expand=True,
                )
                tbl3.add_column("CLSID", style="bold white", min_width=36, max_width=40)
                tbl3.add_column("Name",  style="cyan",       max_width=30)
                tbl3.add_column("Flags", style="yellow",     max_width=7)
                tbl3.add_column("Notes", style="dim",        max_width=50)

                for f in low_findings:
                    flags = "[T]" if f.task_correlated else ""
                    tbl3.add_row(
                        f.clsid,
                        f.friendly_name or "[dim]-[/]",
                        flags,
                        f.notes or "",
                    )
                console.print(tbl3)
                console.print()

            if any([high_findings, medium_findings, low_findings]):
                console.print(
                    "[dim]  Flags:  [P] = DLL in user-writable path   "
                    "[T] = Referenced by a ComHandler scheduled task[/]"
                )
                console.print()

        else:
            for f in self.findings:
                print(f"  [{f.risk}] {f.clsid}")
                print(f"    Name           : {f.friendly_name}")
                print(f"    HKCU DLL       : {f.hkcu_dll}")
                print(f"    HKLM DLL       : {f.hklm_dll or 'N/A'}")
                print(f"    Status         : {f.status}")
                print(f"    Suspicious Path: {f.suspicious_path}")
                print(f"    Task Correlated: {f.task_correlated}")
                print(f"    Notes          : {f.notes}")
                print()

    # -- File Output ----------------------------------------------------------

    def save_csv(self, output_path: str):
        path = Path(output_path)
        with open(path, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "clsid", "friendly_name", "hkcu_dll", "hklm_dll",
                "status", "risk", "notes", "suspicious_path", "task_correlated",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding.to_dict())

        if HAS_RICH:
            console.print(f"[cyan][+] CSV report saved -> [bold]{output_path}[/][/]")
        else:
            print(f"[+] CSV report saved: {output_path}")

    def save_json(self, output_path: str):
        path   = Path(output_path)
        report = {
            "report_generated_at":   self.scan_time,
            "analyzer_version":      VERSION,
            "mitre_technique":       MITRE_ID,
            "hklm_clsid_count":      self.hklm_count,
            "hkcu_clsid_count":      self.hkcu_count,
            "task_comhandler_count": self.task_count,
            "source_metadata":       self.metadata,
            "summary": {
                "total_findings": len(self.findings),
                "high_risk":      sum(1 for f in self.findings if f.risk == RISK_HIGH),
                "medium_risk":    sum(1 for f in self.findings if f.risk == RISK_MEDIUM),
                "low_risk":       sum(1 for f in self.findings if f.risk == RISK_LOW),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        if HAS_RICH:
            console.print(f"[cyan][+] JSON report saved -> [bold]{output_path}[/][/]")
        else:
            print(f"[+] JSON report saved: {output_path}")


# -----------------------------------------------------------------------------
# ARGUMENT PARSER
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="com_hijack_detector",
        description=(
            "COM Hijack Detector - Identifies potential COM Object Hijacking\n"
            f"MITRE ATT&CK: {MITRE_ID}  |  v{VERSION}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan the local machine (Windows only):
  python com_hijack_detector.py --mode live

  # Scan local machine and correlate with scheduled tasks:
  python com_hijack_detector.py --mode live --correlate-tasks

  # Analyze an exported JSON from a remote machine:
  python com_hijack_detector.py --mode analyze --input registry_export.json

  # Analyze, correlate tasks, save to CSV and JSON:
  python com_hijack_detector.py --mode analyze --input dump.json \\
      --correlate-tasks --csv report.csv --json report.json

  # Show HIGH and MEDIUM only (suppress LOW / Phantom COM):
  python com_hijack_detector.py --mode live --no-low

  # Show HIGH only:
  python com_hijack_detector.py --mode live --no-medium --no-low
        """,
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["live", "analyze"],
        help="live: scan this machine | analyze: parse a PowerShell JSON export",
    )
    parser.add_argument(
        "--input", "-i",
        metavar="FILE",
        help="Path to the JSON export file (required for --mode analyze)",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Save findings to a CSV file",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings to a JSON report file",
    )
    parser.add_argument(
        "--no-medium",
        action="store_true",
        help="Suppress MEDIUM risk findings from the output",
    )
    parser.add_argument(
        "--no-low",
        action="store_true",
        help="Suppress LOW risk (Phantom COM) findings from the output",
    )
    parser.add_argument(
        "--correlate-tasks",
        action="store_true",
        help=(
            f"Scan {TASKS_PATH} for ComHandler scheduled tasks "
            "and correlate their CLSIDs with findings (Windows only)"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def main():
    parser = build_parser()
    args   = parser.parse_args()

    banner()

    metadata   = {}
    hklm_map   = {}
    hkcu_map   = {}
    mode_label = ""
    source     = ""

    # -- Mode: Live ------------------------------------------------------------
    if args.mode == "live":
        if not WINDOWS:
            cprint(
                "[red][!] Live mode requires Windows. "
                "Use --mode analyze with a JSON export from a Windows machine.[/]"
            )
            sys.exit(1)

        mode_label = "Live Scan"
        source     = f"localhost ({socket.gethostname()})"
        scanner    = LiveScanner()
        hklm_map, hkcu_map = scanner.scan()

    # -- Mode: Analyze ---------------------------------------------------------
    elif args.mode == "analyze":
        if not args.input:
            cprint("[red][!] --input FILE is required for --mode analyze.[/]")
            sys.exit(1)

        mode_label = "External File Analysis"
        analyzer   = ExternalAnalyzer(args.input)
        try:
            hklm_map, hkcu_map = analyzer.load()
            metadata  = analyzer.metadata
            source    = f"File: {args.input} (Host: {metadata.get('hostname', 'unknown')})"
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
            cprint(f"[red][!] Failed to load export file: {e}[/]")
            sys.exit(1)

    # -- Task Correlation (v1.0.1) ---------------------------------------------
    task_clsids  : Set[str] = set()
    logon_clsids : Set[str] = set()
    task_count   : int      = 0

    if args.correlate_tasks:
        if not WINDOWS:
            cprint(
                "[yellow][~] --correlate-tasks is only supported on Windows. "
                "Skipping task correlation.[/]"
            )
        else:
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    transient=True,
                    console=console,
                ) as progress:
                    progress.add_task("[cyan]Scanning scheduled tasks...", total=None)
                    correlator = TaskCorrelator()
                    task_clsids, logon_clsids = correlator.scan()
                    task_count = len(task_clsids)
            else:
                print(f"[*] Scanning scheduled tasks in {TASKS_PATH}...")
                correlator = TaskCorrelator()
                task_clsids, logon_clsids = correlator.scan()
                task_count = len(task_clsids)
                print(f"    Found {task_count} ComHandler task(s)")

    # -- Compare ---------------------------------------------------------------
    engine   = ComparisonEngine(hklm_map, hkcu_map, task_clsids, logon_clsids)
    findings = engine.compare()

    # Apply filters
    if args.no_medium:
        findings = [f for f in findings if f.risk != RISK_MEDIUM]
    if args.no_low:
        findings = [f for f in findings if f.risk != RISK_LOW]

    # -- Report ----------------------------------------------------------------
    reporter = Reporter(
        findings   = findings,
        hklm_count = len(hklm_map),
        hkcu_count = len(hkcu_map),
        metadata   = metadata,
        task_count = task_count,
    )

    reporter.print_metadata(mode_label, source)
    reporter.print_summary(engine.high_count, engine.medium_count, engine.low_count)
    reporter.print_findings_table()

    if args.csv:
        reporter.save_csv(args.csv)
    if args.json:
        reporter.save_json(args.json)

    if HAS_RICH:
        console.print()
        console.print(Rule(style="dim"))
        console.print(
            f"[dim]  Scan complete - "
            f"HIGH: [bold red]{engine.high_count}[/]  "
            f"MEDIUM: [bold yellow]{engine.medium_count}[/]  "
            f"LOW: [bold blue]{engine.low_count}[/]  "
            f"Total: {len(findings)}[/]"
        )
        console.print()
    else:
        print(
            f"\n[*] Done - HIGH: {engine.high_count}  "
            f"MEDIUM: {engine.medium_count}  LOW: {engine.low_count}\n"
        )

    sys.exit(1 if engine.high_count > 0 else 0)


if __name__ == "__main__":
    main()