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
Version : 1.0.0
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
from pathlib import Path
from typing import Optional, Dict, List, Tuple

# ── Rich for terminal output ──────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.padding import Padding
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ── winreg (Windows only for live mode) ──────────────────────────────────────
if platform.system() == "Windows":
    import winreg
    WINDOWS = True
else:
    WINDOWS = False

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION       = "1.0.0"
MITRE_ID      = "T1546.015"
CLSID_SUBKEY  = r"SOFTWARE\Classes\CLSID"

RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_INFO     = "INFO"

STATUS_HIJACK = "POSSIBLE COM HIJACK"
STATUS_HKCU   = "HKCU ONLY (No HKLM counterpart)"
STATUS_SAME   = "MATCH"

# Known benign HKCU-only patterns (common false positives)
KNOWN_BENIGN_PREFIXES = [
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "C:\\Users",
]


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE SETUP
# ─────────────────────────────────────────────────────────────────────────────

console = Console() if HAS_RICH else None


def cprint(msg: str, style: str = ""):
    """Print with rich styling if available, else plain."""
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def banner():
    """Display the application banner."""
    if HAS_RICH:
        title = Text()
        title.append("  COM Hijack Detector  ", style="bold white")
        title.append(f"v{VERSION}", style="dim white")

        subtitle = Text()
        subtitle.append("  MITRE ATT&CK: ", style="dim")
        subtitle.append(MITRE_ID, style="bold yellow")
        subtitle.append("  •  Component Object Model Hijacking", style="dim")

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


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class CLSIDEntry:
    """Represents a single CLSID registry entry."""

    def __init__(self, clsid: str, dll_path: Optional[str], friendly_name: str = ""):
        self.clsid         = clsid
        self.dll_path      = dll_path
        self.friendly_name = friendly_name

    def __repr__(self):
        return f"CLSIDEntry(clsid={self.clsid!r}, dll={self.dll_path!r})"


class Finding:
    """Represents a single detection finding."""

    def __init__(
        self,
        clsid: str,
        friendly_name: str,
        hkcu_dll: Optional[str],
        hklm_dll: Optional[str],
        status: str,
        risk: str,
        notes: str = "",
    ):
        self.clsid         = clsid
        self.friendly_name = friendly_name
        self.hkcu_dll      = hkcu_dll
        self.hklm_dll      = hklm_dll
        self.status        = status
        self.risk          = risk
        self.notes         = notes

    def to_dict(self) -> dict:
        return {
            "clsid":         self.clsid,
            "friendly_name": self.friendly_name,
            "hkcu_dll":      self.hkcu_dll or "",
            "hklm_dll":      self.hklm_dll or "",
            "status":        self.status,
            "risk":          self.risk,
            "notes":         self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# LIVE SCANNER (Windows only)
# ─────────────────────────────────────────────────────────────────────────────

class LiveScanner:
    """Scans the local Windows registry for COM hijacking indicators."""

    def _open_hive(self, hive_const, subkey: str):
        """Safely open a registry key, return None on failure."""
        try:
            return winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            return None
        except PermissionError:
            return None

    def _get_inproc_dll(self, parent_key, clsid_name: str) -> Optional[str]:
        """Read the InprocServer32 default value for a CLSID."""
        try:
            clsid_key   = winreg.OpenKey(parent_key, clsid_name)
            inproc_key  = winreg.OpenKey(clsid_key, "InprocServer32")
            value, _    = winreg.QueryValueEx(inproc_key, "")
            return value.strip() if value else None
        except (FileNotFoundError, OSError):
            return None

    def _get_friendly_name(self, parent_key, clsid_name: str) -> str:
        """Read the default value (friendly name) of a CLSID key."""
        try:
            clsid_key = winreg.OpenKey(parent_key, clsid_name)
            value, _  = winreg.QueryValueEx(clsid_key, "")
            return str(value).strip() if value else ""
        except (FileNotFoundError, OSError):
            return ""

    def _collect_clsids(self, hive_const, hive_label: str) -> Dict[str, CLSIDEntry]:
        """Enumerate all CLSIDs under a registry hive and return a dict keyed by CLSID."""
        entries = {}
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
        """
        Collect HKLM and HKCU CLSID maps.
        Returns: (hklm_map, hkcu_map)
        """
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                t1 = progress.add_task("[cyan]Collecting HKLM CLSIDs...", total=None)
                hklm = self._collect_clsids(winreg.HKEY_LOCAL_MACHINE, "HKLM")
                progress.update(t1, description=f"[green]HKLM: {len(hklm)} CLSIDs collected")

                t2 = progress.add_task("[cyan]Collecting HKCU CLSIDs...", total=None)
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


# ─────────────────────────────────────────────────────────────────────────────
# EXTERNAL FILE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class ExternalAnalyzer:
    """
    Parses a JSON export file produced by Invoke-COMHijackDetector.ps1
    and returns HKLM/HKCU maps compatible with the comparison engine.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.metadata: dict = {}

    def load(self) -> Tuple[dict, dict]:
        """Load and parse the JSON export file."""
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
        """Convert a list of CLSID dicts into a CLSIDEntry map."""
        result = {}
        for item in entries:
            clsid         = item.get("CLSID", "")
            dll_path      = item.get("DLLPath") or None
            friendly_name = item.get("FriendlyName", "")
            if clsid:
                result[clsid] = CLSIDEntry(clsid, dll_path, friendly_name)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# COMPARISON ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ComparisonEngine:
    """
    Core logic: compares HKCU CLSIDs against HKLM to identify hijacking.

    Rules:
      HIGH   - CLSID exists in both hives but DLL paths differ.
      MEDIUM - CLSID exists in HKCU with a DLL but has no HKLM counterpart.
      INFO   - CLSID exists in both and DLL paths match (clean).
    """

    def __init__(self, hklm_map: dict, hkcu_map: dict):
        self.hklm_map = hklm_map
        self.hkcu_map = hkcu_map
        self.findings: List[Finding] = []

    def _is_likely_benign(self, dll_path: str) -> bool:
        """Heuristic: some HKCU-only entries are benign user installs."""
        if not dll_path:
            return False
        lower = dll_path.lower()
        for prefix in KNOWN_BENIGN_PREFIXES:
            if lower.startswith(prefix.lower()):
                return True
        return False

    def compare(self) -> List[Finding]:
        """Run the comparison and return a list of findings."""
        self.findings = []

        for clsid, hkcu_entry in self.hkcu_map.items():
            if clsid in self.hklm_map:
                hklm_entry = self.hklm_map[clsid]

                hkcu_dll = hkcu_entry.dll_path
                hklm_dll = hklm_entry.dll_path

                if hkcu_dll and hklm_dll:
                    if hkcu_dll.lower() != hklm_dll.lower():
                        # HIGH: Both exist but DLL paths differ — classic hijack pattern
                        notes = ""
                        if self._is_likely_benign(hkcu_dll):
                            notes = "Possible benign user install — verify manually"
                        self.findings.append(Finding(
                            clsid         = clsid,
                            friendly_name = hkcu_entry.friendly_name,
                            hkcu_dll      = hkcu_dll,
                            hklm_dll      = hklm_dll,
                            status        = STATUS_HIJACK,
                            risk          = RISK_HIGH,
                            notes         = notes,
                        ))
            else:
                # CLSID in HKCU but not in HKLM
                if hkcu_entry.dll_path:
                    self.findings.append(Finding(
                        clsid         = clsid,
                        friendly_name = hkcu_entry.friendly_name,
                        hkcu_dll      = hkcu_entry.dll_path,
                        hklm_dll      = None,
                        status        = STATUS_HKCU,
                        risk          = RISK_MEDIUM,
                        notes         = "No HKLM counterpart found",
                    ))

        return self.findings

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RISK_HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RISK_MEDIUM)


# ─────────────────────────────────────────────────────────────────────────────
# REPORTER
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:
    """Formats and outputs findings to terminal and/or files."""

    # Risk level → rich style
    RISK_STYLES = {
        RISK_HIGH:   "bold red",
        RISK_MEDIUM: "bold yellow",
        RISK_INFO:   "dim",
    }

    def __init__(
        self,
        findings: List[Finding],
        hklm_count: int,
        hkcu_count: int,
        metadata: Optional[dict] = None,
    ):
        self.findings   = findings
        self.hklm_count = hklm_count
        self.hkcu_count = hkcu_count
        self.metadata   = metadata or {}
        self.scan_time  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Terminal Output ───────────────────────────────────────────────────────

    def print_metadata(self, mode: str, source: str = "local"):
        """Print scan metadata header."""
        if HAS_RICH:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="dim")
            grid.add_column()

            grid.add_row("Mode",       mode)
            grid.add_row("Source",     source)
            grid.add_row("Scan Time",  self.scan_time)
            grid.add_row("HKLM CLSIDs", str(self.hklm_count))
            grid.add_row("HKCU CLSIDs", str(self.hkcu_count))

            if self.metadata:
                grid.add_row("Remote Host",     self.metadata.get("hostname", ""))
                grid.add_row("Remote User",     self.metadata.get("username", ""))
                grid.add_row("Remote OS",       self.metadata.get("os", ""))
                grid.add_row("Exported At",     self.metadata.get("exported_at", ""))

            console.print(Panel(grid, title="[bold cyan]Scan Information", border_style="cyan", padding=(0, 1)))
            console.print()
        else:
            print(f"[*] Mode      : {mode}")
            print(f"[*] Source    : {source}")
            print(f"[*] Scan Time : {self.scan_time}")
            print(f"[*] HKLM CLSIDs : {self.hklm_count}")
            print(f"[*] HKCU CLSIDs : {self.hkcu_count}")
            if self.metadata:
                for k, v in self.metadata.items():
                    print(f"[*] {k:16}: {v}")
            print()

    def print_summary(self, high: int, medium: int):
        """Print the findings summary box."""
        if HAS_RICH:
            total = high + medium
            if total == 0:
                style = "bold green"
                msg   = "[bold green]✔  No COM Hijacking indicators detected.[/]"
            elif high > 0:
                style = "bold red"
                msg   = f"[bold red]⚠  {high} HIGH risk indicator(s) found![/]"
                if medium > 0:
                    msg += f"\n[yellow]   {medium} MEDIUM risk indicator(s) found.[/]"
            else:
                style = "bold yellow"
                msg   = f"[yellow]~  {medium} MEDIUM risk indicator(s) found (review recommended).[/]"

            console.print(Panel(msg, title="[bold]Summary", border_style=style, padding=(0, 2)))
            console.print()
        else:
            total = high + medium
            if total == 0:
                print("[+] No COM Hijacking indicators detected.")
            else:
                print(f"[!] HIGH: {high}  MEDIUM: {medium}")
            print()

    def print_findings_table(self):
        """Print all findings in a rich table."""
        if not self.findings:
            return

        high_findings   = [f for f in self.findings if f.risk == RISK_HIGH]
        medium_findings = [f for f in self.findings if f.risk == RISK_MEDIUM]

        if HAS_RICH:
            # ── HIGH Risk Table ──
            if high_findings:
                console.print(Rule("[bold red]HIGH Risk Findings — Possible COM Hijacking", style="red"))
                console.print()

                tbl = Table(
                    box=box.SIMPLE_HEAVY,
                    show_header=True,
                    header_style="bold white on red",
                    border_style="red",
                    show_lines=True,
                    expand=True,
                )
                tbl.add_column("CLSID",         style="bold white", min_width=36, max_width=40)
                tbl.add_column("Name",           style="cyan",       max_width=28)
                tbl.add_column("HKCU DLL",       style="red",        max_width=50)
                tbl.add_column("HKLM DLL",       style="green",      max_width=50)
                tbl.add_column("Notes",          style="dim",        max_width=30)

                for f in high_findings:
                    tbl.add_row(
                        f.clsid,
                        f.friendly_name or "[dim]—[/]",
                        f.hkcu_dll      or "[dim]—[/]",
                        f.hklm_dll      or "[dim]—[/]",
                        f.notes         or "",
                    )

                console.print(tbl)
                console.print()

            # ── MEDIUM Risk Table ──
            if medium_findings:
                console.print(Rule("[bold yellow]MEDIUM Risk Findings — HKCU-only DLL Entries", style="yellow"))
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
                tbl2.add_column("Name",     style="cyan",       max_width=30)
                tbl2.add_column("HKCU DLL", style="yellow",     max_width=60)
                tbl2.add_column("Notes",    style="dim",        max_width=30)

                for f in medium_findings:
                    tbl2.add_row(
                        f.clsid,
                        f.friendly_name or "[dim]—[/]",
                        f.hkcu_dll      or "[dim]—[/]",
                        f.notes         or "",
                    )

                console.print(tbl2)
                console.print()

        else:
            # Plain-text fallback
            for f in self.findings:
                print(f"  [{f.risk}] {f.clsid}")
                print(f"    Name     : {f.friendly_name}")
                print(f"    HKCU DLL : {f.hkcu_dll}")
                print(f"    HKLM DLL : {f.hklm_dll or 'N/A'}")
                print(f"    Status   : {f.status}")
                print(f"    Notes    : {f.notes}")
                print()

    # ── File Output ───────────────────────────────────────────────────────────

    def save_csv(self, output_path: str):
        """Export findings to a CSV file."""
        path = Path(output_path)
        with open(path, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["clsid", "friendly_name", "hkcu_dll", "hklm_dll", "status", "risk", "notes"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding.to_dict())

        if HAS_RICH:
            console.print(f"[cyan][+] CSV report saved → [bold]{output_path}[/][/]")
        else:
            print(f"[+] CSV report saved: {output_path}")

    def save_json(self, output_path: str):
        """Export findings to a JSON file with metadata."""
        path = Path(output_path)
        report = {
            "report_generated_at": self.scan_time,
            "analyzer_version":    VERSION,
            "mitre_technique":     MITRE_ID,
            "hklm_clsid_count":    self.hklm_count,
            "hkcu_clsid_count":    self.hkcu_count,
            "source_metadata":     self.metadata,
            "summary": {
                "total_findings": len(self.findings),
                "high_risk":      sum(1 for f in self.findings if f.risk == RISK_HIGH),
                "medium_risk":    sum(1 for f in self.findings if f.risk == RISK_MEDIUM),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        if HAS_RICH:
            console.print(f"[cyan][+] JSON report saved → [bold]{output_path}[/][/]")
        else:
            print(f"[+] JSON report saved: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="com_hijack_detector",
        description=(
            "COM Hijack Detector — Identifies potential COM Object Hijacking\n"
            f"MITRE ATT&CK: {MITRE_ID}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan the local machine (Windows only):
  python com_hijack_detector.py --mode live

  # Analyze an exported JSON from a remote machine:
  python com_hijack_detector.py --mode analyze --input registry_export.json

  # Analyze and save results to both CSV and JSON:
  python com_hijack_detector.py --mode analyze --input dump.json --csv report.csv --json report.json
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
        help="Suppress MEDIUM risk findings from the output (show HIGH only)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    banner()

    metadata  = {}
    hklm_map  = {}
    hkcu_map  = {}
    mode_label = ""
    source     = ""

    # ── Mode: Live ────────────────────────────────────────────────────────────
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

    # ── Mode: Analyze ─────────────────────────────────────────────────────────
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

    # ── Compare ───────────────────────────────────────────────────────────────
    engine   = ComparisonEngine(hklm_map, hkcu_map)
    findings = engine.compare()

    # Filter if requested
    if args.no_medium:
        findings = [f for f in findings if f.risk == RISK_HIGH]

    # ── Report ────────────────────────────────────────────────────────────────
    reporter = Reporter(
        findings   = findings,
        hklm_count = len(hklm_map),
        hkcu_count = len(hkcu_map),
        metadata   = metadata,
    )

    reporter.print_metadata(mode_label, source)
    reporter.print_summary(engine.high_count, engine.medium_count)
    reporter.print_findings_table()

    # ── Save outputs ──────────────────────────────────────────────────────────
    if args.csv:
        reporter.save_csv(args.csv)
    if args.json:
        reporter.save_json(args.json)

    if HAS_RICH:
        console.print()
        console.print(Rule(style="dim"))
        console.print(
            f"[dim]  Scan complete — HIGH: [bold red]{engine.high_count}[/]  "
            f"MEDIUM: [bold yellow]{engine.medium_count}[/]  "
            f"Total findings: {len(findings)}[/]"
        )
        console.print()
    else:
        print(f"\n[*] Done — HIGH: {engine.high_count}  MEDIUM: {engine.medium_count}\n")

    # Exit code: 1 if any HIGH findings, 0 otherwise
    sys.exit(1 if engine.high_count > 0 else 0)


if __name__ == "__main__":
    main()