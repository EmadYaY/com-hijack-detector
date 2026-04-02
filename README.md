# COM Hijack Detector

> **MITRE ATT&CK: [T1546.015](https://attack.mitre.org/techniques/T1546/015/) — Component Object Model Hijacking**

A forensic tool for detecting COM Object Hijacking on Windows systems by comparing CLSID registrations between `HKCU` (Current User) and `HKLM` (Local Machine) registry hives.

---

## How It Works

When Windows resolves a COM object, it checks `HKCU` **before** `HKLM`. An attacker can register a malicious DLL under `HKCU` using the same CLSID as a legitimate system COM object — causing their DLL to be loaded instead, without touching any protected system paths or requiring elevated privileges.

This tool detects that discrepancy.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    COM Hijack Detector — Detection Flow                 │
└─────────────────────────────────────────────────────────────────────────┘

   ┌──────────────────────────┐      ┌──────────────────────────┐
   │   1. Collect CLSIDs      │      │   2. Collect CLSIDs      │
   │   HKLM:\...\CLSID        │      │   HKCU:\...\CLSID        │
   │   (Local Machine)        │      │   (Current User)         │
   └────────────┬─────────────┘      └─────────────┬────────────┘
                │                                  │
                └──────────────┬───────────────────┘
                               │
                               ▼
                  ┌────────────────────────┐
                  │  3. Loop over HKCU     │
                  │  foreach CLSID in HKCU │
                  └────────────┬───────────┘
                               │
               ┌───────────────┴──────────────┐
               │                              │
               ▼                              ▼
   ┌───────────────────────┐      ┌───────────────────────┐
   │  4a. Read DLL path    │      │  4b. Read DLL path    │
   │  from HKCU            │      │  from HKLM            │
   │  InprocServer32 →     │ ───► │  (same CLSID)         │
   │  (default)            │      │  InprocServer32 →     │
   └───────────────────────┘      │  (default)            │
                                  └───────────────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │  5. Compare DLL paths      │
                  │  HKCU_DLL ≠ HKLM_DLL ?     │
                  └────────────┬───────────────┘
                               │
               ┌───────────────┴─────────────────┐
               │                                 │
           YES │                              NO │
               ▼                                 ▼
   ┌───────────────────────┐         ┌────────────────────┐
   │  6. Flag as           │         │  Skip / No action  │
   │  POSSIBLE COM HIJACK  │         │  (paths match)     │
   │  [HIGH RISK]          │         └────────────────────┘
   │                       │
   │  CLSID                │
   │  HKCU_DLL (malicious) │
   │  HKLM_DLL (original)  │
   └───────────┬───────────┘
               │
               ▼
   ┌───────────────────────┐
   │  7. Output Results    │
   │  Terminal table +     │
   │  CSV / JSON report    │
   └───────────────────────┘
```

---

## Detection Logic

| Scenario | Risk | Description |
|---|---|---|
| CLSID in both HKCU & HKLM, **DLL paths differ** | 🔴 HIGH | Classic COM Hijack pattern |
| CLSID in HKCU only, has a DLL path | 🟡 MEDIUM | No HKLM counterpart — review recommended |
| CLSID in both, DLL paths match | ✅ CLEAN | No issue |

---

## Project Structure

```
com-hijack-detector/
├── powershell/
│   └── Invoke-COMHijackDetector.ps1   # PowerShell agent (run on target)
├── python/
│   └── com_hijack_detector.py         # Python analyzer (run anywhere)
├── sample_data/
│   └── sample_export.json             # Example export for testing
├── requirements.txt                   # Python dependencies
└── README.md
```

---

## Quickstart

### Option A — Live Scan (Windows only, Python)

```bash
pip install -r requirements.txt
python python/com_hijack_detector.py --mode live
```

### Option B — Remote Machine Analysis (two-step)

**Step 1:** On the target Windows machine, export registry data with PowerShell:

```powershell
# Export registry snapshot to JSON
.\powershell\Invoke-COMHijackDetector.ps1 -Mode Export -OutputPath "C:\Temp\registry_dump.json"
```

**Step 2:** Transfer the JSON to your analyst machine, then run the Python analyzer:

```bash
python python/com_hijack_detector.py --mode analyze --input registry_dump.json
```

### Save Reports

```bash
# Save findings to CSV and JSON simultaneously
python python/com_hijack_detector.py --mode analyze --input dump.json \
    --csv findings.csv \
    --json findings.json

# Suppress MEDIUM risk, show HIGH only
python python/com_hijack_detector.py --mode analyze --input dump.json --no-medium
```

---

## PowerShell Script

```powershell
# Live scan + save CSV report
.\Invoke-COMHijackDetector.ps1 -Mode Scan -ReportPath "C:\Reports\com_findings.csv"

# Export to JSON for Python analysis
.\Invoke-COMHijackDetector.ps1 -Mode Export -OutputPath "C:\Exports\dump.json"

# Export to CSV format instead
.\Invoke-COMHijackDetector.ps1 -Mode Export -OutputPath "dump.csv" -ExportFormat CSV
```

---

## Python Analyzer — CLI Reference

```
usage: com_hijack_detector.py --mode {live,analyze} [options]

Required:
  --mode {live,analyze}   live: scan this machine | analyze: parse JSON export

Options:
  --input FILE, -i FILE   Path to JSON export file (required for analyze mode)
  --csv FILE              Save findings to CSV
  --json FILE             Save findings to JSON report
  --no-medium             Show HIGH risk findings only
  --version               Show version and exit
```

---

## Output Example

```
╔══════════════════════════════════════════════════════╗
║         COM Hijack Detector  v1.0.0                  ║
║         MITRE ATT&CK: T1546.015                      ║
╚══════════════════════════════════════════════════════╝

  Scan Information
  ─────────────────────────────────────────
  Mode          External File Analysis
  Source        File: dump.json (Host: CORP-WS-042)
  Scan Time     2024-11-15 15:03:22
  HKLM CLSIDs   4821
  HKCU CLSIDs   7

  ⚠  1 HIGH risk indicator(s) found!

  HIGH Risk Findings — Possible COM Hijacking
  ┌──────────────────────────────────────────┬─────────────────────────────┬────────────────────────────────┬──────────────────────┐
  │ CLSID                                    │ HKCU DLL                    │ HKLM DLL                       │ Notes                │
  ├──────────────────────────────────────────┼─────────────────────────────┼────────────────────────────────┼──────────────────────┤
  │ {0358b920-0ac7-461f-98f4-58e32cd89148}   │ C:\ProgramData\comhijack... │ C:\Windows\System32\wininet... │                      │
  └──────────────────────────────────────────┴─────────────────────────────┴────────────────────────────────┴──────────────────────┘
```

---

## Requirements

- **Python 3.8+**
- `rich` library (`pip install -r requirements.txt`)
- **PowerShell 5.1+** (for the `.ps1` script, Windows only)
- Live mode requires Windows; analyze mode works on any OS

---

## Running the PowerShell Script — Execution Policy

Windows blocks unsigned PowerShell scripts by default. Follow these two steps before running `Invoke-COMHijackDetector.ps1` for the first time.

**Step 1 — Set Execution Policy for your user:**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
This changes the policy only for your user account (not system-wide). `RemoteSigned` means: locally created scripts run freely, but scripts downloaded from the internet must be digitally signed — **except** we still need Step 2 because the file was downloaded.

**Step 2 — Unblock the downloaded file:**
```powershell
Unblock-File -Path .\Invoke-COMHijackDetector.ps1
```
When Windows downloads a file from the internet or a network share, it attaches a hidden metadata tag called the **Zone Identifier** (Zone 3 = Internet). Even with `RemoteSigned`, PowerShell refuses to run Zone 3 files unless they are signed. `Unblock-File` removes this tag, telling Windows you reviewed and trust the file.

After both steps, the script runs normally:
```powershell
.\Invoke-COMHijackDetector.ps1 -Mode Scan
```

> **Why two steps?** `Set-ExecutionPolicy` controls the *policy*, `Unblock-File` removes the *internet mark* from the specific file. Both are needed when running downloaded scripts with `RemoteSigned`.

---

## Detection with SIEM — Splunk & Elastic

This section covers how to detect COM Hijacking in your SIEM environment using the same indicators this tool looks for.

### Splunk — SPL Queries

**1. Detect reg.exe modifying InprocServer32 (via EDR/Sysmon):**
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE `process_reg` Processes.process=*inprocserver32*
  BY Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```
Looks for `reg.exe` (or any process) whose command line contains `inprocserver32` — the key used in COM Hijacking.

**2. Detect PowerShell modifying CLSID InprocServer32 (PowerShell ScriptBlock Logging, Event 4104):**
```spl
`powershell` EventCode=4104
  ScriptBlockText="*Software\\Classes\\CLSID\\*\\InProcServer32*"
| stats count min(_time) as firstTime max(_time) as lastTime
  by dest user EventID ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```
Catches PowerShell scripts that directly write to the COM registry path — the exact pattern used by attackers who use `New-Item` or `Set-ItemProperty` on CLSID keys.

**3. Hunt for any new InprocServer32 registry entries:**
```spl
| tstats `security_content_summariesonly` count
  FROM datamodel=Endpoint.Registry
  WHERE Registry.registry_path="*\\InProcServer32\\*"
  BY Registry.registry_path Registry.registry_value_data Registry.dest Registry.user
| `drop_dm_object_name(Registry)`
```
Broad hunt query — use after an incident or as a baseline sweep to find all new COM registrations.

**4. Detect DLL load from suspicious path via Sysmon (Event ID 7):**
```spl
`sysmon` EventCode=7
  NOT (ImageLoaded IN ("*\\system32\\*", "*\\syswow64\\*", "*\\winsxs\\*", "*\\wbem\\*"))
| search ImageLoaded IN ("*\\ProgramData\\*", "*\\AppData\\*", "*\\Temp\\*", "*\\Users\\*")
| stats count min(_time) as firstTime max(_time) as lastTime
  by Image ImageLoaded dest user
```
Catches the DLL actually being loaded from a non-standard path — this fires when the hijacked COM object gets invoked.

> **Prerequisites:** Requires Splunk with the CIM Endpoint data model. For Sysmon queries, the Sysmon TA must be installed.
> Source: [Splunk Security Content — research.splunk.com](https://research.splunk.com/endpoint/b7bd83c0-92b5-4fc7-b286-23eccfa2c561/)

---

### Elastic Security — EQL Rules

**1. Prebuilt rule — Component Object Model Hijacking:**

Elastic's prebuilt rule identifies COM hijacking via registry modification, targeting adversaries that establish persistence by executing malicious content through hijacked COM object references.

Rule metadata:
- **Type:** EQL
- **Index:** `logs-endpoint.events.registry-*`
- **Severity:** Low | **Risk Score:** 21
- **Tactic:** Persistence, Defense Evasion, Privilege Escalation

```eql
registry where host.os.type == "windows" and event.type == "change"
  and user.domain != "NT AUTHORITY"
  and process.executable != null
  and (
    /* Script-based COM server registration via scrobj.dll */
    (
      registry.path : "HK*\\InprocServer32\\"
      and registry.data.strings : ("scrobj.dll", "?:\\*\\scrobj.dll")
      and not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*"
    )
    or
    /* HKLM InprocServer32 pointing to user-writable paths */
    (
      registry.path : "HKLM\\*\\InProcServer32\\*"
      and registry.data.strings : ("*\\Users\\*", "*\\ProgramData\\*")
    )
    or
    /* Any InprocServer32 change in the user hive — high signal, low noise */
    (
      registry.path : (
        "HKEY_USERS\\*\\InprocServer32\\",
        "HKEY_USERS\\*\\LocalServer32\\",
        "HKEY_USERS\\*\\DelegateExecute",
        "HKEY_USERS\\*\\TreatAs\\",
        "HKEY_USERS\\*\\ScriptletURL*"
      )
    )
  )
```

**2. Custom KQL hunt — HKCU InprocServer32 writes:**
```kql
event.category: "registry" and
event.type: "change" and
registry.path: *HKEY_USERS* and
registry.path: *InprocServer32* and
not user.name: ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
```

**3. Timeline query — correlate registry write → DLL load:**
```eql
sequence by host.id with maxspan=5m
  [registry where registry.path : "HKEY_USERS\\*\\InprocServer32\\"
   and event.type == "change"]
  [library where dll.path : ("*\\ProgramData\\*", "*\\AppData\\*", "*\\Temp\\*")]
```
This sequence rule fires when a HKCU InprocServer32 registry change is followed within 5 minutes by a DLL load from a suspicious path — very high fidelity signal.

> Source: [Elastic Prebuilt Rule — persistence_suspicious_com_hijack_registry](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_suspicious_com_hijack_registry)

---

### Sysmon Configuration

To capture the events needed for these queries, configure Sysmon with at minimum:

```xml
<!-- Event ID 12/13: Registry key creation and value modification -->
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">InprocServer32</TargetObject>
  <TargetObject condition="contains">HKCU\SOFTWARE\Classes\CLSID</TargetObject>
  <TargetObject condition="contains">HKEY_USERS</TargetObject>
</RegistryEvent>

<!-- Event ID 7: DLL image load -->
<ImageLoad onmatch="include">
  <ImageLoaded condition="contains">\ProgramData\</ImageLoaded>
  <ImageLoaded condition="contains">\AppData\</ImageLoaded>
  <ImageLoaded condition="contains">\Temp\</ImageLoaded>
</ImageLoad>
```

Key Sysmon Event IDs for COM Hijacking detection:
| Event ID | Description |
|---|---|
| 12 | Registry key/value created or deleted |
| 13 | Registry value modified |
| 7 | DLL/Image loaded into process |
| 1 | Process creation (reg.exe, powershell.exe) |

---

## References

- [MITRE ATT&CK T1546.015](https://attack.mitre.org/techniques/T1546/015/)
- [Sysmon Event IDs — Registry & Image Load](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk — COM Hijacking InprocServer32 Detection](https://research.splunk.com/endpoint/b7bd83c0-92b5-4fc7-b286-23eccfa2c561/)
- [Splunk — PowerShell COM Hijacking Detection](https://research.splunk.com/endpoint/ea61e291-af05-4716-932a-67faddb6ae6f/)
- [Elastic Security — COM Hijacking Prebuilt Rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_suspicious_com_hijack_registry)
- [LinkedIn — Looking at COM Hijacking with Splunk & Sysmon (Nathan Webb)](https://www.linkedin.com/pulse/looking-com-hijacking-splunk-sysmon-nathan-webb-vfyce/)
- [Abusing the COM Registry Structure — bohops](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)
- [Revisiting COM Hijacking — SpecterOps](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [Atomic Red Team — T1546.015](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.015/T1546.015.md)

---

## License

MIT License — use freely, contribute back.
