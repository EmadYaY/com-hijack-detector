#Requires -Version 5.1
<#
.SYNOPSIS
    COM Hijack Detector - Detects potential COM Object Hijacking via registry analysis.

.DESCRIPTION
    Compares CLSIDs registered under HKCU (Current User) against HKLM (Local Machine).
    When a CLSID exists in both hives but points to different DLL paths, it is flagged
    as a potential COM Hijacking attempt (MITRE ATT&CK T1546.015).

    Modes:
        Scan   - Live scan on this machine, compare HKCU vs HKLM.
        Export - Export registry data as JSON for Python analysis on another machine.

.PARAMETER Mode
    Operation mode. Valid values: 'Scan', 'Export'.

.PARAMETER OutputPath
    Path to save the JSON export. Used in Export mode.
    Default: .\com_baseline_export.json

.PARAMETER ReportPath
    Path to save the CSV report. Used in Scan mode.
    Default: .\com_hijack_report.csv

.PARAMETER ExportFormat
    Format for export file. Valid values: 'JSON', 'CSV'. Default: 'JSON'.

.EXAMPLE
    .\Invoke-COMHijackDetector.ps1 -Mode Scan

.EXAMPLE
    .\Invoke-COMHijackDetector.ps1 -Mode Export -OutputPath "C:\Exports\dump.json"

.EXAMPLE
    .\Invoke-COMHijackDetector.ps1 -Mode Scan -ReportPath "C:\Reports\findings.csv"

.NOTES
    Author      : EmadYaY
    GitHub      : github.com/EmadYaY
    Version     : 1.0.0
    MITRE ATT&CK: T1546.015 - Component Object Model Hijacking
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('Scan', 'Export')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\com_baseline_export.json",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\com_hijack_report.csv",

    [Parameter(Mandatory = $false)]
    [ValidateSet('JSON', 'CSV')]
    [string]$ExportFormat = 'JSON'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ==============================================================
# BANNER
# ==============================================================
function Show-Banner {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  COM Hijack Detector  v1.0.0                " -ForegroundColor Cyan
    Write-Host "  MITRE ATT&CK: T1546.015                    " -ForegroundColor Cyan
    Write-Host "  github.com/EmadYaY                         " -ForegroundColor DarkCyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
}

# ==============================================================
# HELPER: Get InprocServer32 DLL path for a CLSID
# ==============================================================
function Get-DLLPath {
    param (
        [string]$RegistryPath
    )
    $inprocPath = Join-Path $RegistryPath "InprocServer32"
    if (Test-Path $inprocPath) {
        $val = (Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue)."(default)"
        if ($val) { return $val.Trim() }
    }
    return $null
}

# ==============================================================
# HELPER: Collect all CLSIDs from a registry hive
# ==============================================================
function Get-CLSIDMap {
    param (
        [string]$HivePath
    )
    $map = @{}
    $clsidRoot = Join-Path $HivePath "SOFTWARE\Classes\CLSID"

    if (-not (Test-Path $clsidRoot)) {
        Write-Warning "[!] Registry path not found: $clsidRoot"
        return $map
    }

    $clsids = Get-ChildItem -Path $clsidRoot -ErrorAction SilentlyContinue
    foreach ($clsid in $clsids) {
        $name         = $clsid.PSChildName
        $dllPath      = Get-DLLPath -RegistryPath $clsid.PSPath
        $friendlyName = (Get-ItemProperty -Path $clsid.PSPath -ErrorAction SilentlyContinue)."(default)"

        $map[$name] = [PSCustomObject]@{
            CLSID        = $name
            DLLPath      = $dllPath
            FriendlyName = if ($friendlyName) { $friendlyName } else { "" }
        }
    }
    return $map
}

# ==============================================================
# MODE: SCAN
# ==============================================================
function Invoke-LiveScan {
    Write-Host "[*] Starting live registry scan..." -ForegroundColor Yellow
    Write-Host "[*] Collecting HKLM CLSIDs..." -ForegroundColor Gray

    $hklmMap = Get-CLSIDMap -HivePath "HKLM:"
    Write-Host "    Found $($hklmMap.Count) CLSIDs in HKLM" -ForegroundColor Gray

    Write-Host "[*] Collecting HKCU CLSIDs..." -ForegroundColor Gray
    $hkcuMap = Get-CLSIDMap -HivePath "HKCU:"
    Write-Host "    Found $($hkcuMap.Count) CLSIDs in HKCU" -ForegroundColor Gray

    Write-Host "[*] Comparing entries..." -ForegroundColor Gray
    Write-Host ""

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hkcuOnly = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($clsid in $hkcuMap.Keys) {
        $hkcuEntry = $hkcuMap[$clsid]

        if ($hklmMap.ContainsKey($clsid)) {
            $hklmEntry = $hklmMap[$clsid]

            if ($hkcuEntry.DLLPath -and $hklmEntry.DLLPath) {
                if ($hkcuEntry.DLLPath -ne $hklmEntry.DLLPath) {
                    $findings.Add([PSCustomObject]@{
                        CLSID        = $clsid
                        FriendlyName = $hkcuEntry.FriendlyName
                        HKCU_DLL     = $hkcuEntry.DLLPath
                        HKLM_DLL     = $hklmEntry.DLLPath
                        Status       = "POSSIBLE COM HIJACK"
                        RiskLevel    = "HIGH"
                    })
                }
            }
        } else {
            if ($hkcuEntry.DLLPath) {
                $hkcuOnly.Add([PSCustomObject]@{
                    CLSID        = $clsid
                    FriendlyName = $hkcuEntry.FriendlyName
                    HKCU_DLL     = $hkcuEntry.DLLPath
                    HKLM_DLL     = "NOT PRESENT"
                    Status       = "HKCU ONLY"
                    RiskLevel    = "MEDIUM"
                })
            }
        }
    }

    Write-Host "=============================================" -ForegroundColor Red
    Write-Host "  SCAN RESULTS                              " -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host ""

    if ($findings.Count -eq 0) {
        Write-Host "[+] No COM Hijacking indicators found (HIGH risk)." -ForegroundColor Green
    } else {
        Write-Host "[!] HIGH RISK - Possible COM Hijacking: $($findings.Count) entries" -ForegroundColor Red
        Write-Host ""
        $findings | ForEach-Object {
            Write-Host "  CLSID    : $($_.CLSID)"        -ForegroundColor White
            Write-Host "  Name     : $($_.FriendlyName)" -ForegroundColor Gray
            Write-Host "  HKCU DLL : $($_.HKCU_DLL)"     -ForegroundColor Red
            Write-Host "  HKLM DLL : $($_.HKLM_DLL)"     -ForegroundColor Green
            Write-Host "  Status   : $($_.Status)"       -ForegroundColor Yellow
            Write-Host "  -------------------------------------------" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    if ($hkcuOnly.Count -gt 0) {
        Write-Host "[~] MEDIUM RISK - HKCU-only DLL entries: $($hkcuOnly.Count)" -ForegroundColor Yellow
        $hkcuOnly | ForEach-Object {
            Write-Host "  CLSID    : $($_.CLSID)"    -ForegroundColor White
            Write-Host "  HKCU DLL : $($_.HKCU_DLL)" -ForegroundColor Yellow
            Write-Host "  -------------------------------------------" -ForegroundColor DarkGray
        }
    }

    $allFindings = @($findings) + @($hkcuOnly)
    if ($allFindings.Count -gt 0) {
        $allFindings | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "[+] Report saved to: $ReportPath" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "[*] Scan complete. HIGH: $($findings.Count) | MEDIUM: $($hkcuOnly.Count)" -ForegroundColor Cyan
}

# ==============================================================
# MODE: EXPORT
# ==============================================================
function Invoke-Export {
    Write-Host "[*] Starting registry export..." -ForegroundColor Yellow

    $hklmMap = Get-CLSIDMap -HivePath "HKLM:"
    Write-Host "    Collected $($hklmMap.Count) HKLM entries" -ForegroundColor Gray

    $hkcuMap = Get-CLSIDMap -HivePath "HKCU:"
    Write-Host "    Collected $($hkcuMap.Count) HKCU entries" -ForegroundColor Gray

    $osCaption = ""
    $wmi = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($wmi) { $osCaption = $wmi.Caption }

    $exportData = [PSCustomObject]@{
        ExportedAt  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname    = $env:COMPUTERNAME
        Username    = $env:USERNAME
        OS          = $osCaption
        HKLM_CLSIDs = @($hklmMap.Values)
        HKCU_CLSIDs = @($hkcuMap.Values)
    }

    if ($ExportFormat -eq 'JSON') {
        $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "[+] Registry export saved to: $OutputPath" -ForegroundColor Cyan
        Write-Host "[*] Transfer this file to your analysis machine and run the Python analyzer." -ForegroundColor Yellow
    } else {
        $hklmPath = $OutputPath -replace '\.csv$', '_HKLM.csv'
        $hkcuPath = $OutputPath -replace '\.csv$', '_HKCU.csv'
        $hklmMap.Values | Export-Csv -Path $hklmPath -NoTypeInformation -Encoding UTF8
        $hkcuMap.Values | Export-Csv -Path $hkcuPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] HKLM exported to: $hklmPath" -ForegroundColor Cyan
        Write-Host "[+] HKCU exported to: $hkcuPath" -ForegroundColor Cyan
    }
}

# ==============================================================
# ENTRY POINT
# ==============================================================
Show-Banner

switch ($Mode) {
    'Scan'   { Invoke-LiveScan }
    'Export' { Invoke-Export }
}