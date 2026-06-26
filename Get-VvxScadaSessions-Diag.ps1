# Get-VvxScadaSessions-Diag.ps1 - read-only diagnostic collector for Get-VvxScadaSessions.ps1.
# Copyright (C) 2026  Adam Woodland
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version. Distributed WITHOUT ANY WARRANTY; see the GNU
# General Public License (LICENSE file) for details. <https://www.gnu.org/licenses/>.

<#
.SYNOPSIS
    Collects everything needed to diagnose problems with Get-VvxScadaSessions.ps1 (sessions not
    matched, wrong user resolved, slow runs, elevation/locale issues) into ONE text report.

.DESCRIPTION
    Read-only. Makes no changes to the system. Designed for a box that CANNOT have Claude (or any
    AI tooling) installed: run it there, copy the single output .txt off the machine, and paste it
    to a Claude instance that DOES have the project context to diagnose.

    It gathers, and times, every input the main script's join relies on:
      * environment (OS, PowerShell, culture/locale, elevation, hostname)
      * the main script's identity (path, size, SHA256) so the diagnosing side knows the exact version
      * live TCP connections to the SCADA port, and the owning processes (ViewX vs broker decoy)
      * all SE.Scada.ViewX processes (PID, SessionId, start time, owner, command line)
      * raw `quser` and `qwinsta` (WTS sessions, accounts, state, logon time) - parsing source
      * per-session ViewX log inventory (rollover/naming) + the relevant connect/logon/license lines
      * a PORT -> LOG cross-reference that mirrors the join, showing why each live port did/didn't match
      * the VirtualViewX web-auth log (timing-fallback source) + a locale parse check
      * the main script's OWN output and -Verbose stream (run with -AcceptDisclaimer), plus errors
      * an automatic "POTENTIAL ISSUES" triage of common failure modes

    PRIVACY: the report contains hostnames, usernames, IP addresses and SCADA usernames in clear.
    Treat it as sensitive (same as CLAUDE.md). Review before sending if that matters.

.PARAMETER ScadaPort
    SCADA server port the main script targets. Default 5481. (Mirror of the main script param.)

.PARAMETER ScadaServer
    Optional specific SCADA server IP/host to focus on. (Mirror of the main script param.)

.PARAMETER ViewXProcessName
    ViewX process name without extension. Default 'SE.Scada.ViewX'. (Mirror of the main script param.)

.PARAMETER LogRoot
    Root of the per-session ViewX logs.
    Default '%ProgramData%\Schneider Electric\ClearSCADA\Logs\ViewX'. (Mirror of the main script param.)

.PARAMETER AuthLog
    VirtualViewX web-auth log.
    Default '%ProgramData%\Schneider Electric\VirtualViewX\VirtualViewXAuthentication.log'. (Mirror.)

.PARAMETER AuthMatchWindowSeconds
    Web-auth timing-fallback window. Default 120. (Mirror of the main script param.)

.PARAMETER MainScript
    Path to Get-VvxScadaSessions.ps1. Default: same folder as this diagnostic script.

.PARAMETER OutputPath
    Report file to write. Default: .\VvxScadaDiag_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.txt in the
    current directory.

.PARAMETER LogSampleLines
    Max relevant log lines (per type, per session) to include from each ViewX log. Default 80.

.PARAMETER SkipRunMain
    Do not execute the main script; only collect the raw inputs.

.PARAMETER AcceptDisclaimer
    Confirms you accept the DISCLAIMER and run at your own risk. Required for non-interactive/scripted
    runs. If omitted in an interactive session, the disclaimer is shown and you are prompted (default
    No). Same gate as the main script.

.EXAMPLE
    .\Get-VvxScadaSessions-Diag.ps1
    # Interactive: prompts to accept the disclaimer, then collects everything (running the main script
    # too) into a timestamped .txt in the current dir.

.EXAMPLE
    # Non-interactive / scheduled: acceptance must be explicit via -AcceptDisclaimer.
    .\Get-VvxScadaSessions-Diag.ps1 -AcceptDisclaimer -SkipRunMain -OutputPath C:\Temp\diag.txt
#>

[CmdletBinding()]
param(
    [int]    $ScadaPort              = 5481,
    [string] $ScadaServer            = $null,
    [string] $ViewXProcessName       = 'SE.Scada.ViewX',
    [string] $LogRoot                = (Join-Path $env:ProgramData 'Schneider Electric\ClearSCADA\Logs\ViewX'),
    [string] $AuthLog                = (Join-Path $env:ProgramData 'Schneider Electric\VirtualViewX\VirtualViewXAuthentication.log'),
    [int]    $AuthMatchWindowSeconds = 120,
    [string] $MainScript             = (Join-Path $PSScriptRoot 'Get-VvxScadaSessions.ps1'),
    [string] $OutputPath,
    [int]    $LogSampleLines         = 80,
    [switch] $SkipRunMain,
    [switch] $AcceptDisclaimer
)

$ErrorActionPreference = 'Continue'

if (-not $OutputPath) {
    $stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Get-Location) ("VvxScadaDiag_{0}_{1}.txt" -f $env:COMPUTERNAME, $stamp)
}

# Shared state populated during collection and reused by the triage section.
$script:OutputPath = $OutputPath
$script:Issues     = New-Object System.Collections.Generic.List[string]
$script:LiveViewX  = @()   # [PSCustomObject] PID, SessionId, LocalPort, RemoteAddress
$script:LivePorts  = @()   # int[]
$script:ViewXProcs = @()   # Win32_Process for ViewX
$script:Elevated   = $false

# ---------------------------------------------------------------------------
# Disclaimer gate (same text/behaviour as Get-VvxScadaSessions.ps1)
# ---------------------------------------------------------------------------
# Returns $true if accepted (via -AcceptDisclaimer or an interactive prompt); throws on a
# non-interactive run with no -AcceptDisclaimer; returns $false if declined.
function Confirm-Disclaimer {
    param([switch]$Accepted)

    $disclaimer = @'
------------------------------------------------------------------------------
 Get-VvxScadaSessions-Diag.ps1  Copyright (C) 2026  Adam Woodland
 Licensed under the GNU GPL v3 (see the LICENSE file). This is free software,
 and you are welcome to redistribute it under those conditions.

 DISCLAIMER
 This script is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or
 implied. The author accepts no liability for any damages arising from its use.
 It reads live network/process/log state for diagnostics and is NOT certified
 for production SCADA systems. Do NOT run it on a production or safety-critical
 system without first reviewing the code and testing on a representative non-
 production system. You run it at your own risk and remain responsible for your
 own change-control and security policies.
------------------------------------------------------------------------------
'@

    if ($Accepted) {
        Write-Verbose 'Disclaimer accepted via -AcceptDisclaimer.'
        return $true
    }

    # Can we prompt? Need an interactive host with a real (non-redirected) input stream.
    $canPrompt = [Environment]::UserInteractive
    try { if ([Console]::IsInputRedirected) { $canPrompt = $false } } catch { }

    if (-not $canPrompt) {
        Write-Host $disclaimer -ForegroundColor Yellow
        throw 'Disclaimer not accepted (non-interactive session). Re-run with -AcceptDisclaimer to confirm acceptance.'
    }

    Write-Host ''
    Write-Host $disclaimer -ForegroundColor Yellow
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'I accept the terms and have tested appropriately.'
    $no  = New-Object System.Management.Automation.Host.ChoiceDescription '&No',  'Do not run.'
    $choices = [System.Management.Automation.Host.ChoiceDescription[]]@($yes, $no)
    try {
        $decision = $Host.UI.PromptForChoice('Disclaimer', 'Do you accept these terms and confirm you have tested appropriately?', $choices, 1)
    } catch {
        # Host refused to prompt (e.g. -NonInteractive) -> treat as non-interactive.
        throw 'Disclaimer not accepted (host could not prompt). Re-run with -AcceptDisclaimer to confirm acceptance.'
    }
    if ($decision -ne 0) {
        Write-Warning 'Disclaimer not accepted. Exiting without running.'
        return $false
    }
    return $true
}

# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------
function Add-Line { param([string]$Text = '') ; Add-Content -LiteralPath $script:OutputPath -Value $Text }

function Add-Issue { param([string]$Text) ; $script:Issues.Add($Text) }

# Run a collection step; capture ALL its output+errors into the report; time it; never abort.
function Invoke-Section {
    param([string]$Title, [scriptblock]$Body)
    $start = Get-Date
    Add-Line ''
    Add-Line ('=' * 80)
    Add-Line "## $Title"
    Add-Line ('=' * 80)
    try {
        # Stream the body's pipeline output to the report as it is produced, so it interleaves in
        # execution order with the body's own direct Add-Line calls (avoids "tables after text").
        & $Body 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Add-Line "[ERROR] $($_.Exception.Message)"
            } else {
                $s = ($_ | Out-String).TrimEnd()
                if ($s) { Add-Line $s }
            }
        }
    } catch {
        Add-Line "[SECTION ERROR] $($_.Exception.Message)"
        if ($_.ScriptStackTrace) { Add-Line $_.ScriptStackTrace }
    }
    $ms = [int]((Get-Date) - $start).TotalMilliseconds
    Add-Line ''
    Add-Line "[section '$Title' took ${ms} ms]"
    Write-Host ("  - {0,-34} {1,7} ms" -f $Title, $ms)
}

$GuidRegex   = '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
$RunTagRegex = '\[([0-9A-Fa-f]+):[0-9A-Fa-f]+\]'   # leftmost "[<hex>:<thread>]" run tag (no-GUID builds)
$LogonRegex  = "Logon\(\s*IN:\s*Username\s*'([^']+)'"

# Per-run join anchor for a line, mirroring the MAIN script: prefer a GUID, else the "[<hex>:<thread>]"
# run tag (6.87 / Geo SCADA Expert 2025 writes no GUID). Returns '' if neither is present.
function Get-LineAnchor {
    param([string]$Line)
    if ($Line -match $GuidRegex)   { return $matches[1].ToUpperInvariant() }
    if ($Line -match $RunTagRegex) { return $matches[1].ToUpperInvariant() }
    return ''
}

# Fast, lock-tolerant log reader. PowerShell's Get-Content is slow (per-line decoration); use .NET.
# Opens with FileShare.ReadWrite so it can read a log ViewX currently has open for writing.
function Read-LogLines {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs)
        $text = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        if ([string]::IsNullOrEmpty($text)) { return @() }
        return [regex]::Split($text, "`r`n|`n|`r")
    } catch { return @() }
}

# All ViewX log files in a Session_<N> folder (matches the main script's generic glob).
function Get-SessionLogFiles {
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return @() }
    Get-ChildItem -LiteralPath $Folder -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' }
}

# Candidate ViewX log files for a given Windows SessionId, mirroring the MAIN script's selection
# across both on-disk layouts:
#   * per-session subfolder : LogRoot\Session_<N>\*SE.Scada.ViewX*log*   (newer versions)
#   * flat (Geo SCADA 2023) : *SE.Scada.ViewX*log* directly in LogRoot   (session number in filename)
# In the flat case the main script reads ALL ViewX logs (the port->GUID anchor, not the folder,
# disambiguates), so the diagnostic must return the same full set to stay an accurate mirror.
function Get-ViewXLogFiles {
    param([int]$SessionId)
    $folder = Join-Path $LogRoot ("Session_{0}" -f $SessionId)
    if (Test-Path -LiteralPath $folder) { return @(Get-SessionLogFiles -Folder $folder) }
    if (Test-Path -LiteralPath $LogRoot) {
        return @(Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' })
    }
    return @()
}

# FileVersionInfo for an on-disk file (no elevation needed to read version info of a readable file).
function Get-FileVersionInfoSafe {
    param([string]$Path)
    try {
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        }
    } catch { }
    return $null
}

# ViewX product/version from the per-run startup banner each ViewX writes near the top of its log, e.g.
#   Product           : EcoStruxure Geo SCADA Expert 2025 Build 6.87.9552.1 (X86 Release)
#   Starting:  EcoStruxure Geo SCADA Expert 2025
#   Version:   6.87.9552.1
# Returns distinct {File, Product, Version} (newest files first). Reads each file only until it has
# both fields (capped) - logs are large, the banner is near the start of each run.
function Get-ViewXLogVersions {
    param([object[]]$Files)
    $found = New-Object System.Collections.Generic.List[object]
    $seen  = New-Object System.Collections.Generic.HashSet[string]
    foreach ($f in (@($Files) | Sort-Object LastWriteTime -Descending)) {
        $product = $null; $version = $null
        try {
            $fs = [System.IO.File]::Open($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $sr = New-Object System.IO.StreamReader($fs)
            $n = 0
            while (-not $sr.EndOfStream -and $n -lt 20000) {
                $line = $sr.ReadLine(); $n++
                if (-not $product -and $line -match 'Product\s*:\s*(.+?)\s*$')         { $product = $matches[1].Trim() }
                if (-not $product -and $line -match 'Starting:\s*(.+?)\s*$')           { $product = $matches[1].Trim() }
                if (-not $version -and $line -match 'Version:\s*([0-9]+(?:\.[0-9]+)+)') { $version = $matches[1] }
                if ($product -and $version) { break }
            }
            $sr.Close(); $fs.Close()
        } catch { }
        if ($product -or $version) {
            $key = "$product|$version"
            if ($seen.Add($key)) {
                $found.Add([PSCustomObject]@{ File = $f.Name; Product = $product; Version = $version; LastWrite = $f.LastWriteTime })
            }
        }
    }
    return $found
}

# Inventory + relevant-line analysis for ONE set of ViewX log files (a Session_<N> folder, or the
# flat LogRoot set). Reads each rolled file once, then reports byte/line inventory, distinct run
# GUIDs, connect/Logon/license-reject counts and sample lines, and raises the same triage issues.
# $Label is only a heading. Used by section 6 for both layouts so the evidence is identical either way.
function Show-LogFileSetAnalysis {
    param([string]$Label, [object[]]$Files)
    $Files = @($Files)
    if (-not $Files) { Add-Line ("  (no files match '*SE.Scada.ViewX*log*' for {0})" -f $Label) ; return }

    # Read each rolled file ONCE (oldest->newest): inventory AND keep the lines for filtering below.
    $totalBytes = 0; $totalLines = 0
    $lines = New-Object System.Collections.Generic.List[string]
    $inv = foreach ($f in ($Files | Sort-Object LastWriteTime)) {
        $content = @(Read-LogLines -Path $f.FullName)
        $lc = $content.Count
        $totalBytes += $f.Length; $totalLines += $lc
        if ($lc -gt 0) { $lines.AddRange([string[]]$content) }
        [PSCustomObject]@{ Name=$f.Name; Bytes=$f.Length; Lines=$lc; LastWrite=$f.LastWriteTime }
    }
    $inv | Format-Table -AutoSize | Out-String
    Add-Line ("  rolled files: {0}   total: {1:N0} bytes, {2:N0} lines" -f ($Files|Measure-Object).Count, $totalBytes, $totalLines)
    if ($totalBytes -gt 50MB) { Add-Issue ("{0}: {1:N0} bytes of ViewX logs are read in full on every run -> a likely cause of slow runs." -f $Label, $totalBytes) }

    # Classify in ONE plain foreach pass (avoids ~5 pipeline passes over what can be 100k+ lines).
    # Track BOTH anchor styles the main script understands: GUIDs and "[<hex>:<thread>]" run tags.
    $connect   = New-Object System.Collections.Generic.List[string]
    $logons    = New-Object System.Collections.Generic.List[string]
    $license   = New-Object System.Collections.Generic.List[string]
    $guidSet   = New-Object System.Collections.Generic.HashSet[string]
    $runTagSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($line in $lines) {
        if ($line -match 'from\s+\S+:\d+\)') { $connect.Add($line) }
        if ($line -match $LogonRegex)        { $logons.Add($line) }
        if ($line -match 'Client License Rejected|C014006A|SCX_E_NO_LICENCE') { $license.Add($line) }
        if ($line -match $GuidRegex)         { [void]$guidSet.Add($matches[1].ToUpperInvariant()) }
        elseif ($line -match $RunTagRegex)   { [void]$runTagSet.Add($matches[1].ToUpperInvariant()) }
    }

    Add-Line ("  distinct run GUIDs: {0}   distinct run tags '[hex:..]': {1}   connect-from lines: {2}   Logon lines: {3}   license-reject lines: {4}" -f $guidSet.Count, $runTagSet.Count, $connect.Count, $logons.Count, $license.Count)
    if ($guidSet.Count -eq 0 -and $runTagSet.Count -gt 0 -and ($connect.Count -gt 0 -or $logons.Count -gt 0)) {
        Add-Line ("  (no GUID anchors; this build tags lines '[<hex>:<thread>]' - the main script's dual-anchor join uses the '[<hex>:' run tag here.)")
    }
    if ($guidSet.Count -eq 0 -and $runTagSet.Count -eq 0 -and ($connect.Count -gt 0 -or $logons.Count -gt 0)) {
        Add-Issue ("{0}: connect/Logon lines exist but NEITHER a GUID nor a '[<hex>:<thread>]' run tag was found on any line -> the main script's port->user join has no anchor to key on and will fall back to 'most recent Logon in the folder' (unreliable). The log line format has likely changed; capture a sample." -f $Label)
    }
    if ($logons.Count -eq 0 -and $license.Count -gt 0) {
        Add-Issue ("{0}: has license-rejection lines and NO Logon line -> classic license-rejected session; SCADA user only resolvable via web-auth timing fallback." -f $Label)
    }
    if ($logons.Count -eq 0 -and $license.Count -eq 0 -and $connect.Count -gt 0) {
        Add-Issue ("{0}: has connect lines but NO Logon line and NO license rejection -> low log verbosity? The ViewX-log join will fail here." -f $Label)
    }

    Add-Line ''
    Add-Line ("  last {0} connect-from lines:" -f $LogSampleLines)
    ($connect | Select-Object -Last $LogSampleLines | ForEach-Object { "    $_" }) -join "`n"
    Add-Line ''
    Add-Line ("  last {0} Logon lines:" -f $LogSampleLines)
    ($logons | Select-Object -Last $LogSampleLines | ForEach-Object { "    $_" }) -join "`n"
    if ($license.Count -gt 0) {
        Add-Line ''
        Add-Line "  last 10 license-reject lines:"
        ($license | Select-Object -Last 10 | ForEach-Object { "    $_" }) -join "`n"
    }
}

# ---------------------------------------------------------------------------
# Disclaimer gate - must be accepted before anything is read or written.
# ---------------------------------------------------------------------------
if (-not (Confirm-Disclaimer -Accepted:$AcceptDisclaimer)) { return }

# ---------------------------------------------------------------------------
# Start report
# ---------------------------------------------------------------------------
Set-Content -LiteralPath $script:OutputPath -Value "Get-VvxScadaSessions DIAGNOSTIC REPORT" -ErrorAction Stop
Add-Line ("Generated : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Add-Line ("Host      : {0}" -f $env:COMPUTERNAME)
Add-Line  "------------------------------------------------------------------------------"
Add-Line  "REVIEW BEFORE SHARING: this file contains REAL hostnames, Windows + SCADA"
Add-Line  "usernames and IP addresses. Open it and redact anything sensitive before sending"
Add-Line  "it anywhere - e.g. mask IP octets 192.168.10.10 -> x.x.10.10, and rename hosts/"
Add-Line  "users. Keep redactions CONSISTENT (same value -> same replacement everywhere) so"
Add-Line  "ports / users / GUIDs still line up across sections, or diagnosis gets harder."
Add-Line  "Then give the reviewed file to the Claude instance with the project context."
Add-Line  "------------------------------------------------------------------------------"

Write-Host ""
Write-Host "Collecting Vvx SCADA diagnostics -> $script:OutputPath"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Environment / elevation / locale
# ---------------------------------------------------------------------------
Invoke-Section 'Environment & elevation' {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:Elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [PSCustomObject]@{
        ComputerName    = $env:COMPUTERNAME
        RunningAsUser   = $id.Name
        Elevated        = $script:Elevated
        OS              = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        OSVersion       = [Environment]::OSVersion.Version.ToString()
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        PSEdition       = $PSVersionTable.PSEdition
        Culture         = (Get-Culture).Name
        UICulture       = (Get-UICulture).Name
        UserInteractive = [Environment]::UserInteractive
    } | Format-List | Out-String

    if (-not $script:Elevated) {
        Add-Issue "Not elevated: LocalViewXRunAsUser will show '(unknown - run elevated)' for cross-session processes. Everything else still resolves."
    }
    if ((Get-Culture).Name -ne 'en-US') {
        Add-Issue ("Culture is '{0}' (not en-US): quser logon-time and auth-log timestamp parsing use current culture. Check the 'date parse check' results below for failures." -f (Get-Culture).Name)
    }
}

# ---------------------------------------------------------------------------
# 2. Parameters & main-script identity
# ---------------------------------------------------------------------------
Invoke-Section 'Parameters & main-script identity' {
    [PSCustomObject]@{
        ScadaPort              = $ScadaPort
        ScadaServer            = if ($ScadaServer) { $ScadaServer } else { '(auto-detect)' }
        ViewXProcessName       = $ViewXProcessName
        LogRoot                = $LogRoot
        AuthLog                = $AuthLog
        AuthMatchWindowSeconds = $AuthMatchWindowSeconds
        MainScript             = $MainScript
        LogSampleLines         = $LogSampleLines
        SkipRunMain            = [bool]$SkipRunMain
    } | Format-List | Out-String

    Add-Line "LogRoot exists  : $([bool](Test-Path -LiteralPath $LogRoot))"
    Add-Line "AuthLog exists  : $([bool](Test-Path -LiteralPath $AuthLog))"
    if (-not (Test-Path -LiteralPath $LogRoot)) { Add-Issue "LogRoot not found: $LogRoot - the ViewX-log join cannot work. Wrong -LogRoot or non-default install path?" }
    if (-not (Test-Path -LiteralPath $AuthLog)) { Add-Issue "AuthLog not found: $AuthLog - the web-auth timing fallback cannot work (license-rejected sessions will stay unresolved)." }

    if (Test-Path -LiteralPath $MainScript) {
        $fi = Get-Item -LiteralPath $MainScript
        $h  = (Get-FileHash -LiteralPath $MainScript -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        Add-Line ''
        Add-Line "Main script    : present"
        Add-Line "  Size         : $($fi.Length) bytes"
        Add-Line "  LastWrite    : $($fi.LastWriteTime)"
        Add-Line "  SHA256       : $h"
    } else {
        Add-Line ''
        Add-Line "Main script    : NOT FOUND at $MainScript"
        Add-Issue "Main script not found at $MainScript - pass -MainScript or run the diag from the same folder."
    }
}

# ---------------------------------------------------------------------------
# 3. Live TCP state (and broker decoy)
# ---------------------------------------------------------------------------
Invoke-Section 'Live TCP connections to SCADA port' {
    $all = Get-NetTCPConnection -State Established -RemotePort $ScadaPort -ErrorAction SilentlyContinue
    if ($ScadaServer) { $all = $all | Where-Object { $_.RemoteAddress -eq $ScadaServer } }

    if (-not $all) {
        Add-Line "No ESTABLISHED connections to remote port $ScadaPort."
        Add-Issue "No established connections to :$ScadaPort - either no ViewX clients are connected right now, or -ScadaPort/-ScadaServer is wrong. See the 'all remote ports in use' list below."
        # Help spot a wrong port: what remote ports DO have established connections?
        Add-Line ''
        Add-Line "All ESTABLISHED remote ports currently in use (to spot a wrong -ScadaPort):"
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Group-Object RemotePort | Sort-Object Count -Descending |
            Select-Object -First 20 Count, Name | Format-Table -AutoSize | Out-String
        return
    }

    $rows = foreach ($c in $all) {
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalPort    = $c.LocalPort
            RemoteAddr   = $c.RemoteAddress
            PID          = $c.OwningProcess
            ProcName     = if ($p) { $p.ProcessName } else { '(gone)' }
            SessionId    = if ($p) { $p.SessionId } else { '?' }
            IsViewX      = ($p -and $p.ProcessName -eq $ViewXProcessName)
        }
    }
    $rows | Sort-Object SessionId, LocalPort | Format-Table -AutoSize | Out-String

    $script:LiveViewX = $rows | Where-Object { $_.IsViewX }
    $script:LivePorts = @($script:LiveViewX.LocalPort | Sort-Object -Unique)

    $broker = $rows | Where-Object { $_.ProcName -like '*Broker*' -or ($_.ProcName -ne $ViewXProcessName -and $_.ProcName -ne '(gone)') }
    Add-Line ''
    Add-Line ("ViewX-owned connections : {0}" -f ($script:LiveViewX | Measure-Object).Count)
    Add-Line ("Live ViewX ephemeral ports: {0}" -f ($(if ($script:LivePorts) { $script:LivePorts -join ', ' } else { '(none)' })))
    Add-Line ("Non-ViewX connections to :$ScadaPort (expected: the Thinfinity broker decoy): {0}" -f ($broker | Measure-Object).Count)
    if ($broker) { $broker | Format-Table -AutoSize | Out-String }
    if (-not $script:LiveViewX) {
        Add-Issue "Connections to :$ScadaPort exist but NONE are owned by '$ViewXProcessName'. Wrong -ViewXProcessName, or only the broker is connected."
    }
}

# ---------------------------------------------------------------------------
# 4. ViewX processes
# ---------------------------------------------------------------------------
Invoke-Section 'ViewX processes (PID / Session / start / owner / cmdline)' {
    $script:ViewXProcs = Get-CimInstance Win32_Process -Filter "Name='$ViewXProcessName.exe'" -ErrorAction SilentlyContinue
    if (-not $script:ViewXProcs) {
        Add-Line "No '$ViewXProcessName.exe' processes running."
        return
    }
    foreach ($p in $script:ViewXProcs) {
        $owner = $null
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" } else { $owner = "(GetOwner rc=$($o.ReturnValue))" }
        } catch { $owner = '(GetOwner failed - needs admin for cross-session)' }
        [PSCustomObject]@{
            PID            = $p.ProcessId
            SessionId      = $p.SessionId
            StartTime      = $p.CreationDate
            RunAsOwner     = $owner
            ExecutablePath = $p.ExecutablePath   # blank cross-session without elevation
            CommandLine    = $p.CommandLine
        } | Format-List | Out-String
    }

    # ViewX whose SessionId yields no readable ViewX log in EITHER layout = guaranteed unresolved from logs.
    foreach ($p in $script:ViewXProcs) {
        if (-not (Get-ViewXLogFiles -SessionId $p.SessionId)) {
            $folder = Join-Path $LogRoot ("Session_{0}" -f $p.SessionId)
            Add-Issue ("ViewX PID {0} is in SessionId {1} but no ViewX log files were found (neither '{2}\' nor flat in LogRoot) -> its SCADA user can't come from a ViewX log (auth-timing fallback only)." -f $p.ProcessId, $p.SessionId, $folder)
        }
    }
}

# ---------------------------------------------------------------------------
# 4b. ViewX version (from the exe and from the log startup banner)
# ---------------------------------------------------------------------------
# Records WHICH ViewX/Geo SCADA build produced this report, so behaviour that is version-specific
# (log line format, GUID vs '[hex:thread]' run tags, folder layout) can be tied to a known version.
# Two independent sources, reported and cross-checked:
#   * the exe's FileVersionInfo (authoritative for the installed binary)
#   * the 'Product/Version' startup banner inside the ViewX log (what actually ran, per session)
Invoke-Section 'ViewX version (exe + log banner)' {
    # ----- (a) exe FileVersionInfo -----
    Add-Line "----- exe version (FileVersionInfo) -----"
    $exePaths = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($script:ViewXProcs)) { if ($p.ExecutablePath) { [void]$exePaths.Add($p.ExecutablePath) } }
    # Common default install locations (probed only if the live process path was blank/unelevated).
    foreach ($pp in @(
        (Join-Path ${env:ProgramFiles(x86)} 'Schneider Electric\ClearSCADA\SE.Scada.ViewX.exe'),
        (Join-Path $env:ProgramFiles        'Schneider Electric\ClearSCADA\SE.Scada.ViewX.exe')
    )) { if ($pp -and (Test-Path -LiteralPath $pp)) { [void]$exePaths.Add($pp) } }
    $exePaths = @($exePaths | Select-Object -Unique)

    $exeVersion = $null
    if (-not $exePaths) {
        Add-Line "  No ViewX exe path resolved (process ExecutablePath is blank without elevation, and the exe"
        Add-Line "  was not at a probed default install path). Pass an explicit path or run elevated; the log"
        Add-Line "  banner below still provides the version."
    } else {
        foreach ($ep in $exePaths) {
            $vi = Get-FileVersionInfoSafe -Path $ep
            if ($vi) {
                if (-not $exeVersion) { $exeVersion = $vi.ProductVersion }
                [PSCustomObject]@{
                    Path           = $ep
                    ProductName    = $vi.ProductName
                    ProductVersion = $vi.ProductVersion
                    FileVersion    = $vi.FileVersion
                } | Format-List | Out-String
            } else {
                Add-Line "  (could not read version info for: $ep)"
            }
        }
    }

    # ----- (b) log startup banner -----
    Add-Line ''
    Add-Line "----- log banner version (Product / Version line each ViewX writes at startup) -----"
    $allLogs = @()
    if (Test-Path -LiteralPath $LogRoot) {
        $allLogs = @(Get-ChildItem -LiteralPath $LogRoot -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' })
    }
    $logVersions = @(Get-ViewXLogVersions -Files $allLogs)
    if (-not $logVersions) {
        Add-Line "  (no Product/Version startup banner found in any ViewX log)"
    } else {
        ($logVersions | Format-Table -AutoSize | Out-String)
        if ($logVersions.Count -gt 1) {
            Add-Issue ("More than one ViewX version appears across the logs ({0}) - the box was likely upgraded; older sessions/logs may differ from the running build." -f (($logVersions | ForEach-Object { $_.Version }) -join ', '))
        }
    }

    # ----- cross-check exe vs log -----
    $logVer = if ($logVersions) { $logVersions[0].Version } else { $null }
    if ($exeVersion -and $logVer -and ($exeVersion -notlike "*$logVer*") -and ($logVer -notlike "*$exeVersion*")) {
        Add-Issue ("ViewX exe version ('{0}') differs from the newest log-banner version ('{1}') - upgraded since the logs were written, or the probed exe is not the one that ran." -f $exeVersion, $logVer)
    }
}

# ---------------------------------------------------------------------------
# 5. WTS sessions (raw quser + qwinsta)
# ---------------------------------------------------------------------------
Invoke-Section 'WTS sessions - raw quser & qwinsta' {
    Add-Line "----- quser (verbatim; the main script parses THIS for account/state/logon-time) -----"
    $q = (quser 2>&1 | Out-String)
    if ($q) { Add-Line $q.TrimEnd() } else { Add-Line '(quser returned nothing)' ; Add-Issue "quser returned nothing - session account/state/start columns will be blank; the script then falls back to the process owner." }
    Add-Line ''
    Add-Line "----- qwinsta / query session (verbatim; cross-check) -----"
    $qw = (qwinsta 2>&1 | Out-String)
    if ($qw) { Add-Line $qw.TrimEnd() } else { Add-Line '(qwinsta returned nothing)' }
}

# ---------------------------------------------------------------------------
# 6. ViewX logs: RAW recursive tree (catches name/structure changes) + per-session inventory & lines
# ---------------------------------------------------------------------------
Invoke-Section 'ViewX log tree (raw) + inventory & lines' {
    if (-not (Test-Path -LiteralPath $LogRoot)) { Add-Line "LogRoot does not exist: $LogRoot" ; return }

    # ----- RAW recursive listing of EVERYTHING under LogRoot -----
    # The main script reads LogRoot\Session_<N>\*SE.Scada.ViewX*log* (newer) OR flat *SE.Scada.ViewX*log*
    # directly in LogRoot (Geo SCADA 2023). Both the FILE NAMES and the FOLDER STRUCTURE have changed
    # across ViewX versions, so dump the whole tree verbatim - independent of any glob/convention - to
    # reveal further naming/layout changes that would silently break the join (a changed name/path just
    # looks like "no logs" otherwise).
    Add-Line "----- RAW recursive listing of LogRoot (independent of any naming/structure assumption) -----"
    Add-Line "LogRoot: $LogRoot"
    $rootLen  = $LogRoot.TrimEnd('\').Length + 1
    $allItems = @(Get-ChildItem -LiteralPath $LogRoot -Recurse -Force -ErrorAction SilentlyContinue)
    $cap = 2000
    ($allItems | Select-Object -First $cap |
        Select-Object @{n='RelPath';e={ $_.FullName.Substring($rootLen) }},
                      @{n='Type';e={ if ($_.PSIsContainer) { 'DIR' } else { 'file' } }},
                      @{n='Bytes';e={ if ($_.PSIsContainer) { $null } else { $_.Length } }},
                      LastWriteTime |
        Sort-Object RelPath | Format-Table -AutoSize | Out-String)
    Add-Line ("  total items under LogRoot: {0}{1}" -f $allItems.Count, $(if ($allItems.Count -gt $cap) { " (showing first $cap)" } else { '' }))

    # Files the main script's glob WOULD match, and where they live.
    $globMatched = @($allItems | Where-Object { -not $_.PSIsContainer -and $_.Name -like '*SE.Scada.ViewX*log*' })

    # (a) Log-like files the glob would MISS -> possible filename change.
    $looksLog = @($allItems | Where-Object {
        -not $_.PSIsContainer -and $_.Name -match '(?i)log' -and
        ($_.Name -match '(?i)viewx' -or $_.Name -match '(?i)scada') -and
        ($_.Name -notlike '*SE.Scada.ViewX*log*')
    })
    if ($looksLog.Count -gt 0) {
        Add-Line ''
        Add-Line "  POSSIBLE NAMING CHANGE - ViewX/SCADA log-like files NOT matched by glob '*SE.Scada.ViewX*log*':"
        ($looksLog | Select-Object @{n='RelPath';e={ $_.FullName.Substring($rootLen) }}, Length, LastWriteTime | Format-Table -AutoSize | Out-String)
        Add-Issue "Log-like files under LogRoot are NOT matched by the glob '*SE.Scada.ViewX*log*' (filenames may have changed) - the main script would skip them. See the RAW listing."
    }

    # (b) The main script reads TWO layouts: LogRoot\Session_<N>\* (newer) and flat *.* directly in
    #     LogRoot (Geo SCADA 2023). Flat files (1 path segment) are supported; anything in any OTHER
    #     location (deeper nesting / different subfolders) it would still miss.
    $matchedFlat  = @($globMatched | Where-Object { (($_.FullName.Substring($rootLen)) -split '\\').Count -eq 1 })
    $matchedOther = @($globMatched | Where-Object {
        $parts = $_.FullName.Substring($rootLen) -split '\\'
        -not (($parts.Count -eq 1) -or ($parts.Count -eq 2 -and $parts[0] -like 'Session_*'))
    })
    if ($matchedFlat.Count -gt 0) {
        Add-Line ''
        Add-Line ("  Flat-layout ViewX logs directly in LogRoot (Geo SCADA 2023 style, supported): {0} file(s)." -f $matchedFlat.Count)
    }
    if ($matchedOther.Count -gt 0) {
        Add-Line ''
        Add-Line "  POSSIBLE STRUCTURE CHANGE - ViewX log files in an UNRECOGNISED location (neither LogRoot\Session_<N>\ nor flat in LogRoot):"
        ($matchedOther | Select-Object @{n='RelPath';e={ $_.FullName.Substring($rootLen) }}, Length, LastWriteTime | Format-Table -AutoSize | Out-String)
        Add-Issue "ViewX log files exist in an unrecognised location (not LogRoot\Session_<N>\ and not flat in LogRoot) - the main script reads only those two layouts, so it would miss these."
    }

    $sessionFolders = Get-ChildItem -LiteralPath $LogRoot -Directory -Filter 'Session_*' -ErrorAction SilentlyContinue | Sort-Object Name
    if ($sessionFolders) {
        # Newer layout: one subfolder per Windows session.
        foreach ($sf in $sessionFolders) {
            Add-Line ''
            Add-Line ("----- {0} -----" -f $sf.Name)
            $files = Get-SessionLogFiles -Folder $sf.FullName
            if (-not $files) {
                Add-Line "  (no files match '*SE.Scada.ViewX*log*'; ALL items in this folder:)"
                $other = @(Get-ChildItem -LiteralPath $sf.FullName -Force -ErrorAction SilentlyContinue)
                if ($other) {
                    ($other | Select-Object @{n='Name';e={ if ($_.PSIsContainer) { $_.Name + '\' } else { $_.Name } }}, Length, LastWriteTime | Sort-Object Name | Format-Table -AutoSize | Out-String)
                } else { Add-Line "    (folder is empty)" }
                continue
            }
            Show-LogFileSetAnalysis -Label $sf.Name -Files $files
        }
    } else {
        # Flat (Geo SCADA 2023) layout: no Session_<N> subfolders; the logs sit directly in LogRoot with
        # the session number in the filename, and the main script reads them as one set (port-anchored).
        $flat = @(Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' })
        if ($flat) {
            Add-Line ''
            Add-Line "----- flat layout: all '*SE.Scada.ViewX*log*' directly in LogRoot (no Session_<N> subfolders) -----"
            Add-Line "(Geo SCADA 2023 style; the main script reads these directly and anchors on the ephemeral port.)"
            Show-LogFileSetAnalysis -Label '(flat LogRoot)' -Files $flat
        } else {
            Add-Line ''
            Add-Line "No Session_* folders AND no '*SE.Scada.ViewX*log*' files directly under $LogRoot (see RAW listing above)."
            Add-Issue "No ViewX logs found under LogRoot in either layout (Session_<N>\ or flat) - the ViewX-log join cannot work. Wrong -LogRoot, logging disabled, or naming changed; check the RAW listing."
        }
    }
}

# ---------------------------------------------------------------------------
# 7. PORT -> LOG cross-reference (mirrors the join: why each live port did/didn't match)
# ---------------------------------------------------------------------------
Invoke-Section 'Port -> log cross-reference (join mirror)' {
    if (-not $script:LivePorts) { Add-Line "No live ViewX ephemeral ports to cross-reference (see TCP section)." ; return }

    foreach ($lv in ($script:LiveViewX | Sort-Object SessionId, LocalPort)) {
        $port      = $lv.LocalPort
        $sessionId = $lv.SessionId
        $folder    = Join-Path $LogRoot ("Session_{0}" -f $sessionId)
        Add-Line ''
        Add-Line ("port {0}  (PID {1}, SessionId {2})" -f $port, $lv.PID, $sessionId)

        $files = Get-ViewXLogFiles -SessionId $sessionId
        if (-not $files) { Add-Line ("    no ViewX log files for SessionId {0} (looked in '{1}\' and flat in LogRoot) -> NO MATCH (would use auth-timing fallback)" -f $sessionId, $folder) ; continue }

        # Find the most-recent '(from ...:port)' across all rolled files (oldest->newest, last wins).
        # Anchor on the GUID if present, else the '[<hex>:<thread>]' run tag - same as the main script.
        $bestAnchor = ''; $bestFile = ''; $hitCount = 0
        foreach ($f in ($files | Sort-Object LastWriteTime)) {
            $ls = Read-LogLines -Path $f.FullName
            foreach ($line in $ls) {
                if ($line -match ("from\s+\S+:{0}\)" -f $port)) {
                    $hitCount++
                    $a = Get-LineAnchor $line
                    if ($a) { $bestAnchor = $a; $bestFile = $f.Name }
                }
            }
        }

        if (-not $bestAnchor) {
            Add-Line "    matches: $hitCount   -> NO anchor-keyed match (port not found in logs) -> auth-timing fallback"
            Add-Issue ("port {0} (SessionId {1}) not found in any ViewX log -> resolved only via web-auth timing (or unresolved). Rolled away or low verbosity?" -f $port, $sessionId)
            continue
        }

        # Most-recent Logon under that anchor = the user the main script would report.
        $user = ''
        foreach ($f in ($files | Sort-Object LastWriteTime)) {
            $ls = Read-LogLines -Path $f.FullName
            foreach ($line in $ls) {
                if ((Get-LineAnchor $line) -eq $bestAnchor -and $line -match $LogonRegex) { $user = $matches[1] }
            }
        }
        Add-Line ("    matches: {0}   newest in: {1}" -f $hitCount, $bestFile)
        Add-Line ("    run anchor (GUID or '[hex:..]' tag): {0}" -f $bestAnchor)
        Add-Line ("    resolved ScadaUser: {0}" -f $(if ($user) { "'$user' (source: ViewX log)" } else { '(anchor found but NO Logon under it -> license-rejected? auth-timing fallback)' }))
        if (-not $user) {
            Add-Issue ("port {0} (SessionId {1}) matched run anchor {2} but that anchor has no Logon line -> license-rejected; needs web-auth timing." -f $port, $sessionId, $bestAnchor)
        }
    }
}

# ---------------------------------------------------------------------------
# 8. Web-auth log (fallback source) + locale parse check
# ---------------------------------------------------------------------------
Invoke-Section 'VirtualViewX web-auth log & timing fallback' {
    if (-not (Test-Path -LiteralPath $AuthLog)) { Add-Line "AuthLog not found: $AuthLog" ; return }
    $fi = Get-Item -LiteralPath $AuthLog
    Add-Line ("AuthLog: {0}" -f $AuthLog)
    Add-Line ("  Size {0:N0} bytes  LastWrite {1}" -f $fi.Length, $fi.LastWriteTime)

    $rx = "^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*LogOn\(\s*\[IN\]\s*userName\s*=\s*'(?<user>[^']+)'"
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($line in (Read-LogLines -Path $AuthLog)) {
        if ($line -match $rx) {
            $parsed = $matches['ts'] -as [datetime]
            $events.Add([PSCustomObject]@{ Time = $matches['ts']; Parsed = $parsed; User = $matches['user'] })
        }
    }
    Add-Line ("  Parsed LogOn events: {0}" -f $events.Count)
    if ($events.Count -eq 0) {
        Add-Issue "No 'LogOn( [IN] userName = ... )' events parsed from AuthLog - different log format/version? The timing fallback will never resolve a user."
        return
    }

    $badParse = @($events | Where-Object { -not $_.Parsed })
    if ($badParse.Count -gt 0) {
        Add-Issue ("{0} auth-log timestamps did NOT parse as DateTime (locale mismatch?) -> timing fallback will mis-match. Example raw: '{1}'" -f $badParse.Count, $badParse[0].Time)
    }

    Add-Line ''
    Add-Line "  last 15 LogOn events (raw ts | parsed | user):"
    ($events | Select-Object -Last 15 | ForEach-Object {
        "    {0} | {1} | {2}" -f $_.Time, $(if ($_.Parsed) { 'OK' } else { 'PARSE-FAIL' }), $_.User
    }) -join "`n"

    # Show the fallback prediction for each live ViewX whose port did not resolve from a log.
    if ($script:ViewXProcs) {
        Add-Line ''
        Add-Line "  timing-fallback prediction per ViewX process (latest LogOn <= proc start, within $AuthMatchWindowSeconds s):"
        foreach ($p in $script:ViewXProcs) {
            $start = $p.CreationDate
            $cand  = $events | Where-Object { $_.Parsed -and $_.Parsed -le $start -and $_.Parsed -ge $start.AddSeconds(-$AuthMatchWindowSeconds) } | Select-Object -Last 1
            $pred  = if ($cand) { "'{0}' (LogOn {1}, {2:N0}s before start)" -f $cand.User, $cand.Time, ($start - $cand.Parsed).TotalSeconds } else { '(no LogOn in window)' }
            Add-Line ("    PID {0} SessionId {1} start {2} -> {3}" -f $p.ProcessId, $p.SessionId, $start, $pred)
        }
    }
}

# ---------------------------------------------------------------------------
# 9. Run the main script (output + -Verbose + errors + timing)
# ---------------------------------------------------------------------------
Invoke-Section 'Main script run (output, -Verbose, errors, timing)' {
    if ($SkipRunMain) { Add-Line "Skipped (-SkipRunMain)." ; return }
    if (-not (Test-Path -LiteralPath $MainScript)) { Add-Line "Main script not found: $MainScript" ; return }

    $mainParams = @{
        ScadaPort              = $ScadaPort
        ViewXProcessName       = $ViewXProcessName
        LogRoot                = $LogRoot
        AuthLog                = $AuthLog
        AuthMatchWindowSeconds = $AuthMatchWindowSeconds
        AcceptDisclaimer       = $true
        Verbose                = $true
    }
    if ($ScadaServer) { $mainParams['ScadaServer'] = $ScadaServer }

    $start = Get-Date
    $captured = & $MainScript @mainParams *>&1
    $ms = [int]((Get-Date) - $start).TotalMilliseconds

    $objects = @($captured | Where-Object { $_ -is [psobject] -and $_.PSObject.Properties['ScadaUser'] })
    $streams = @($captured | Where-Object { -not ($_ -is [psobject] -and $_.PSObject.Properties['ScadaUser']) })

    Add-Line ("Main script wall-clock: {0} ms" -f $ms)
    if ($ms -gt 15000) { Add-Issue ("Main script took {0} ms (>15s) - see ViewX log sizes for the likely cause." -f $ms) }
    Add-Line ''
    Add-Line "----- result rows ($($objects.Count)) -----"
    if ($objects.Count -gt 0) {
        ($objects | Format-List | Out-String).TrimEnd()
    } else {
        Add-Line "(no rows returned)"
    }
    Add-Line ''
    Add-Line "----- verbose / warnings / errors stream -----"
    if ($streams) { ($streams | ForEach-Object { $_.ToString() }) -join "`n" } else { Add-Line "(none)" }

    foreach ($o in $objects) {
        if ("$($o.ScadaUser)" -like '*unresolved*') {
            Add-Issue ("Result row unresolved: session '{0}', ports {1}. See its Port->log cross-reference and auth-fallback prediction above." -f $o.VVxManagedWindowsSession, $o.LocalEphemeralPort)
        }
    }
}

# ---------------------------------------------------------------------------
# 10. Potential issues (auto-triage)
# ---------------------------------------------------------------------------
Invoke-Section 'POTENTIAL ISSUES (auto-triage)' {
    if ($script:Issues.Count -eq 0) {
        Add-Line "No common problems auto-detected. If something is still wrong, the raw sections above have the evidence."
    } else {
        $i = 0
        foreach ($msg in $script:Issues) { $i++; Add-Line ("{0}. {1}" -f $i, $msg) }
    }
}

Write-Host ""
Write-Host "Done. Report written to:"
Write-Host "  $script:OutputPath"
Write-Host ""
Write-Host "===================  PLEASE READ THE REPORT BEFORE SHARING  ===================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  It contains REAL hostnames, Windows + SCADA usernames and IP addresses." -ForegroundColor Yellow
Write-Host "  Open it and remove / redact anything you consider sensitive before sending" -ForegroundColor Yellow
Write-Host "  it anywhere. For example:" -ForegroundColor Yellow
Write-Host ""
Write-Host "      mask IP octets    :  192.168.10.10  ->  x.x.10.10" -ForegroundColor Yellow
Write-Host "      rename hosts/users:  WIN-ABC123 -> HOST1 ,  adamwoodland -> usr1" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Keep each redaction CONSISTENT (same value -> same replacement everywhere)" -ForegroundColor Yellow
Write-Host "  so ports / users / GUIDs still line up across sections - otherwise the" -ForegroundColor Yellow
Write-Host "  diagnosis is harder." -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Then give the reviewed file to the Claude instance with the project context."
