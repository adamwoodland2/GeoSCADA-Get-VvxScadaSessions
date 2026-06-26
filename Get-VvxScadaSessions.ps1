# Get-VvxScadaSessions.ps1 - correlate Geo SCADA users to Virtual ViewX Windows sessions.
# Copyright (C) 2026  Adam Woodland
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program (see the
# LICENSE file). If not, see <https://www.gnu.org/licenses/>.

<#
.SYNOPSIS
    Correlates Geo SCADA users to the Windows (Thinfinity/Virtual ViewX) session they run in
    and the ephemeral TCP port their ViewX uses to reach the Geo SCADA server.

.DESCRIPTION
    On a "Virtual ViewX" box, each web user is authenticated with their Geo SCADA credentials,
    Thinfinity spawns a Windows session, and a ViewX (SE.Scada.ViewX.exe) process runs in that
    session and connects out to the Geo SCADA server (default TCP 5481).

    There is no single API that exposes "SCADA user <-> Windows session", but the data exists in
    two places that share a common key (the ViewX outbound source/ephemeral port):

      1. LIVE NETWORK STATE (this box):
         ViewX PID  ->  Windows SessionId / account  ->  ephemeral source port(s) to the SCADA server.
         (Get-NetTCPConnection + Get-Process / Win32_Process)

      2. PER-SESSION VIEWX LOG(S) (this box):
         %ProgramData%\Schneider Electric\ClearSCADA\Logs\ViewX\...*SE.Scada.ViewX*log*
         Two on-disk layouts are supported: a per-session subfolder (Session_<N>\, newer versions)
         or flat files in the ViewX folder with the session number in the name (Geo SCADA 2023,
         e.g. Virtualized_SE.Scada.ViewX_Session<N>.log).
         (ALL rolled logs are read, not just the active one.) Each ViewX run tags its lines with a
         per-run ANCHOR that appears on BOTH:
            "... Connected to <server>:5481 (from <localip>:<ephemeralport>)"
            "... Logon( IN: Username '<scadauser>' )"
         The anchor has two forms by version: a run GUID (e.g. "Virtualized.<guid>", newer builds)
         or, on 6.87 / Geo SCADA Expert 2025 which writes no GUID, the "[<hex>:<thread>]" run tag
         (e.g. "[1FF0:12]") whose <hex> is shared by a run's Connected and Logon lines.

    This script joins the two: for each live ViewX connection it finds, across all rolled logs, the
    MOST RECENT "(from ...:port)" line for that ephemeral port, takes its run anchor (GUID, else run
    tag), and reads the SCADA username from the Logon line under that same anchor. Anchoring this way
    plus "most recent wins" ties the SCADA user to the exact live connection and is robust to
    ephemeral-port reuse, Windows session-id reuse, and log rollover (rather than guessing by "most
    recent login").

    If a session's ViewX was license-rejected before it ever authenticated, its log has no Logon
    line and the port join yields nothing. As a fallback the script then infers the typed SCADA
    user from the VirtualViewX web-auth log by timing (the ViewX process start vs the preceding web
    LogOn). The 'ScadaUserSource' column flags which method produced each row: authoritative
    'ViewX log' vs inferred 'web-auth (timing)'.

.PARAMETER ScadaPort
    The Geo SCADA server port ViewX connects to. Default 5481.

.PARAMETER ScadaServer
    Optional. Restrict to a specific Geo SCADA server IP/host. If omitted, all remote servers
    that ViewX connects to on ScadaPort are auto-detected.

.PARAMETER ViewXProcessName
    Process name (no extension) of the ViewX client. Default 'SE.Scada.ViewX'.

.PARAMETER LogRoot
    Root of the per-session ViewX logs.
    Default '%ProgramData%\Schneider Electric\ClearSCADA\Logs\ViewX'.

.PARAMETER AuthLog
    VirtualViewX web-auth log, used only as a fallback name source for a session whose ViewX never
    authenticated (e.g. license-rejected before logon, so no Logon line exists in the ViewX log).
    Default '%ProgramData%\Schneider Electric\VirtualViewX\VirtualViewXAuthentication.log'.

.PARAMETER AuthMatchWindowSeconds
    Max seconds a ViewX process launch may trail its web-auth LogOn for the timing fallback to accept
    the match. Default 120. Only relevant when the AuthLog fallback is used.

.PARAMETER AcceptDisclaimer
    Confirms you accept the DISCLAIMER below and run the script at your own risk. Required for
    non-interactive/scripted runs. If omitted in an interactive session, the disclaimer is shown
    and you are prompted to accept (default No).

.OUTPUTS
    One PSCustomObject per ViewX process (= per Windows session), with properties:
      ScadaUser                     - SCADA username for the connection.
      ScadaUserSource               - 'ViewX log' (authoritative) | 'web-auth (timing)' (inferred fallback).
      VVxManagedWindowsSession      - '<SessionId> (<interactive account>)'.
      VVxManagedWindowsSessionState - WTS state: Active | Disc | Listen.
      VVxManagedWindowsSessionStart - session start time (DateTime; raw string if it didn't parse).
      LocalViewXRunAsUser           - account the ViewX PROCESS runs under (shared 'VVXLocalUser';
                                      needs admin to read cross-session, else '(unknown - run elevated)').
      LocalEphemeralPort            - comma-separated source ports of this ViewX's live links.
      LocalViewXPID                 - ViewX process id.
      TargetScadaServer             - Geo SCADA server address(es) connected to.

.NOTES
    VVxManagedWindowsSession is the session's INTERACTIVE logged-on user (e.g. 'geoscadavirtualui'),
    resolved from `quser`/WTS. This works the same elevated or not. It is NOT the process-token owner:
    under Virtual ViewX, ViewX runs as a shared service account (e.g. 'VVXLocalUser') that is identical
    for every web user, so the token owner cannot distinguish sessions. The token owner is reported
    separately, for information only, in LocalViewXRunAsUser (and is used as a last-resort fallback for
    the session account only if `quser` yields nothing).
    Reading the logs and the network/process tables does NOT require admin on a default install; only
    LocalViewXRunAsUser (process owner in another session) needs elevation.

    LICENSE
    Copyright (C) 2026 Adam Woodland. Licensed under the GNU General Public License v3.0 (GPLv3);
    see the LICENSE file distributed alongside this script or <https://www.gnu.org/licenses/gpl-3.0>.

    DISCLAIMER
    This script is provided "AS IS", without warranty of any kind, express or implied, including but
    not limited to the warranties of merchantability, fitness for a particular purpose and non-
    infringement. In no event shall the author be liable for any claim, damages or other liability
    arising from, out of or in connection with the script or its use. It is a diagnostic/forensic
    tool that reads live network, process and log state; it is NOT certified for production SCADA
    environments. Do NOT run it on a production or safety-critical system without first reviewing
    the code and testing it on a representative non-production system. You run it at your own risk
    and are responsible for compliance with your own change-control and security policies.

.EXAMPLE
    # Interactive: prompts to accept the disclaimer (default No), then prints the table.
    .\Get-VvxScadaSessions.ps1 | Format-Table -AutoSize

.EXAMPLE
    # Non-interactive / scheduled: acceptance must be explicit via -AcceptDisclaimer.
    .\Get-VvxScadaSessions.ps1 -AcceptDisclaimer -ScadaServer 192.168.31.134 | Export-Csv sessions.csv -NoTypeInformation
#>

[CmdletBinding()]
param(
    [int]    $ScadaPort        = 5481,
    [string] $ScadaServer      = $null,
    [string] $ViewXProcessName = 'SE.Scada.ViewX',
    [string] $LogRoot          = (Join-Path $env:ProgramData 'Schneider Electric\ClearSCADA\Logs\ViewX'),

    # VirtualViewX web-auth log. Fallback source for the SCADA user when the per-session ViewX log
    # has no Logon (e.g. the ViewX->server connection was license-rejected before authentication).
    [string] $AuthLog          = (Join-Path $env:ProgramData 'Schneider Electric\VirtualViewX\VirtualViewXAuthentication.log'),

    # Max seconds a ViewX launch may trail its web-auth LogOn for the timing fallback to accept the match.
    [int]    $AuthMatchWindowSeconds = 120,

    # Accept the "as-is / no warranty / not for production without testing" disclaimer (see .NOTES).
    # Required for non-interactive runs; interactive runs without it are prompted to accept.
    [switch] $AcceptDisclaimer
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Disclaimer gate. Returns $true if the user has accepted (via -AcceptDisclaimer or an interactive
# prompt); throws on a non-interactive run with no -AcceptDisclaimer; returns $false if declined.
function Confirm-Disclaimer {
    param([switch]$Accepted)

    $disclaimer = @'
------------------------------------------------------------------------------
 Get-VvxScadaSessions.ps1  Copyright (C) 2026  Adam Woodland
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

# SessionId -> @{ User; State; LogonTime (DateTime or $null); LogonTimeRaw }, parsed from `quser`
# (no elevation needed). LogonTime is the WTS session-start time; State is Active|Disc|Listen.
# User is the session's interactive account; preferred over the process-token owner (see notes).
function Get-SessionInfoMap {
    $map = @{}
    try {
        $lines = quser 2>$null
        foreach ($line in ($lines | Select-Object -Skip 1)) {
            # Columns: USERNAME [SESSIONNAME] ID STATE IDLE LOGON-TIME
            # Two layouts: ">adam  console  1  Active  none  6/18/2026 4:53 PM"
            #          and " svcacct          2  Disc    2     6/18/2026 6:07 PM" (no session name)
            if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(Active|Disc|Listen)\s+(\S+)\s+(.+?)\s*$') {
                $raw = $matches[6].Trim()
                $dt  = $raw -as [datetime]   # current-culture parse; $null if it doesn't parse
                $map[[int]$matches[3]] = [PSCustomObject]@{
                    User         = $matches[1]
                    State        = $matches[4]   # Active | Disc | Listen
                    LogonTime    = $dt
                    LogonTimeRaw = $raw
                }
            }
        }
    } catch { }
    return $map
}

# PID -> "DOMAIN\User" of the PROCESS TOKEN via WMI (needs admin for processes in other sessions).
# NOTE: on a Virtual ViewX box this is the shared service account ViewX runs as (e.g. 'VVXLocalUser'),
# which is the SAME for every web user and is NOT the interactive session's logged-on user.
# It is therefore only a last-resort fallback for the session-account column; prefer Get-SessionUserMap.
function Get-ProcessOwner {
    param([int]$ProcessId)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
        $o = $p | Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop
        if ($o.ReturnValue -eq 0 -and $o.User) {
            if ($o.Domain) { return "$($o.Domain)\$($o.User)" } else { return $o.User }
        }
    } catch { }
    return $null
}

# From a session's ViewX log(s), find the SCADA username for a given set of LIVE ephemeral ports.
#
# Each ViewX run tags every line with a per-run ANCHOR that appears on both the
# "Connected ... (from <ip>:<port>)" lines and the "Logon( IN: Username ... )" lines for that run.
# A reconnect, a reused Windows session, or a different SCADA login each get a NEW anchor, so the
# anchor is the join key. Two anchor styles exist depending on the ViewX/Geo SCADA version:
#   * GUID    : newer builds tag a connection-block GUID (e.g. "Virtualized.<guid>").
#   * run tag : 6.87 / Geo SCADA Expert 2025 has NO GUID; it tags every line "[<hex>:<thread>]"
#               (e.g. "[1FF0:12]") and shares the <hex> run id between a run's Connected and Logon
#               lines. We take the leftmost "[<hex>:<hex>]" bracket as the run id.
# Per line we prefer the GUID and fall back to the run tag, so the SAME logic resolves both versions.
#
# Rollover- and reuse-safe strategy (single chronological pass over ALL rolled logs, oldest->newest):
#   * For each live port, the MOST RECENT "(from ...:port)" line wins -> its anchor is the live run.
#     "Most recent wins" is what defeats reuse: an OS won't reassign a source port that is still
#     ESTABLISHED, so no newer line can claim a live port; and older runs left in a reused Session_N
#     folder (Windows session-id reuse) or older connections that recycled the same port number are,
#     by definition, older -> they lose. This holds even if the live run's connect line has already
#     rolled into an archived file, because all rolled files are read.
#   * The user is the Logon recorded under THAT anchor -> keeps a SCADA user who has logged into
#     several different sessions correctly separated per session. (GUIDs are globally unique; run-tag
#     hex is only per-run and could in theory recur via PID reuse, but most-recent-wins + the fact
#     that a live ESTABLISHED port cannot belong to an older run keeps the live match correct.)
#   * Fallback (ports not in any log: rolled fully away or low verbosity) = most recent Logon overall.
#     This is NOT port-anchored and can be wrong after reuse; it is flagged via Write-Verbose.
function Resolve-ScadaUserFromLog {
    param(
        [string[]] $LogFiles,
        [int[]]    $Ports
    )

    # Oldest -> newest so a forward pass makes "last match seen" == "most recent".
    $files = $LogFiles |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Get-Item -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime
    if (-not $files) { return $null }

    $guidRegex   = '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
    $runTagRegex = '\[([0-9A-Fa-f]+):[0-9A-Fa-f]+\]'   # leftmost "[<hex>:<thread>]" -> run id (no-GUID builds)
    $logonRegex  = "Logon\(\s*IN:\s*Username\s*'([^']+)'"
    $portSet     = @{}
    foreach ($p in $Ports) { $portSet["$p"] = $true }

    $liveAnchor   = $null    # anchor (GUID or run tag) of the run currently owning a live port (most recent wins)
    $anchorToUser = @{}      # anchor -> most recent Logon username seen under it
    $lastFileUser = $null    # most recent Logon anywhere (fallback only)

    foreach ($f in $files) {
        try { $lines = Get-Content -LiteralPath $f.FullName -ErrorAction Stop } catch { continue }
        foreach ($line in $lines) {
            # Capture the per-run anchor first (GUID preferred, else run tag); later -match calls
            # overwrite $matches. Normalise hex case so a run's connect and Logon lines key identically.
            $anchor = $null
            if     ($line -match $guidRegex)   { $anchor = $matches[1].ToUpperInvariant() }
            elseif ($line -match $runTagRegex) { $anchor = $matches[1].ToUpperInvariant() }

            if ($line -match $logonRegex) {
                $lastFileUser = $matches[1]
                if ($anchor) { $anchorToUser[$anchor] = $matches[1] }
            }
            elseif ($line -match 'from\s+\S+:(\d+)\)') {
                if ($anchor -and $portSet.ContainsKey($matches[1])) { $liveAnchor = $anchor }
            }
        }
    }

    # Primary: port-anchored user for the live run.
    if ($liveAnchor -and $anchorToUser.ContainsKey($liveAnchor)) {
        return $anchorToUser[$liveAnchor]
    }

    # Fallback: no live port found in any log.
    if ($lastFileUser) {
        Write-Verbose "No live-port match in logs; used most recent Logon ('$lastFileUser') as a heuristic (may be stale after session/port reuse)."
    }
    return $lastFileUser
}

# Parse the VirtualViewX web-auth log into a time-ordered list of successful logons:
#   @{ Time = [datetime]; User = '<scadauser>' }
# Each web login writes "<ts>: LogOn( [IN] userName = '<user>' )" just BEFORE Thinfinity spawns the
# Windows session and launches ViewX. This is the only local record of the typed SCADA user when the
# ViewX->server connection is license-rejected (no Logon ever reaches the per-session ViewX log).
function Get-WebAuthLogons {
    param([string]$AuthLog)
    $events = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $AuthLog)) { return $events }
    $rx = "^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*LogOn\(\s*\[IN\]\s*userName\s*=\s*'(?<user>[^']+)'"
    foreach ($line in (Get-Content -LiteralPath $AuthLog -ErrorAction SilentlyContinue)) {
        if ($line -match $rx) {
            $ts = $matches['ts'] -as [datetime]
            if ($ts) { $events.Add([PSCustomObject]@{ Time = $ts; User = $matches['user'] }) }
        }
    }
    return ($events | Sort-Object Time)
}

# Best-effort SCADA user for a session that ViewX never logged on, by timing: the latest web-auth
# LogOn at or before the ViewX process start (within $WindowSeconds). Inferred, not authoritative.
function Resolve-ScadaUserFromAuth {
    param(
        [object[]] $AuthLogons,
        [datetime] $ProcStart,
        [int]      $WindowSeconds
    )
    if (-not $AuthLogons -or -not $ProcStart) { return $null }
    $cand = $AuthLogons |
        Where-Object { $_.Time -le $ProcStart -and $_.Time -ge $ProcStart.AddSeconds(-$WindowSeconds) } |
        Select-Object -Last 1
    if ($cand) { return $cand.User }
    return $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Require disclaimer acceptance before doing anything (prompt interactively, else demand the switch).
if (-not (Confirm-Disclaimer -Accepted:$AcceptDisclaimer)) { return }

# No elevation needed: session account comes from quser/WTS, and reading the logs and
# network/process tables works unelevated on a default install. (The admin-only GetOwner
# path is just a last-resort fallback and returns the shared run-as account, not the session user.)
$sessionInfoMap = Get-SessionInfoMap

# Web-auth logons (fallback name source) and ViewX process start times (the join key for that
# fallback). CreationDate via CIM is readable unelevated, unlike Get-Process.StartTime cross-session.
$authLogons   = Get-WebAuthLogons -AuthLog $AuthLog
$procStartMap = @{}
Get-CimInstance Win32_Process -Filter "Name='$ViewXProcessName.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object { $procStartMap[[int]$_.ProcessId] = $_.CreationDate }

# All live, established ViewX -> SCADA connections.
$conns = Get-NetTCPConnection -State Established -RemotePort $ScadaPort -ErrorAction SilentlyContinue
if ($ScadaServer) { $conns = $conns | Where-Object { $_.RemoteAddress -eq $ScadaServer } }
if (-not $conns) {
    Write-Warning "No established connections to a Geo SCADA server on port $ScadaPort were found."
    return
}

# Keep only connections owned by a ViewX process (excludes the Thinfinity broker's
# credential-validation link, which also hits :5481).
$viewxConns = foreach ($c in $conns) {
    $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -eq $ViewXProcessName) {
        [PSCustomObject]@{
            PID          = $proc.Id
            SessionId    = $proc.SessionId
            LocalPort    = $c.LocalPort
            RemoteServer = $c.RemoteAddress
        }
    }
}
if (-not $viewxConns) {
    Write-Warning "Connections to :$ScadaPort exist, but none are owned by '$ViewXProcessName'. (Broker-only?)"
    return
}

# One result row per ViewX process (= per Windows session). A ViewX uses several links,
# hence several ephemeral ports; all are reported.
$results = foreach ($g in ($viewxConns | Group-Object PID)) {
    $procPid   = [int]$g.Name
    $sessionId = $g.Group[0].SessionId
    $servers   = ($g.Group.RemoteServer | Sort-Object -Unique) -join ','
    $ports     = $g.Group.LocalPort | Sort-Object -Unique

    # Interactive account logged on to the session (e.g. 'geoscadavirtualui') and the session start
    # time. Use the WTS/quser session map as the PRIMARY source: it reports the session's logged-on
    # user regardless of elevation. The process-token owner (Get-ProcessOwner) is only a fallback,
    # because under Virtual ViewX it returns the shared run-as account (VVXLocalUser), not the session
    # user (and it carries no session start time).
    $sessInfo  = $sessionInfoMap[$sessionId]
    $winUser   = if ($sessInfo) { $sessInfo.User } else { $null }
    $winState  = if ($sessInfo) { $sessInfo.State } else { '(unknown)' }
    $winLogon  = if ($sessInfo) { if ($sessInfo.LogonTime) { $sessInfo.LogonTime } else { $sessInfo.LogonTimeRaw } } else { $null }

    # The account the ViewX PROCESS actually runs under (its token owner) -- the shared VVx service
    # account (e.g. 'VVXLocalUser'), distinct from the interactive session user above. Needs admin to
    # read for a process in another session; null/unknown when not elevated.
    $runAsUser = Get-ProcessOwner -ProcessId $procPid
    if (-not $winUser)   { $winUser   = $runAsUser }          # last-resort for the session account
    if (-not $winUser)   { $winUser   = '(unknown)' }
    if (-not $runAsUser) { $runAsUser = '(unknown - run elevated)' }

    # SCADA user from the per-session log(s). Read ALL rolled logs (active + archived) so a long-lived
    # connection whose connect/logon lines have rolled into an older file still resolves. The roll naming
    # for ViewX is unknown/version-specific, so match generically: any file whose name contains
    # 'SE.Scada.ViewX' and 'log' (catches '.log', '.log.1', '.log.bak', 'SE.Scada.ViewX_<date>.log',
    # 'Virtualized_' prefix, '_Session<N>.<roll>.log', etc.).
    #
    # Two on-disk layouts exist depending on the Geo SCADA version:
    #   * Newer: one subfolder per Windows session, $LogRoot\Session_<SessionId>\...
    #   * Geo SCADA 2023: flat files directly in $LogRoot, session number encoded in the FILENAME
    #     (e.g. 'SE.Scada.ViewX_Session2.log', 'Virtualized_SE.Scada.ViewX_Session1671.1.log').
    # When there is no per-session subfolder we read every ViewX log in $LogRoot; the authoritative
    # join is the port->GUID anchor (not the folder/filename), so reading the full set is correct.
    $logFiles = @()
    $sessFolder = Join-Path $LogRoot ("Session_{0}" -f $sessionId)
    if (Test-Path $sessFolder) {
        $logFiles = Get-ChildItem -LiteralPath $sessFolder -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' } |
                    Select-Object -ExpandProperty FullName
    }
    elseif (Test-Path $LogRoot) {
        # Flat (Geo SCADA 2023) layout: no Session_<N> subfolder, logs live directly in $LogRoot.
        $logFiles = Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like '*SE.Scada.ViewX*log*' } |
                    Select-Object -ExpandProperty FullName
    }
    $scadaUser   = if ($logFiles) { Resolve-ScadaUserFromLog -LogFiles $logFiles -Ports $ports } else { $null }
    $scadaSource = if ($scadaUser) { 'ViewX log' } else { $null }

    # Fallback when ViewX never authenticated (e.g. license-rejected before logon): infer the typed
    # SCADA user from the web-auth log by matching this ViewX process's start time to the latest
    # preceding LogOn. Inferred, not authoritative -> flagged in ScadaUserSource.
    if (-not $scadaUser) {
        $authUser = Resolve-ScadaUserFromAuth -AuthLogons $authLogons `
                        -ProcStart $procStartMap[$procPid] -WindowSeconds $AuthMatchWindowSeconds
        if ($authUser) {
            $scadaUser   = $authUser
            $scadaSource = 'web-auth (timing)'
        }
    }
    if (-not $scadaUser) { $scadaUser = '(unresolved - check log verbosity)'; $scadaSource = '' }

    [PSCustomObject]@{
        ScadaUser                     = $scadaUser
        ScadaUserSource               = $scadaSource
        VVxManagedWindowsSession      = "$sessionId ($winUser)"
        VVxManagedWindowsSessionState = $winState
        VVxManagedWindowsSessionStart = $winLogon
        LocalViewXRunAsUser           = $runAsUser
        LocalEphemeralPort            = ($ports -join ', ')
        LocalViewXPID                 = $procPid
        TargetScadaServer             = $servers
    }
}

$results | Sort-Object { [int]($_.VVxManagedWindowsSession -split ' ')[0] }
