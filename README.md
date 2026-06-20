# Get-VvxScadaSessions

Correlate connected **Geo SCADA** users to the Windows (**Thinfinity / Virtual ViewX**) session
their ViewX client runs in, and to the ephemeral TCP source port(s) that ViewX uses to reach the
Geo SCADA server.

On a Virtual ViewX box there is no single API that exposes *"SCADA user ↔ Windows session"*. This
script reconstructs the mapping locally by joining two sources that share a common key — ViewX's
outbound (ephemeral) TCP source port:

1. **Live network/process state** — `Get-NetTCPConnection` + `Win32_Process` give
   *ephemeral port ↔ ViewX PID ↔ Windows SessionId*, with the interactive account, start time and
   WTS state from `quser`.
2. **Per-session ViewX log(s)** — each ViewX run tags every line with a run GUID that appears on
   both the `Connected to <server>:<port> (from <ip>:<ephemeralport>)` line and the
   `Logon( IN: Username '<user>' )` line, giving *ephemeral port ↔ SCADA username*.

For each live connection the script finds the most recent log line for that ephemeral port, takes
its run GUID, and reads the username from the `Logon` line under the same GUID. Anchoring on the
GUID with "most recent wins" is robust to ephemeral-port reuse, session-id reuse and log rollover.

If a session was **license-rejected** before it authenticated (no `Logon` line in its ViewX log),
the script falls back to inferring the typed user from the VirtualViewX web-auth log by timing the
web login against the ViewX process start. The `ScadaUserSource` column flags which method produced
each row.

## Requirements

- Windows with Virtual ViewX / Thinfinity and a local Geo SCADA ViewX client.
- PowerShell 5.1 or later.
- Runs **unelevated** for everything except the `LocalViewXRunAsUser` column (cross-session process
  owner), which needs admin; without it that one column shows `(unknown - run elevated)`.

## Usage

```powershell
# Interactive: prompts to accept the disclaimer (default No), then prints results.
.\Get-VvxScadaSessions.ps1 | Format-Table -AutoSize

# Non-interactive / scheduled: acceptance MUST be explicit or the script throws.
.\Get-VvxScadaSessions.ps1 -AcceptDisclaimer | Export-Csv sessions.csv -NoTypeInformation
```

### Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-ScadaPort` | `5481` | Geo SCADA server port ViewX connects to. |
| `-ScadaServer` | auto-detected | Restrict to a specific Geo SCADA server IP/host. |
| `-ViewXProcessName` | `SE.Scada.ViewX` | Process name (no extension) of the ViewX client. |
| `-LogRoot` | `%ProgramData%\Schneider Electric\ClearSCADA\Logs\ViewX` | ViewX per-session log root. |
| `-AuthLog` | `%ProgramData%\Schneider Electric\VirtualViewX\VirtualViewXAuthentication.log` | Web auth log (timing fallback). |
| `-AuthMatchWindowSeconds` | `120` | Max gap for the web-auth timing fallback. |
| `-AcceptDisclaimer` | — | Accept the disclaimer non-interactively (required when not interactive). |

### Output columns (one row per ViewX process = per Windows session)

| Column | Meaning |
|---|---|
| `ScadaUser` | SCADA username for the connection. |
| `ScadaUserSource` | `ViewX log` (authoritative) \| `web-auth (timing)` (inferred fallback). |
| `VVxManagedWindowsSession` | `<SessionId> (<interactive account>)`. |
| `VVxManagedWindowsSessionState` | WTS state: `Active` \| `Disc` \| `Listen`. |
| `VVxManagedWindowsSessionStart` | Session start time. |
| `LocalViewXRunAsUser` | Account the ViewX **process** runs under (needs admin cross-session). |
| `LocalEphemeralPort` | Comma-separated source ports of this ViewX's live links. |
| `LocalViewXPID` | ViewX process id. |
| `TargetScadaServer` | Geo SCADA server address(es). |

## Diagnostics

If the main script misbehaves — a session not matched, the wrong user resolved, or a slow run —
`Get-VvxScadaSessions-Diag.ps1` collects everything needed to diagnose it into a single text report.
It is **read-only** and needs no special tooling on the target box, so it can be run on a machine that
cannot have developer tooling installed and the resulting report handed to someone who can analyse it.

```powershell
# Interactive: prompts to accept the disclaimer, then writes the report to the current directory.
.\Get-VvxScadaSessions-Diag.ps1

# Non-interactive: acceptance must be explicit. Collect inputs only (don't run the main script).
.\Get-VvxScadaSessions-Diag.ps1 -AcceptDisclaimer -SkipRunMain -OutputPath C:\Temp\diag.txt
```

It mirrors the main script's parameters (`-ScadaPort`, `-ScadaServer`, `-ViewXProcessName`, `-LogRoot`,
`-AuthLog`, `-AuthMatchWindowSeconds`, `-AcceptDisclaimer`) and adds `-MainScript`, `-OutputPath`,
`-LogSampleLines` and `-SkipRunMain`. The report (timed per stage) includes:

- environment / elevation / locale, and the main script's path + SHA-256;
- live TCP connections to the SCADA port and their owning processes (ViewX vs the Thinfinity broker);
- ViewX processes (PID / session / start / owner / command line);
- raw `quser` and `qwinsta`;
- a **raw recursive listing of the whole log root** (catches changed log filenames or folder layout),
  plus per-session inventory and the relevant connect / logon / license lines;
- a **port → log cross-reference** that mirrors the join and shows why each live port did or didn't
  resolve;
- the web-auth log, a locale parse check, and the timing-fallback prediction per process;
- the main script's own output, `-Verbose` stream, errors and run time;
- an automatic **"potential issues"** summary of common failure modes.

> ⚠️ **The report contains real hostnames, usernames and IP addresses.** Review it and redact anything
> sensitive before sharing — e.g. mask IP octets (`192.168.10.10` → `x.x.10.10`) and rename hosts/users
> — keeping each replacement **consistent** so ports, users and GUIDs still line up across sections.
> Generated reports (`VvxScadaDiag_*.txt`) are git-ignored.

## Disclaimer

This script is provided **as-is, without warranty of any kind**, and is intended for diagnostic
use. Test it before relying on it in production. An interactive run requires you to accept this
disclaimer (default *No*); a non-interactive run requires the `-AcceptDisclaimer` switch.

## Licence

GPL-3.0-or-later. Copyright © 2026 Adam Woodland. See [LICENSE](LICENSE) for the full text.
