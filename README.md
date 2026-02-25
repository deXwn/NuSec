# NuSecurity
Nushell config and helper commands for security research workflows.

## Available Commands
![commands](https://github.com/user-attachments/assets/2f467c46-e7c5-441d-91b4-2be33fd101bd)

## Requirements
- `nu` (Nushell)
- Common CLI tools (`python`, `git`, `curl`/network access)
- Optional: `go` for auto-installing some tools (`httpx`, `hednsextractor`)
- Optional: `yara` for local rule scanning with `yrs`
- Optional on Linux: `apt` + `sudo` for package helper commands
- Optional on Linux: `journalctl` for richer `log-hunt` output
- Optional on Windows: `winget` for package helper commands
- Optional on Windows: `powershell` for `windows-evt-hunt` / `log-hunt` / `persist-hunt`
- Optional on Windows: `procdump` (Sysinternals) for `proc-dump`

## Setup
Run this in Nushell (Linux/macOS/Windows):

```nu
cp $nu.config-path $"($nu.config-path).backup"
cp configs/config.nu $nu.config-path
```

Restart your Nu shell after copying.

## Optional Startup Sysinfo
System info output (`neofetch`) is disabled by default.

Enable it with:

```nu
$env.NUSECURITY_SHOW_SYSINFO = true
```

## Quick Examples
```nu
hlp                         # compact command list with summary + sample
hlp -v                      # verbose command list
hlp triage                  # show detailed usage/examples for one command
chkbgp 8.8.8.8              # BGP information for IP
haus                        # URLHaus online feed (default)
haus normal --limit 20      # full feed, first 20 URLs
haus --host-only --contains "in.net" --limit 10  # unique hosts filtered by keyword
haus --host-ends-with ".tr" --host-only --limit 20 # hosts ending with .tr
rware TR --limit 20          # country-specific ransomware victims
rware --limit 20             # global recent ransomware victims
rware TR --monitor --interval 30  # live monitor mode for newly added entries
tfox --dtype url            # ThreatFox URL-only output
triage --family agenttesla --limit 5      # fetch reports + C2 candidates
triage --family remcos --limit 3          # includes C2 + MalwareConfig
triage --query "sha1:..." --limit 3 --no-c2 --no-config # fastest report listing
triage --query "sha256:..." --limit 1 | get 0.MalwareConfig  # expand parsed config fields
hx subdomains.txt           # httpx scan over a file
shx example.com             # subfinder + httpx
yrs suspicious.bin          # YARA scan using ~/rules
persist-hunt --contains cron --limit 50 # Linux/Windows persistence artifacts
proc-hunt --min-score 2 --limit 50      # heuristic suspicious process scoring
proc-dump lsass --out-dir C:\dumps      # dump process memory with ProcDump
proc-dump ollama.exe --out-dir C:\dumps --mini # mini dump
proc-dump notepad.exe --out-dir C:\dumps --full # full dump
log-hunt "failed password" --since-hours 24 --limit 100 # suspicious log lines
timeline-lite /var/tmp --with-hash --limit 100 # quick file timeline + optional SHA256
windows-evt-hunt --log Security --event-id 4625 --since-hours 24 # Windows event triage
```

`triage` C2 output is heuristic and focuses on likely payload/C2 hosts from behavioral requests.
When available, domains are shown together with IP as `domain [ip]`.
`MalwareConfig` is now a structured record (`family/version/botnet/c2/URLs/Deobfuscated/credentials/mutex`) for cleaner table output.
`haus` supports `--limit`, `--host-only`, `--contains`, `--host-contains`, `--host-ends-with`, `--https-only`, and `--raw`.
`rware` supports `--monitor`, `--interval`, `--limit`, and `--max-cycles` (test/debug loop count).
`windows-evt-hunt` is Windows-only and uses PowerShell `Get-WinEvent`.
`persist-hunt` checks common persistence points (Linux cron/systemd/autostart/shell init, Windows Run keys/startup/scheduled tasks).
`proc-hunt` is heuristic scoring and may include false positives; tune with `--min-score` and `--contains`.
`proc-dump` is Windows-only and wraps Sysinternals ProcDump (`-ma` full dump by default, `--mini` for `-mp`); it auto-downloads ProcDump on first use and passes `-accepteula`.
`log-hunt` reads Linux log files + `journalctl` (if available) or Windows Event Logs.
`timeline-lite` supports `--with-hash` for SHA256 at extra runtime cost.

## Safety Notes
- `fixu` formats a disk. Double-check target device before running.
- `clean`, `aget`, `arem` run privileged operations.
- `upc` pulls config from GitHub and overwrites your current Nu config path.

## Update Config
After setup, you can pull the latest upstream config from inside Nu:

```nu
upc
```
