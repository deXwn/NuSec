# NuSecurity
Nushell config and helper commands for security research workflows.

## Available Commands
![commands](https://github.com/user-attachments/assets/2f467c46-e7c5-441d-91b4-2be33fd101bd)

## Requirements
- `nu` (Nushell)
- Common Linux CLI tools (`python`, `git`, `curl`/network access)
- Optional: `go` for auto-installing some tools (`httpx`, `hednsextractor`)
- Optional: `apt` + `sudo` for package helper commands (`aget`, `arem`, `ff` auto-install path)

## Setup
Run this in Nushell:

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
hlp -v                      # list custom commands with parameter details
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
```

`triage` C2 output is heuristic and focuses on likely payload/C2 hosts from behavioral requests.
When available, domains are shown together with IP as `domain [ip]`.
`MalwareConfig` is now a structured record (`family/version/botnet/c2/urls/credentials/mutex`) for cleaner table output.
`haus` supports `--limit`, `--host-only`, `--contains`, `--host-contains`, `--host-ends-with`, `--https-only`, and `--raw`.
`rware` supports `--monitor`, `--interval`, `--limit`, and `--max-cycles` (test/debug loop count).

## Safety Notes
- `fixu` formats a disk. Double-check target device before running.
- `clean`, `aget`, `arem` run privileged operations.
- `upc` pulls config from GitHub and overwrites your current Nu config path.

## Update Config
After setup, you can pull the latest upstream config from inside Nu:

```nu
upc
```
