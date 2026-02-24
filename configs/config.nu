$env.config.buffer_editor = "vim" # Can be anything for ex. (nvim, nano, ...)
$env.config.show_banner = false

# Ensure HOME exists on Windows sessions
let is_windows = (($nu.os-info.name | str downcase) == "windows")
if ($is_windows and ($env.HOME? == null) and ($env.USERPROFILE? != null)) {
    $env.HOME = $env.USERPROFILE
}

# Optional startup system info; set $env.NUSECURITY_SHOW_SYSINFO = true to enable
let show_sysinfo = (try {
    let value = $env.NUSECURITY_SHOW_SYSINFO?
    if $value == null {
        false
    } else if (($value | describe) == "bool") {
        $value
    } else {
        let normalized = ($value | into string | str trim | str downcase)
        $normalized in ["1", "true", "yes", "on"]
    }
} catch {
    false
})

let has_neofetch = (try {
    let command_paths = (which --all neofetch | where type == "external" | get path)
    (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
} catch {
    false
})

if ($show_sysinfo and $has_neofetch) {
    neofetch
}

# Add Go paths
let go_paths = if $is_windows {
    let windows_go = if ($env.ProgramFiles? != null) {
        $"($env.ProgramFiles)\\Go\\bin"
    } else {
        "C:\\Program Files\\Go\\bin"
    }
    [$"($env.HOME)\\go\\bin", $windows_go]
} else {
    [$"($env.HOME)/go/bin", "/usr/local/go/bin"]
}

for go_path in $go_paths {
    if (($env.PATH | to text | str contains $go_path) == false) {
        $env.PATH ++= [$go_path]
    }
}

# Apply the custom prompt
$env.PROMPT_COMMAND = {
    let username = (whoami | str trim)
    let hostname = (hostname | str trim)
    let current_dir = (pwd)
    $"\n(ansi blue_bold)<----- ($username)@($hostname) ----->\n[(ansi red)($current_dir)(ansi blue_bold)]"
}
$env.PROMPT_INDICATOR = $"(ansi blue_bold)>> "

# Get information about the target IP address using bgpview
def chkbgp [ipaddr: string] {
    let data = (http get $"https://api.bgpview.io/ip/($ipaddr)")
    if $data.status == "ok" {
        $data.data
    }
}

# Start HTTPSERVER
def hs [--path: string] {
    if $path != null {
        let abs_path = ($path | str trim)
        python -m http.server -d $abs_path
    } else {
        python -m http.server
    }
}

# Output with syntax highlighting
def catt [targetfile: string] {
    python -m rich.syntax $targetfile
}

# Get Ifaces
alias ifc = sys net

# Get disks
alias sd = sys disks

# Verbose LS for disk usage checks
def lsv [] {
    ls -a -d -l | sort-by size
}

# Verbose LS for last created file and mime checks
def lsl [] {
    ls -a -m | sort-by modified
}

# Access shell of a docker image
def dosh [image_id: string] {
    docker run -it $image_id /bin/bash
}

# Remove selected docker image
def drmi [target_id: string] {
    docker rmi --force $target_id
}

# Install desired package
def aget [target_package: string] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        if (do $has_cmd "winget") {
            winget install --accept-source-agreements --accept-package-agreements $target_package
        } else {
            error make { msg: "winget not found. Install App Installer from Microsoft Store first." }
        }
    } else {
        sudo apt install -y $target_package
    }
}

# Remove package
def arem [target_package: string] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        if (do $has_cmd "winget") {
            winget uninstall $target_package
        } else {
            error make { msg: "winget not found. Install App Installer from Microsoft Store first." }
        }
    } else {
        sudo apt remove $target_package
    }
}

# List connections and listening ports
def netcon [] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        netstat -ano | lines | where { |line| ($line | str trim) =~ "LISTENING" }
    } else {
        if (do $has_external_cmd "lsof") {
            lsof -i4 -V -E -R | awk '$1 ~ /:*(-|$)/{ gsub(/:[^-]*/, "", $1); print $1,$2,$3,$4,$9,$10,$11 }' | to text | lines | split column " " | rename COMMAND PID PPID USER PROTO CONNECTION STATUS | skip 1
        } else if (do $has_external_cmd "ss") {
            ss -lntup
        } else if (do $has_external_cmd "netstat") {
            netstat -tulpn
        } else {
            error make { msg: "No supported network tool found (lsof/ss/netstat)." }
        }
    }
}

# Fetch last 50 C2 panel from Viriback
def vrb [] {
    http get https://tracker.viriback.com/last50.php | to json | from json
}

# Fetch data from URLHAUS
def haus [
    datatype?: string = "online" # online | normal
    --limit: int = 0             # Limit output rows (0 = unlimited)
    --host-only                  # Return unique hosts instead of URLs
    --contains: string           # Case-insensitive contains filter
    --host-contains: string      # Case-insensitive host contains filter
    --host-ends-with: string     # Host suffix filter, e.g. .tr
    --https-only                 # Keep only https URLs
    --raw                        # Return raw feed without cleanup/filtering
] {
    let url_host = { |url_value: string|
        (try {
            $url_value | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
        } catch {
            null
        })
    }

    let normalized_type = ($datatype | str trim | str downcase)
    let source_type = if ($normalized_type in ["normal", "full"]) {
        "normal"
    } else if ($normalized_type in ["online", "active"]) {
        "online"
    } else {
        error make { msg: "Invalid datatype. Use: online | normal" }
    }

    let source_url = if $source_type == "normal" {
        "https://urlhaus.abuse.ch/downloads/text"
    } else {
        "https://urlhaus.abuse.ch/downloads/text_online"
    }

    let content = (http get $source_url)
    if $raw {
        if $limit > 0 {
            $content | lines | first $limit
        } else {
            $content | lines
        }
    } else {
        mut urls = ($content
            | lines
            | each { |line| $line | str trim }
            | where { |line| $line != "" and ($line | str starts-with "http") }
            | uniq)

        if $https_only {
            $urls = ($urls | where { |u| $u | str starts-with "https://" })
        }

        if ($contains != null) {
            let needle = ($contains | str downcase)
            $urls = ($urls | where { |u| ($u | str downcase | str contains $needle) })
        }

        if ($host_contains != null) {
            let needle = ($host_contains | str downcase)
            $urls = ($urls | where { |u|
                let host = (do $url_host $u)
                $host != null and ($host | str downcase | str contains $needle)
            })
        }

        if ($host_ends_with != null) {
            let suffix = ($host_ends_with | str downcase)
            $urls = ($urls | where { |u|
                let host = (do $url_host $u)
                $host != null and ($host | str downcase | str ends-with $suffix)
            })
        }

        if $host_only {
            let hosts = ($urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" } | uniq)
            if $limit > 0 { $hosts | first $limit } else { $hosts }
        } else {
            if $limit > 0 { $urls | first $limit } else { $urls }
        }
    }
}

# Fetch data from ThreatFox
def tfox [--dtype: string] {
    let buffer = http get https://threatfox.abuse.ch/export/json/urls/recent/ | values
    mut data_array = []
    if $dtype == "all" {
        for data in ($buffer) {
            $data_array ++= [{
                "ioc": $data.ioc_value.0, 
                "threat_type": $data.threat_type.0, 
                "malware": $data.malware.0, 
                "malware_printable": $data.malware_printable.0, 
                "tags": $data.tags, 
                "reference": $data.reference
            }]
        }
        $data_array | table
    } else if $dtype == "url" {
        for data in ($buffer) {
            $data_array ++= [($data | get 0 | get ioc_value | to text)]
        }
        $data_array
    } else {
        "You must use: --dtype all/url"
    }
}

# Perform httpx scan against list of urls
def hx [listfile: string] {
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if (($listfile | path exists) == false) {
        error make { msg: $"List file not found: ($listfile)" }
    }
    if ((do $has_cmd "httpx") == false) {
        if ((do $has_cmd "go") == false) {
            error make { msg: "Go is not installed. Please install Go first." }
        }
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)httpx(ansi reset)"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    }
    httpx -l $listfile -silent -td -title -sc
}

# Projectdiscovery tool downloader
def pdsc [tool_name: string] {
    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)($tool_name)"
    go install -v github.com/projectdiscovery/($tool_name)/cmd/($tool_name)@latest
}

# Get project commands with compact usage/samples
def hlp [command?: string, --verbose (-v)] {
    let summaries = {
        chkbgp: "Fetch ASN/BGP details for an IP."
        hs: "Start a quick HTTP file server."
        catt: "Show a file with syntax highlighting."
        ifc: "List network interfaces."
        sd: "List disks."
        lsv: "Sort files by size."
        lsl: "Sort files by modified time."
        dosh: "Run bash inside a Docker image."
        drmi: "Force remove a Docker image."
        aget: "Install a package via APT."
        arem: "Remove a package via APT."
        netcon: "List IPv4 connections and listening ports."
        vrb: "Fetch latest 50 panel entries from Viriback."
        haus: "Fetch and filter URLHaus feed entries."
        tfox: "Fetch recent URL IoCs from ThreatFox."
        hx: "Scan a target list with httpx."
        pdsc: "Install a ProjectDiscovery tool with Go."
        hlp: "Show commands and usage examples."
        shx: "Run subfinder + httpx domain scan."
        bdc: "Decode Base64 text."
        hdns: "Hunt candidate C2 domains with hednsextractor."
        "windows-evt-hunt": "Hunt Windows Event Log entries quickly."
        "persist-hunt": "Hunt persistence artifacts on host."
        "proc-hunt": "Score suspicious running processes."
        "log-hunt": "Hunt suspicious auth/system log lines."
        "timeline-lite": "Build quick file timeline for a path."
        upc: "Pull latest config from GitHub."
        clean: "Run APT and cache cleanup."
        arpt: "Parse and list ARP table entries."
        ff: "Search files by name system-wide."
        serv: "Show service active/inactive status."
        dls: "List disk partitions via lsblk."
        fixu: "Format disk with wipefs + vfat."
        yrs: "Scan a file with YARA rules."
        rware: "List/monitor ransomware victim feed."
        pls: "Fetch proxy list with geo/ISP info."
        crt: "Enumerate subdomains via crt.sh."
        rip: "Run reverse IP lookup."
        dchr: "Query DNS history (A records)."
        gf: "Extract href file names from open directory."
        triage: "Fetch tria.ge reports and C2/config summary."
    }

    let samples = {
        chkbgp: "chkbgp 8.8.8.8"
        hs: "hs --path /tmp/share"
        catt: "catt configs/config.nu"
        ifc: "ifc"
        sd: "sd"
        lsv: "lsv"
        lsl: "lsl"
        dosh: "dosh ubuntu:24.04"
        drmi: "drmi <image_id>"
        aget: "aget nmap"
        arem: "arem nmap"
        netcon: "netcon"
        vrb: "vrb"
        haus: "haus normal --limit 20"
        tfox: "tfox --dtype url"
        hx: "hx subdomains.txt"
        pdsc: "pdsc nuclei"
        hlp: "hlp -v"
        shx: "shx example.com"
        bdc: "bdc SGVsbG8="
        hdns: "hdns suspicious-domain.com"
        "windows-evt-hunt": "windows-evt-hunt --log Security --event-id 4625 --since-hours 24"
        "persist-hunt": "persist-hunt --contains cron --limit 50"
        "proc-hunt": "proc-hunt --min-score 2 --limit 50"
        "log-hunt": "log-hunt \"failed password\" --since-hours 24 --limit 100"
        "timeline-lite": "timeline-lite /var/tmp --with-hash --limit 100"
        upc: "upc"
        clean: "clean"
        arpt: "arpt"
        ff: "ff sshd_config"
        serv: "serv"
        dls: "dls"
        fixu: "fixu /dev/sdb1"
        yrs: "yrs suspicious.bin"
        rware: "rware tr --limit 20"
        pls: "pls"
        crt: "crt example.com"
        rip: "rip 1.1.1.1"
        dchr: "dchr example.com"
        gf: "gf https://example.com/open/"
        triage: "triage --family remcos --limit 3"
    }

    let examples = {
        haus: [
            "haus normal --limit 20"
            "haus --host-only --contains \"in.net\" --limit 10"
            "haus --host-ends-with \".tr\" --host-only --limit 20"
        ]
        tfox: [
            "tfox --dtype url"
            "tfox --dtype all"
        ]
        triage: [
            "triage --family agenttesla --limit 5"
            "triage --family remcos --limit 3"
            "triage --query \"sha1:...\" --limit 3 --no-c2 --no-config"
            "triage --query \"sha256:...\" --limit 1 | get 0.MalwareConfig"
        ]
        rware: [
            "rware tr --limit 20"
            "rware --limit 20"
            "rware tr --monitor --interval 30 --max-cycles 20"
        ]
    }

    let tracked_names = ($samples | columns)
    let format_usage_part = { |param: record|
        let is_option = ($param.name | str starts-with "--")
        if $is_option {
            if $param.type == "switch" {
                if $param.required { $param.name } else { $"[($param.name)]" }
            } else {
                if $param.required { $"($param.name) <($param.type)>" } else { $"[($param.name) <($param.type)>]" }
            }
        } else {
            if $param.required { $"<($param.name):($param.type)>" } else { $"[($param.name):($param.type)]" }
        }
    }

    let commands = (help commands
        | where command_type =~ "custom"
        | where { |cmd| ($tracked_names | any { |n| $n == $cmd.name }) }
        | each { |cmd|
            let command_params = ($cmd.params | where { |p| ($p.name | str starts-with "--help") == false })
            let usage_parts = ($command_params | each { |p| do $format_usage_part $p })
            let usage_text = (([$cmd.name] | append $usage_parts) | str join " ")
            let params_detail = (if (($command_params | length) == 0) {
                "-"
            } else {
                $command_params
                | each { |p| if $p.required { $"($p.name)*" } else { $p.name } }
                | str join ", "
            })
            let summary_text = (try {
                $summaries | get $cmd.name
            } catch {
                let raw_desc = ($cmd.description | str trim)
                if (($raw_desc | str length) > 60) {
                    $"(($raw_desc | str substring 0..57))..."
                } else {
                    $raw_desc
                }
            })
            let sample_text = (try { $samples | get $cmd.name } catch { "-" })
            $cmd | merge { usage: $usage_text, params_detail: $params_detail, sample: $sample_text, summary: $summary_text }
        }
        | sort-by name)

    if $command != null {
        let selected = ($commands | where { |c| $c.name == $command })
        if (($selected | length) == 0) {
            error make { msg: $"Unknown command: ($command). Use 'hlp' to list available project commands." }
        }
        let cmd = ($selected | first)
        let cmd_examples = (try { $examples | get $cmd.name } catch { [$cmd.sample] })
        let cmd_params = ($cmd.params | where { |p| ($p.name | str starts-with "--help") == false } | select name type required description)
        let example_lines = (if (($cmd_examples | length) == 0) {
            "  - -"
        } else {
            $cmd_examples | each { |ex| $"  - ($ex)" } | str join "\n"
        })
        let param_lines = (if (($cmd_params | length) == 0) {
            "  - -"
        } else {
            $cmd_params | each { |p|
                let req = (if $p.required { "required" } else { "optional" })
                $"  - ($p.name) <($p.type)> [($req)] :: ($p.description)"
            } | str join "\n"
        })

        $"
name: ($cmd.name)
description: ($cmd.description)
usage: ($cmd.usage)
sample: ($cmd.sample)
examples:
($example_lines)
params:
($param_lines)"
    } else if $verbose {
        ($commands
            | each { |cmd|
                $"
($cmd.name)
  desc: ($cmd.description)
  usage: ($cmd.usage)
  sample: ($cmd.sample)
  params: ($cmd.params_detail)"
            }
            | str join "\n\n")
    } else {
        $commands | select name summary sample | rename name description sample
    }
}

# Enumerate subdomains using subfinder/httpx combination
def shx [target_domain: string] {
    subfinder -silent -d $target_domain | httpx -silent -mc 200 -sc -title -td
}

# Base64 decoder
def bdc [pattern: string] {
    echo $pattern | base64 -d
}

# Hunt suspicious Windows events quickly
def windows-evt-hunt [
    --log: string = "Security"  # Security | System | Application
    --event-id: int             # Optional exact EventID filter
    --contains: string          # Optional case-insensitive keyword filter for Message
    --since-hours: int = 24     # Search window in hours
    --limit: int = 200          # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    if ($is_windows == false) {
        error make { msg: "windows-evt-hunt can only run on Windows." }
    }

    let safe_log = ($log | str trim)
    if $safe_log == "" {
        error make { msg: "--log cannot be empty." }
    }

    let safe_contains = if $contains != null {
        ($contains | str replace --all "'" "''")
    } else {
        null
    }

    mut ps_lines = [
        "$ErrorActionPreference = 'SilentlyContinue'"
        ("$start = (Get-Date).AddHours(-" + ($since_hours | into string) + ")")
        ("$events = Get-WinEvent -FilterHashtable @{LogName='" + $safe_log + "'; StartTime=$start}")
    ]

    if $event_id != null {
        $ps_lines ++= [("$events = $events | Where-Object { $_.Id -eq " + ($event_id | into string) + " }")]
    }

    if $safe_contains != null {
        $ps_lines ++= [("$events = $events | Where-Object { $_.Message -like '*" + $safe_contains + "*' }")]
    }

    $ps_lines ++= [("$events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message | Sort-Object TimeCreated -Descending | Select-Object -First " + ($limit | into string) + " | ConvertTo-Json -Depth 4")]

    let raw = (powershell -NoProfile -Command ($ps_lines | str join "; "))
    if (($raw | str trim) == "") {
        []
    } else {
        let parsed = (try { $raw | from json } catch { [] })
        let parsed_desc = ($parsed | describe)
        if ($parsed_desc | str starts-with "record") {
            [$parsed]
        } else if ($parsed_desc | str starts-with "list") {
            $parsed
        } else {
            []
        }
    }
}

# Hunt persistence artifacts on Linux/Windows
def persist-hunt [
    --contains: string  # Optional case-insensitive keyword filter
    --limit: int = 300  # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let keyword = if $contains != null { ($contains | str downcase | str trim) } else { null }

    if $is_windows {
        let safe_keyword = if $keyword != null {
            ($keyword | str replace --all "'" "''")
        } else {
            null
        }

        mut ps_lines = [
            "$ErrorActionPreference = 'SilentlyContinue'"
            "$items = @()"
            "$runPaths = @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run')"
            "foreach ($p in $runPaths) { if (Test-Path $p) { $props = Get-ItemProperty -Path $p; foreach ($prop in $props.PSObject.Properties) { if ($prop.Name -notmatch '^PS') { $items += [PSCustomObject]@{ category='registry-run'; location=$p; name=$prop.Name; value=[string]$prop.Value } } } } }"
            "$startupDirs = @(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\", \"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\")"
            "foreach ($d in $startupDirs) { if (Test-Path $d) { Get-ChildItem -Path $d -Force | ForEach-Object { $items += [PSCustomObject]@{ category='startup-folder'; location=$_.FullName; name=$_.Name; value=$_.FullName } } } }"
            "$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | Select-Object TaskName, TaskPath, State"
            "foreach ($t in $tasks) { $items += [PSCustomObject]@{ category='scheduled-task'; location=$t.TaskPath; name=$t.TaskName; value=[string]$t.State } }"
        ]

        if $safe_keyword != null {
            $ps_lines ++= [("$items = $items | Where-Object { (($_.location + ' ' + $_.name + ' ' + $_.value).ToLower()) -like '*" + $safe_keyword + "*' }")]
        }

        $ps_lines ++= [("$items | Select-Object -First " + ($limit | into string) + " | ConvertTo-Json -Depth 4")]
        let raw = (powershell -NoProfile -Command ($ps_lines | str join "; "))
        if (($raw | str trim) == "") {
            []
        } else {
            let parsed = (try { $raw | from json } catch { [] })
            let parsed_desc = ($parsed | describe)
            if ($parsed_desc | str starts-with "record") {
                [$parsed]
            } else if ($parsed_desc | str starts-with "list") {
                $parsed
            } else {
                []
            }
        }
    } else {
        let candidates = [
            "/etc/crontab"
            "/etc/cron.d/*"
            "/etc/cron.daily/*"
            "/etc/cron.hourly/*"
            "/etc/cron.weekly/*"
            "/etc/cron.monthly/*"
            "/etc/systemd/system/*.service"
            "/etc/systemd/system/*.timer"
            "/lib/systemd/system/*.service"
            $"($env.HOME)/.config/systemd/user/*.service"
            $"($env.HOME)/.config/autostart/*.desktop"
            "/etc/rc.local"
            $"($env.HOME)/.bashrc"
            $"($env.HOME)/.profile"
            $"($env.HOME)/.zshrc"
        ]

        mut rows = []
        for pattern in $candidates {
            let matches = (try { glob $pattern } catch { [] })
            for path_item in $matches {
                if (($path_item | path exists) == false) {
                    continue
                }
                if ((try { $path_item | path type } catch { "other" }) != "file") {
                    continue
                }

                let path_text = ($path_item | into string)
                let lc_path = ($path_text | str downcase)
                let category = if ($lc_path | str contains "/cron") {
                    "cron"
                } else if ($lc_path | str contains "systemd") {
                    "systemd"
                } else if ($lc_path | str contains "autostart") {
                    "autostart"
                } else if ($lc_path | str ends-with "rc.local") {
                    "rc-local"
                } else if (($lc_path | str ends-with ".bashrc") or ($lc_path | str ends-with ".profile") or ($lc_path | str ends-with ".zshrc")) {
                    "shell-init"
                } else {
                    "persistence-file"
                }

                let clue = (try {
                    open $path_item
                    | lines
                    | each { |line| $line | str trim }
                    | where { |line| $line != "" and (($line | str starts-with "#") == false) and (($line | str starts-with ";") == false) }
                    | first
                } catch {
                    "-"
                })

                let matches_keyword = if $keyword == null {
                    true
                } else {
                    (($path_text | str downcase | str contains $keyword) or ($clue | str downcase | str contains $keyword))
                }

                if $matches_keyword {
                    let meta = (try { ls -a $path_item | first } catch { null })
                    if $meta != null {
                        $rows ++= [{
                            category: $category
                            path: $path_text
                            modified: (try { $meta.modified } catch { null })
                            size: (try { $meta.size } catch { 0 })
                            clue: $clue
                        }]
                    }
                }
            }
        }

        let out = ($rows | sort-by modified -r)
        if $limit > 0 { $out | first $limit } else { $out }
    }
}

# Score suspicious running processes
def proc-hunt [
    --contains: string  # Optional case-insensitive keyword filter
    --min-score: int = 1 # Minimum heuristic score to keep
    --limit: int = 200   # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let needle = if $contains != null { ($contains | str downcase | str trim) } else { null }

    let process_rows = if $is_windows {
        let raw = (powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json -Depth 4")
        let parsed = (try { $raw | from json } catch { [] })
        let parsed_desc = ($parsed | describe)
        let rows = if ($parsed_desc | str starts-with "record") {
            [$parsed]
        } else if ($parsed_desc | str starts-with "list") {
            $parsed
        } else {
            []
        }

        $rows | each { |p|
            {
                pid: (try { $p.ProcessId | into int } catch { 0 })
                ppid: (try { $p.ParentProcessId | into int } catch { 0 })
                user: "-"
                name: (try { $p.Name | into string } catch { "-" })
                cmdline: (try { $p.CommandLine | into string } catch { "" })
            }
        }
    } else {
        let raw = (^ps -eo pid=,ppid=,user=,comm=,args=)
        $raw
        | lines
        | parse --regex '^\s*(?<pid>\d+)\s+(?<ppid>\d+)\s+(?<user>\S+)\s+(?<name>\S+)\s*(?<cmdline>.*)$'
        | each { |p|
            {
                pid: (try { $p.pid | into int } catch { 0 })
                ppid: (try { $p.ppid | into int } catch { 0 })
                user: (try { $p.user | into string } catch { "-" })
                name: (try { $p.name | into string } catch { "-" })
                cmdline: (try { $p.cmdline | into string } catch { "" })
            }
        }
    }

    let scored = ($process_rows | each { |proc|
        let cmd = ($proc.cmdline | str downcase)
        mut score = 0
        mut reasons = []

        if ($cmd =~ '(/tmp/|/dev/shm/)') {
            $score = ($score + 2)
            $reasons ++= ["temp-exec-path"]
        }
        if ($cmd =~ '(curl|wget).*(http|https)') {
            $score = ($score + 2)
            $reasons ++= ["download-behavior"]
        }
        if ($cmd =~ '(powershell.+-enc|encodedcommand|frombase64string|base64 -d)') {
            $score = ($score + 3)
            $reasons ++= ["encoded-payload"]
        }
        if ($cmd =~ '(certutil|mshta|rundll32|regsvr32)') {
            $score = ($score + 2)
            $reasons ++= ["lolbin-usage"]
        }
        if ($cmd =~ '(nc |ncat |socat |reverse shell|/dev/tcp/)') {
            $score = ($score + 3)
            $reasons ++= ["shell-tunneling"]
        }
        if (($proc.name | str downcase) =~ '(python|bash|sh|powershell|cmd|wscript|cscript)') and ($cmd =~ '(http://|https://)') {
            $score = ($score + 1)
            $reasons ++= ["script-with-url"]
        }

        let matches_needle = if $needle == null {
            true
        } else {
            ((($proc.name | str downcase) | str contains $needle) or ($cmd | str contains $needle))
        }

        if ($score >= $min_score and $matches_needle) {
            {
                pid: $proc.pid
                ppid: $proc.ppid
                user: $proc.user
                name: $proc.name
                score: $score
                reasons: ($reasons | str join ", ")
                cmdline: $proc.cmdline
            }
        } else {
            null
        }
    } | where { |item| $item != null } | sort-by score -r)

    if $limit > 0 { $scored | first $limit } else { $scored }
}

# Hunt suspicious log lines quickly
def log-hunt [
    pattern?: string      # Optional keyword/regex-like text match (case-insensitive contains)
    --since-hours: int = 24 # Journal/Event lookback in hours
    --limit: int = 300      # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let default_pattern = "failed password|authentication failure|invalid user|sudo:|powershell|cmd.exe|wget|curl|base64|rundll32|mshta|certutil"
    let needle = if $pattern != null { ($pattern | str trim | str downcase) } else { null }

    if $is_windows {
        let safe_pattern = if $pattern != null {
            ($pattern | str replace --all "'" "''")
        } else {
            $default_pattern
        }

        let ps = [
            "$ErrorActionPreference = 'SilentlyContinue'"
            ("$start = (Get-Date).AddHours(-" + ($since_hours | into string) + ")")
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start} -ErrorAction SilentlyContinue"
            "$events += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -ErrorAction SilentlyContinue"
            "$events += Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start} -ErrorAction SilentlyContinue"
            ("$events = $events | Where-Object { $_.Message -match '(?i)" + $safe_pattern + "' }")
            "$events | Sort-Object TimeCreated -Descending | Select-Object -First 9999 TimeCreated, Id, LogName, ProviderName, Message"
            ("$events | Select-Object -First " + ($limit | into string) + " | ConvertTo-Json -Depth 4")
        ]

        let raw = (powershell -NoProfile -Command ($ps | str join "; "))
        if (($raw | str trim) == "") {
            []
        } else {
            let parsed = (try { $raw | from json } catch { [] })
            let parsed_desc = ($parsed | describe)
            if ($parsed_desc | str starts-with "record") {
                [$parsed]
            } else if ($parsed_desc | str starts-with "list") {
                $parsed
            } else {
                []
            }
        }
    } else {
        let has_journalctl = (try {
            let cmd_paths = (which --all journalctl | where type == "external" | get path)
            (($cmd_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })

        let file_candidates = [
            "/var/log/auth.log"
            "/var/log/secure"
            "/var/log/syslog"
            "/var/log/messages"
        ]

        mut rows = []
        for log_file in $file_candidates {
            if (($log_file | path exists) == false) {
                continue
            }

            let found = (try {
                open $log_file
                | lines
                | enumerate
                | where { |row|
                    let line = ($row.item | str downcase)
                    if $needle != null {
                        $line | str contains $needle
                    } else {
                        $line =~ $default_pattern
                    }
                }
                | each { |row|
                    {
                        source: $log_file
                        line: ($row.index + 1)
                        message: ($row.item | str trim)
                    }
                }
            } catch {
                []
            })
            $rows = ($rows | append $found)
        }

        if $has_journalctl {
            let journal_lines = (try {
                journalctl --since $"($since_hours) hours ago" --no-pager
                | lines
                | where { |line|
                    let lc = ($line | str downcase)
                    if $needle != null {
                        $lc | str contains $needle
                    } else {
                        $lc =~ $default_pattern
                    }
                }
                | each { |line| { source: "journalctl", line: "-", message: ($line | str trim) } }
            } catch {
                []
            })
            $rows = ($rows | append $journal_lines)
        }

        if $limit > 0 { $rows | first $limit } else { $rows }
    }
}

# Build a quick file timeline for a directory
def timeline-lite [
    target_path?: string = "."  # Directory to timeline
    --contains: string          # Optional path keyword filter
    --limit: int = 300          # Max returned rows
    --with-hash                 # Include SHA256 (slower)
] {
    if (($target_path | path exists) == false) {
        error make { msg: $"Path not found: ($target_path)" }
    }

    let needle = if $contains != null { ($contains | str downcase | str trim) } else { null }
    mut files = (glob $"($target_path)/**")
    $files = ($files | where { |entry| (try { ($entry | path type) == "file" } catch { false }) })

    if $needle != null {
        $files = ($files | where { |entry| (($entry | into string | str downcase) | str contains $needle) })
    }

    let rows = ($files | each { |entry|
        let meta = (try { ls -a $entry | first } catch { null })
        if $meta == null {
            null
        } else {
            let digest = if $with_hash {
                (try { open --raw $entry | hash sha256 } catch { "-" })
            } else {
                "-"
            }

            {
                path: ($entry | into string)
                size: (try { $meta.size } catch { 0 })
                modified: (try { $meta.modified } catch { null })
                created: (try { $meta.created } catch { null })
                sha256: $digest
            }
        }
    } | where { |item| $item != null } | sort-by modified -r)

    if $limit > 0 { $rows | first $limit } else { $rows }
}

# Hunt possible C2 domains using hednsextractor
def hdns [target_domain: string] {
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if (($target_domain | str trim) == "") {
        error make { msg: "Target domain cannot be empty." }
    }
    if ((do $has_cmd "hednsextractor") == false) {
        if ((do $has_cmd "go") == false) {
            error make { msg: "Go is not installed. Please install Go first." }
        }
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)hednsextractor(ansi reset)"
        go install -v github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest
    }
    echo $target_domain | hednsextractor -silent -only-domains
}

# Get latest config.nu from repository
def upc [] {
    try {
        http get https://raw.githubusercontent.com/CYB3RMX/NuSecurity/refs/heads/main/configs/config.nu | save -f $nu.config-path
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Config updated successfully! Restart Nu shell to apply changes."
    } catch {
        error make { msg: "Unable to fetch latest config from GitHub." }
    }
}

#System Cleaner
def clean [] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    let confirm = (input $"(ansi red_bold)System cache will be cleaned. Are you sure? [Y/n]: (ansi reset)" | str trim | str downcase)
    if $confirm == "y" or $confirm == "" {
        if $is_windows {
            if (do $has_cmd "powershell") {
                powershell -NoProfile -Command 'Get-ChildItem -Path $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue'
            } else {
                error make { msg: "powershell not found in PATH." }
            }
        } else {
            sudo apt autoremove -y
            sudo apt autoclean -y
            sudo rm -rf ~/.cache/*
        }
        echo "System Cleaned!"
    } else {
        echo "Operation cancelled."
    }
}

# Get ARP table with style!
def arpt [] {
    arp -a | lines | split column " " | select column2 column4 column5 column7 | rename IP_Address MAC_Address Proto Interface
}

# Search for target file in the system
def ff [target_file: string] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        let matches = (glob $"**/*($target_file)*" | where { |entry| ($entry | path type) == "file" })
        $matches
        return
    }

    if (do $has_external_cmd "fdfind") {
        fdfind -H --glob -t f $target_file / | lines
    } else {
        if (do $has_cmd "apt") and (do $has_cmd "sudo") {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi red_bold) fd-find not found, installing automatically...(ansi reset)"
            aget fd-find
        }

        if (do $has_external_cmd "fdfind") {
            fdfind -H --glob -t f $target_file / | lines
        } else {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi yellow_bold) Falling back to recursive glob in current directory(ansi reset)"
            glob $"**/*($target_file)*" | where { |entry| ($entry | path type) == "file" }
        }
    }
}

# List active and inactive services
def serv [] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    if $is_windows {
        powershell -NoProfile -Command 'Get-Service | Select-Object Name,Status | Sort-Object Name'
        return
    }

    let services = (ls /etc/init.d/ | get name) 
    $services | each { |serv_path|
        let serv_name = ($serv_path | path basename | str trim)
        let status_output = (try { systemctl is-active $serv_name } catch { 'unknown' })
        if ($status_output == "active") {
            let status = $"(ansi green_bold)active(ansi reset)"
            { service: $serv_name, status: $status }
        } else {
            let status = $"(ansi red_bold)inactive(ansi reset)"
            { service: $serv_name, status: $status }
        }
    }
}

# List disk partitions (lsblk with style!)
def dls [] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        sys disks
    } else {
        if (do $has_external_cmd "lsblk") {
            lsblk -r | lines | split column " " | skip 1 |select column1 column2 column3 column4 column5 column6 column7 | rename NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS
        } else {
            sys disks
        }
    }
}

# Format/fix USB or USB like devices
def fixu [target_disk: string] {
    let is_windows = (($nu.os-info.name | str downcase) == "windows")
    if $is_windows {
        error make { msg: "fixu is disabled on Windows. Use Disk Management or diskpart carefully." }
    }

    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Formatting: (ansi green_bold)($target_disk)(ansi reset)"
    sudo wipefs --all $target_disk
    sudo mkfs.vfat -F 32 $target_disk
    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi green_bold) ($target_disk)(ansi reset) formatted successfully!"
}

# Perform YARA scan against the given file
def yrs [target_file: string] {
    # Check rules first!
    if (($"($env.HOME)/rules" | path exists) == true ) {
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Performing YARA scan against: (ansi green_bold)($target_file)(ansi reset) Please wait!"
        let rule_arr = (glob $"($env.HOME)/rules/**")
        mut matched_rules = []
        for rul in ($rule_arr) {
            if (($rul | str contains ".yar") == true) {
                try {
                    let rulz = (yara -w $rul $target_file | str replace --all $target_file "")
                    for rr in ($rulz) {
                        if (($matched_rules | to text | str contains $rr) == false) {
                            $matched_rules ++= [$rr]
                        }
                    }
                } catch {}
            }
        }
        $matched_rules | split row "\n" | uniq | table
    } else {
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Downloading latest YARA rules from: (ansi green_bold)https://github.com/Yara-Rules/rules(ansi reset)"
        git clone https://github.com/Yara-Rules/rules $"($env.HOME)/rules"
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Download complete. (ansi yellow_bold)You must re-execute the command!"
    }
}

# Fetch ransomware victims (country or global) with optional monitoring mode
def rware [
    country_code?: string   # Optional ISO country code (TR, US). If empty, uses global recent feed.
    --limit: int = 0        # Limit output rows (0 = unlimited)
    --monitor (-m)          # Poll feed continuously and print only new entries
    --interval: int = 30    # Monitor poll interval in seconds
    --max-cycles: int = 0   # Monitor loop count (0 = infinite)
] {
    let field = { |entry: record, field_name: string|
        if ($entry | columns | any { |column| $column == $field_name }) {
            (try { $entry | get $field_name | into string | str trim } catch { "" })
        } else {
            ""
        }
    }

    let first_nonempty = { |values: list<any>|
        (try {
            $values
            | each { |v| $v | into string | str trim }
            | where { |v| $v != "" }
            | first
        } catch {
            ""
        })
    }

    let entry_id = { |entry: record|
        let url_id = (do $first_nonempty [
            (do $field $entry "url")
            (do $field $entry "post_url")
            (do $field $entry "claim_url")
        ])

        if $url_id != "" {
            $url_id
        } else {
            let victim = (do $first_nonempty [(do $field $entry "victim"), (do $field $entry "post_title")])
            let group = (do $first_nonempty [(do $field $entry "group"), (do $field $entry "group_name")])
            let published = (do $first_nonempty [(do $field $entry "attackdate"), (do $field $entry "published"), (do $field $entry "discovered")])
            $"($victim)|($group)|($published)"
        }
    }

    let entry_datetime = { |entry: record|
        let raw_value = (do $first_nonempty [
            (do $field $entry "discovered")
            (do $field $entry "published")
            (do $field $entry "attackdate")
        ])

        if $raw_value == "" {
            null
        } else {
            (try { $raw_value | into datetime } catch { null })
        }
    }

    let fetch = { |selected_country_code?|
        if ($selected_country_code != null and (($selected_country_code | str trim) != "")) {
            let code = ($selected_country_code | str trim | str upcase)
            let data = (http get $"https://api.ransomware.live/v2/countryvictims/($code)" | to json | from json)
            $data | each { |d|
                {
                    post_title: $d.post_title
                    published: $d.published
                    group_name: $d.group_name
                    website: $d.website
                    post_url: $d.post_url
                    country: (try { $d.country } catch { "" })
                    discovered: (try { $d.discovered } catch { "" })
                }
            }
        } else {
            let data = (http get "https://api.ransomware.live/v2/recentvictims" | to json | from json)
            $data | each { |d|
                {
                    victim: $d.victim
                    attackdate: $d.attackdate
                    group: $d.group
                    domain: $d.domain
                    country: $d.country
                    url: $d.url
                    claim_url: $d.claim_url
                    discovered: (try { $d.discovered } catch { "" })
                }
            }
        }
    }

    if $interval < 5 {
        error make { msg: "--interval must be at least 5 seconds" }
    }

    if $monitor {
        let monitor_started_at = (date now)
        let initial = (do $fetch $country_code)
        let initial_total = ($initial | length)
        let first_batch = if $limit > 0 { $initial | first $limit } else { $initial }
        print $"(ansi cyan_bold)[rware](ansi reset) Monitoring started. Baseline entries: ($initial_total). Interval: ($interval)s"
        if (($first_batch | length) > 0) {
            print ($first_batch | table -e)
        }

        mut seen_ids = ($initial | each { |entry| do $entry_id $entry } | uniq)
        mut cycle = 0

        loop {
            if ($max_cycles > 0 and $cycle >= $max_cycles) {
                break
            }

            sleep ($interval * 1sec)
            let latest = (do $fetch $country_code)
            let new_entries = ($latest | where { |entry|
                let current_entry_id = (do $entry_id $entry)
                let entry_time = (do $entry_datetime $entry)
                let is_recent = if $entry_time == null { true } else { $entry_time >= $monitor_started_at }
                $is_recent and (($seen_ids | any { |id| $id == $current_entry_id }) == false)
            })

            if (($new_entries | length) > 0) {
                let now = (date now | format date "%Y-%m-%d %H:%M:%S")
                print $"(ansi green_bold)[rware](ansi reset) New entries detected at ($now): ($new_entries | length)"
                let out = if $limit > 0 { $new_entries | first $limit } else { $new_entries }
                print ($out | table -e)
            }

            let latest_ids = ($latest | each { |entry| do $entry_id $entry })
            $seen_ids = (($seen_ids | append $latest_ids | uniq | last 5000))
            $cycle = ($cycle + 1)
        }
    } else {
        let data = (do $fetch $country_code)
        if $limit > 0 { $data | first $limit } else { $data }
    }
}

# Fetch latest proxy list
def pls [] {
    let pdata = (http get https://raw.githubusercontent.com/themiralay/Proxy-List-World/refs/heads/master/data-with-geolocation.json | to json | from json)
    mut p_array = []
    for d in ($pdata) {
        $p_array ++= [{
            "ip": $d.ip,
            "port": $d.port,
            "country": $d.geolocation.country,
            "country_code": $d.geolocation.countryCode,
            "isp": $d.geolocation.isp,
            "org": $d.geolocation.org,
            "as": $d.geolocation.as
        }]
    }
    $p_array
}

# Enumerate subdomains using crt.sh (faster than shx command but no httpx!)
def crt [target_domain: string] {
    let resp = (http get $"https://crt.sh/?q=%25.($target_domain)&output=json")
    mut r_array = []
    for d in ($resp) {
        $r_array ++= [{
            "common_name": $d.common_name
        }]
    }
    $r_array | uniq
}

# Perform reverse IP lookup
def rip [target_ipaddr: string] {
    let key_file = $"($env.HOME)/.whoisxmlkey.txt"
    let api_key = if ($key_file | path exists) {
        open $key_file | str trim
    } else {
        let entered_key = (input $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Enter your WHOISXMLAPI key: " | str trim)
        if $entered_key == "" {
            error make { msg: "WHOISXMLAPI key cannot be empty." }
        }
        $entered_key | save -f $key_file
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Key saved."
        $entered_key
    }
    let response = (http get $"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=($api_key)&ip=($target_ipaddr)" | get result)
    $response
}

# Perform DNS Chronicle lookup
def dchr [target_domain: string] {
    let key_file = $"($env.HOME)/.whoisxmlkey.txt"
    let api_key = if ($key_file | path exists) {
        open $key_file | str trim
    } else {
        let entered_key = (input $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Enter your WHOISXMLAPI key: " | str trim)
        if $entered_key == "" {
            error make { msg: "WHOISXMLAPI key cannot be empty." }
        }
        $entered_key | save -f $key_file
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Key saved."
        $entered_key
    }
    let response = (http post --content-type application/json https://dns-history.whoisxmlapi.com/api/v1 {"apiKey": $api_key, "searchType": "forward", "recordType": "a", "domainName": $target_domain} | get result)
    if (($response | get count) > 0) {
        $response | get records
    }
}

# Fetch file names from target open directory
def gf [target_url: string] {
    http get $target_url | lines | parse --regex 'href="([^"]+)"' | rename Files
}

# Triage IoC query
def triage [
    --family: string    # For ex: snakekeylogger
    --query: string     # For ex: domain, hash etc.
    --limit: int = 10   # Max report count
    --no-c2             # Skip C2 candidate extraction
    --no-config         # Skip malware config extraction
] {
    let known_benign = [
        "bing.com"
        "bing.net"
        "msedge.net"
        "microsoft.com"
        "windows.com"
        "ipify.org"
        "ip-api.com"
        "google.com"
        "googleapis.com"
        "gstatic.com"
        "github.com"
        "githubassets.com"
        "githubusercontent.com"
        "backblazeb2.com"
        "openh264.org"
        "vx-underground.org"
        "pki.goog"
        "cloudflare.com"
    ]

    let benign_host = { |host: string|
        let normalized = ($host | str downcase | str trim)
        (($known_benign | where { |item|
            ($normalized == $item) or ($normalized | str ends-with $".($item)")
        } | length) > 0)
    }

    let url_host = { |url_value: string|
        let cleaned = ($url_value | str replace --all "\\u0026" "&" | str replace --all "\\/" "/")
        (try {
            $cleaned | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
        } catch {
            null
        })
    }

    let is_ipv4 = { |value: string|
        (($value | str trim | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0)
    }

    let suspicious_host = { |host: string|
        let normalized = ($host | str downcase | str trim)
        if $normalized == "" {
            false
        } else if (do $benign_host $normalized) {
            false
        } else if (
            ($normalized | str starts-with "10.")
            or ($normalized | str starts-with "127.")
            or ($normalized | str starts-with "192.168.")
            or ($normalized | str starts-with "169.254.")
            or ($normalized | str starts-with "0.")
        ) {
            false
        } else if (($normalized | str starts-with "172.") and (try {
            let second_octet = ($normalized | split row "." | get 1 | into int)
            $second_octet >= 16 and $second_octet <= 31
        } catch {
            false
        })) {
            false
        } else {
            true
        }
    }

    let behavior_html = { |report_id: string|
        let behavior_url = $"https://tria.ge/($report_id)/behavioral1"
        (try { http get $behavior_url } catch { "" })
    }

    let first_capture = { |source: string, pattern: string|
        (try {
            $source | parse --regex $pattern | get 0.capture0 | str trim
        } catch {
            ""
        })
    }

    let clean_html_text = { |value: string|
        ($value
            | str replace --all --regex '<[^>]+>' ''
            | str replace --all '&amp;' '&'
            | str replace --all '&#160;' ' '
            | str replace --all '&nbsp;' ' '
            | str replace --all '&quot;' '"'
            | str replace --all '&#39;' "'"
            | str replace --all '&#10;' ' '
            | str replace --all '&#13;' ' '
            | str trim)
    }

    let config_block = { |config_section: string, heading: string|
        let marker = $"<div class=\"config-entry-heading\">($heading)</div>"
        (try {
            $config_section
            | split row $marker
            | get 1
            | split row '<div class="config-entry-heading">'
            | get 0
        } catch {
            ""
        })
    }

    let clean_list = { |items: list<any>, list_limit: int = 3|
        ($items
            | each { |item| do $clean_html_text ($item | into string) }
            | where { |v| ($v | str trim) != "" }
            | uniq
            | first $list_limit)
    }

    let c2_candidates = { |current_behavior_html: string|
        if (($current_behavior_html | str length) == 0) {
            return "-"
        }

        let raw_urls = (try {
            $current_behavior_html | parse --regex '"url":"(https?://[^"]+)"' | get capture0
        } catch {
            []
        })
        let flow_pairs = (try {
            $current_behavior_html | parse --regex '"domain":"([^"]+)","dst":"([^"]+)"'
        } catch {
            []
        })

        let download_urls = ($raw_urls | where { |u|
            ($u | str downcase) =~ '\.(bin|exe|dll|dat|ps1|vbs|scr|bat|cmd|zip|rar|7z|hta|msi|jar)(\?|$)'
        })

        let download_hosts = ($download_urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" })
        let url_hosts = ($raw_urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" })
        let ipv4_hosts = ($url_hosts | where { |h| do $is_ipv4 $h })

        let candidates = ($download_hosts | append $ipv4_hosts | uniq | where { |h| do $suspicious_host $h })
        mut ip_domain_pairs = []

        for pair in $flow_pairs {
            let flow_domain = $pair.capture0
            let dst_host = (try {
                $pair.capture1 | parse --regex '^([^:]+)' | get 0.capture0
            } catch {
                ""
            })

            if (
                (do $is_ipv4 $dst_host)
                and ((do $is_ipv4 $flow_domain) == false)
                and (do $suspicious_host $flow_domain)
            ) {
                $ip_domain_pairs ++= [{ ip: $dst_host, domain: $flow_domain }]
            }
        }

        mut formatted_candidates = []
        for host in $candidates {
            if (do $is_ipv4 $host) {
                let mapped_domains = (try {
                    $ip_domain_pairs | where ip == $host | get domain | uniq
                } catch {
                    []
                })

                if (($mapped_domains | length) > 0) {
                    for domain in ($mapped_domains | first 3) {
                        $formatted_candidates ++= [$"($domain) [($host)]"]
                    }
                } else {
                    $formatted_candidates ++= [$host]
                }
            } else {
                $formatted_candidates ++= [$host]
            }
        }

        let final_candidates = ($formatted_candidates | uniq)

        if (($final_candidates | length) == 0) {
            "-"
        } else {
            $final_candidates | first 5 | str join ", "
        }
    }

    let malware_config = { |current_behavior_html: string|
        let empty_config = {
            family: "-"
            version: "-"
            botnet: "-"
            c2: []
            urls: []
            credentials: []
            mutex: "-"
        }

        if (($current_behavior_html | str length) == 0) {
            return $empty_config
        }

        let config_section = (try {
            $current_behavior_html
            | split row '<div id="malware-config-container"'
            | get 1
            | split row '<div id="signatures"'
            | get 0
        } catch {
            ""
        })

        if (($config_section | str length) == 0) {
            return $empty_config
        }

        let family = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Family</div>.*?<p[^>]*>(.*?)</p>'))
        let version = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Version</div>.*?<p[^>]*>(.*?)</p>'))
        let botnet = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Botnet</div>.*?<p[^>]*>(.*?)</p>'))
        let mutex = (do $clean_html_text (do $first_capture $config_section '(?s)<b>mutex</b><p class="prewrap">(.*?)</p>'))

        let c2_entries = (try {
            let c2_block = (do $config_block $config_section "C2")
            $c2_block | parse --regex '(?s)<p[^>]*>(.*?)</p>' | get capture0
        } catch {
            []
        })

        let url_entries = (try {
            let urls_block = (do $config_block $config_section "URLs")
            $urls_block | parse --regex '(?i)https?://[^<" ]+' | get capture0
        } catch {
            []
        })

        let credential_entries = (try {
            let cred_block = ($config_section | parse --regex '(?s)<div class="credentials">.*?<ul class="list">(.*?)</ul>' | get 0.capture0)
            $cred_block
            | parse --regex '(?s)<li class="nano"><b>(?:<br>)?([^<:]+):\s*</b>(.*?)</li>'
            | each { |row|
                let k = (do $clean_html_text $row.capture0 | str downcase)
                let v = (do $clean_html_text $row.capture1)
                if ($k != "" and $v != "") { $"($k)=($v)" } else { null }
            }
            | where { |x| $x != null }
        } catch {
            []
        })

        let cleaned_c2 = (do $clean_list $c2_entries 4)
        let cleaned_urls = (do $clean_list $url_entries 3)
        let cleaned_credentials = (do $clean_list $credential_entries 8)

        {
            family: (if $family != "" { $family } else { "-" })
            version: (if $version != "" { $version } else { "-" })
            botnet: (if $botnet != "" { $botnet } else { "-" })
            c2: $cleaned_c2
            urls: $cleaned_urls
            credentials: $cleaned_credentials
            mutex: (if $mutex != "" { $mutex } else { "-" })
        }
    }

    let base_url = if ($family != null) {
        $"https://tria.ge/s/family:($family)"
    } else if ($query != null) {
        $"https://tria.ge/s?q=($query)"
    } else {
        error make { msg: "You must provide either --family or --query" }
    }

    let html = http get $base_url
    let names = $html | parse --regex '<div class="column-target"[^>]*>(.*?)</div>' | get capture0
    let ids   = $html | parse --regex 'data-sample-id="(.*?)"' | get capture0
    let scores = $html | parse --regex '<div class="score"[^>]*>(.*?)</div>' | get capture0

    let rows = ($names | zip $ids | zip $scores | each { |row|
        {
            FileName: $row.0.0
            ReportID: $row.0.1
            Score: $row.1
        }
    })

    let selected_rows = if $limit > 0 { $rows | first $limit } else { $rows }

    if $no_c2 and $no_config {
        $selected_rows
    } else {
        $selected_rows | each { |row|
            let current_behavior_html = (do $behavior_html $row.ReportID)
            mut out = $row

            if ($no_c2 == false) {
                $out = ($out | merge { C2: (do $c2_candidates $current_behavior_html) })
            }

            if ($no_config == false) {
                $out = ($out | merge { MalwareConfig: (do $malware_config $current_behavior_html) })
            }

            $out
        }
    }
}
