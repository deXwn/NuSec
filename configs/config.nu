$env.config.buffer_editor = "vim" # Can be anything for ex. (nvim, nano, ...)
$env.config.show_banner = false

# Returns true if command exists in PATH
def has-cmd [command: string] {
    (try {
        let command_paths = (which --all $command | get path)
        (($command_paths | where {|candidate| ($candidate | path exists)} | length) > 0)
    } catch {
        false
    })
}

# Install a Go tool if it is not available in PATH
def ensure-go-tool [binary: string, package: string] {
    if (has-cmd $binary) == false {
        if (has-cmd "go") == false {
            error make { msg: "Go is not installed. Please install Go first." }
        }
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)($binary)(ansi reset)"
        go install -v $package
    }
}

# Read or prompt/store WHOISXMLAPI key
def get-whoisxml-key [] {
    let key_file = $"($env.HOME)/.whoisxmlkey.txt"
    if ($key_file | path exists) {
        open $key_file | str trim
    } else {
        let api_key = (input $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Enter your WHOISXMLAPI key: " | str trim)
        if $api_key == "" {
            error make { msg: "WHOISXMLAPI key cannot be empty." }
        }
        $api_key | save -f $key_file
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Key saved."
        $api_key
    }
}

# Parse environment flags safely (supports bool and common string values)
def env-flag-enabled [value: any] {
    if $value == null {
        false
    } else if (($value | describe) == "bool") {
        $value
    } else {
        let normalized = ($value | into string | str trim | str downcase)
        $normalized in ["1", "true", "yes", "on"]
    }
}

# Optional startup system info; set $env.NUSECURITY_SHOW_SYSINFO = true to enable
if ((env-flag-enabled ($env.NUSECURITY_SHOW_SYSINFO?)) and (has-cmd "neofetch")) {
    neofetch
}

# Add Go paths
for go_path in [$"($env.HOME)/go/bin", "/usr/local/go/bin"] {
    if (($env.PATH | to text | str contains $go_path) == false) {
        $env.PATH ++= [$go_path]
    }
}

# Skeleton of the prompt
def left_prompt [] {
    # Function to get the username
    let username = (whoami | str trim)

    # Function to get the hostname
    let hostname = (hostname | str trim)

    # Function to get the current directory
    let current_dir = (pwd)
    $"\n(ansi blue_bold)<----- ($username)@($hostname) ----->\n[(ansi red)($current_dir)(ansi blue_bold)]"
}

# Apply the custom prompt
$env.PROMPT_COMMAND = { left_prompt }
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
    sudo apt install -y $target_package
}

# Remove package
def arem [target_package: string] {
    sudo apt remove $target_package
}

# List connections and listening ports
def netcon [] {
    lsof -i4 -V -E -R | awk '$1 ~ /:*(-|$)/{ gsub(/:[^-]*/, "", $1); print $1,$2,$3,$4,$9,$10,$11 }' | to text | lines | split column " " | rename COMMAND PID PPID USER PROTO CONNECTION STATUS | skip 1
}

# Fetch last 50 C2 panel from Viriback
def vrb [] {
    http get https://tracker.viriback.com/last50.php | to json | from json
}

# Extract host from URLHAUS URL row
def haus-url-host [url_value: string] {
    (try {
        $url_value | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
    } catch {
        null
    })
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
                let host = (haus-url-host $u)
                $host != null and ($host | str downcase | str contains $needle)
            })
        }

        if ($host_ends_with != null) {
            let suffix = ($host_ends_with | str downcase)
            $urls = ($urls | where { |u|
                let host = (haus-url-host $u)
                $host != null and ($host | str downcase | str ends-with $suffix)
            })
        }

        if $host_only {
            let hosts = ($urls | each { |u| haus-url-host $u } | where { |h| $h != null and ($h | str trim) != "" } | uniq)
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
    if (($listfile | path exists) == false) {
        error make { msg: $"List file not found: ($listfile)" }
    }
    ensure-go-tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    httpx -l $listfile -silent -td -title -sc
}

# Projectdiscovery tool downloader
def pdsc [tool_name: string] {
    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)($tool_name)"
    go install -v github.com/projectdiscovery/($tool_name)/cmd/($tool_name)@latest
}

# Get user defined commands/aliases
def hlp [--verbose (-v)] {
    if ($verbose) {
        help commands | where command_type =~ "custom" | select name description params
    } else {
        help commands | where command_type =~ "custom" | select name description
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

# Hunt possible C2 domains using hednsextractor
def hdns [target_domain: string] {
    if (($target_domain | str trim) == "") {
        error make { msg: "Target domain cannot be empty." }
    }
    ensure-go-tool "hednsextractor" "github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest"
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
    let confirm = (input $"(ansi red_bold)System cache will be cleaned. Are you sure? [Y/n]: (ansi reset)" | str trim | str downcase)
    if $confirm == "y" or $confirm == "" {
        sudo apt autoremove -y
        sudo apt autoclean -y
        sudo rm -rf ~/.cache/*
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
    if (has-cmd "fdfind") {
        fdfind -H --glob -t f $target_file / | lines
    } else {
        if (has-cmd "apt") and (has-cmd "sudo") {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi red_bold) fd-find not found, installing automatically...(ansi reset)"
            aget fd-find
        }

        if (has-cmd "fdfind") {
            fdfind -H --glob -t f $target_file / | lines
        } else {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi yellow_bold) Falling back to 'find'(ansi reset)"
            ^find / -type f -iname $"*($target_file)*" err> /dev/null | lines
        }
    }
}

# List active and inactive services
def serv [] {
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
    lsblk -r | lines | split column " " | skip 1 |select column1 column2 column3 column4 column5 column6 column7 | rename NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS
}

# Format/fix USB or USB like devices
def fixu [target_disk: string] {
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
                    let rulz = (yara -w $rul $target_file err> /dev/null | str replace --all $target_file "")
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

# Fetch latest ransomware victims by country code
def rware [country_code: string] {
    let data = (http get $"https://api.ransomware.live/v2/countryvictims/($country_code)" | to json | from json)
    mut json_array = []
    for d in ($data) {
        $json_array ++= [{
            "post_title": $d.post_title, 
            "published": $d.published,
            "group_name": $d.group_name,
            "website": $d.website,
            "post_url": $d.post_url
        }]
    }
    $json_array
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
    let api_key = (get-whoisxml-key)
    let response = (http get $"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=($api_key)&ip=($target_ipaddr)" | get result)
    $response
}

# Perform DNS Chronicle lookup
def dchr [target_domain: string] {
    let api_key = (get-whoisxml-key)
    let response = (http post --content-type application/json https://dns-history.whoisxmlapi.com/api/v1 {"apiKey": $api_key, "searchType": "forward", "recordType": "a", "domainName": $target_domain} | get result)
    if (($response | get count) > 0) {
        $response | get records
    }
}

# Fetch file names from target open directory
def gf [target_url: string] {
    http get $target_url | lines | parse --regex 'href="([^"]+)"' | rename Files
}

# Known-good infrastructure filter to reduce noisy C2 candidates
def triage-benign-host [host: string] {
    let normalized = ($host | str downcase | str trim)
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

    (($known_benign | where { |item|
        ($normalized == $item) or ($normalized | str ends-with $".($item)")
    } | length) > 0)
}

# Extract host portion from a URL string
def triage-url-host [url_value: string] {
    let cleaned = ($url_value | str replace --all "\\u0026" "&" | str replace --all "\\/" "/")
    (try {
        $cleaned | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
    } catch {
        null
    })
}

# Basic host scoring for likely malicious destinations
def triage-suspicious-host [host: string] {
    let normalized = ($host | str downcase | str trim)
    if $normalized == "" {
        false
    } else if (triage-benign-host $normalized) {
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

# Check if value is an IPv4 literal
def triage-is-ipv4 [value: string] {
    (($value | str trim | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0)
}

# Fetch behavioral report HTML
def triage-behavior-html [report_id: string] {
    let behavior_url = $"https://tria.ge/($report_id)/behavioral1"
    (try { http get $behavior_url } catch { "" })
}

# Return first regex capture or empty string
def triage-first-capture [source: string, pattern: string] {
    (try {
        $source | parse --regex $pattern | get 0.capture0 | str trim
    } catch {
        ""
    })
}

# Strip basic HTML tags/entities for readable summaries
def triage-clean-html-text [value: string] {
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

# Extract content block for a malware-config heading
def triage-config-block [config_section: string, heading: string] {
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

# Normalize scraped config lists to clean unique text values
def triage-clean-list [items: list<any>, limit: int = 3] {
    ($items
        | each { |item| triage-clean-html-text ($item | into string) }
        | where { |v| ($v | str trim) != "" }
        | uniq
        | first $limit)
}

# Pull candidate C2 hosts from behavioral HTML
def triage-c2-candidates [behavior_html: string] {

    if (($behavior_html | str length) == 0) {
        return "-"
    }

    let raw_urls = (try {
        $behavior_html | parse --regex '"url":"(https?://[^"]+)"' | get capture0
    } catch {
        []
    })
    let flow_pairs = (try {
        $behavior_html | parse --regex '"domain":"([^"]+)","dst":"([^"]+)"'
    } catch {
        []
    })

    let download_urls = ($raw_urls | where { |u|
        ($u | str downcase) =~ '\.(bin|exe|dll|dat|ps1|vbs|scr|bat|cmd|zip|rar|7z|hta|msi|jar)(\?|$)'
    })

    let download_hosts = ($download_urls | each { |u| triage-url-host $u } | where { |h| $h != null and ($h | str trim) != "" })
    let url_hosts = ($raw_urls | each { |u| triage-url-host $u } | where { |h| $h != null and ($h | str trim) != "" })
    let ipv4_hosts = ($url_hosts | where { |h| triage-is-ipv4 $h })

    let candidates = ($download_hosts | append $ipv4_hosts | uniq | where { |h| triage-suspicious-host $h })
    mut ip_domain_pairs = []

    for pair in $flow_pairs {
        let flow_domain = $pair.capture0
        let dst_host = (try {
            $pair.capture1 | parse --regex '^([^:]+)' | get 0.capture0
        } catch {
            ""
        })

        if (
            (triage-is-ipv4 $dst_host)
            and ((triage-is-ipv4 $flow_domain) == false)
            and (triage-suspicious-host $flow_domain)
        ) {
            $ip_domain_pairs ++= [{ ip: $dst_host, domain: $flow_domain }]
        }
    }

    mut formatted_candidates = []
    for host in $candidates {
        if (triage-is-ipv4 $host) {
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

# Pull summarized malware config from behavioral HTML
def triage-malware-config [behavior_html: string] {
    let empty_config = {
        family: "-"
        version: "-"
        botnet: "-"
        c2: []
        urls: []
        credentials: []
        mutex: "-"
    }

    if (($behavior_html | str length) == 0) {
        return $empty_config
    }

    let config_section = (try {
        $behavior_html
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

    let family = (triage-clean-html-text (triage-first-capture $config_section '(?s)<div class="config-entry-heading">Family</div>.*?<p[^>]*>(.*?)</p>'))
    let version = (triage-clean-html-text (triage-first-capture $config_section '(?s)<div class="config-entry-heading">Version</div>.*?<p[^>]*>(.*?)</p>'))
    let botnet = (triage-clean-html-text (triage-first-capture $config_section '(?s)<div class="config-entry-heading">Botnet</div>.*?<p[^>]*>(.*?)</p>'))
    let mutex = (triage-clean-html-text (triage-first-capture $config_section '(?s)<b>mutex</b><p class="prewrap">(.*?)</p>'))

    let c2_entries = (try {
        let c2_block = (triage-config-block $config_section "C2")
        $c2_block | parse --regex '(?s)<p[^>]*>(.*?)</p>' | get capture0
    } catch {
        []
    })

    let url_entries = (try {
        let urls_block = (triage-config-block $config_section "URLs")
        $urls_block | parse --regex '(?i)https?://[^<" ]+' | get capture0
    } catch {
        []
    })

    let credential_entries = (try {
        let cred_block = ($config_section | parse --regex '(?s)<div class="credentials">.*?<ul class="list">(.*?)</ul>' | get 0.capture0)
        $cred_block
        | parse --regex '(?s)<li class="nano"><b>(?:<br>)?([^<:]+):\s*</b>(.*?)</li>'
        | each { |row|
            let k = (triage-clean-html-text $row.capture0 | str downcase)
            let v = (triage-clean-html-text $row.capture1)
            if ($k != "" and $v != "") { $"($k)=($v)" } else { null }
        }
        | where { |x| $x != null }
    } catch {
        []
    })

    let cleaned_c2 = (triage-clean-list $c2_entries 4)
    let cleaned_urls = (triage-clean-list $url_entries 3)
    let cleaned_credentials = (triage-clean-list $credential_entries 8)

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

# Triage IoC query
def triage [
    --family: string    # For ex: snakekeylogger
    --query: string     # For ex: domain, hash etc.
    --limit: int = 10   # Max report count
    --no-c2             # Skip C2 candidate extraction
    --no-config         # Skip malware config extraction
] {
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
            let behavior_html = (triage-behavior-html $row.ReportID)
            mut out = $row

            if ($no_c2 == false) {
                $out = ($out | merge { C2: (triage-c2-candidates $behavior_html) })
            }

            if ($no_config == false) {
                $out = ($out | merge { MalwareConfig: (triage-malware-config $behavior_html) })
            }

            $out
        }
    }
}
