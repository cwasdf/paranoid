#!/usr/bin/env bash
#==============================================================================
# PARANOID macOS DISCOVERY TOOLS MODULE
#==============================================================================
# Focused, deterministic investigation tools for macOS security scanning.
# Each tool runs a specific, bounded, read-only evidence collection probe.
#
# The LLM calls these by name instead of writing freestyle shell commands.
# This keeps scans reproducible, safe, and auditable.
#
# SOURCE this from the main scanner:
#   source ./paranoid_macos_tools.sh
#
# Categories:
#   net.*          — DNS, proxy, sockets
#   mdns.*         — Bonjour / mDNS / multicast DNS
#   sharing.*      — File sharing, SSH, FTP, WebDAV, iCal/CalDAV, invites
#   persistence.*  — LaunchAgents/Daemons, cron, login items
#   p2p.*          — AirDrop, Continuity, AWDL, Bluetooth
#   printing.*     — CUPS
#   serial.*       — Serial device nodes, USB adapters
#   legacy.*       — UUCP artifacts
#   keychain.*     — Keychain, securityd, CloudKit Keychain (CKKS)
#   profiles.*     — MDM, configuration profiles
#   extensions.*   — System extensions, kernel extensions
#   tcc.*          — Transparency, Consent, Control database
#   codesign.*     — Code signature + spctl verification
#   env.*          — Environment variables, shell profiles
#   recent.*       — Recently modified files in system paths
#==============================================================================

#==============================================================================
# TOOL IMPLEMENTATIONS
#==============================================================================
# Each tool uses tool_shell_exec (from main scanner) for safe execution.
# If tool_shell_exec is not defined, we define a minimal fallback.
#==============================================================================

if ! type tool_shell_exec &>/dev/null; then
  tool_shell_exec() {
    local cmd="$1"
    local timeout="${2:-30}"
    if [ -z "$cmd" ]; then echo "TOOL_ERROR: missing cmd"; return 0; fi
    bash -c "$cmd" 2>&1 &
    local pid=$!
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
      [ "$waited" -ge "$timeout" ] && { kill "$pid" 2>/dev/null; echo "[TIMEOUT]"; break; }
      sleep 1; waited=$((waited + 1))
    done
    wait "$pid" 2>/dev/null
  }
fi

if ! type expand_path &>/dev/null; then
  expand_path() {
    local s="$1"
    s="${s//\$HOME/$HOME}"
    s="${s//\$USER/$(whoami)}"
    s="${s//\~/$HOME}"
    echo "$s"
  }
fi

# Helper: save full output to workdir, return path
_save_full_output() {
  local name="$1" content="$2"
  local wdir="${CMDBOT_WORKDIR:-${SCRIPT_DIR:-$HOME}/paranoid_findings/work}"
  mkdir -p "$wdir"
  local path="$wdir/${name}.txt"
  printf '%s' "$content" > "$path"
  echo "$path"
}

# Known Apple/system process names for filtering
_APPLE_PROCS='(apsd|trustd|mDNSRespo|syspolicy|symptomsd|airportd|wifip2pd|wifianaly|wifiveloc|configd|nsurlsess|identitys|rapportd|sharingd|locationd|cloudd|bird|cfprefsd|corebrigh|distnoted|launchd|kernel_ta|loginwind|opendirec|fseventsd|logd|syslogd|mds|mds_stor|mdworker|WindowServer|diskarbit|iconservi|coreaudio|bluetoothd|coreservi|nearbyd|spindump|ReportCra|diagnosti|usermanag|remoted|containerm|notificat|revisiond|deleted|photolibd|callservic|routined|homed|knowledge|corespeec|touchbare|SystemUIServe|ControlCe|Dock|Spotlight|com\.apple)'

# ── NET: DNS & Proxy ─────────────────────────────────────────────────────────

tool_dns_state() {
  local full_output full_path hosts_anomalies primary_resolver
  full_output=$(bash -c '
    echo "=== DNS Configuration (scutil) ==="
    scutil --dns 2>/dev/null
    echo
    echo "=== resolv.conf / hosts ==="
    ls -la /etc/resolv.conf /etc/hosts 2>/dev/null
    echo
    cat /etc/hosts 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "dns_state" "$full_output")

  # Extract only: primary resolver + any non-standard hosts entries
  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # Primary resolver nameservers
  echo "$full_output" | grep -A5 'resolver #1$' | grep 'nameserver' | head -n 4
  # Non-standard hosts entries (not localhost/broadcasthost)
  hosts_anomalies=$(echo "$full_output" | grep -v '^#' | grep -v '^$' | grep -v '127.0.0.1.*localhost' | grep -v '255.255.255.255.*broadcasthost' | grep -v '::1.*localhost' | grep -v '=== ' || true)
  if [ -n "$hosts_anomalies" ]; then
    echo "NON_APPLE: /etc/hosts anomalies:"
    echo "$hosts_anomalies"
  else
    echo "/etc/hosts: clean (standard entries only)"
  fi
  # Flag any unusual resolvers (not common public DNS)
  local unusual_dns
  unusual_dns=$(echo "$full_output" | grep 'nameserver' | grep -vE '(1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|208\.67\.|fe80::|127\.0\.0\.1|::1)' || true)
  if [ -n "$unusual_dns" ]; then
    echo "DEVIATION: Non-standard DNS resolvers:"
    echo "$unusual_dns"
  fi
}

tool_dns_networksetup() {
  tool_shell_exec "echo '=== Network Services ==='; networksetup -listallnetworkservices 2>/dev/null; echo; for svc in Wi-Fi Ethernet 'Thunderbolt Ethernet' 'USB 10/100/1000 LAN'; do echo \"--- DNS for \$svc ---\"; networksetup -getdnsservers \"\$svc\" 2>/dev/null; done" 15
}

tool_proxy_state() {
  local full_output full_path enabled_proxies
  full_output=$(bash -c '
    echo "=== System Proxy (scutil) ==="
    scutil --proxy 2>/dev/null
    echo
    echo "=== Web Proxy (Wi-Fi) ==="
    networksetup -getwebproxy Wi-Fi 2>/dev/null
    echo "=== Secure Web Proxy (Wi-Fi) ==="
    networksetup -getsecurewebproxy Wi-Fi 2>/dev/null
    echo "=== SOCKS Proxy (Wi-Fi) ==="
    networksetup -getsocksfirewallproxy Wi-Fi 2>/dev/null
    echo "=== Auto Proxy ==="
    networksetup -getautoproxyurl Wi-Fi 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "proxy_state" "$full_output")

  echo "SAVED: $full_path"
  # Only report if any proxy is actually enabled
  enabled_proxies=$(echo "$full_output" | grep -i 'Enabled: Yes' || true)
  if [ -n "$enabled_proxies" ]; then
    echo "WARNING: Active proxies detected:"
    echo "$enabled_proxies"
    echo "$full_output" | grep -iE '(Server:|Port:|URL:)' | grep -v ': 0$' | grep -v ': $' || true
  else
    echo "SUMMARY: No proxies enabled (clean)"
  fi
}

tool_sockets_ownership() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== LISTEN ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null
    echo
    echo "=== ESTABLISHED ==="
    sudo lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null
    echo
    echo "=== UDP ==="
    sudo lsof -nP -iUDP 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "sockets_full" "$full_output")

  local total_lines non_apple_listen non_apple_established non_apple_udp
  total_lines=$(echo "$full_output" | wc -l | tr -d ' ')
  echo "SAVED: $full_path ($total_lines lines)"

  # Filter to non-Apple processes only — this is what the LLM actually needs
  non_apple_listen=$(echo "$full_output" | sed -n '/=== LISTEN ===/,/=== ESTABLISHED ===/p' | grep -vE "$_APPLE_PROCS" | grep -v '^COMMAND' | grep -v '^===' | grep -v '^$' || true)
  non_apple_established=$(echo "$full_output" | sed -n '/=== ESTABLISHED ===/,/=== UDP ===/p' | grep -vE "$_APPLE_PROCS" | grep -v '^COMMAND' | grep -v '^===' | grep -v '^$' || true)
  non_apple_udp=$(echo "$full_output" | sed -n '/=== UDP ===/,$p' | grep -vE "$_APPLE_PROCS" | grep -v '^COMMAND' | grep -v '^===' | grep -v '^$' || true)

  echo "---- NON-APPLE LISTEN SOCKETS ----"
  if [ -n "$non_apple_listen" ]; then
    echo "$non_apple_listen" | head -n 30
  else
    echo "(none — all listeners are Apple system processes)"
  fi

  echo "---- NON-APPLE ESTABLISHED ----"
  if [ -n "$non_apple_established" ]; then
    echo "$non_apple_established" | head -n 30
  else
    echo "(none — all established connections are Apple system processes)"
  fi

  echo "---- NON-APPLE UDP ----"
  if [ -n "$non_apple_udp" ]; then
    echo "$non_apple_udp" | head -n 20
  else
    echo "(none)"
  fi

  # Flag any SYN_SENT/CLOSE_WAIT as those are always interesting
  local stuck_conns
  stuck_conns=$(echo "$full_output" | grep -E '(SYN_SENT|CLOSE_WAIT|CLOSED)' || true)
  if [ -n "$stuck_conns" ]; then
    echo "---- SUSPECT: STUCK/ABNORMAL CONNECTIONS ----"
    echo "$stuck_conns" | head -n 10
  fi
}

tool_network_interfaces() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== All interfaces ==="
    ifconfig -a 2>/dev/null
    echo
    echo "=== Routing table ==="
    netstat -rn 2>/dev/null
    echo
    echo "=== ARP table ==="
    arp -a 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "interfaces_full" "$full_output")

  local total_lines
  total_lines=$(echo "$full_output" | wc -l | tr -d ' ')
  echo "SAVED: $full_path ($total_lines lines)"

  # Only return active interfaces (skip all the inactive ones that waste tokens)
  echo "---- ACTIVE INTERFACES ----"
  echo "$full_output" | awk '/^[a-z].*: flags=.*UP.*RUNNING/{name=$0; getline; while(/^[[:space:]]/){print name; name=""; print; getline}}' | head -n 40

  # utun interfaces are always security-relevant
  local utun_ifaces
  utun_ifaces=$(echo "$full_output" | grep -A3 '^utun' || true)
  if [ -n "$utun_ifaces" ]; then
    echo "---- UTUN/TUNNEL INTERFACES ----"
    echo "$utun_ifaces"
  fi

  # Non-standard ARP entries (skip multicast)
  echo "---- ARP TABLE ----"
  echo "$full_output" | sed -n '/=== ARP table ===/,$p' | grep -v '^===' | grep -v 'mdns.mcast' | head -n 10

  # Default gateway
  echo "---- DEFAULT ROUTE ----"
  echo "$full_output" | grep '^default' | head -n 4
}

# ── MDNS: Bonjour / Multicast DNS ────────────────────────────────────────────

tool_mdns_state() {
  local full_output full_path non_apple_5353
  full_output=$(bash -c '
    echo "=== mDNSResponder process ==="
    ps aux | grep -i "mDNSResponder\|discoveryd" | grep -v grep
    echo "=== Port 5353 listeners ==="
    sudo lsof -nP -iUDP:5353 2>/dev/null
    echo "=== Bonjour in launchd ==="
    launchctl print system 2>/dev/null | grep -i "mdns\|bonjour\|mDNSResponder"
  ' 2>&1)
  full_path=$(_save_full_output "mdns_state" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # mDNSResponder process (1-2 lines)
  echo "$full_output" | grep -i 'mDNSResponder' | grep -v grep | grep -v '^===' | head -n 2
  # Non-Apple processes on port 5353
  non_apple_5353=$(echo "$full_output" | sed -n '/=== Port 5353/,/=== Bonjour/p' | grep -vE "$_APPLE_PROCS" | grep -v '^COMMAND' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$non_apple_5353" ]; then
    echo "NON_APPLE: Unexpected processes on mDNS port 5353:"
    echo "$non_apple_5353" | head -n 10
  else
    echo "Port 5353: only mDNSResponder (expected)"
  fi
  # Count total 5353 listeners
  local listener_count
  listener_count=$(echo "$full_output" | sed -n '/=== Port 5353/,/=== Bonjour/p' | grep -c -v '^===' | tr -d ' ')
  echo "Total 5353 bindings: $((listener_count - 1))"
}

tool_mdns_browse_sample() {
  local full_output full_path service_count unique_services
  full_output=$(bash -c '(dns-sd -B _services._dns-sd._udp 2>/dev/null & pid=$!; sleep 8; kill $pid 2>/dev/null)' 2>&1)
  full_path=$(_save_full_output "mdns_browse_sample" "$full_output")

  service_count=$(echo "$full_output" | grep -c 'Add' || echo "0")
  unique_services=$(echo "$full_output" | grep 'Add' | awk '{print $NF}' | sort -u)
  echo "SAVED: $full_path ($service_count advertisements in 8s)"
  echo "SUMMARY: Unique service types advertised on local network:"
  echo "$unique_services" | head -n 30
}

tool_mdns_registered_services() {
  local full_output full_path
  full_output=$(bash -c '
    (dns-sd -B _http._tcp 2>/dev/null & p1=$!
     dns-sd -B _smb._tcp 2>/dev/null & p2=$!
     dns-sd -B _ssh._tcp 2>/dev/null & p3=$!
     dns-sd -B _rfb._tcp 2>/dev/null & p4=$!
     dns-sd -B _ipp._tcp 2>/dev/null & p5=$!
     sleep 8; kill $p1 $p2 $p3 $p4 $p5 2>/dev/null)
  ' 2>&1)
  full_path=$(_save_full_output "mdns_registered_services" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY: Registered services found on local network:"
  # Show unique service+host pairs
  echo "$full_output" | grep 'Add' | awk '{print $(NF-1), $NF}' | sort -u | head -n 30
  # Flag security-relevant services
  local ssh_services vnc_services smb_services
  ssh_services=$(echo "$full_output" | grep '_ssh._tcp' | grep 'Add' || true)
  vnc_services=$(echo "$full_output" | grep '_rfb._tcp' | grep 'Add' || true)
  smb_services=$(echo "$full_output" | grep '_smb._tcp' | grep 'Add' || true)
  [ -n "$ssh_services" ] && echo "SUSPECT: SSH services advertised: $(echo "$ssh_services" | wc -l | tr -d ' ')"
  [ -n "$vnc_services" ] && echo "SUSPECT: VNC/Screen Sharing advertised: $(echo "$vnc_services" | wc -l | tr -d ' ')"
  [ -n "$smb_services" ] && echo "SUSPECT: SMB file shares advertised: $(echo "$smb_services" | wc -l | tr -d ' ')"
}

# ── SHARING SERVICES ─────────────────────────────────────────────────────────

tool_sharing_overview() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== AFP Server ==="
    sudo defaults read /Library/Preferences/com.apple.AppleFileServer 2>/dev/null || echo "(not configured)"
    echo "=== Remote Login ==="
    systemsetup -getremotelogin 2>/dev/null
    echo "=== Remote Apple Events ==="
    systemsetup -getremoteappleevents 2>/dev/null
    echo "=== Computer Names ==="
    systemsetup -getcomputername 2>/dev/null
    scutil --get ComputerName 2>/dev/null
    scutil --get LocalHostName 2>/dev/null
    echo "=== Sharing LaunchDaemons ==="
    ls -la /System/Library/LaunchDaemons /Library/LaunchDaemons 2>/dev/null | grep -iE "ssh|smb|afp|ftp|webdav|calendar|ical|cups|bonjour|sharing|screensharing|remote|vnc|rfb"
  ' 2>&1)
  full_path=$(_save_full_output "sharing_overview" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Key status lines
  echo "$full_output" | grep -iE '(Remote Login|Remote Apple Events|Computer Name)' | head -n 4
  # Flag anything enabled
  local enabled
  enabled=$(echo "$full_output" | grep -iE '(: On|: Yes|Enabled)' | grep -v '^===' || true)
  if [ -n "$enabled" ]; then
    echo "WARNING: Active sharing services:"
    echo "$enabled"
  else
    echo "All sharing services: OFF"
  fi
  # Non-Apple sharing daemons
  local non_apple_sharing
  non_apple_sharing=$(echo "$full_output" | sed -n '/=== Sharing LaunchDaemons ===/,$p' | grep -v '^===' | grep -vE 'com\.apple\.' | grep -v '^$' || true)
  if [ -n "$non_apple_sharing" ]; then
    echo "NON_APPLE: Third-party sharing daemons:"
    echo "$non_apple_sharing"
  fi
}

tool_file_sharing_smb_afp() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== SMB config ==="
    defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server 2>/dev/null || echo "(not configured)"
    echo "=== SMB processes ==="
    ps aux | grep -i "smbd\|nmbd" | grep -v grep
    echo "=== SMB/AFP listeners ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ":(445|139|548)\b"
    echo "=== Shared folders ==="
    sharing -l 2>/dev/null || echo "(not available)"
  ' 2>&1)
  full_path=$(_save_full_output "file_sharing_smb_afp" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Are SMB/AFP ports actually listening?
  local listeners
  listeners=$(echo "$full_output" | sed -n '/=== SMB\/AFP listeners ===/,/=== Shared folders ===/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$listeners" ]; then
    echo "WARNING: SMB/AFP ports are LISTENING:"
    echo "$listeners" | head -n 10
  else
    echo "SMB/AFP ports: not listening (clean)"
  fi
  # Shared folders
  local shares
  shares=$(echo "$full_output" | sed -n '/=== Shared folders ===/,$p' | grep -v '^===' | grep -v '(not available)' | grep -v '^$' || true)
  if [ -n "$shares" ]; then
    echo "Shared folders:"
    echo "$shares" | head -n 10
  else
    echo "Shared folders: none"
  fi
}

tool_remote_login_ssh() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== Remote Login ==="
    systemsetup -getremotelogin 2>/dev/null
    echo "=== sshd listening ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep ":22\b"
    echo "=== sshd_config (active) ==="
    grep -v "^#" /etc/ssh/sshd_config 2>/dev/null | grep -v "^$"
    echo "=== authorized_keys ==="
    for d in /root "$HOME"; do
      echo "--- $d ---"
      cat "$d/.ssh/authorized_keys" 2>/dev/null || echo "(none)"
      ls -la "$d/.ssh/" 2>/dev/null
    done
  ' 2>&1)
  full_path=$(_save_full_output "remote_login_ssh" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Remote login status
  local login_status
  login_status=$(echo "$full_output" | grep -i 'Remote Login' | head -n 1)
  echo "Status: ${login_status:-unknown}"
  # Is sshd actually listening?
  local sshd_listen
  sshd_listen=$(echo "$full_output" | sed -n '/=== sshd listening ===/,/=== sshd_config/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$sshd_listen" ]; then
    echo "WARNING: sshd is LISTENING on port 22:"
    echo "$sshd_listen" | head -n 5
  else
    echo "sshd: not listening (clean)"
  fi
  # Key sshd_config settings
  local sshd_risky
  sshd_risky=$(echo "$full_output" | sed -n '/=== sshd_config/,/=== authorized_keys/p' | grep -iE '(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|GatewayPorts)' || true)
  if [ -n "$sshd_risky" ]; then
    echo "sshd_config security settings:"
    echo "$sshd_risky"
  fi
  # Authorized keys
  local auth_keys
  auth_keys=$(echo "$full_output" | sed -n '/=== authorized_keys ===/,$p' | grep -E '^(ssh-|ecdsa-|sk-)' || true)
  if [ -n "$auth_keys" ]; then
    echo "SUSPECT: authorized_keys entries found:"
    echo "$auth_keys" | head -n 10
  else
    echo "authorized_keys: empty (clean)"
  fi
}

tool_screen_sharing_vnc() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== VNC/SS listeners ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ":(5900|5988|3283)\b"
    echo "=== SS processes ==="
    ps aux | grep -i "screensharingd\|ARDAgent" | grep -v grep
    echo "=== ARD config ==="
    defaults read /Library/Preferences/com.apple.RemoteDesktop 2>/dev/null || echo "(not configured)"
  ' 2>&1)
  full_path=$(_save_full_output "screen_sharing_vnc" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  local vnc_listen
  vnc_listen=$(echo "$full_output" | sed -n '/=== VNC\/SS listeners ===/,/=== SS processes ===/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$vnc_listen" ]; then
    echo "WARNING: Screen Sharing/VNC is LISTENING:"
    echo "$vnc_listen" | head -n 5
  else
    echo "VNC/Screen Sharing: not listening (clean)"
  fi
  local ard_conf
  ard_conf=$(echo "$full_output" | sed -n '/=== ARD config ===/,$p' | grep -v '^===' | grep -v '(not configured)' | grep -v '^$' || true)
  if [ -n "$ard_conf" ]; then
    echo "ARD configured:"
    echo "$ard_conf" | head -n 10
  else
    echo "ARD: not configured"
  fi
}

tool_ftp_webdav_http() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== HTTP/FTP listeners ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ":(20|21|80|443|8008|8080|8443)\b"
    echo "=== Web server procs ==="
    ps aux | grep -iE "httpd|apache|nginx|lighttpd|caddy|python.*http" | grep -v grep
    echo "=== Web LaunchDaemons ==="
    ls -la /System/Library/LaunchDaemons /Library/LaunchDaemons 2>/dev/null | grep -iE "webdav|http|apache|web"
  ' 2>&1)
  full_path=$(_save_full_output "ftp_webdav_http" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  local listeners
  listeners=$(echo "$full_output" | sed -n '/=== HTTP\/FTP listeners ===/,/=== Web server procs ===/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$listeners" ]; then
    echo "WARNING: HTTP/FTP/WebDAV ports LISTENING:"
    echo "$listeners" | head -n 15
  else
    echo "HTTP/FTP/WebDAV: not listening (clean)"
  fi
  local web_procs
  web_procs=$(echo "$full_output" | sed -n '/=== Web server procs ===/,/=== Web Launch/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$web_procs" ]; then
    echo "Web server processes running:"
    echo "$web_procs" | head -n 10
  fi
}

tool_ical_caldav() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== CalDAV processes ==="
    ps aux | grep -iE "calaccessd|CalendarAgent|accountsd|cloudd|bird" | grep -v grep
    echo "=== Calendar accounts ==="
    defaults read com.apple.CalendarAgent 2>/dev/null || echo "(not available)"
    echo "=== Internet accounts ==="
    defaults read MobileMeAccounts 2>/dev/null || echo "(not available)"
  ' 2>&1)
  full_path=$(_save_full_output "ical_caldav" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Non-Apple calendar processes
  local non_apple_cal
  non_apple_cal=$(echo "$full_output" | sed -n '/=== CalDAV processes ===/,/=== Calendar accounts ===/p' | grep -vE "$_APPLE_PROCS" | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$non_apple_cal" ]; then
    echo "NON_APPLE: Calendar-related processes:"
    echo "$non_apple_cal" | head -n 10
  else
    echo "CalDAV: only Apple processes (expected)"
  fi
  # Account info (just account names/types, not full config)
  local accounts
  accounts=$(echo "$full_output" | grep -iE '(AccountDescription|AccountType|Username|AccountDSID)' | head -n 10 || true)
  if [ -n "$accounts" ]; then
    echo "Configured accounts:"
    echo "$accounts"
  fi
}

tool_sharing_invites_logs() {
  local full_output full_path anomalies
  full_output=$(bash -c 'log show --style syslog --predicate '\''(process == "sharingd" OR process == "rapportd" OR process == "nearbyd")'\'' --last 30m 2>/dev/null || echo "(log not available)"' 2>&1)
  full_path=$(_save_full_output "sharing_invites_logs" "$full_output")

  local total_lines
  total_lines=$(echo "$full_output" | wc -l | tr -d ' ')
  echo "SAVED: $full_path ($total_lines lines)"
  echo "SUMMARY:"
  # Only surface errors, warnings, and connection-related entries
  anomalies=$(echo "$full_output" | grep -iE '(error|fail|denied|connect|accept|pair|invite|request|unauthorized|timeout|refused)' | tail -n 20 || true)
  if [ -n "$anomalies" ]; then
    echo "ANOMALY: Interesting log entries ($total_lines total lines, showing filtered):"
    echo "$anomalies"
  else
    echo "No errors/connection events in $total_lines log lines (last 30m)"
  fi
}

# ── PERSISTENCE ──────────────────────────────────────────────────────────────

tool_persistence_launchd() {
  local full_output full_path non_apple_daemons non_apple_agents non_apple_user_agents
  full_output=$(bash -c '
    echo "=== /Library/LaunchDaemons ==="
    ls -la /Library/LaunchDaemons/ 2>/dev/null || echo "(empty)"
    echo "=== /Library/LaunchAgents ==="
    ls -la /Library/LaunchAgents/ 2>/dev/null || echo "(empty)"
    echo "=== ~/Library/LaunchAgents ==="
    ls -la "$HOME/Library/LaunchAgents/" 2>/dev/null || echo "(empty)"
  ' 2>&1)
  full_path=$(_save_full_output "persistence_launchd" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"

  # Filter to ONLY non-Apple items — Apple items in /Library are com.apple.*
  non_apple_daemons=$(echo "$full_output" | sed -n '/=== \/Library\/LaunchDaemons ===/,/=== \/Library\/LaunchAgents ===/p' | grep -v '^===' | grep -v '^total' | grep -v '^$' | grep -vE 'com\.apple\.' || true)
  non_apple_agents=$(echo "$full_output" | sed -n '/=== \/Library\/LaunchAgents ===/,/=== ~\/Library/p' | grep -v '^===' | grep -v '^total' | grep -v '^$' | grep -vE 'com\.apple\.' || true)
  non_apple_user_agents=$(echo "$full_output" | sed -n '/=== ~\/Library\/LaunchAgents ===/,$p' | grep -v '^===' | grep -v '^total' | grep -v '^$' | grep -vE 'com\.apple\.' || true)

  echo "---- NON-APPLE LaunchDaemons (/Library) ----"
  if [ -n "$non_apple_daemons" ]; then
    echo "$non_apple_daemons"
  else
    echo "(none — all Apple)"
  fi

  echo "---- NON-APPLE LaunchAgents (/Library) ----"
  if [ -n "$non_apple_agents" ]; then
    echo "$non_apple_agents"
  else
    echo "(none — all Apple)"
  fi

  echo "---- NON-APPLE User LaunchAgents ----"
  if [ -n "$non_apple_user_agents" ]; then
    echo "$non_apple_user_agents"
  else
    echo "(none)"
  fi
}

tool_persistence_launchd_contents() {
  # Read plist contents of non-Apple LaunchDaemons/Agents only
  local full_output full_path non_apple_content
  full_output=$(bash -c '
    for dir in /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents"; do
      echo "=== $dir ==="
      if ls "$dir"/*.plist >/dev/null 2>&1; then
        for p in "$dir"/*.plist; do
          [ -f "$p" ] || continue
          basename "$p" | grep -q "^com\.apple\." && continue
          echo "--- $p ---"
          plutil -p "$p" 2>/dev/null | head -n 30
          echo
        done
      fi
    done
  ' 2>&1)
  full_path=$(_save_full_output "persistence_launchd_contents" "$full_output")

  # Only return content if there are non-Apple items
  non_apple_content=$(echo "$full_output" | grep -v '^===' | grep -v '^$' | head -n 5)
  if [ -n "$non_apple_content" ]; then
    echo "SAVED: $full_path"
    echo "$full_output"
  else
    echo "SAVED: $full_path"
    echo "SUMMARY: No non-Apple LaunchDaemons/Agents plists found (clean)"
  fi
}

tool_persistence_extract_executables() {
  tool_shell_exec "python3 -c \"
import glob, plistlib, os, subprocess
paths = set()
for d in ['/Library/LaunchAgents', '/Library/LaunchDaemons', os.path.expanduser('~/Library/LaunchAgents')]:
    for f in glob.glob(d + '/*.plist'):
        try:
            with open(f, 'rb') as fp:
                pl = plistlib.load(fp)
            pa = pl.get('ProgramArguments') or []
            pr = pl.get('Program')
            if pr: paths.add((f, pr))
            if isinstance(pa, list) and pa: paths.add((f, pa[0]))
        except Exception:
            pass
for plist_path, binary_path in sorted(paths):
    print(f'PLIST: {plist_path}')
    print(f'BINARY: {binary_path}')
    if os.path.exists(binary_path):
        r = subprocess.run(['codesign', '-dv', '--verbose=4', binary_path], capture_output=True, text=True, timeout=10)
        print(r.stderr[:500] if r.stderr else '(no codesign output)')
        r2 = subprocess.run(['shasum', '-a', '256', binary_path], capture_output=True, text=True, timeout=10)
        print(f'SHA256: {r2.stdout.strip()[:80]}')
    else:
        print(f'WARNING: binary not found on disk!')
    print()
\" 2>&1 | head -n 400" 45
}

tool_persistence_cron() {
  tool_shell_exec "echo '=== User crontab ==='; crontab -l 2>/dev/null || echo '(none)'; echo; echo '=== Root crontab ==='; sudo crontab -l 2>/dev/null || echo '(none)'; echo; echo '=== Periodic scripts ==='; ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null; echo; echo '=== at jobs ==='; sudo atq 2>/dev/null || echo '(atq not available or empty)'" 15
}

tool_persistence_login_items() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== loginwindow ==="
    defaults read com.apple.loginwindow 2>/dev/null || echo "(not available)"
    echo "=== backgrounditems BTM plist ==="
    local_plist="$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
    if [ -f "$local_plist" ]; then
      plutil -p "$local_plist" 2>/dev/null || echo "(cannot read btm plist)"
    else
      echo "(no backgrounditems.btm found)"
    fi
    echo "=== LaunchAgents ==="
    ls -la "$HOME/Library/LaunchAgents/" 2>/dev/null || echo "(none)"
    echo "=== Global LaunchAgents ==="
    ls -la /Library/LaunchAgents/ 2>/dev/null || echo "(none)"
  ' 2>&1)
  full_path=$(_save_full_output "persistence_login_items" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # loginwindow entries
  local loginwindow_items
  loginwindow_items=$(echo "$full_output" | sed -n '/=== loginwindow ===/,/=== backgrounditems/p' | grep -vE '(^===$|^$|not available)' || true)
  if [ -n "$loginwindow_items" ]; then
    echo "loginwindow entries:"
    echo "$loginwindow_items" | head -n 10
  else
    echo "loginwindow: clean"
  fi
  # Login items from BTM plist
  local login_items
  login_items=$(echo "$full_output" | sed -n '/=== backgrounditems BTM plist ===/,/=== LaunchAgents ===/p' | grep -v '^===' | grep -v '(no backgrounditems' | grep -v '(cannot read' | grep -v '^$' || true)
  if [ -n "$login_items" ]; then
    echo "Login items (BTM plist):"
    echo "$login_items" | head -n 10
  else
    echo "Login items: none"
  fi
  # Non-Apple LaunchAgents
  local non_apple_agents
  non_apple_agents=$(echo "$full_output" | sed -n '/=== LaunchAgents ===/,/=== Global LaunchAgents ===/p' | grep -vE '(^===$|^$|com\.apple\.|^\(none\))' || true)
  if [ -n "$non_apple_agents" ]; then
    echo "NON_APPLE: User LaunchAgents:"
    echo "$non_apple_agents" | head -n 10
  fi
}

# ── PEER-TO-PEER ─────────────────────────────────────────────────────────────

tool_p2p_airdrop_continuity() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== AWDL ==="
    ifconfig awdl0 2>/dev/null || echo "(awdl0 not present)"
    echo "=== LLW ==="
    ifconfig llw0 2>/dev/null || echo "(llw0 not present)"
    echo "=== P2P processes ==="
    ps aux | grep -iE "sharingd|nearbyd|rapportd|bluetoothd|AirPlay|wifip2pd" | grep -v grep
    echo "=== P2P sockets ==="
    sudo lsof -nP -i 2>/dev/null | grep -iE "sharingd|nearbyd|rapportd|bluetoothd|wifip2pd"
    echo "=== Bluetooth ==="
    system_profiler SPBluetoothDataType 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "p2p_airdrop" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # AWDL/LLW status
  local awdl_active llw_active
  awdl_active=$(echo "$full_output" | sed -n '/=== AWDL ===/,/=== LLW ===/p' | grep -c 'status: active' || echo "0")
  llw_active=$(echo "$full_output" | sed -n '/=== LLW ===/,/=== P2P processes ===/p' | grep -c 'status: active' || echo "0")
  echo "AWDL: $([ "$awdl_active" -gt 0 ] && echo 'ACTIVE' || echo 'inactive')"
  echo "LLW: $([ "$llw_active" -gt 0 ] && echo 'ACTIVE' || echo 'inactive')"
  # Count P2P connections
  local p2p_conn_count
  p2p_conn_count=$(echo "$full_output" | sed -n '/=== P2P sockets ===/,/=== Bluetooth ===/p' | grep -c -v '^===' || echo "0")
  echo "P2P socket connections: $((p2p_conn_count - 1))"
  # Bluetooth — just connected devices and state
  echo "---- BLUETOOTH ----"
  echo "$full_output" | sed -n '/=== Bluetooth ===/,$p' | grep -iE '(State:|Address:|Connected:|Name:|Discoverable:)' | head -n 15
  # Flag if AWDL is active — that means AirDrop is in use
  if [ "$awdl_active" -gt 0 ]; then
    echo "WARNING: AWDL is active (AirDrop/Continuity in use)"
  fi
}

# ── PRINTING (CUPS) ──────────────────────────────────────────────────────────

tool_cups_printing() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== CUPS processes ==="
    ps aux | grep -iE "cupsd|cups-browsed" | grep -v grep
    echo "=== CUPS listening ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep ":631\b"
    echo "=== CUPS recent mods ==="
    find /etc/cups -maxdepth 2 -type f -mtime -14 2>/dev/null
    echo "=== Printers ==="
    lpstat -p -d 2>/dev/null
    echo "=== Web interface ==="
    grep -i "WebInterface" /etc/cups/cupsd.conf 2>/dev/null || echo "(default)"
  ' 2>&1)
  full_path=$(_save_full_output "cups_printing" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Is CUPS listening?
  local cups_listen
  cups_listen=$(echo "$full_output" | sed -n '/=== CUPS listening ===/,/=== CUPS recent/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$cups_listen" ]; then
    echo "CUPS: listening on port 631"
  else
    echo "CUPS: not listening"
  fi
  # Recently modified files
  local recent_cups
  recent_cups=$(echo "$full_output" | sed -n '/=== CUPS recent mods ===/,/=== Printers ===/p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$recent_cups" ]; then
    echo "Recently modified CUPS files (14d):"
    echo "$recent_cups" | head -n 10
  fi
  # Printers
  echo "$full_output" | sed -n '/=== Printers ===/,/=== Web interface ===/p' | grep -v '^===' | head -n 5
  # Web interface
  echo "$full_output" | sed -n '/=== Web interface ===/,$p' | grep -v '^===' | head -n 2
}

# ── SERIAL CONNECTIONS ───────────────────────────────────────────────────────

tool_serial_connections() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== Serial device nodes ==="
    ls -la /dev/cu.* /dev/tty.* 2>/dev/null || echo "(none)"
    echo "=== USB devices ==="
    system_profiler SPUSBDataType 2>/dev/null
    echo "=== IORegistry serial ==="
    ioreg -p IOUSB -l 2>/dev/null | grep -iE "FTDI|Serial|CDC|Modem|CP210|CH34|Prolific|\"USB Product Name\""
  ' 2>&1)
  full_path=$(_save_full_output "serial_connections" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # Serial device nodes (usually small)
  local serial_devs
  serial_devs=$(echo "$full_output" | sed -n '/=== Serial device nodes ===/,/=== USB devices ===/p' | grep -v '^===' | grep -v '^$' | grep -v '(none)' || true)
  if [ -n "$serial_devs" ]; then
    echo "Serial devices:"
    echo "$serial_devs" | head -n 10
  else
    echo "Serial devices: none"
  fi
  # USB — just product names and vendor info, not the full tree
  local usb_products
  usb_products=$(echo "$full_output" | grep -iE '(Product ID:|Vendor ID:|Serial Number:|Manufacturer:|^    [A-Z])' | grep -v 'Apple' | head -n 20 || true)
  if [ -n "$usb_products" ]; then
    echo "NON_APPLE USB devices:"
    echo "$usb_products"
  else
    echo "USB: Apple-only devices"
  fi
  # Serial-specific IORegistry hits
  local serial_io
  serial_io=$(echo "$full_output" | sed -n '/=== IORegistry serial ===/,$p' | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$serial_io" ]; then
    echo "SUSPECT: Serial/modem hardware detected:"
    echo "$serial_io" | head -n 10
  fi
}

# ── LEGACY PROTOCOLS (UUCP) ─────────────────────────────────────────────────

tool_uucp_artifacts() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== UUCP binaries ==="
    for b in uucp uux uuxqt uucico cu tip; do
      p=$(command -v "$b" 2>/dev/null)
      [ -n "$p" ] && echo "FOUND: $b -> $p" && codesign -dv "$p" 2>&1 | head -n 5
    done
    echo "=== UUCP dirs ==="
    ls -la /etc/uucp /usr/lib/uucp /var/spool/uucp 2>/dev/null || echo "(none)"
    echo "=== Unusual listeners ==="
    sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -vE ":(22|53|80|88|443|631|5353|8080|8443|49152)\b"
  ' 2>&1)
  full_path=$(_save_full_output "uucp_artifacts" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # UUCP binaries
  local uucp_found
  uucp_found=$(echo "$full_output" | grep '^FOUND:' || true)
  if [ -n "$uucp_found" ]; then
    echo "SUSPECT: UUCP binaries present:"
    echo "$uucp_found"
  else
    echo "UUCP: no binaries found (clean)"
  fi
  # Unusual listeners (non-standard ports)
  local unusual
  unusual=$(echo "$full_output" | sed -n '/=== Unusual listeners ===/,$p' | grep -vE "^(==|$|COMMAND)" | grep -vE "$_APPLE_PROCS" || true)
  if [ -n "$unusual" ]; then
    echo "NON_APPLE: Unusual port listeners:"
    echo "$unusual" | head -n 15
  else
    echo "Unusual ports: none (or Apple-only)"
  fi
}

# ── KEYCHAIN / SECURITYD / CKKS ──────────────────────────────────────────────

tool_keychain_audit() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== Keychain processes ==="
    ps aux | grep -iE "securityd|trustd|cloudd|ckks|Keychain|akd|accountsd|secd" | grep -v grep
    echo "=== Keychain search list ==="
    security list-keychains 2>/dev/null
    echo "=== Default keychain ==="
    security default-keychain 2>/dev/null
    echo "=== Keychain files ==="
    ls -la "$HOME/Library/Keychains/" 2>/dev/null
    ls -la /Library/Keychains/ 2>/dev/null
    echo "=== Root cert count ==="
    security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c "keychain:" || echo "(error)"
  ' 2>&1)
  full_path=$(_save_full_output "keychain_audit" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # Keychain search list (usually 2-3 lines)
  echo "Search list:"
  echo "$full_output" | sed -n '/=== Keychain search list ===/,/=== Default keychain ===/p' | grep -v '^===' | head -n 5
  # Default keychain
  echo "Default: $(echo "$full_output" | sed -n '/=== Default keychain ===/,/=== Keychain files ===/p' | grep -v '^===' | head -n 1)"
  # Root cert count
  local cert_count
  cert_count=$(echo "$full_output" | sed -n '/=== Root cert count ===/,$p' | grep -v '^===' | head -n 1)
  echo "System root certs: $cert_count"
  # Non-Apple keychain processes (filter out standard ones)
  local non_apple_kc
  non_apple_kc=$(echo "$full_output" | sed -n '/=== Keychain processes ===/,/=== Keychain search/p' | grep -vE "$_APPLE_PROCS" | grep -v '^===' | grep -v '^$' || true)
  if [ -n "$non_apple_kc" ]; then
    echo "NON_APPLE: Unexpected keychain-related processes:"
    echo "$non_apple_kc" | head -n 10
  fi
  # Non-standard keychain files
  local non_std_kc_files
  non_std_kc_files=$(echo "$full_output" | sed -n '/=== Keychain files ===/,/=== Root cert/p' | grep -v '^===' | grep -v '^$' | grep -vE '(login\.keychain|System\.keychain|metadata|CloudKit|locked|\.db-wal|\.db-shm)' || true)
  if [ -n "$non_std_kc_files" ]; then
    echo "DEVIATION: Unusual keychain files:"
    echo "$non_std_kc_files" | head -n 10
  fi
}

tool_keychain_ckks_logs() {
  local full_output full_path anomalies
  full_output=$(bash -c 'log show --style syslog --predicate '\''(process == "securityd" OR process == "trustd" OR eventMessage CONTAINS[c] "CKKS" OR eventMessage CONTAINS[c] "CloudKit Keychain" OR eventMessage CONTAINS[c] "SOS" OR process == "secd")'\'' --last 30m 2>/dev/null || echo "(log not available)"' 2>&1)
  full_path=$(_save_full_output "keychain_ckks_logs" "$full_output")

  local total_lines
  total_lines=$(echo "$full_output" | wc -l | tr -d ' ')
  echo "SAVED: $full_path ($total_lines lines)"
  echo "SUMMARY:"
  # Surface only errors, trust failures, SOS events, key changes
  anomalies=$(echo "$full_output" | grep -iE '(error|fail|denied|untrust|revoke|SOS|circle|peer|reset|escrow|recovery|compromise|tamper|invalid|expire)' | tail -n 20 || true)
  if [ -n "$anomalies" ]; then
    echo "ANOMALY: Security-relevant CKKS/keychain events:"
    echo "$anomalies"
  else
    echo "No errors or security events in $total_lines log lines (last 30m)"
  fi
}

tool_keychain_user_certs() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== User keychain certs ==="
    security find-certificate -a "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null | grep -E "keychain:|\"labl\""
    echo "=== System keychain certs ==="
    security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -E "keychain:|\"labl\""
  ' 2>&1)
  full_path=$(_save_full_output "keychain_user_certs" "$full_output")

  local user_count sys_count
  user_count=$(echo "$full_output" | sed -n '/=== User keychain certs ===/,/=== System keychain certs ===/p' | grep -c '"labl"' || echo "0")
  sys_count=$(echo "$full_output" | sed -n '/=== System keychain certs ===/,$p' | grep -c '"labl"' || echo "0")
  echo "SAVED: $full_path"
  echo "SUMMARY:"
  echo "User keychain certificates: $user_count"
  echo "System keychain certificates: $sys_count"
  # Show non-standard cert labels (not Apple/common CAs)
  local unusual_certs
  unusual_certs=$(echo "$full_output" | grep '"labl"' | grep -viE '(Apple|DigiCert|VeriSign|GlobalSign|Comodo|GeoTrust|Thawte|Symantec|Baltimore|ISRG|USERTrust|Entrust|GoDaddy|Starfield|Amazon|Microsoft|Google|Sectigo)' || true)
  if [ -n "$unusual_certs" ]; then
    echo "DEVIATION: Non-standard certificates:"
    echo "$unusual_certs" | head -n 15
  else
    echo "All certs from known CAs (clean)"
  fi
}

# ── PROFILES & MDM ───────────────────────────────────────────────────────────

tool_profiles_mdm() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== Enrollment ==="
    profiles status -type enrollment 2>/dev/null || echo "(not enrolled)"
    echo "=== Profiles list ==="
    profiles list 2>/dev/null || echo "(none)"
    echo "=== Profile details ==="
    profiles show -type configuration 2>/dev/null || echo "(none)"
  ' 2>&1)
  full_path=$(_save_full_output "profiles_mdm" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # Enrollment status
  echo "$full_output" | sed -n '/=== Enrollment ===/,/=== Profiles list ===/p' | grep -v '^===' | head -n 3
  # Count profiles
  local profile_count
  profile_count=$(echo "$full_output" | grep -c 'profileIdentifier' || echo "0")
  echo "Installed profiles: $profile_count"
  # Show profile names/identifiers
  if [ "$profile_count" -gt 0 ]; then
    echo "$full_output" | grep -E '(profileIdentifier|profileDisplayName|profileOrganization)' | head -n 15
  fi
}

# ── SYSTEM EXTENSIONS / KEXTS ────────────────────────────────────────────────

tool_extensions_system_kext() {
  local full_output full_path third_party_kexts third_party_sysext
  full_output=$(bash -c '
    echo "=== System Extensions ==="
    systemextensionsctl list 2>/dev/null || echo "(not available)"
    echo "=== Loaded kexts ==="
    kmutil showloaded 2>/dev/null || kextstat 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "extensions_kexts" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # Third-party system extensions (non-Apple)
  third_party_sysext=$(echo "$full_output" | sed -n '/=== System Extensions ===/,/=== Loaded kexts ===/p' | grep -vE '(com\.apple\.|^===$|^\*|^$|not available)' || true)
  if [ -n "$third_party_sysext" ]; then
    echo "NON_APPLE: Third-party system extensions:"
    echo "$third_party_sysext" | head -n 20
  else
    echo "System extensions: Apple-only (clean)"
  fi
  # Third-party kexts
  third_party_kexts=$(echo "$full_output" | sed -n '/=== Loaded kexts ===/,$p' | grep -v 'com\.apple' | grep -v '^===' | grep -v '^$' | grep -v '^Index' | grep -v '^No variant' || true)
  if [ -n "$third_party_kexts" ]; then
    echo "NON_APPLE: Third-party kernel extensions:"
    echo "$third_party_kexts" | head -n 20
  else
    echo "Kernel extensions: Apple-only (clean)"
  fi
  # Total kext count for context
  local kext_count
  kext_count=$(echo "$full_output" | sed -n '/=== Loaded kexts ===/,$p' | grep -c -v '^===' || echo "0")
  echo "Total loaded kexts: $((kext_count - 1))"
}

# ── TCC (Transparency, Consent, Control) ─────────────────────────────────────

tool_tcc_database() {
  local full_output full_path
  full_output=$(bash -c '
    echo "=== TCC user ==="
    sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client, service, auth_value, last_modified FROM access ORDER BY last_modified DESC LIMIT 60;" 2>/dev/null || echo "(requires Full Disk Access)"
    echo "=== TCC system ==="
    sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client, service, auth_value, last_modified FROM access ORDER BY last_modified DESC LIMIT 60;" 2>/dev/null || echo "(requires Full Disk Access)"
  ' 2>&1)
  full_path=$(_save_full_output "tcc_database" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # Count grants
  local user_grants sys_grants
  user_grants=$(echo "$full_output" | sed -n '/=== TCC user ===/,/=== TCC system ===/p' | grep -c '|' || echo "0")
  sys_grants=$(echo "$full_output" | sed -n '/=== TCC system ===/,$p' | grep -c '|' || echo "0")
  echo "User TCC grants: $user_grants"
  echo "System TCC grants: $sys_grants"
  # Show non-Apple grants (most interesting)
  local non_apple_tcc
  non_apple_tcc=$(echo "$full_output" | grep '|' | grep -vE 'com\.apple\.' | head -n 20 || true)
  if [ -n "$non_apple_tcc" ]; then
    echo "NON_APPLE TCC grants:"
    echo "$non_apple_tcc"
  fi
  # Flag high-risk services
  local risky_tcc
  risky_tcc=$(echo "$full_output" | grep '|' | grep -iE '(kTCCServiceScreenCapture|kTCCServiceAccessibility|kTCCServiceSystemPolicyAllFiles|kTCCServiceMicrophone|kTCCServiceCamera)' | grep -vE 'com\.apple\.' || true)
  if [ -n "$risky_tcc" ]; then
    echo "SUSPECT: High-risk TCC permissions granted to non-Apple apps:"
    echo "$risky_tcc"
  fi
}

# ── CODESIGN VERIFICATION ────────────────────────────────────────────────────

tool_codesign_verify() {
  local target="$1"
  target="$(expand_path "$target")"
  if [ -z "$target" ] || [ ! -e "$target" ]; then
    echo "TOOL_ERROR: codesign.verify — target not found: $target"
    return 0
  fi
  tool_shell_exec "echo '=== Code Signature ==='; codesign -dv --verbose=4 \"$target\" 2>&1 | head -n 40; echo; echo '=== Gatekeeper Assessment ==='; spctl -a -vv \"$target\" 2>&1 | head -n 15; echo; echo '=== SHA256 ==='; shasum -a 256 \"$target\" 2>/dev/null | head -n 1" 15
}

tool_codesign_entitlements() {
  local target="$1"
  target="$(expand_path "$target")"
  if [ -z "$target" ] || [ ! -e "$target" ]; then
    echo "TOOL_ERROR: codesign.entitlements — target not found: $target"
    return 0
  fi
  tool_shell_exec "echo '=== Entitlements ==='; codesign -d --entitlements - \"$target\" 2>&1 | head -n 200" 10
}

# ── ENVIRONMENT / SHELL PROFILES ─────────────────────────────────────────────

tool_env_audit() {
  local full_output suspicious_env dyld_launchctl
  full_output=$(bash -c '
    echo "=== Security env vars ==="
    env | grep -iE "DYLD_|LD_|NSA|CFNET|SSH_|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|SUDO_" 2>/dev/null || echo "(none set)"
    echo "=== launchctl DYLD ==="
    launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null || echo "(not set)"
    launchctl getenv DYLD_LIBRARY_PATH 2>/dev/null || echo "(not set)"
    launchctl getenv DYLD_FRAMEWORK_PATH 2>/dev/null || echo "(not set)"
  ' 2>&1)

  echo "SUMMARY:"
  # DYLD injection is always critical
  suspicious_env=$(echo "$full_output" | grep -iE 'DYLD_INSERT|DYLD_LIBRARY|DYLD_FRAMEWORK' | grep -v '(not set)' || true)
  if [ -n "$suspicious_env" ]; then
    echo "WARNING: DYLD injection variables detected:"
    echo "$suspicious_env"
  fi
  # Proxy settings
  local proxy_env
  proxy_env=$(echo "$full_output" | grep -iE '(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|SOCKS)' || true)
  if [ -n "$proxy_env" ]; then
    echo "Proxy env vars: $proxy_env"
  fi
  # SSH variables
  local ssh_env
  ssh_env=$(echo "$full_output" | grep -i 'SSH_' || true)
  if [ -n "$ssh_env" ]; then
    echo "SSH env: $ssh_env"
  fi
  # If nothing interesting
  if [ -z "$suspicious_env" ] && [ -z "$proxy_env" ]; then
    echo "Environment: clean (no DYLD injection, no proxy override)"
  fi
}

tool_env_shell_profiles() {
  local full_output full_path suspicious
  full_output=$(bash -c '
    for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.zlogin" /etc/zshrc /etc/bashrc /etc/profile; do
      if [ -f "$f" ]; then
        echo "--- $f ($(wc -l < "$f" 2>/dev/null | tr -d " ") lines) ---"
        cat "$f" 2>/dev/null
        echo
      fi
    done
  ' 2>&1)
  full_path=$(_save_full_output "env_shell_profiles" "$full_output")

  echo "SAVED: $full_path ($(echo "$full_output" | wc -l | tr -d ' ') lines)"
  echo "SUMMARY:"
  # List which files exist
  echo "Files found:"
  echo "$full_output" | grep '^--- ' | head -n 15

  # Search for security-relevant patterns
  suspicious=$(echo "$full_output" | grep -inE '(DYLD_|LD_PRELOAD|curl.*\||wget.*\||eval\s|base64|nc\s+-|/dev/tcp|reverse|backdoor|alias\s+sudo|proxy|HTTPS?_PROXY|socks|ssh.*-D|ssh.*-R|ncat|socat|export\s+PATH.*:|chmod\s+777)' || true)
  if [ -n "$suspicious" ]; then
    echo "SUSPECT: Security-relevant patterns in shell profiles:"
    echo "$suspicious" | head -n 15
  else
    echo "No suspicious patterns detected"
  fi
  # Show any non-standard PATH additions
  local path_mods
  path_mods=$(echo "$full_output" | grep -iE '(export\s+PATH|path\+?=)' | grep -v '^#' | head -n 10 || true)
  if [ -n "$path_mods" ]; then
    echo "PATH modifications:"
    echo "$path_mods"
  fi
}

# ── RECENTLY MODIFIED FILES ──────────────────────────────────────────────────

tool_recent_system_modifications() {
  local full_output full_path non_apple_mods
  full_output=$(bash -c '
    echo "=== System paths (14d) ==="
    find /usr/local/bin /usr/bin /bin /sbin /usr/sbin /Library/LaunchDaemons /Library/LaunchAgents -xdev -type f -mtime -14 2>/dev/null
    echo "=== Applications (14d) ==="
    find /Applications -xdev -type f \( -perm -111 -o -name "*.dylib" -o -name "*.so" \) -mtime -14 2>/dev/null
  ' 2>&1)
  full_path=$(_save_full_output "recent_system_mods" "$full_output")

  local total_count
  total_count=$(echo "$full_output" | grep -c -v '^===' || echo "0")
  echo "SAVED: $full_path ($total_count files)"
  echo "SUMMARY:"

  # Filter out Apple/system standard paths — focus on non-standard modifications
  non_apple_mods=$(echo "$full_output" | grep -v '^===' | grep -v '^$' | grep -vE '(/System/|/usr/bin/|/bin/|/sbin/|/usr/sbin/)' | grep -vE '(com\.apple\.)' || true)
  if [ -n "$non_apple_mods" ]; then
    echo "NON_APPLE: Recently modified non-system files:"
    echo "$non_apple_mods" | head -n 30
  else
    echo "No non-system modifications in last 14 days"
  fi

  # Flag any modifications in sensitive system dirs
  local sensitive_mods
  sensitive_mods=$(echo "$full_output" | grep -E '(/Library/Launch(Daemons|Agents)/)' | grep -vE 'com\.apple\.' || true)
  if [ -n "$sensitive_mods" ]; then
    echo "SUSPECT: Recently modified non-Apple LaunchDaemons/Agents:"
    echo "$sensitive_mods" | head -n 15
  fi
}

tool_recent_user_modifications() {
  local full_output full_path
  full_output=$(bash -c "find \"$HOME\" -xdev -type f \\( -perm -111 -o -name '*.dylib' -o -name '*.so' \\) -mtime -14 -not -path '*/Library/Caches/*' -not -path '*/.Trash/*' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/venv/*' -not -path '*/__pycache__/*' 2>/dev/null" 2>&1)
  full_path=$(_save_full_output "recent_user_mods" "$full_output")

  local total_count
  total_count=$(echo "$full_output" | grep -c -v '^$' || echo "0")
  echo "SAVED: $full_path ($total_count files)"
  echo "SUMMARY:"

  # Highlight suspicious patterns: hidden directories, Launch dirs, dylibs in unexpected places
  local suspicious
  suspicious=$(echo "$full_output" | grep -E '(\.[^/]+/|LaunchAgent|LaunchDaemon|\.dylib|\.so$|/bin/)' | grep -v '^$' || true)
  if [ -n "$suspicious" ]; then
    echo "SUSPECT: Files in hidden/sensitive paths or dylibs:"
    echo "$suspicious" | head -n 20
  fi

  # Show rest but capped
  echo "---- RECENT USER EXECUTABLES (top 25) ----"
  echo "$full_output" | head -n 25
  if [ "$total_count" -gt 25 ]; then
    echo "... and $((total_count - 25)) more (see full list in saved file)"
  fi
}

# ── SIP / GATEKEEPER / AMFI STATUS ──────────────────────────────────────────

tool_security_status() {
  local full_output full_path sip gk gk_test nvram_sec fw_check
  full_output=$(bash -c '
    echo "=== SIP ==="
    csrutil status 2>/dev/null
    echo "=== Gatekeeper ==="
    spctl --status 2>/dev/null
    echo "=== GK assess /bin/ls ==="
    spctl --assess --type execute /bin/ls 2>&1 | head -n 5
    echo "=== NVRAM security ==="
    nvram -p 2>/dev/null | grep -iE "sip|csr|boot-args|amfi" || echo "(none)"
    echo "=== Firmware password ==="
    sudo firmwarepasswd -check 2>&1 | head -n 3
  ' 2>&1)
  full_path=$(_save_full_output "security_status" "$full_output")

  echo "SAVED: $full_path"
  echo "SUMMARY:"
  # SIP — one line
  sip=$(echo "$full_output" | grep -i 'System Integrity Protection' | head -n 1)
  echo "SIP: ${sip:-unknown}"
  # Gatekeeper — one line
  gk=$(echo "$full_output" | grep -i 'assessments' | head -n 1)
  echo "Gatekeeper: ${gk:-unknown}"
  # GK assessment
  gk_test=$(echo "$full_output" | sed -n '/=== GK assess/,/=== NVRAM/p' | grep -v '^===' | head -n 2)
  [ -n "$gk_test" ] && echo "GK test: $gk_test"
  # NVRAM — only if there's something interesting
  nvram_sec=$(echo "$full_output" | sed -n '/=== NVRAM security ===/,/=== Firmware/p' | grep -v '^===' | grep -v '^$')
  if echo "$nvram_sec" | grep -qvE '^\(none\)$'; then
    echo "NVRAM: $nvram_sec"
  else
    echo "NVRAM: clean (no security-related boot args)"
  fi
  # Firmware password — just the check result, NOT the help text
  fw_check=$(echo "$full_output" | sed -n '/=== Firmware password ===/,$p' | grep -v '^===' | grep -iE '(Password Enabled|No Firmware|not supported|not available|check not)' | head -n 1)
  echo "FirmwarePW: ${fw_check:-(check unavailable)}"
  # Flag deviations
  if echo "$sip" | grep -qi 'disabled'; then
    echo "WARNING: SIP is DISABLED"
  fi
  if echo "$gk" | grep -qi 'disabled'; then
    echo "WARNING: Gatekeeper is DISABLED"
  fi
}

#==============================================================================
# DISPATCHER FOR macOS TOOLS
#==============================================================================
# Call this from the main execute_tool_call() as a fallback.
# Returns 0 + output if handled, returns 1 if not a macOS tool.
#==============================================================================

execute_macos_tool_call() {
  local tool_json="$1"
  local tool
  tool="$(echo "$tool_json" | jq -r '.tool // empty' 2>/dev/null)"

  case "$tool" in
    # Net
    net.dns_state)          tool_dns_state ;;
    net.dns_networksetup)   tool_dns_networksetup ;;
    net.proxy_state)        tool_proxy_state ;;
    net.sockets_ownership)  tool_sockets_ownership ;;
    net.interfaces)         tool_network_interfaces ;;

    # mDNS
    mdns.state)             tool_mdns_state ;;
    mdns.browse_sample)     tool_mdns_browse_sample ;;
    mdns.registered)        tool_mdns_registered_services ;;

    # Sharing
    sharing.overview)           tool_sharing_overview ;;
    sharing.files.smb_afp)      tool_file_sharing_smb_afp ;;
    sharing.remote_ssh)         tool_remote_login_ssh ;;
    sharing.screen_vnc)         tool_screen_sharing_vnc ;;
    sharing.ftp_webdav_http)    tool_ftp_webdav_http ;;
    sharing.ical_caldav)        tool_ical_caldav ;;
    sharing.invites_logs)       tool_sharing_invites_logs ;;

    # Persistence
    persistence.launchd)            tool_persistence_launchd ;;
    persistence.launchd_contents)   tool_persistence_launchd_contents ;;
    persistence.extract_executables) tool_persistence_extract_executables ;;
    persistence.cron)               tool_persistence_cron ;;
    persistence.login_items)        tool_persistence_login_items ;;

    # P2P
    p2p.airdrop_continuity)  tool_p2p_airdrop_continuity ;;

    # Printing
    printing.cups)           tool_cups_printing ;;

    # Serial
    serial.audit)            tool_serial_connections ;;

    # Legacy
    legacy.uucp_artifacts)   tool_uucp_artifacts ;;

    # Keychain
    keychain.audit)          tool_keychain_audit ;;
    keychain.ckks_logs)      tool_keychain_ckks_logs ;;
    keychain.user_certs)     tool_keychain_user_certs ;;

    # Profiles
    profiles.mdm)            tool_profiles_mdm ;;

    # Extensions
    extensions.system_kext)  tool_extensions_system_kext ;;

    # TCC
    tcc.database)            tool_tcc_database ;;

    # Code signing
    codesign.verify)
      local target
      target="$(echo "$tool_json" | jq -r '.args.path // .args.target // empty')"
      tool_codesign_verify "$target"
      ;;
    codesign.entitlements)
      local target
      target="$(echo "$tool_json" | jq -r '.args.path // .args.target // empty')"
      tool_codesign_entitlements "$target"
      ;;

    # Environment
    env.audit)               tool_env_audit ;;
    env.shell_profiles)      tool_env_shell_profiles ;;

    # Recent modifications
    recent.system)           tool_recent_system_modifications ;;
    recent.user)             tool_recent_user_modifications ;;

    # Security status
    security.status)         tool_security_status ;;

    *)
      echo "TOOL_NOT_HANDLED"
      return 1
      ;;
  esac
  return 0
}

#==============================================================================
# PROMPT FRAGMENT
#==============================================================================
# Add to system prompt so the LLM knows about these focused tools.
#==============================================================================

MACOS_TOOLS_PROMPT_FRAGMENT='
═══════════════════════════════════════════════════════════════
macOS FOCUSED INVESTIGATION TOOLS
═══════════════════════════════════════════════════════════════
Deterministic, read-only probes. Prefer these over shell.exec.
Each tool PRE-ANALYZES output: saves full evidence to disk,
returns ONLY anomalies and summaries. Look for these markers:
  NON_APPLE: — items not from Apple (always investigate)
  WARNING:   — active services or risky configurations
  SUSPECT:   — patterns that warrant deeper investigation
  DEVIATION: — non-standard settings or certificates
  SAVED:     — full evidence file path (for manual review)

NETWORK:
  net.dns_state          — DNS resolvers + /etc/hosts anomalies
  net.dns_networksetup   — Per-interface DNS servers
  net.proxy_state        — Active proxy detection
  net.sockets_ownership  — Non-Apple LISTEN/ESTABLISHED/UDP sockets
  net.interfaces         — Active interfaces, tunnels, ARP, default route

mDNS / BONJOUR:
  mdns.state             — mDNSResponder status, non-Apple 5353 listeners
  mdns.browse_sample     — Unique service types on local network (8s)
  mdns.registered        — SSH/VNC/SMB/HTTP services advertised nearby

SHARING PROTOCOLS:
  sharing.overview       — Sharing service status (on/off summary)
  sharing.files.smb_afp  — SMB/AFP listening status + shared folders
  sharing.remote_ssh     — SSH listening, sshd_config risks, authorized_keys
  sharing.screen_vnc     — VNC/Screen Sharing listening, ARD config
  sharing.ftp_webdav_http — HTTP/FTP/WebDAV listener detection
  sharing.ical_caldav    — Non-Apple CalDAV processes, account info
  sharing.invites_logs   — Error/connection events from sharing logs (30min)

PERSISTENCE:
  persistence.launchd            — Non-Apple LaunchDaemons/Agents only
  persistence.launchd_contents   — Plist contents of non-Apple items only
  persistence.extract_executables — Codesign verify all referenced binaries
  persistence.cron               — Crontabs, periodic, at jobs
  persistence.login_items        — Non-Apple BTM entries, login items

PEER-TO-PEER:
  p2p.airdrop_continuity — AWDL/LLW status, P2P connections, Bluetooth

PRINTING:
  printing.cups          — CUPS listening status, recent config changes

SERIAL:
  serial.audit           — Serial devices, non-Apple USB, modem hardware

LEGACY PROTOCOLS:
  legacy.uucp_artifacts  — UUCP binaries, non-Apple unusual port listeners

KEYCHAIN / SECURITY:
  keychain.audit         — Keychain list, non-Apple processes, unusual files
  keychain.ckks_logs     — Security events from CKKS/keychain logs (30min)
  keychain.user_certs    — Non-standard certificate detection

PROFILES & MDM:
  profiles.mdm           — Enrollment status, installed profile summary

EXTENSIONS:
  extensions.system_kext — Non-Apple system extensions + kernel extensions

TCC (PRIVACY):
  tcc.database           — Non-Apple TCC grants, high-risk permissions

CODE SIGNING:
  codesign.verify        — {"tool":"codesign.verify","args":{"path":"/path"}}
  codesign.entitlements  — {"tool":"codesign.entitlements","args":{"path":"/path"}}

ENVIRONMENT:
  env.audit              — DYLD injection, proxy, SSH env detection
  env.shell_profiles     — Suspicious patterns in shell profiles

RECENT CHANGES:
  recent.system          — Non-Apple modifications in system paths (14d)
  recent.user            — Suspicious user executables/dylibs (14d)

SECURITY STATUS:
  security.status        — SIP/Gatekeeper/AMFI status + deviations
'
