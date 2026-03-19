#!/usr/bin/env bash
#==============================================================================
# PARANOID THREAT INTELLIGENCE MODULE
#==============================================================================
# Adds real-world threat intelligence to the paranoid scanner:
#
#   1. YARA (local)        — Community rules from signature-base (Florian Roth)
#   2. VirusTotal          — SHA256 hash lookups (free tier: 4/min, 500/day)
#   3. abuse.ch            — MalwareBazaar hash lookups (free, no key)
#   4. CIRCL hashlookup    — Known-good/known-bad hash database (free, no key)
#   5. Hash batch          — Compute SHA256 for directories, then check all
#
# PHILOSOPHY:
#   - Never upload files to any service (hash lookups only)
#   - Rate-limit API calls to stay within free tiers
#   - All network calls are optional — scanner works offline too
#   - YARA rules are fetched once, then used locally forever
#
# INTEGRATION:
#   Source this file from the main scanner script:
#     source ./paranoid_threat_intel.sh
#   Then the LLM can call these tools via execute_tool_call()
#
# REQUIREMENTS:
#   - curl, jq, shasum (all standard on macOS)
#   - yara (optional: brew install yara)
#   - VIRUSTOTAL_API_KEY env var (optional, free at virustotal.com)
#==============================================================================

#==============================================================================
# CONFIGURATION
#==============================================================================

# ── Directories ──────────────────────────────────────────────────────────────
CMDBOT_INTEL_DIR="${PARANOID_INTEL_DIR:-${CMDBOT_INTEL_DIR:-$HOME/.paranoid/threat_intel}}"
CMDBOT_YARA_RULES_DIR="$CMDBOT_INTEL_DIR/yara_rules"
CMDBOT_HASH_CACHE_DIR="$CMDBOT_INTEL_DIR/hash_cache"
CMDBOT_YARA_INDEX="$CMDBOT_YARA_RULES_DIR/.rule_index"

mkdir -p "$CMDBOT_INTEL_DIR" "$CMDBOT_YARA_RULES_DIR" "$CMDBOT_HASH_CACHE_DIR"

# ── API Keys (from environment) ─────────────────────────────────────────────
VT_API_KEY="${VIRUSTOTAL_API_KEY:-}"

# ── Rate Limiting ────────────────────────────────────────────────────────────
VT_LAST_CALL=0
VT_MIN_INTERVAL=16  # 4 requests/min = 1 every 15s, we add 1s buffer
ABUSECH_LAST_CALL=0
ABUSECH_MIN_INTERVAL=2
CIRCL_LAST_CALL=0
CIRCL_MIN_INTERVAL=1

# ── Detection State ─────────────────────────────────────────────────────────
yara_installed=false
yara_path=""

#==============================================================================
# DETECTION HELPERS
#==============================================================================

detect_yara() {
  yara_installed=false
  yara_path=""
  if command -v yara >/dev/null 2>&1; then
    yara_installed=true
    yara_path="$(command -v yara)"
  fi
}

rate_limit_wait() {
  # Usage: rate_limit_wait VARNAME MIN_INTERVAL
  # e.g.:  rate_limit_wait VT_LAST_CALL 16
  local varname="$1"
  local interval="$2"
  local last_call=${!varname}
  local now
  now=$(date +%s)
  local diff=$((now - last_call))
  if [ "$diff" -lt "$interval" ]; then
    local wait_time=$((interval - diff))
    echo -e "  (rate limit: waiting ${wait_time}s)" >&2
    sleep "$wait_time"
  fi
  printf -v "$varname" '%s' "$(date +%s)"
}

#==============================================================================
# 1. YARA RULES MANAGEMENT
#==============================================================================
# We pull from well-known, trusted open-source rule repositories.
# Rules are fetched ONCE and stored locally. No auto-update (you control when).
#==============================================================================

# List of trusted YARA rule sources (GitHub raw URLs)
# These are individual high-signal rule files, not entire repos.
YARA_RULE_SOURCES=(
  # Florian Roth (Neo23x0) signature-base — most trusted community rules
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_suspicious_strings.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_suspicious_scripts.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_trojan_agent.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_rats_malwareconfig.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_powershell_empire.yar"
  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_osx_backdoor_d.yar"

  # Elastic Security YARA rules (macOS focused ones)
  "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/MacOS_Trojan_Generic.yar"
  "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/MacOS_Hacktool_Swiftbelt.yar"

  # JPCERT/CC — incident response rules
  "https://raw.githubusercontent.com/JPCERTCC/jpcert-yara/main/other/malware_common_strings.yar"
)

tool_yara_update_rules() {
  # Downloads/refreshes YARA rules from trusted sources.
  # This is the ONLY network-fetching operation for YARA.
  # Safe: we only download .yar text files from known GitHub repos.
  detect_yara
  if [ "$yara_installed" != true ]; then
    echo "YARA not installed. Install with: brew install yara"
    echo "Rules will still be downloaded for when you install it."
  fi

  echo "Updating YARA rules from ${#YARA_RULE_SOURCES[@]} trusted sources..."
  echo "Target directory: $CMDBOT_YARA_RULES_DIR"
  echo ""

  local success=0
  local failed=0
  local skipped=0

  for url in "${YARA_RULE_SOURCES[@]}"; do
    local filename
    filename="$(basename "$url")"
    local dest="$CMDBOT_YARA_RULES_DIR/$filename"

    # Skip if already exists and is less than 7 days old
    if [ -f "$dest" ]; then
      local age_days
      age_days=$(( ($(date +%s) - $(stat -f %m "$dest" 2>/dev/null || echo 0)) / 86400 ))
      if [ "$age_days" -lt 7 ]; then
        echo "  SKIP (fresh): $filename"
        skipped=$((skipped + 1))
        continue
      fi
    fi

    echo -n "  Fetching: $filename ... "
    if curl -sS -L --max-time 30 -o "$dest" "$url" 2>/dev/null; then
      # Validate: must contain at least one "rule" keyword
      if grep -q "^rule " "$dest" 2>/dev/null; then
        echo "OK ($(wc -c < "$dest" | tr -d ' ') bytes)"
        success=$((success + 1))
      else
        echo "INVALID (no YARA rules found, removing)"
        rm -f "$dest"
        failed=$((failed + 1))
      fi
    else
      echo "FAILED"
      failed=$((failed + 1))
    fi
  done

  echo ""
  echo "Summary: $success updated, $skipped fresh, $failed failed"
  echo ""

  # Build index of available rules
  echo "Available rule files:" > "$CMDBOT_YARA_INDEX"
  ls -la "$CMDBOT_YARA_RULES_DIR"/*.yar 2>/dev/null >> "$CMDBOT_YARA_INDEX" || true
  cat "$CMDBOT_YARA_INDEX"

  # Count total rules across all files
  local total_rules
  total_rules=$(grep -c "^rule " "$CMDBOT_YARA_RULES_DIR"/*.yar 2>/dev/null | tail -1 | cut -d: -f2 || echo 0)
  echo ""
  echo "Total YARA rules available: $total_rules"
}

tool_yara_scan_path() {
  # Scan a specific path (file or directory) with all available YARA rules.
  # Args: path, max_matches (default 200), recursive (default true)
  local target="$1"
  local max_matches="${2:-200}"
  local recursive="${3:-true}"

  detect_yara
  if [ "$yara_installed" != true ]; then
    echo "TOOL_ERROR: yara not installed (brew install yara)"
    return 0
  fi

  target="$(expand_path "$target" 2>/dev/null || echo "$target")"

  if [ -z "$target" ] || [ ! -e "$target" ]; then
    echo "TOOL_ERROR: yara.scan target not found: $target"
    return 0
  fi

  # Block scanning root
  if [ "$target" = "/" ]; then
    echo "TOOL_BLOCKED: refusing to scan /"
    return 0
  fi

  # Check for available rules
  local rule_files
  rule_files=$(ls "$CMDBOT_YARA_RULES_DIR"/*.yar 2>/dev/null)
  if [ -z "$rule_files" ]; then
    echo "TOOL_ERROR: No YARA rules found in $CMDBOT_YARA_RULES_DIR"
    echo "Run tool yara.update_rules first, or place .yar files manually."
    return 0
  fi

  local rule_count
  rule_count=$(echo "$rule_files" | wc -l | tr -d ' ')
  echo "Scanning: $target"
  echo "Rules:   $rule_count files from $CMDBOT_YARA_RULES_DIR"
  echo "---"

  local flags="-s"  # show matching strings
  [ "$recursive" = "true" ] && flags="$flags -r"

  local hits=0
  # Scan with each rule file separately to handle parse errors gracefully
  while IFS= read -r rule_file; do
    local matches
    matches=$(yara $flags "$rule_file" "$target" 2>/dev/null | head -n "$max_matches")
    if [ -n "$matches" ]; then
      echo "=== $(basename "$rule_file") ==="
      echo "$matches"
      hits=$((hits + $(echo "$matches" | wc -l | tr -d ' ')))
      echo ""
    fi
  done <<< "$rule_files"

  if [ "$hits" -eq 0 ]; then
    echo "No YARA matches found."
  else
    echo "---"
    echo "Total matches: $hits"
  fi
}

tool_yara_list_rules() {
  # Show what YARA rules are available
  echo "YARA rules directory: $CMDBOT_YARA_RULES_DIR"
  echo ""
  if ls "$CMDBOT_YARA_RULES_DIR"/*.yar >/dev/null 2>&1; then
    for f in "$CMDBOT_YARA_RULES_DIR"/*.yar; do
      local name rules_in_file
      name="$(basename "$f")"
      rules_in_file=$(grep -c "^rule " "$f" 2>/dev/null || echo 0)
      local size
      size=$(wc -c < "$f" | tr -d ' ')
      local age_days
      age_days=$(( ($(date +%s) - $(stat -f %m "$f" 2>/dev/null || echo 0)) / 86400 ))
      printf "  %-50s %3d rules  %6s bytes  %dd old\n" "$name" "$rules_in_file" "$size" "$age_days"
    done
  else
    echo "  (no rules installed)"
    echo "  Run yara.update_rules to download community rules."
  fi
}

#==============================================================================
# 2. VIRUSTOTAL HASH LOOKUP
#==============================================================================
# Free tier: 4 lookups/minute, 500/day, 15.5K/month
# We ONLY submit SHA256 hashes. We NEVER upload files.
# Requires: VIRUSTOTAL_API_KEY environment variable
#==============================================================================

tool_vt_hash_lookup() {
  # Look up a single SHA256 hash on VirusTotal
  local hash="$1"

  if [ -z "$VT_API_KEY" ]; then
    echo "TOOL_ERROR: VIRUSTOTAL_API_KEY not set."
    echo "Get a free key at: https://www.virustotal.com/gui/join-us"
    echo "Then: export VIRUSTOTAL_API_KEY='your-key-here'"
    return 0
  fi

  if [ -z "$hash" ]; then
    echo "TOOL_ERROR: vt.hash_lookup missing hash"
    return 0
  fi

  # Validate hash format (SHA256 = 64 hex chars)
  if ! echo "$hash" | grep -qE '^[a-fA-F0-9]{64}$'; then
    echo "TOOL_ERROR: invalid SHA256 hash format: $hash"
    return 0
  fi

  # Check cache first
  local cache_file="$CMDBOT_HASH_CACHE_DIR/vt_${hash}.json"
  if [ -f "$cache_file" ]; then
    local age_hours
    age_hours=$(( ($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || echo 0)) / 3600 ))
    if [ "$age_hours" -lt 24 ]; then
      echo "(cached result, ${age_hours}h old)"
      cat "$cache_file"
      return 0
    fi
  fi

  # Rate limit
  rate_limit_wait VT_LAST_CALL "$VT_MIN_INTERVAL"

  local response
  response=$(curl -sS --max-time 15 \
    -H "x-apikey: $VT_API_KEY" \
    "https://www.virustotal.com/api/v3/files/$hash" 2>&1)

  # Check for API errors
  local error_code
  error_code=$(echo "$response" | jq -r '.error.code // empty' 2>/dev/null)

  if [ "$error_code" = "NotFoundError" ]; then
    echo "VT_RESULT: UNKNOWN — hash not in VirusTotal database"
    echo "  Hash: $hash"
    echo "  This means the file has never been submitted to VT."
    echo "  For a legitimate Apple binary, this is unusual."
    return 0
  elif [ -n "$error_code" ]; then
    echo "VT_ERROR: $error_code"
    echo "$response" | jq -r '.error.message // empty' 2>/dev/null
    return 0
  fi

  # Cache the result
  echo "$response" > "$cache_file"

  # Extract key fields
  local malicious suspicious undetected harmless
  malicious=$(echo "$response" | jq '.data.attributes.last_analysis_stats.malicious // 0')
  suspicious=$(echo "$response" | jq '.data.attributes.last_analysis_stats.suspicious // 0')
  undetected=$(echo "$response" | jq '.data.attributes.last_analysis_stats.undetected // 0')
  harmless=$(echo "$response" | jq '.data.attributes.last_analysis_stats.harmless // 0')

  local total_engines=$((malicious + suspicious + undetected + harmless))
  local detections=$((malicious + suspicious))

  local name type_desc first_seen
  name=$(echo "$response" | jq -r '.data.attributes.meaningful_name // .data.attributes.names[0] // "unknown"')
  type_desc=$(echo "$response" | jq -r '.data.attributes.type_description // "unknown"')
  first_seen=$(echo "$response" | jq -r '.data.attributes.first_submission_date // 0')

  # Format first_seen as date
  local first_seen_str="unknown"
  if [ "$first_seen" != "0" ] && [ "$first_seen" != "null" ]; then
    first_seen_str=$(date -r "$first_seen" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$first_seen")
  fi

  echo "VT_RESULT:"
  echo "  Hash:        $hash"
  echo "  Name:        $name"
  echo "  Type:        $type_desc"
  echo "  Detections:  $detections / $total_engines engines"
  echo "    Malicious:  $malicious"
  echo "    Suspicious: $suspicious"
  echo "    Undetected: $undetected"
  echo "    Harmless:   $harmless"
  echo "  First Seen:  $first_seen_str"

  # Verdict
  if [ "$detections" -gt 5 ]; then
    echo "  VERDICT:     *** MALICIOUS *** ($detections engines flagged)"
  elif [ "$detections" -gt 0 ]; then
    echo "  VERDICT:     SUSPICIOUS ($detections engines flagged — investigate)"
  else
    echo "  VERDICT:     CLEAN (0 detections)"
  fi

  # Show top engine detections if any
  if [ "$malicious" -gt 0 ]; then
    echo ""
    echo "  Top detections:"
    echo "$response" | jq -r '
      .data.attributes.last_analysis_results
      | to_entries[]
      | select(.value.category == "malicious")
      | "    \(.key): \(.value.result)"
    ' 2>/dev/null | head -n 10
  fi
}

tool_vt_file_lookup() {
  # Compute SHA256 of a file, then look it up on VirusTotal
  local filepath="$1"
  filepath="$(expand_path "$filepath" 2>/dev/null || echo "$filepath")"

  if [ -z "$filepath" ] || [ ! -f "$filepath" ]; then
    echo "TOOL_ERROR: vt.file_lookup — file not found: $filepath"
    return 0
  fi

  local hash
  hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
  echo "File:  $filepath"
  echo "SHA256: $hash"
  echo "---"
  tool_vt_hash_lookup "$hash"
}

#==============================================================================
# 3. ABUSE.CH MALWAREBAZAAR HASH LOOKUP
#==============================================================================
# Completely free, no API key required.
# Checks if a hash is in the MalwareBazaar database (known malware samples).
# API docs: https://bazaar.abuse.ch/api/
#==============================================================================

tool_abusech_hash_lookup() {
  local hash="$1"

  if [ -z "$hash" ]; then
    echo "TOOL_ERROR: abusech.hash_lookup missing hash"
    return 0
  fi

  # Check cache
  local cache_file="$CMDBOT_HASH_CACHE_DIR/abusech_${hash}.json"
  if [ -f "$cache_file" ]; then
    local age_hours
    age_hours=$(( ($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || echo 0)) / 3600 ))
    if [ "$age_hours" -lt 24 ]; then
      echo "(cached result, ${age_hours}h old)"
      cat "$cache_file"
      return 0
    fi
  fi

  rate_limit_wait ABUSECH_LAST_CALL "$ABUSECH_MIN_INTERVAL"

  local response
  response=$(curl -sS --max-time 15 \
    -X POST \
    -d "query=get_info&hash=$hash" \
    "https://mb-api.abuse.ch/api/v1/" 2>&1)

  local query_status
  query_status=$(echo "$response" | jq -r '.query_status // empty' 2>/dev/null)

  if [ "$query_status" = "hash_not_found" ] || [ "$query_status" = "no_results" ]; then
    local result="ABUSECH_RESULT: CLEAN — hash not in MalwareBazaar database
  Hash: $hash
  Status: Not a known malware sample"
    echo "$result"
    echo "$result" > "$cache_file"
    return 0
  elif [ "$query_status" != "ok" ]; then
    echo "ABUSECH_ERROR: query_status=$query_status"
    echo "$response" | jq '.' 2>/dev/null | head -n 20
    return 0
  fi

  # Cache it
  echo "$response" > "$cache_file"

  # Extract fields from first result
  local file_name file_type sig first_seen tags
  file_name=$(echo "$response" | jq -r '.data[0].file_name // "unknown"')
  file_type=$(echo "$response" | jq -r '.data[0].file_type_mime // "unknown"')
  sig=$(echo "$response" | jq -r '.data[0].signature // "unknown"')
  first_seen=$(echo "$response" | jq -r '.data[0].first_seen // "unknown"')
  tags=$(echo "$response" | jq -r '.data[0].tags // [] | join(", ")' 2>/dev/null)

  echo "ABUSECH_RESULT: *** KNOWN MALWARE ***"
  echo "  Hash:        $hash"
  echo "  File Name:   $file_name"
  echo "  File Type:   $file_type"
  echo "  Signature:   $sig"
  echo "  First Seen:  $first_seen"
  echo "  Tags:        $tags"
  echo "  VERDICT:     This file is cataloged as MALWARE in MalwareBazaar"
}

tool_abusech_file_lookup() {
  local filepath="$1"
  filepath="$(expand_path "$filepath" 2>/dev/null || echo "$filepath")"

  if [ -z "$filepath" ] || [ ! -f "$filepath" ]; then
    echo "TOOL_ERROR: abusech.file_lookup — file not found: $filepath"
    return 0
  fi

  local hash
  hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
  echo "File:  $filepath"
  echo "SHA256: $hash"
  echo "---"
  tool_abusech_hash_lookup "$hash"
}

#==============================================================================
# 4. CIRCL HASHLOOKUP
#==============================================================================
# Free service by CIRCL (Computer Incident Response Center Luxembourg).
# Checks if a hash is KNOWN-GOOD (in their database of legitimate software).
# If a system binary's hash is NOT in CIRCL, that's a red flag.
# API: https://hashlookup.circl.lu/
# No API key required.
#==============================================================================

tool_circl_hash_lookup() {
  local hash="$1"

  if [ -z "$hash" ]; then
    echo "TOOL_ERROR: circl.hash_lookup missing hash"
    return 0
  fi

  # Check cache
  local cache_file="$CMDBOT_HASH_CACHE_DIR/circl_${hash}.json"
  if [ -f "$cache_file" ]; then
    local age_hours
    age_hours=$(( ($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || echo 0)) / 3600 ))
    if [ "$age_hours" -lt 72 ]; then  # Cache for 3 days (known-good changes slowly)
      echo "(cached result, ${age_hours}h old)"
      cat "$cache_file"
      return 0
    fi
  fi

  rate_limit_wait CIRCL_LAST_CALL "$CIRCL_MIN_INTERVAL"

  local response http_code tmpfile
  tmpfile=$(mktemp /tmp/cmdbot_circl.XXXXXX)
  http_code=$(curl -sS --max-time 15 -o "$tmpfile" \
    -w "%{http_code}" \
    "https://hashlookup.circl.lu/lookup/sha256/$hash" 2>/dev/null) || http_code="000"

  response=$(cat "$tmpfile" 2>/dev/null || echo "")
  rm -f "$tmpfile"

  if [ "$http_code" = "404" ]; then
    local result="CIRCL_RESULT: UNKNOWN — hash NOT in known-good database
  Hash: $hash
  Interpretation: This file is NOT recognized as known legitimate software.
  For system binaries, this could indicate tampering or replacement."
    echo "$result"
    echo "$result" > "$cache_file"
    return 0
  elif [ "$http_code" != "200" ]; then
    echo "CIRCL_ERROR: HTTP $http_code"
    echo "$response" | head -n 10
    return 0
  fi

  # Cache it
  echo "$response" > "$cache_file"

  local file_name source package_name
  file_name=$(echo "$response" | jq -r '.FileName // "unknown"')
  source=$(echo "$response" | jq -r '.source // "unknown"')
  package_name=$(echo "$response" | jq -r '.PackageName // .KnownAs // "unknown"')

  local result="CIRCL_RESULT: KNOWN-GOOD — hash recognized as legitimate software
  Hash:        $hash
  File Name:   $file_name
  Source:      $source
  Package:     $package_name
  Interpretation: This file matches a known legitimate distribution."
  echo "$result"
  echo "$result" > "$cache_file"
}

tool_circl_file_lookup() {
  local filepath="$1"
  filepath="$(expand_path "$filepath" 2>/dev/null || echo "$filepath")"

  if [ -z "$filepath" ] || [ ! -f "$filepath" ]; then
    echo "TOOL_ERROR: circl.file_lookup — file not found: $filepath"
    return 0
  fi

  local hash
  hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
  echo "File:  $filepath"
  echo "SHA256: $hash"
  echo "---"
  tool_circl_hash_lookup "$hash"
}

#==============================================================================
# 5. BATCH HASH OPERATIONS
#==============================================================================
# Compute hashes for all executables in a directory, then check them
# against multiple sources.
#==============================================================================

tool_hash_directory() {
  # Compute SHA256 for all executable files in a directory.
  # Returns: path → hash mapping
  local dir="$1"
  local max_files="${2:-100}"
  dir="$(expand_path "$dir" 2>/dev/null || echo "$dir")"

  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    echo "TOOL_ERROR: hash.directory — not a directory: $dir"
    return 0
  fi
  if [ "$dir" = "/" ]; then
    echo "TOOL_BLOCKED: refusing to hash entire root filesystem"
    return 0
  fi

  echo "Computing SHA256 hashes for executables in: $dir"
  echo "Max files: $max_files"
  echo "---"

  local count=0
  find "$dir" -maxdepth 2 -type f \( -perm -111 -o -name "*.dylib" -o -name "*.so" -o -name "*.bundle" \) 2>/dev/null \
    | head -n "$max_files" \
    | while IFS= read -r filepath; do
        local hash
        hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
        if [ -n "$hash" ]; then
          printf "%s  %s\n" "$hash" "$filepath"
          count=$((count + 1))
        fi
      done

  echo "---"
  echo "Done."
}

tool_multi_lookup() {
  # Look up a single hash across ALL available services.
  # This is the "throw everything at it" tool.
  local hash="$1"

  if [ -z "$hash" ]; then
    echo "TOOL_ERROR: intel.multi_lookup missing hash"
    return 0
  fi

  echo "═══════════════════════════════════════"
  echo "MULTI-SOURCE LOOKUP: $hash"
  echo "═══════════════════════════════════════"

  # 1. abuse.ch (no key needed, fast)
  echo ""
  echo "── abuse.ch MalwareBazaar ──"
  tool_abusech_hash_lookup "$hash"

  # 2. CIRCL (no key needed)
  echo ""
  echo "── CIRCL Hashlookup ──"
  tool_circl_hash_lookup "$hash"

  # 3. VirusTotal (if key available)
  echo ""
  echo "── VirusTotal ──"
  if [ -n "$VT_API_KEY" ]; then
    tool_vt_hash_lookup "$hash"
  else
    echo "  (skipped — VIRUSTOTAL_API_KEY not set)"
  fi

  echo ""
  echo "═══════════════════════════════════════"
  echo "LOOKUP COMPLETE"
  echo "═══════════════════════════════════════"
}

tool_multi_file_lookup() {
  # Hash a file, then look it up across all services.
  local filepath="$1"
  filepath="$(expand_path "$filepath" 2>/dev/null || echo "$filepath")"

  if [ -z "$filepath" ] || [ ! -f "$filepath" ]; then
    echo "TOOL_ERROR: intel.multi_file_lookup — file not found: $filepath"
    return 0
  fi

  local hash
  hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
  echo "File:   $filepath"
  echo "SHA256: $hash"
  echo ""
  tool_multi_lookup "$hash"
}

#==============================================================================
# 6. THREAT INTEL STATUS
#==============================================================================

tool_intel_status() {
  echo "═══════════════════════════════════════"
  echo "THREAT INTELLIGENCE STATUS"
  echo "═══════════════════════════════════════"

  # YARA
  detect_yara
  echo ""
  echo "── YARA ──"
  if [ "$yara_installed" = true ]; then
    echo "  Status:    INSTALLED ($yara_path)"
    echo "  Version:   $(yara --version 2>/dev/null || echo unknown)"
  else
    echo "  Status:    NOT INSTALLED"
    echo "  Install:   brew install yara"
  fi
  local rule_count=0
  if ls "$CMDBOT_YARA_RULES_DIR"/*.yar >/dev/null 2>&1; then
    rule_count=$(ls "$CMDBOT_YARA_RULES_DIR"/*.yar | wc -l | tr -d ' ')
    local total_rules
    total_rules=$(grep -c "^rule " "$CMDBOT_YARA_RULES_DIR"/*.yar 2>/dev/null | tail -1 | cut -d: -f2 || echo 0)
    echo "  Rules:     $rule_count files ($total_rules individual rules)"
  else
    echo "  Rules:     NONE (run yara.update_rules to download)"
  fi
  echo "  Rules Dir: $CMDBOT_YARA_RULES_DIR"

  # VirusTotal
  echo ""
  echo "── VirusTotal ──"
  if [ -n "$VT_API_KEY" ]; then
    echo "  Status:    API KEY SET"
    echo "  Rate:      4 lookups/min (free tier)"
  else
    echo "  Status:    NO API KEY"
    echo "  Setup:     export VIRUSTOTAL_API_KEY='your-key'"
    echo "  Get key:   https://www.virustotal.com/gui/join-us"
  fi

  # abuse.ch
  echo ""
  echo "── abuse.ch MalwareBazaar ──"
  echo "  Status:    ALWAYS AVAILABLE (no key needed)"
  echo "  API:       https://bazaar.abuse.ch/api/"

  # CIRCL
  echo ""
  echo "── CIRCL Hashlookup ──"
  echo "  Status:    ALWAYS AVAILABLE (no key needed)"
  echo "  API:       https://hashlookup.circl.lu/"

  # Cache stats
  echo ""
  echo "── Cache ──"
  echo "  Location:  $CMDBOT_HASH_CACHE_DIR"
  local cache_count
  cache_count=$(ls "$CMDBOT_HASH_CACHE_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
  echo "  Entries:   $cache_count cached lookups"

  echo ""
  echo "═══════════════════════════════════════"
}

#==============================================================================
# DISPATCHER INTEGRATION
#==============================================================================
# Add these cases to the main execute_tool_call() function.
# These tool names are what the LLM will use in its JSON tool calls.
#==============================================================================

execute_intel_tool_call() {
  # This function handles threat intel tool calls.
  # Call it from your main execute_tool_call() as a fallback/extension.
  local tool_json="$1"
  local tool
  tool="$(echo "$tool_json" | jq -r '.tool // empty' 2>/dev/null)"

  case "$tool" in
    # ── YARA tools ──
    yara.update_rules)
      tool_yara_update_rules
      ;;
    yara.scan)
      local target max_matches recursive
      target="$(echo "$tool_json" | jq -r '.args.path // .args.target // empty')"
      max_matches="$(echo "$tool_json" | jq -r '.args.max_matches // 200')"
      recursive="$(echo "$tool_json" | jq -r '.args.recursive // "true"')"
      tool_yara_scan_path "$target" "$max_matches" "$recursive"
      ;;
    yara.list_rules)
      tool_yara_list_rules
      ;;

    # ── VirusTotal tools ──
    vt.hash_lookup)
      local hash
      hash="$(echo "$tool_json" | jq -r '.args.hash // empty')"
      tool_vt_hash_lookup "$hash"
      ;;
    vt.file_lookup)
      local filepath
      filepath="$(echo "$tool_json" | jq -r '.args.path // empty')"
      tool_vt_file_lookup "$filepath"
      ;;

    # ── abuse.ch tools ──
    abusech.hash_lookup)
      local hash
      hash="$(echo "$tool_json" | jq -r '.args.hash // empty')"
      tool_abusech_hash_lookup "$hash"
      ;;
    abusech.file_lookup)
      local filepath
      filepath="$(echo "$tool_json" | jq -r '.args.path // empty')"
      tool_abusech_file_lookup "$filepath"
      ;;

    # ── CIRCL tools ──
    circl.hash_lookup)
      local hash
      hash="$(echo "$tool_json" | jq -r '.args.hash // empty')"
      tool_circl_hash_lookup "$hash"
      ;;
    circl.file_lookup)
      local filepath
      filepath="$(echo "$tool_json" | jq -r '.args.path // empty')"
      tool_circl_file_lookup "$filepath"
      ;;

    # ── Multi-source tools ──
    intel.multi_lookup)
      local hash
      hash="$(echo "$tool_json" | jq -r '.args.hash // empty')"
      tool_multi_lookup "$hash"
      ;;
    intel.multi_file_lookup)
      local filepath
      filepath="$(echo "$tool_json" | jq -r '.args.path // empty')"
      tool_multi_file_lookup "$filepath"
      ;;

    # ── Batch tools ──
    hash.directory)
      local dir max_files
      dir="$(echo "$tool_json" | jq -r '.args.dir // empty')"
      max_files="$(echo "$tool_json" | jq -r '.args.max_files // 100')"
      tool_hash_directory "$dir" "$max_files"
      ;;

    # ── Status ──
    intel.status)
      tool_intel_status
      ;;

    *)
      # Not a threat intel tool — return error so main dispatcher can try
      echo "TOOL_NOT_HANDLED"
      return 1
      ;;
  esac
  return 0
}

#==============================================================================
# SYSTEM PROMPT ADDITIONS
#==============================================================================
# Add this to your scanner's system prompt so the LLM knows about these tools.
#==============================================================================

THREAT_INTEL_PROMPT_FRAGMENT='
═══════════════════════════════════════════════════════════════
THREAT INTELLIGENCE TOOLS
═══════════════════════════════════════════════════════════════
You have access to real-world threat intelligence databases.
Use them to VERIFY suspicious files with hard evidence.

YARA SCANNING (local pattern matching):
  yara.update_rules    — {"tool":"yara.update_rules","args":{}}
                         Downloads community rules (Florian Roth signature-base,
                         Elastic Security). Run once before scanning.
  yara.scan            — {"tool":"yara.scan","args":{"path":"/Library/LaunchDaemons","max_matches":200}}
                         Scan a file or directory against all YARA rules.
  yara.list_rules      — {"tool":"yara.list_rules","args":{}}
                         Show available YARA rules.

VIRUSTOTAL (hash lookup, free tier — needs VIRUSTOTAL_API_KEY):
  vt.hash_lookup       — {"tool":"vt.hash_lookup","args":{"hash":"SHA256_HERE"}}
  vt.file_lookup       — {"tool":"vt.file_lookup","args":{"path":"/path/to/suspicious/binary"}}
                         Computes SHA256 then looks up. NEVER uploads the file.

ABUSE.CH MALWAREBAZAAR (free, no key needed):
  abusech.hash_lookup  — {"tool":"abusech.hash_lookup","args":{"hash":"SHA256_HERE"}}
  abusech.file_lookup  — {"tool":"abusech.file_lookup","args":{"path":"/path/to/file"}}
                         Checks if hash matches known malware samples.

CIRCL HASHLOOKUP (free, no key needed):
  circl.hash_lookup    — {"tool":"circl.hash_lookup","args":{"hash":"SHA256_HERE"}}
  circl.file_lookup    — {"tool":"circl.file_lookup","args":{"path":"/path/to/file"}}
                         Checks if hash matches KNOWN-GOOD software.
                         IMPORTANT: If a system binary is NOT in CIRCL,
                         it may have been tampered with.

MULTI-SOURCE LOOKUP (checks all services at once):
  intel.multi_lookup      — {"tool":"intel.multi_lookup","args":{"hash":"SHA256_HERE"}}
  intel.multi_file_lookup — {"tool":"intel.multi_file_lookup","args":{"path":"/path/to/file"}}
                            Best tool for thorough verification of suspicious files.

BATCH HASHING:
  hash.directory        — {"tool":"hash.directory","args":{"dir":"/Library/LaunchDaemons","max_files":100}}
                          Compute SHA256 for all executables in a directory.

STATUS:
  intel.status          — {"tool":"intel.status","args":{}}
                          Show what threat intel sources are available.

═══════════════════════════════════════════════════════════════
THREAT INTEL WORKFLOW (recommended)
═══════════════════════════════════════════════════════════════
When you find a suspicious binary:
  1. Use apple.codesign_verify to check if it is Apple-signed
  2. If unsigned/ad-hoc/suspicious signer:
     a. Use intel.multi_file_lookup to check all databases at once
     b. If YARA rules are available, use yara.scan on the file
  3. Report findings with scan.finding including the evidence

For batch checks:
  1. Use hash.directory on high-signal directories
  2. Pick suspicious hashes and run intel.multi_lookup on them

IMPORTANT:
  - We NEVER upload files. Only SHA256 hashes are sent to services.
  - VirusTotal requires VIRUSTOTAL_API_KEY (free registration).
  - abuse.ch and CIRCL require NO API key.
  - CIRCL checks known-GOOD hashes. If a system binary is NOT found,
    that is itself suspicious and should be reported.
  - Always start with intel.status to see what is available.
'
