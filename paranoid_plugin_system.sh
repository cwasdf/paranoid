#!/usr/bin/env bash
#==============================================================================
# PARANOID SCANNER — PLUGIN SYSTEM
#==============================================================================
# Secure, capability-gated plugin infrastructure.
#
# Security model (four layers):
#   1. Core app     — policy, discovery, enforcement, logging, all final decisions
#   2. Manifest     — plugin identity, version, capabilities, signature
#   3. Policy       — built-in map of approved plugin IDs → rules
#   4. Plugin proc  — subprocess: JSON stdin, JSON stdout, no shell, no escalation
#
# Design principles:
#   - Core never evals plugin output
#   - Core never grants write just because a file exists in plugins/
#   - Deny-by-default for all capabilities
#   - Plugins are proposal engines; core brokers all writes
#   - All operations are audit-logged
#
# SOURCE this from the main scanner:
#   source ./paranoid_plugin_system.sh
#==============================================================================

#==============================================================================
# CONFIGURATION
#==============================================================================
PLUGIN_DIR="${PARANOID_PLUGIN_DIR:-${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/plugins}"
PLUGIN_POLICY_FILE="${PARANOID_PLUGIN_POLICY_FILE:-${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/plugin-policies.json}"
PLUGIN_TRUSTED_KEYS_DIR="${PARANOID_TRUSTED_KEYS_DIR:-${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/trusted_keys}"
PLUGIN_STATE_DIR="${PARANOID_PLUGIN_STATE_DIR:-${HOME}/Library/Application Support/Paranoid}"
PLUGIN_AUDIT_LOG="${PLUGIN_STATE_DIR}/plugin_audit.log"
PLUGIN_DEV_MODE="${PARANOID_PLUGIN_DEV_MODE:-false}"

mkdir -p "$PLUGIN_STATE_DIR" 2>/dev/null || true

# ── App self-integrity snapshot (computed at source time) ────────────────────
# Store hashes of the scanner and plugin system so we can detect if anything
# modifies them at runtime. These are checked before any plugin write is brokered.
_PLUGIN_SELF_PATH="${BASH_SOURCE[0]}"
_PLUGIN_SELF_HASH="$(shasum -a 256 "$_PLUGIN_SELF_PATH" 2>/dev/null | awk '{print $1}')"
_SCANNER_PATH="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/paranoid_scanner.sh"
_SCANNER_HASH=""
if [ -f "$_SCANNER_PATH" ]; then
  _SCANNER_HASH="$(shasum -a 256 "$_SCANNER_PATH" 2>/dev/null | awk '{print $1}')"
fi

plugin_check_app_integrity() {
  local current_self current_scanner
  current_self="$(shasum -a 256 "$_PLUGIN_SELF_PATH" 2>/dev/null | awk '{print $1}')"
  if [ "$current_self" != "$_PLUGIN_SELF_HASH" ]; then
    plugin_log "INTEGRITY_FAIL: paranoid_plugin_system.sh has been modified at runtime"
    return 1
  fi
  if [ -n "$_SCANNER_HASH" ] && [ -f "$_SCANNER_PATH" ]; then
    current_scanner="$(shasum -a 256 "$_SCANNER_PATH" 2>/dev/null | awk '{print $1}')"
    if [ "$current_scanner" != "$_SCANNER_HASH" ]; then
      plugin_log "INTEGRITY_FAIL: paranoid_scanner.sh has been modified at runtime"
      return 1
    fi
  fi
  return 0
}

# ── Diagnostics tmp directory (created fresh each launch) ────────────────────
PARANOID_DIAG_TMP="${TMPDIR:-/tmp}/paranoid_diag_$$"
mkdir -p "$PARANOID_DIAG_TMP" 2>/dev/null || true
# Resolve to canonical path (macOS: /var/folders → /private/var/folders)
PARANOID_DIAG_TMP="$(cd "$PARANOID_DIAG_TMP" && pwd -P)"

# ── Watermark key (regenerated each launch) ──────────────────────────────────
plugin_generate_watermark_key() {
  local date_part user_part random_part
  date_part="$(date +%Y%m%d)"
  user_part="$(whoami 2>/dev/null || echo "unknown")"
  random_part="$(head -c 16 /dev/urandom | shasum -a 256 | cut -c1-16)"
  echo "PARANOID-${date_part}-${user_part}-${random_part}"
}
PARANOID_WATERMARK_KEY="$(plugin_generate_watermark_key)"

# ── Runtime state ────────────────────────────────────────────────────────────
declare -a LOADED_PLUGIN_IDS=()
declare -a LOADED_PLUGIN_DIRS=()
declare -a LOADED_PLUGIN_NAMES=()
declare -a LOADED_PLUGIN_CAPS=()
declare -a LOADED_PLUGIN_RUNTIMES=()
declare -a LOADED_PLUGIN_ENTRYPOINTS=()
PLUGIN_SYSTEM_LOADED=false

# Per-plugin activation state (set by plugin_activate_rules)
ACTIVE_PLUGIN_ID=""
ACTIVE_PLUGIN_DIR=""
ACTIVE_PLUGIN_ALLOWED_CAPS=""
ACTIVE_PLUGIN_ALLOWED_TARGETS=""
ACTIVE_PLUGIN_FORBIDDEN_TARGETS=""
ACTIVE_PLUGIN_TIMEOUT=10
ACTIVE_PLUGIN_MAX_ACTIONS=20
ACTIVE_PLUGIN_MAX_FILE_SIZE=10485760
ACTIVE_PLUGIN_RUNTIME=""
ACTIVE_PLUGIN_ENTRYPOINT=""

#==============================================================================
# LOGGING
#==============================================================================
plugin_log() {
  local msg="$1"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '%s %s\n' "$ts" "$msg" >> "$PLUGIN_AUDIT_LOG" 2>/dev/null || true
  # Also log to findings if available
  if type log_to_findings &>/dev/null; then
    log_to_findings "PLUGIN: $msg"
  fi
}

#==============================================================================
# UTILITY FUNCTIONS
#==============================================================================
plugin_sha256() {
  shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
}

# Semantic version comparison: returns 0 if ver is within [min, max]
plugin_semver_in_range() {
  local ver="$1" min_ver="$2" max_ver="$3"
  local v_major v_minor v_patch
  local min_major min_minor min_patch
  local max_major max_minor max_patch

  IFS='.' read -r v_major v_minor v_patch <<< "$ver"
  IFS='.' read -r min_major min_minor min_patch <<< "$min_ver"
  IFS='.' read -r max_major max_minor max_patch <<< "$max_ver"

  # Default missing components to 0
  v_major="${v_major:-0}"; v_minor="${v_minor:-0}"; v_patch="${v_patch:-0}"
  min_major="${min_major:-0}"; min_minor="${min_minor:-0}"; min_patch="${min_patch:-0}"
  max_major="${max_major:-0}"; max_minor="${max_minor:-0}"; max_patch="${max_patch:-0}"

  # Convert to comparable integer: major*1000000 + minor*1000 + patch
  local v_num=$(( v_major * 1000000 + v_minor * 1000 + v_patch ))
  local min_num=$(( min_major * 1000000 + min_minor * 1000 + min_patch ))
  local max_num=$(( max_major * 1000000 + max_minor * 1000 + max_patch ))

  [ "$v_num" -ge "$min_num" ] && [ "$v_num" -le "$max_num" ]
}

# Expand path variables and resolve
plugin_expand_path() {
  local s="$1"
  s="${s//\~/$HOME}"
  s="${s//\$HOME/$HOME}"
  s="${s//\$USER/$(whoami)}"
  s="${s//\$CMDBOT_WORKDIR/${CMDBOT_WORKDIR:-}}"
  s="${s//\$CMDBOT_FINDINGS_DIR/${CMDBOT_FINDINGS_DIR:-}}"
  # Resolve to absolute: try the file itself, then its parent directory
  if [ -e "$s" ]; then
    s="$(cd "$(dirname "$s")" 2>/dev/null && pwd)/$(basename "$s")"
  elif [ -d "$(dirname "$s")" ]; then
    s="$(cd "$(dirname "$s")" 2>/dev/null && pwd)/$(basename "$s")"
  fi
  echo "$s"
}

# Check if a path matches a glob-style allow/deny pattern
plugin_path_matches_pattern() {
  local path="$1" pattern="$2"
  pattern="$(plugin_expand_path "$pattern")"
  if [[ "$pattern" == *"/**" ]]; then
    local prefix="${pattern%/**}"
    [[ "$path" == "$prefix"/* ]] || [[ "$path" == "$prefix" ]]
  else
    [[ "$path" == "$pattern" ]]
  fi
}

# Check path against allow/deny lists (deny takes precedence)
plugin_path_allowed() {
  local path="$1"
  local allowed_json="$2"
  local forbidden_json="$3"
  local pattern

  # Resolve the path
  if [ -e "$path" ]; then
    path="$(cd "$(dirname "$path")" 2>/dev/null && pwd)/$(basename "$path")"
  fi

  # Check forbidden first (deny wins)
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    if plugin_path_matches_pattern "$path" "$pattern"; then
      return 1
    fi
  done < <(echo "$forbidden_json" | jq -r '.[]' 2>/dev/null)

  # Check allowed
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    if plugin_path_matches_pattern "$path" "$pattern"; then
      return 0
    fi
  done < <(echo "$allowed_json" | jq -r '.[]' 2>/dev/null)

  # Default deny
  return 1
}

# Check if a capability is in the allowed list
plugin_capability_allowed() {
  local cap="$1"
  local allowed_json="$2"
  echo "$allowed_json" | jq -e --arg c "$cap" 'index($c) != null' >/dev/null 2>&1
}

#==============================================================================
# MANIFEST VERIFICATION
#==============================================================================
plugin_verify_manifest_signature() {
  local manifest="$1" sig="$2" key_file="$3"

  if [ ! -f "$key_file" ]; then
    plugin_log "VERIFY_FAIL: trusted key not found: $key_file"
    return 1
  fi

  if ! openssl dgst -sha256 -verify "$key_file" -signature "$sig" "$manifest" >/dev/null 2>&1; then
    plugin_log "VERIFY_FAIL: manifest signature invalid: $manifest"
    return 1
  fi

  return 0
}

plugin_verify_binary_hash() {
  local binary="$1" expected_hash="$2"
  local actual_hash
  actual_hash="$(plugin_sha256 "$binary")"
  if [ "$actual_hash" != "$expected_hash" ]; then
    plugin_log "VERIFY_FAIL: hash mismatch for $binary (expected=$expected_hash actual=$actual_hash)"
    return 1
  fi
  return 0
}

plugin_verify_macos_signature() {
  local entrypoint="$1"
  # Only check Mach-O binaries and bundles
  if file "$entrypoint" 2>/dev/null | grep -qiE 'Mach-O|bundle'; then
    if ! codesign --verify --deep --strict "$entrypoint" >/dev/null 2>&1; then
      plugin_log "VERIFY_FAIL: macOS code signature invalid: $entrypoint"
      return 1
    fi
  fi
  return 0
}

#==============================================================================
# POLICY LOOKUP
#==============================================================================
plugin_policy_lookup() {
  local plugin_id="$1"
  if [ ! -f "$PLUGIN_POLICY_FILE" ]; then
    plugin_log "POLICY_FAIL: policy file not found: $PLUGIN_POLICY_FILE"
    return 1
  fi
  local policy
  policy="$(jq -c --arg id "$plugin_id" '.plugins[$id] // empty' "$PLUGIN_POLICY_FILE" 2>/dev/null)"
  if [ -z "$policy" ]; then
    plugin_log "POLICY_FAIL: plugin not in policy registry: $plugin_id"
    return 1
  fi
  echo "$policy"
}

plugin_is_allowed() {
  local manifest="$1"
  local plugin_id version publisher_key_id

  plugin_id="$(jq -r '.plugin_id' "$manifest" 2>/dev/null)"
  version="$(jq -r '.version' "$manifest" 2>/dev/null)"
  publisher_key_id="$(jq -r '.publisher.key_id' "$manifest" 2>/dev/null)"

  local policy
  policy="$(plugin_policy_lookup "$plugin_id")" || return 1

  # Check publisher key matches
  local allowed_key_id
  allowed_key_id="$(echo "$policy" | jq -r '.publisher_key_id' 2>/dev/null)"
  if [ "$publisher_key_id" != "$allowed_key_id" ]; then
    plugin_log "POLICY_FAIL: publisher key mismatch for $plugin_id (manifest=$publisher_key_id policy=$allowed_key_id)"
    return 1
  fi

  # Check version in range
  local min_version max_version
  min_version="$(echo "$policy" | jq -r '.min_version' 2>/dev/null)"
  max_version="$(echo "$policy" | jq -r '.max_version' 2>/dev/null)"
  if ! plugin_semver_in_range "$version" "$min_version" "$max_version"; then
    plugin_log "POLICY_FAIL: version $version out of range [$min_version, $max_version] for $plugin_id"
    return 1
  fi

  return 0
}

#==============================================================================
# PLUGIN ACTIVATION
#==============================================================================
plugin_activate_rules() {
  local plugin_id="$1" plugin_dir="$2"
  local policy manifest runtime entrypoint

  policy="$(plugin_policy_lookup "$plugin_id")" || return 1
  manifest="${plugin_dir}/manifest.json"

  ACTIVE_PLUGIN_ID="$plugin_id"
  ACTIVE_PLUGIN_DIR="$plugin_dir"
  ACTIVE_PLUGIN_ALLOWED_CAPS="$(echo "$policy" | jq -c '.allowed_capabilities' 2>/dev/null)"
  ACTIVE_PLUGIN_ALLOWED_TARGETS="$(echo "$policy" | jq -c '.allowed_targets' 2>/dev/null)"
  ACTIVE_PLUGIN_TIMEOUT="$(echo "$policy" | jq -r '.exec_timeout_sec // 10' 2>/dev/null)"
  ACTIVE_PLUGIN_MAX_ACTIONS="$(echo "$policy" | jq -r '.max_actions_per_invocation // 20' 2>/dev/null)"
  ACTIVE_PLUGIN_MAX_FILE_SIZE="$(echo "$policy" | jq -r '.max_file_size_bytes // 10485760' 2>/dev/null)"
  ACTIVE_PLUGIN_RUNTIME="$(jq -r '.runtime' "$manifest" 2>/dev/null)"
  ACTIVE_PLUGIN_ENTRYPOINT="$(jq -r '.entrypoint' "$manifest" 2>/dev/null)"

  # Merge policy forbidden targets with hardcoded app-protection list.
  # These paths are ALWAYS forbidden regardless of what any policy file says.
  # This prevents any plugin from modifying the scanner, plugin system, or its own code.
  local _script_dir="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
  local policy_forbidden
  policy_forbidden="$(echo "$policy" | jq -c '.forbidden_targets // []' 2>/dev/null)"
  ACTIVE_PLUGIN_FORBIDDEN_TARGETS="$(jq -n \
    --argjson pf "$policy_forbidden" \
    --arg app_dir "${_script_dir}/**" \
    --arg plugin_dir "${PLUGIN_DIR}/**" \
    --arg policy_file "$PLUGIN_POLICY_FILE" \
    --arg registry "$PLUGIN_REGISTRY_FILE" \
    --arg audit_log "$PLUGIN_AUDIT_LOG" \
    --arg state_dir "${PLUGIN_STATE_DIR}/**" \
    --arg env_file "${_script_dir}/.env" \
    '$pf + [$app_dir, $plugin_dir, $policy_file, $registry, $audit_log, $state_dir, $env_file] | unique'
  )"

  plugin_log "ACTIVATE: plugin=$plugin_id caps=$ACTIVE_PLUGIN_ALLOWED_CAPS timeout=${ACTIVE_PLUGIN_TIMEOUT}s"
}

#==============================================================================
# PLUGIN REGISTRY (persistent trust store)
#==============================================================================
PLUGIN_REGISTRY_FILE="${PLUGIN_STATE_DIR}/connected_plugins.json"

plugin_registry_init() {
  if [ ! -f "$PLUGIN_REGISTRY_FILE" ]; then
    echo '{"schema_version":"1","plugins":{}}' > "$PLUGIN_REGISTRY_FILE"
    chmod 600 "$PLUGIN_REGISTRY_FILE" 2>/dev/null || true
  fi
}

plugin_registry_is_connected() {
  local plugin_id="$1"
  plugin_registry_init
  local entry
  entry="$(jq -r --arg id "$plugin_id" '.plugins[$id].connected // empty' "$PLUGIN_REGISTRY_FILE" 2>/dev/null)"
  [ "$entry" = "true" ]
}

plugin_registry_get_hash() {
  local plugin_id="$1"
  plugin_registry_init
  jq -r --arg id "$plugin_id" '.plugins[$id].verified_hash // empty' "$PLUGIN_REGISTRY_FILE" 2>/dev/null
}

plugin_registry_connect() {
  local plugin_id="$1" manifest_hash="$2" entrypoint_hash="$3" version="$4"
  plugin_registry_init
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local tmp_reg
  tmp_reg="$(mktemp "${PLUGIN_REGISTRY_FILE}.XXXXXX")"
  jq --arg id "$plugin_id" \
     --arg mhash "$manifest_hash" \
     --arg ehash "$entrypoint_hash" \
     --arg ver "$version" \
     --arg ts "$ts" \
     '.plugins[$id] = {connected:true, manifest_hash:$mhash, verified_hash:$ehash, version:$ver, connected_at:$ts}' \
     "$PLUGIN_REGISTRY_FILE" > "$tmp_reg" 2>/dev/null
  mv "$tmp_reg" "$PLUGIN_REGISTRY_FILE"
  chmod 600 "$PLUGIN_REGISTRY_FILE" 2>/dev/null || true
  plugin_log "REGISTRY_CONNECT: plugin=$plugin_id version=$version"
}

plugin_registry_disconnect() {
  local plugin_id="$1"
  plugin_registry_init
  local tmp_reg
  tmp_reg="$(mktemp "${PLUGIN_REGISTRY_FILE}.XXXXXX")"
  jq --arg id "$plugin_id" 'del(.plugins[$id])' "$PLUGIN_REGISTRY_FILE" > "$tmp_reg" 2>/dev/null
  mv "$tmp_reg" "$PLUGIN_REGISTRY_FILE"
  chmod 600 "$PLUGIN_REGISTRY_FILE" 2>/dev/null || true
  plugin_log "REGISTRY_DISCONNECT: plugin=$plugin_id"
}

#==============================================================================
# PLUGIN DISCOVERY & VERIFICATION
#==============================================================================
plugin_discover() {
  if [ ! -d "$PLUGIN_DIR" ]; then
    return 0
  fi
  find "$PLUGIN_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null
}

# Full verification — runs when connecting a plugin for the first time or
# when the entrypoint hash has changed since it was last connected.
plugin_verify_and_load() {
  local dir="$1"
  local force_connect="${2:-false}"
  local manifest="${dir}/manifest.json"
  local sig="${dir}/manifest.sig"
  local plugin_id entrypoint expected_hash key_id key_file plugin_name runtime caps

  # Check required files
  if [ ! -f "$manifest" ]; then
    plugin_log "SKIP: missing manifest in ${dir}"
    return 1
  fi

  plugin_id="$(jq -r '.plugin_id // empty' "$manifest" 2>/dev/null)"
  plugin_name="$(jq -r '.name // "unknown"' "$manifest" 2>/dev/null)"
  entrypoint="$(jq -r '.entrypoint // empty' "$manifest" 2>/dev/null)"
  expected_hash="$(jq -r '.hash.executable // empty' "$manifest" 2>/dev/null)"
  key_id="$(jq -r '.publisher.key_id // empty' "$manifest" 2>/dev/null)"
  runtime="$(jq -r '.runtime // empty' "$manifest" 2>/dev/null)"
  caps="$(jq -c '.capabilities // []' "$manifest" 2>/dev/null)"

  if [ -z "$plugin_id" ] || [ -z "$entrypoint" ]; then
    plugin_log "SKIP: incomplete manifest in ${dir} (missing plugin_id or entrypoint)"
    return 1
  fi

  local entrypoint_path="${dir}/${entrypoint#./}"
  if [ ! -f "$entrypoint_path" ]; then
    plugin_log "REJECT: entrypoint not found: $entrypoint_path"
    return 1
  fi

  local current_ep_hash manifest_hash version
  current_ep_hash="$(plugin_sha256 "$entrypoint_path")"
  manifest_hash="$(plugin_sha256 "$manifest")"
  version="$(jq -r '.version // "0.0.0"' "$manifest" 2>/dev/null)"

  # ── Check if already connected ──
  if [ "$force_connect" != "true" ] && plugin_registry_is_connected "$plugin_id"; then
    local stored_hash
    stored_hash="$(plugin_registry_get_hash "$plugin_id")"
    if [ "$current_ep_hash" = "$stored_hash" ]; then
      # Already verified — fast-load without re-running full auth
      if ! plugin_is_allowed "$manifest"; then
        plugin_log "REJECT: policy check failed for connected plugin $plugin_id"
        return 1
      fi
      if [ -n "$runtime" ] && ! command -v "$runtime" &>/dev/null; then
        plugin_log "REJECT: runtime not available: $runtime (for $plugin_id)"
        return 1
      fi
      plugin_activate_rules "$plugin_id" "$dir" || return 1
      LOADED_PLUGIN_IDS+=("$plugin_id")
      LOADED_PLUGIN_DIRS+=("$dir")
      LOADED_PLUGIN_NAMES+=("$plugin_name")
      LOADED_PLUGIN_CAPS+=("$caps")
      LOADED_PLUGIN_RUNTIMES+=("$runtime")
      LOADED_PLUGIN_ENTRYPOINTS+=("$entrypoint_path")
      plugin_log "FAST_LOAD: $plugin_id (hash unchanged, already connected)"
      echo -e "\033[32m  Loaded: $plugin_id ($plugin_name) [connected]\033[0m"
      return 0
    else
      echo -e "\033[33m  Plugin $plugin_id entrypoint changed — re-verifying...\033[0m"
      plugin_log "HASH_CHANGED: plugin=$plugin_id stored=$stored_hash current=$current_ep_hash"
    fi
  fi

  # ── Policy check ──
  if ! plugin_is_allowed "$manifest"; then
    plugin_log "REJECT: policy check failed for $plugin_id"
    return 1
  fi

  # ── Signature verification ──
  if [ "$PLUGIN_DEV_MODE" = "true" ]; then
    echo -e "\033[33m  WARNING: Plugin dev mode — skipping signature verification for $plugin_id\033[0m"
    plugin_log "DEV_MODE: skipping signature verification for $plugin_id"
  else
    local key_file="${PLUGIN_TRUSTED_KEYS_DIR}/${key_id}.pub"

    if [ ! -f "$sig" ]; then
      plugin_log "REJECT: missing manifest signature: $sig"
      echo -e "\033[31m  REJECT: $plugin_id — missing manifest.sig\033[0m"
      return 1
    fi

    if ! plugin_verify_manifest_signature "$manifest" "$sig" "$key_file"; then
      echo -e "\033[31m  REJECT: $plugin_id — manifest signature verification failed\033[0m"
      return 1
    fi

    # ── Binary hash ──
    if [ -n "$expected_hash" ] && [ "$expected_hash" != "PLACEHOLDER_HASH_RUN_SETUP_TO_GENERATE" ]; then
      if ! plugin_verify_binary_hash "$entrypoint_path" "$expected_hash"; then
        echo -e "\033[31m  REJECT: $plugin_id — executable hash mismatch\033[0m"
        return 1
      fi
    elif [ "$expected_hash" = "PLACEHOLDER_HASH_RUN_SETUP_TO_GENERATE" ]; then
      plugin_log "REJECT: $plugin_id has placeholder hash — run setup to generate"
      echo -e "\033[31m  REJECT: $plugin_id — executable hash not configured (see trusted_keys/README.md)\033[0m"
      return 1
    fi

    # ── macOS code signature (for compiled binaries) ──
    if ! plugin_verify_macos_signature "$entrypoint_path"; then
      echo -e "\033[31m  REJECT: $plugin_id — macOS code signature invalid\033[0m"
      return 1
    fi
  fi

  # ── Check runtime availability ──
  if [ -n "$runtime" ] && ! command -v "$runtime" &>/dev/null; then
    plugin_log "REJECT: runtime not available: $runtime (for $plugin_id)"
    echo -e "\033[31m  REJECT: $plugin_id — runtime '$runtime' not found\033[0m"
    return 1
  fi

  # ── Activate policy rules ──
  plugin_activate_rules "$plugin_id" "$dir" || return 1

  # ── Register in trust store ──
  plugin_registry_connect "$plugin_id" "$manifest_hash" "$current_ep_hash" "$version"

  # ── Register in runtime ──
  LOADED_PLUGIN_IDS+=("$plugin_id")
  LOADED_PLUGIN_DIRS+=("$dir")
  LOADED_PLUGIN_NAMES+=("$plugin_name")
  LOADED_PLUGIN_CAPS+=("$caps")
  LOADED_PLUGIN_RUNTIMES+=("$runtime")
  LOADED_PLUGIN_ENTRYPOINTS+=("$entrypoint_path")

  plugin_log "LOADED: $plugin_id ($plugin_name) v$version caps=$caps"
  echo -e "\033[32m  Loaded: $plugin_id ($plugin_name)\033[0m"
  return 0
}

# Connect a new plugin interactively — prompts user for confirmation
plugin_connect() {
  local dir="$1"
  local manifest="${dir}/manifest.json"

  if [ ! -f "$manifest" ]; then
    echo -e "\033[31mNo manifest.json found in $dir\033[0m"
    return 1
  fi

  local plugin_id plugin_name version caps
  plugin_id="$(jq -r '.plugin_id // empty' "$manifest" 2>/dev/null)"
  plugin_name="$(jq -r '.name // "unknown"' "$manifest" 2>/dev/null)"
  version="$(jq -r '.version // "0.0.0"' "$manifest" 2>/dev/null)"
  caps="$(jq -c '.capabilities // []' "$manifest" 2>/dev/null)"

  echo ""
  echo -e "\033[1m  ── Connect Plugin ──\033[0m"
  echo -e "  Plugin:       $plugin_name"
  echo -e "  ID:           $plugin_id"
  echo -e "  Version:      $version"
  echo -e "  Capabilities: $caps"
  echo ""

  if plugin_registry_is_connected "$plugin_id"; then
    echo -e "\033[33m  This plugin is already connected.\033[0m"
    read -rp "  Re-verify and reconnect? (y/N): " _reconnect
    if [[ ! "$_reconnect" =~ ^[Yy] ]]; then
      echo -e "\033[2m  Skipped.\033[0m"
      return 0
    fi
  else
    echo -e "  \033[33mConnecting a plugin grants it the capabilities listed above.\033[0m"
    echo -e "  \033[33mOnly connect plugins you trust.\033[0m"
    echo ""
    read -rp "  Connect this plugin? (y/N): " _connect
    if [[ ! "$_connect" =~ ^[Yy] ]]; then
      echo -e "\033[2m  Cancelled.\033[0m"
      return 1
    fi
  fi

  echo ""
  echo -e "\033[2m  Verifying...\033[0m"
  if plugin_verify_and_load "$dir" "true"; then
    echo -e "\033[32m  Plugin connected and verified.\033[0m"
    return 0
  else
    echo -e "\033[31m  Plugin verification failed. Not connected.\033[0m"
    return 1
  fi
}

# Disconnect a plugin
plugin_disconnect() {
  local plugin_id="$1"

  if ! plugin_registry_is_connected "$plugin_id"; then
    echo -e "\033[33m  Plugin $plugin_id is not connected.\033[0m"
    return 1
  fi

  plugin_registry_disconnect "$plugin_id"
  echo -e "\033[32m  Plugin $plugin_id disconnected.\033[0m"

  # Remove from runtime arrays
  local i
  for i in "${!LOADED_PLUGIN_IDS[@]}"; do
    if [ "${LOADED_PLUGIN_IDS[$i]}" = "$plugin_id" ]; then
      unset 'LOADED_PLUGIN_IDS[$i]'
      unset 'LOADED_PLUGIN_DIRS[$i]'
      unset 'LOADED_PLUGIN_NAMES[$i]'
      unset 'LOADED_PLUGIN_CAPS[$i]'
      unset 'LOADED_PLUGIN_RUNTIMES[$i]'
      unset 'LOADED_PLUGIN_ENTRYPOINTS[$i]'
      break
    fi
  done
}

plugin_load_all() {
  local count=0 new_count=0 dir

  echo -e "\033[1mDiscovering plugins...\033[0m"

  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "\033[2m  No plugins directory found ($PLUGIN_DIR)\033[0m"
    PLUGIN_SYSTEM_LOADED=true
    return 0
  fi

  plugin_registry_init

  while IFS= read -r dir; do
    [ -z "$dir" ] && continue
    local manifest="${dir}/manifest.json"
    [ ! -f "$manifest" ] && continue
    local pid
    pid="$(jq -r '.plugin_id // empty' "$manifest" 2>/dev/null)"
    [ -z "$pid" ] && continue

    if plugin_registry_is_connected "$pid"; then
      # Already connected — load (will fast-path if hash unchanged)
      if plugin_verify_and_load "$dir"; then
        count=$((count + 1))
      fi
    else
      # New plugin discovered — prompt to connect
      local pname
      pname="$(jq -r '.name // "unknown"' "$manifest" 2>/dev/null)"
      echo -e "\033[36m  New plugin found: $pname ($pid)\033[0m"
      new_count=$((new_count + 1))
    fi
  done < <(plugin_discover)

  if [ "$count" -eq 0 ] && [ "$new_count" -eq 0 ]; then
    echo -e "\033[2m  No verified plugins loaded\033[0m"
  else
    [ "$count" -gt 0 ] && echo -e "\033[32m  $count plugin(s) loaded\033[0m"
    [ "$new_count" -gt 0 ] && echo -e "\033[36m  $new_count new plugin(s) available — use Plugin Diagnostics (menu 8) to connect\033[0m"
  fi

  PLUGIN_SYSTEM_LOADED=true
  plugin_log "DISCOVERY_COMPLETE: loaded=$count new=$new_count from=$PLUGIN_DIR"
}

#==============================================================================
# PLUGIN EXECUTION (subprocess with JSON I/O)
#==============================================================================
plugin_run() {
  local plugin_id="$1"
  local request_json="$2"
  local idx=-1 i

  # Find plugin index
  for i in "${!LOADED_PLUGIN_IDS[@]}"; do
    if [ "${LOADED_PLUGIN_IDS[$i]}" = "$plugin_id" ]; then
      idx=$i
      break
    fi
  done

  if [ "$idx" -lt 0 ]; then
    plugin_log "EXEC_FAIL: plugin not loaded: $plugin_id"
    echo '{"status":"error","error":{"code":"not_loaded","message":"plugin not loaded"}}'
    return 1
  fi

  local runtime="${LOADED_PLUGIN_RUNTIMES[$idx]}"
  local entrypoint="${LOADED_PLUGIN_ENTRYPOINTS[$idx]}"

  # Activate this plugin's rules
  plugin_activate_rules "$plugin_id" "${LOADED_PLUGIN_DIRS[$idx]}" || {
    echo '{"status":"error","error":{"code":"activation_failed","message":"failed to activate plugin rules"}}'
    return 1
  }

  plugin_log "EXEC_START: plugin=$plugin_id runtime=$runtime timeout=${ACTIVE_PLUGIN_TIMEOUT}s"

  local response_json tmpfile
  tmpfile="$(mktemp "${PLUGIN_STATE_DIR}/plugin_response.XXXXXX")"

  # Run plugin as subprocess with shell-based timeout (macOS has no coreutils timeout)
  "$runtime" "$entrypoint" > "$tmpfile" 2>/dev/null <<< "$request_json" &
  local plugin_pid=$!
  local waited=0
  while kill -0 "$plugin_pid" 2>/dev/null; do
    if [ "$waited" -ge "$ACTIVE_PLUGIN_TIMEOUT" ]; then
      kill "$plugin_pid" 2>/dev/null || true
      wait "$plugin_pid" 2>/dev/null || true
      plugin_log "EXEC_FAIL: plugin=$plugin_id reason=timeout after ${ACTIVE_PLUGIN_TIMEOUT}s"
      rm -f "$tmpfile"
      echo '{"status":"error","error":{"code":"exec_timeout","message":"plugin timed out"}}'
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$plugin_pid" 2>/dev/null
  local exit_code=$?

  if [ "$exit_code" -ne 0 ]; then
    plugin_log "EXEC_FAIL: plugin=$plugin_id exit_code=$exit_code"
    rm -f "$tmpfile"
    echo '{"status":"error","error":{"code":"exec_failed","message":"plugin process exited with code '"$exit_code"'"}}'
    return 1
  fi

  response_json="$(cat "$tmpfile" 2>/dev/null)"
  rm -f "$tmpfile"

  # Validate response is valid JSON
  if ! echo "$response_json" | jq -e '.' >/dev/null 2>&1; then
    plugin_log "EXEC_FAIL: plugin=$plugin_id reason=invalid_json_response"
    echo '{"status":"error","error":{"code":"invalid_response","message":"plugin returned invalid JSON"}}'
    return 1
  fi

  plugin_log "EXEC_OK: plugin=$plugin_id response_bytes=${#response_json}"
  echo "$response_json"
}

#==============================================================================
# RESPONSE VALIDATION
#==============================================================================
plugin_validate_response() {
  local plugin_id="$1"
  local response_json="$2"

  # Check basic structure
  if ! echo "$response_json" | jq -e '.status' >/dev/null 2>&1; then
    plugin_log "VALIDATE_FAIL: plugin=$plugin_id reason=missing_status"
    return 1
  fi

  local status
  status="$(echo "$response_json" | jq -r '.status' 2>/dev/null)"
  if [ "$status" = "error" ]; then
    # Error responses are valid but should be logged
    local err_code err_msg
    err_code="$(echo "$response_json" | jq -r '.error.code // "unknown"' 2>/dev/null)"
    err_msg="$(echo "$response_json" | jq -r '.error.message // "unknown"' 2>/dev/null)"
    plugin_log "PLUGIN_ERROR: plugin=$plugin_id code=$err_code msg=$err_msg"
    return 0
  fi

  # Validate actions array
  if ! echo "$response_json" | jq -e '.actions and (.actions | type == "array")' >/dev/null 2>&1; then
    plugin_log "VALIDATE_FAIL: plugin=$plugin_id reason=missing_or_invalid_actions"
    return 1
  fi

  # Validate each action has required fields
  local invalid_actions
  invalid_actions="$(echo "$response_json" | jq '[.actions[] | select(.type == null or .target == null or .capability == null)] | length' 2>/dev/null)"
  if [ "${invalid_actions:-0}" -gt 0 ]; then
    plugin_log "VALIDATE_FAIL: plugin=$plugin_id reason=actions_missing_fields count=$invalid_actions"
    return 1
  fi

  # Check action count limit
  local action_count
  action_count="$(echo "$response_json" | jq '.actions | length' 2>/dev/null)"
  if [ "${action_count:-0}" -gt "$ACTIVE_PLUGIN_MAX_ACTIONS" ]; then
    plugin_log "VALIDATE_FAIL: plugin=$plugin_id reason=too_many_actions count=$action_count max=$ACTIVE_PLUGIN_MAX_ACTIONS"
    return 1
  fi

  plugin_log "VALIDATE_OK: plugin=$plugin_id action_count=$action_count"
  return 0
}

#==============================================================================
# ACTION BROKERING
#==============================================================================
# The core processes each action from the plugin response.
# Only approved capabilities and targets are executed.
#==============================================================================

plugin_broker_actions() {
  local plugin_id="$1"
  local response_json="$2"
  local results='[]'
  local action_count idx action type target capability reason

  # Pre-flight: verify app integrity before brokering any actions
  if ! plugin_check_app_integrity; then
    plugin_log "BROKER_ABORT: plugin=$plugin_id reason=app_integrity_check_failed"
    echo '[{"type":"error","reason":"app integrity check failed — brokering aborted","brokered":"aborted"}]'
    return 1
  fi

  action_count="$(echo "$response_json" | jq '.actions | length' 2>/dev/null)"

  idx=0
  while [ "$idx" -lt "$action_count" ]; do
    action="$(echo "$response_json" | jq -c ".actions[$idx]" 2>/dev/null)"
    type="$(echo "$action" | jq -r '.type' 2>/dev/null)"
    target="$(echo "$action" | jq -r '.target' 2>/dev/null)"
    capability="$(echo "$action" | jq -r '.capability' 2>/dev/null)"
    reason="$(echo "$action" | jq -r '.reason // "no reason"' 2>/dev/null)"

    # Sanitize target — reject shell metacharacters and path traversal
    if [[ "$target" == *".."* ]] || [[ "$target" =~ [\;\|\&\$\`\(\)\{\}\<\>\\] ]] || [[ "$target" == *$'\n'* ]]; then
      plugin_log "DENY: plugin=$plugin_id target=$target reason=malicious_path_characters"
      results="$(echo "$results" | jq --arg t "$target" '. + [{"type":"denied","target":$t,"reason":"target contains forbidden characters"}]')"
      idx=$((idx + 1))
      continue
    fi

    # Skip error actions from plugin
    if [ "$type" = "error" ]; then
      plugin_log "ACTION_SKIP: plugin=$plugin_id type=error target=$target reason=$reason"
      results="$(echo "$results" | jq --argjson a "$action" '. + [$a + {"brokered": "skipped_error"}]')"
      idx=$((idx + 1))
      continue
    fi

    # Capability check
    if ! plugin_capability_allowed "$capability" "$ACTIVE_PLUGIN_ALLOWED_CAPS"; then
      plugin_log "DENY: plugin=$plugin_id capability=$capability target=$target reason=capability_not_allowed"
      results="$(echo "$results" | jq --arg t "$target" --arg c "$capability" '. + [{"type":"denied","target":$t,"capability":$c,"reason":"capability not in allowed list"}]')"
      idx=$((idx + 1))
      continue
    fi

    # Path check (for write actions)
    if [[ "$type" == write_* ]] || [[ "$type" == dry_run_write_* ]]; then
      if ! plugin_path_allowed "$target" "$ACTIVE_PLUGIN_ALLOWED_TARGETS" "$ACTIVE_PLUGIN_FORBIDDEN_TARGETS"; then
        plugin_log "DENY: plugin=$plugin_id capability=$capability target=$target reason=path_not_allowed"
        results="$(echo "$results" | jq --arg t "$target" --arg c "$capability" '. + [{"type":"denied","target":$t,"capability":$c,"reason":"target path not allowed by policy"}]')"
        idx=$((idx + 1))
        continue
      fi
    fi

    # Broker the action
    case "$type" in
      report)
        plugin_log "REPORT: plugin=$plugin_id target=$target reason=$reason"
        results="$(echo "$results" | jq --argjson a "$action" '. + [$a + {"brokered": "accepted"}]')"
        ;;

      write_patch_text)
        local patch_result
        patch_result="$(plugin_perform_text_patch "$plugin_id" "$action")"
        results="$(echo "$results" | jq --argjson r "$patch_result" '. + [$r]')"
        ;;

      write_replace_file)
        local replace_result
        replace_result="$(plugin_perform_atomic_replace "$plugin_id" "$action")"
        results="$(echo "$results" | jq --argjson r "$replace_result" '. + [$r]')"
        ;;

      dry_run_write_patch_text|dry_run_write_replace_file)
        plugin_log "DRY_RUN: plugin=$plugin_id type=$type target=$target reason=$reason"
        results="$(echo "$results" | jq --argjson a "$action" '. + [$a + {"brokered": "dry_run_accepted"}]')"
        ;;

      *)
        plugin_log "DENY: plugin=$plugin_id target=$target reason=unknown_action_type type=$type"
        results="$(echo "$results" | jq --arg t "$target" --arg type "$type" '. + [{"type":"denied","target":$t,"reason":"unknown action type","original_type":$type}]')"
        ;;
    esac

    idx=$((idx + 1))
  done

  echo "$results"
}

#==============================================================================
# ATOMIC WRITE OPERATIONS (performed by core, never by plugin)
#==============================================================================

plugin_perform_text_patch() {
  local plugin_id="$1"
  local action_json="$2"
  local target patch_format find_str replace_str pattern content_str
  local create_backup before_hash

  target="$(echo "$action_json" | jq -r '.target' 2>/dev/null)"
  create_backup="$(echo "$action_json" | jq -r '.create_backup // true' 2>/dev/null)"
  before_hash="$(echo "$action_json" | jq -r '.before_hash // empty' 2>/dev/null)"
  patch_format="$(echo "$action_json" | jq -r '.patch.format // empty' 2>/dev/null)"

  # Preflight: file must exist, be readable, be writable
  if [ ! -f "$target" ]; then
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=file_not_found"
    echo '{"type":"error","target":"'"$target"'","reason":"file not found","brokered":"failed"}'
    return 0
  fi

  if [ ! -r "$target" ] || [ ! -w "$target" ]; then
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=permission_denied"
    echo '{"type":"error","target":"'"$target"'","reason":"permission denied","brokered":"failed"}'
    return 0
  fi

  # Verify hash hasn't changed since plugin read it (race protection)
  if [ -n "$before_hash" ]; then
    local current_hash
    current_hash="$(plugin_sha256 "$target")"
    if [ "$current_hash" != "$before_hash" ]; then
      plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=hash_changed_since_proposal"
      echo '{"type":"error","target":"'"$target"'","reason":"file modified since proposal (hash mismatch)","brokered":"failed"}'
      return 0
    fi
  fi

  # Create backup
  if [ "$create_backup" = "true" ]; then
    local backup_dir="${PLUGIN_STATE_DIR}/backups"
    mkdir -p "$backup_dir" 2>/dev/null || true
    local backup_path="${backup_dir}/$(basename "$target").$(date +%Y%m%d_%H%M%S).bak"
    if ! cp -p "$target" "$backup_path" 2>/dev/null; then
      plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=backup_failed"
      echo '{"type":"error","target":"'"$target"'","reason":"backup creation failed","brokered":"failed"}'
      return 0
    fi
    plugin_log "BACKUP: $target -> $backup_path"
  fi

  # Perform the patch atomically via temp file
  local tmp_file
  tmp_file="$(mktemp "${target}.XXXXXX.tmp")"
  cp -p "$target" "$tmp_file" 2>/dev/null

  case "$patch_format" in
    line_replace)
      find_str="$(echo "$action_json" | jq -r '.patch.find // empty' 2>/dev/null)"
      replace_str="$(echo "$action_json" | jq -r '.patch.replace // empty' 2>/dev/null)"
      if [ -z "$find_str" ]; then
        rm -f "$tmp_file"
        echo '{"type":"error","target":"'"$target"'","reason":"missing find pattern","brokered":"failed"}'
        return 0
      fi
      # Use python3 for safe text replacement (avoids sed escaping issues)
      if ! python3 -c "
import sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
with open(sys.argv[1], 'w') as f:
    f.write(content.replace(sys.argv[2], sys.argv[3]))
" "$tmp_file" "$find_str" "$replace_str" 2>/dev/null; then
        rm -f "$tmp_file"
        plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=patch_apply_failed"
        echo '{"type":"error","target":"'"$target"'","reason":"text replacement failed","brokered":"failed"}'
        return 0
      fi
      ;;

    append_if_missing)
      content_str="$(echo "$action_json" | jq -r '.patch.content // empty' 2>/dev/null)"
      if [ -z "$content_str" ]; then
        rm -f "$tmp_file"
        echo '{"type":"error","target":"'"$target"'","reason":"missing content to append","brokered":"failed"}'
        return 0
      fi
      if ! grep -qF "$content_str" "$tmp_file" 2>/dev/null; then
        printf '%s\n' "$content_str" >> "$tmp_file"
      fi
      ;;

    remove_if_present)
      pattern="$(echo "$action_json" | jq -r '.patch.pattern // empty' 2>/dev/null)"
      if [ -z "$pattern" ]; then
        rm -f "$tmp_file"
        echo '{"type":"error","target":"'"$target"'","reason":"missing pattern to remove","brokered":"failed"}'
        return 0
      fi
      python3 -c "
import sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
with open(sys.argv[1], 'w') as f:
    f.write(content.replace(sys.argv[2], ''))
" "$tmp_file" "$pattern" 2>/dev/null
      ;;

    *)
      rm -f "$tmp_file"
      plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=unknown_patch_format format=$patch_format"
      echo '{"type":"error","target":"'"$target"'","reason":"unknown patch format: '"$patch_format"'","brokered":"failed"}'
      return 0
      ;;
  esac

  # Verify patch produced a different file (not a no-op that wastes a write)
  local new_hash
  new_hash="$(plugin_sha256 "$tmp_file")"
  if [ -n "$before_hash" ] && [ "$new_hash" = "$before_hash" ]; then
    rm -f "$tmp_file"
    plugin_log "WRITE_SKIP: plugin=$plugin_id target=$target reason=no_change_after_patch"
    echo '{"type":"report","target":"'"$target"'","reason":"no change after patch (already in desired state)","brokered":"skipped_no_change"}'
    return 0
  fi

  # Atomic move
  if ! mv "$tmp_file" "$target" 2>/dev/null; then
    rm -f "$tmp_file"
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=atomic_move_failed"
    echo '{"type":"error","target":"'"$target"'","reason":"atomic move failed","brokered":"failed"}'
    return 0
  fi

  plugin_log "WRITE_OK: plugin=$plugin_id type=patch_text target=$target format=$patch_format after_hash=$new_hash"
  jq -n --arg target "$target" --arg hash "$new_hash" --arg fmt "$patch_format" \
    '{"type":"write_patch_text","target":$target,"brokered":"completed","after_hash":$hash,"patch_format":$fmt}'
}

plugin_perform_atomic_replace() {
  local plugin_id="$1"
  local action_json="$2"
  local target new_content create_backup before_hash

  target="$(echo "$action_json" | jq -r '.target' 2>/dev/null)"
  new_content="$(echo "$action_json" | jq -r '.new_content // empty' 2>/dev/null)"
  create_backup="$(echo "$action_json" | jq -r '.create_backup // true' 2>/dev/null)"
  before_hash="$(echo "$action_json" | jq -r '.before_hash // empty' 2>/dev/null)"

  if [ ! -f "$target" ]; then
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=file_not_found"
    echo '{"type":"error","target":"'"$target"'","reason":"file not found","brokered":"failed"}'
    return 0
  fi

  if [ ! -w "$target" ]; then
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=permission_denied"
    echo '{"type":"error","target":"'"$target"'","reason":"permission denied","brokered":"failed"}'
    return 0
  fi

  # Race protection
  if [ -n "$before_hash" ]; then
    local current_hash
    current_hash="$(plugin_sha256 "$target")"
    if [ "$current_hash" != "$before_hash" ]; then
      plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=hash_changed_since_proposal"
      echo '{"type":"error","target":"'"$target"'","reason":"file modified since proposal","brokered":"failed"}'
      return 0
    fi
  fi

  # Backup
  if [ "$create_backup" = "true" ]; then
    local backup_dir="${PLUGIN_STATE_DIR}/backups"
    mkdir -p "$backup_dir" 2>/dev/null || true
    local backup_path="${backup_dir}/$(basename "$target").$(date +%Y%m%d_%H%M%S).bak"
    cp -p "$target" "$backup_path" 2>/dev/null || true
    plugin_log "BACKUP: $target -> $backup_path"
  fi

  # Write to temp, then atomic move
  local tmp_file
  tmp_file="$(mktemp "${target}.XXXXXX.tmp")"
  printf '%s' "$new_content" > "$tmp_file"

  local new_hash
  new_hash="$(plugin_sha256 "$tmp_file")"

  if ! mv "$tmp_file" "$target" 2>/dev/null; then
    rm -f "$tmp_file"
    plugin_log "WRITE_FAIL: plugin=$plugin_id target=$target reason=atomic_move_failed"
    echo '{"type":"error","target":"'"$target"'","reason":"atomic move failed","brokered":"failed"}'
    return 0
  fi

  plugin_log "WRITE_OK: plugin=$plugin_id type=atomic_replace target=$target after_hash=$new_hash"
  jq -n --arg target "$target" --arg hash "$new_hash" \
    '{"type":"write_replace_file","target":$target,"brokered":"completed","after_hash":$hash}'
}

#==============================================================================
# LLM TOOL FUNCTIONS (called by the scanner's dispatch_tool_call)
#==============================================================================

tool_plugin_list() {
  local count="${#LOADED_PLUGIN_IDS[@]}"
  if [ "$count" -eq 0 ]; then
    echo "No plugins loaded."
    return 0
  fi

  echo "Loaded plugins: $count"
  echo ""
  local i
  for i in "${!LOADED_PLUGIN_IDS[@]}"; do
    echo "  Plugin: ${LOADED_PLUGIN_IDS[$i]}"
    echo "  Name:   ${LOADED_PLUGIN_NAMES[$i]}"
    echo "  Caps:   ${LOADED_PLUGIN_CAPS[$i]}"
    echo ""
  done
}

tool_plugin_propose() {
  local plugin_id="$1"
  local target="$2"
  local capability="$3"
  local find_str="$4"
  local replace_str="$5"
  local reason="$6"
  local dry_run="${7:-false}"

  if [ -z "$plugin_id" ]; then
    echo "TOOL_ERROR: plugin.propose requires plugin_id"
    return 0
  fi

  if [ "${#LOADED_PLUGIN_IDS[@]}" -eq 0 ]; then
    echo "TOOL_ERROR: no plugins loaded"
    return 0
  fi

  # Build request JSON
  local mode="propose"
  [ "$dry_run" = "true" ] && mode="dry_run"

  local proposal
  proposal="$(jq -n \
    --arg target "$target" \
    --arg capability "$capability" \
    --arg find "$find_str" \
    --arg replace "$replace_str" \
    --arg reason "$reason" \
    --argjson backup true \
    --argjson dry_run "$( [ "$dry_run" = "true" ] && echo true || echo false )" \
    '{target:$target, capability:$capability, find:$find, replace:$replace,
      reason:$reason, create_backup:$backup, dry_run:$dry_run}'
  )"

  # Activate plugin rules
  plugin_activate_rules "$plugin_id" "$(plugin_get_dir "$plugin_id")" || {
    echo "TOOL_ERROR: failed to activate rules for $plugin_id"
    return 0
  }

  local request_json
  request_json="$(jq -n \
    --arg mode "$mode" \
    --argjson proposals "[$proposal]" \
    --argjson allowedCaps "$ACTIVE_PLUGIN_ALLOWED_CAPS" \
    --argjson allowedTargets "$ACTIVE_PLUGIN_ALLOWED_TARGETS" \
    --argjson forbiddenTargets "$ACTIVE_PLUGIN_FORBIDDEN_TARGETS" \
    '{mode:$mode, request:{proposals:$proposals},
      allowedCaps:$allowedCaps, allowedTargets:$allowedTargets,
      forbiddenTargets:$forbiddenTargets}'
  )"

  # Run plugin
  local response
  response="$(plugin_run "$plugin_id" "$request_json")"

  # Validate response
  if ! plugin_validate_response "$plugin_id" "$response"; then
    echo "TOOL_ERROR: plugin returned invalid response"
    echo "$response" | jq '.' 2>/dev/null | head -n 20
    return 0
  fi

  local status
  status="$(echo "$response" | jq -r '.status' 2>/dev/null)"
  if [ "$status" = "error" ]; then
    echo "PLUGIN_ERROR: $(echo "$response" | jq -r '.error.message // "unknown error"' 2>/dev/null)"
    return 0
  fi

  echo "PLUGIN_PROPOSAL:"
  echo "$response" | jq '.actions' 2>/dev/null
}

tool_plugin_execute() {
  local plugin_id="$1"
  local proposal_json="$2"

  if [ -z "$plugin_id" ] || [ -z "$proposal_json" ]; then
    echo "TOOL_ERROR: plugin.execute requires plugin_id and proposal (JSON)"
    return 0
  fi

  # Activate plugin rules
  plugin_activate_rules "$plugin_id" "$(plugin_get_dir "$plugin_id")" || {
    echo "TOOL_ERROR: failed to activate rules for $plugin_id"
    return 0
  }

  # Build a response object from the proposal for brokering
  local response_json
  response_json="$(jq -n --argjson actions "$proposal_json" '{status:"ok", actions:$actions}')"

  if ! plugin_validate_response "$plugin_id" "$response_json"; then
    echo "TOOL_ERROR: proposal validation failed"
    return 0
  fi

  local results
  results="$(plugin_broker_actions "$plugin_id" "$response_json")"

  echo "PLUGIN_RESULTS:"
  echo "$results" | jq '.' 2>/dev/null
}

# Helper to get plugin dir by ID
plugin_get_dir() {
  local plugin_id="$1" i
  for i in "${!LOADED_PLUGIN_IDS[@]}"; do
    if [ "${LOADED_PLUGIN_IDS[$i]}" = "$plugin_id" ]; then
      echo "${LOADED_PLUGIN_DIRS[$i]}"
      return 0
    fi
  done
  return 1
}

#==============================================================================
# TOOL SCHEMA GENERATION (for LLM tool definitions)
#==============================================================================
generate_plugin_tools_json() {
  if [ "${#LOADED_PLUGIN_IDS[@]}" -eq 0 ]; then
    echo '[]'
    return 0
  fi

  cat << 'PLUGIN_TOOLS_EOF'
[
  {
    "type": "function",
    "name": "plugin_list",
    "description": "List all loaded and verified plugins with their capabilities. Use this to see what plugins are available before proposing changes.",
    "parameters": {
      "type": "object",
      "properties": {}
    }
  },
  {
    "type": "function",
    "name": "plugin_propose",
    "description": "Ask a loaded plugin to propose a write action. The plugin analyzes the target and returns a structured proposal. The core app will validate and broker the actual write. Use this when you have identified an issue that can be fixed by modifying a file within allowed targets.",
    "parameters": {
      "type": "object",
      "properties": {
        "plugin_id": {"type": "string", "description": "Plugin ID (e.g. com.paranoid.plugin.write). Use plugin_list to see available plugins."},
        "target": {"type": "string", "description": "File path to modify. Must be within the plugin's allowed targets."},
        "capability": {"type": "string", "enum": ["write.patch_text", "write.atomic_replace", "write.append_if_missing", "write.remove_if_present"], "description": "The write capability to use."},
        "find": {"type": "string", "description": "For patch_text: the text to find and replace. For remove_if_present: the text to remove."},
        "replace": {"type": "string", "description": "For patch_text: the replacement text."},
        "reason": {"type": "string", "description": "Why this change is needed (logged for audit)."},
        "dry_run": {"type": "string", "enum": ["true", "false"], "description": "If true, simulate without writing (default false)."}
      },
      "required": ["plugin_id", "target", "capability", "reason"]
    }
  },
  {
    "type": "function",
    "name": "plugin_execute",
    "description": "Execute a previously proposed plugin action. Pass the actions array from a plugin_propose result. The core validates capabilities and paths, creates backups, and performs the write atomically.",
    "parameters": {
      "type": "object",
      "properties": {
        "plugin_id": {"type": "string", "description": "Plugin ID that generated the proposal."},
        "proposal": {"type": "string", "description": "The JSON actions array from a plugin_propose result (as a string)."}
      },
      "required": ["plugin_id", "proposal"]
    }
  }
]
PLUGIN_TOOLS_EOF
}

#==============================================================================
# TOOL DISPATCH (called from main scanner's dispatch_tool_call)
#==============================================================================
execute_plugin_tool_call() {
  local call_json="$1"
  local tool_name args_json

  tool_name="$(echo "$call_json" | jq -r '.tool // empty' 2>/dev/null)"
  args_json="$(echo "$call_json" | jq -c '.args // {}' 2>/dev/null)"

  case "$tool_name" in
    plugin.list)
      tool_plugin_list
      ;;
    plugin.propose)
      tool_plugin_propose \
        "$(echo "$args_json" | jq -r '.plugin_id // empty')" \
        "$(echo "$args_json" | jq -r '.target // empty')" \
        "$(echo "$args_json" | jq -r '.capability // empty')" \
        "$(echo "$args_json" | jq -r '.find // empty')" \
        "$(echo "$args_json" | jq -r '.replace // empty')" \
        "$(echo "$args_json" | jq -r '.reason // empty')" \
        "$(echo "$args_json" | jq -r '.dry_run // "false"')"
      ;;
    plugin.execute)
      tool_plugin_execute \
        "$(echo "$args_json" | jq -r '.plugin_id // empty')" \
        "$(echo "$args_json" | jq -r '.proposal // empty')"
      ;;
    *)
      echo "TOOL_NOT_HANDLED"
      return 1
      ;;
  esac
}

#==============================================================================
# PLUGIN SELF-TEST / DIAGNOSTICS
#==============================================================================
# Exercises every layer of the plugin system end-to-end without touching
# the scan loop or any real user files. Creates a temporary test file in a
# safe directory, runs the plugin against it, validates the proposal, brokers
# a dry-run, then cleans up.
#==============================================================================

# Run a command with a timeout (macOS-compatible, no coreutils needed)
_diag_run_plugin() {
  local runtime="$1" entrypoint="$2" input="$3" max_sec="${4:-10}"
  local tmpout pid waited
  tmpout="$(mktemp /tmp/paranoid_diag.XXXXXX)"
  "$runtime" "$entrypoint" > "$tmpout" 2>/dev/null <<< "$input" &
  pid=$!
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    [ "$waited" -ge "$max_sec" ] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -f "$tmpout"; return 1; }
    sleep 1; waited=$((waited + 1))
  done
  wait "$pid" 2>/dev/null || { rm -f "$tmpout"; return 1; }
  cat "$tmpout"; rm -f "$tmpout"
}

_diag_pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
_diag_fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
_diag_warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
_diag_info() { printf '  \033[2m       %s\033[0m\n' "$1"; }
_diag_section() {
  echo ""
  printf '  \033[1m── %s ──\033[0m\n' "$1"
}

plugin_run_diagnostics() {
  local pass=0 fail=0 warn=0
  local test_dir test_file

  echo ""
  printf '  \033[1m╔═══════════════════════════════════════╗\033[0m\n'
  printf '  \033[1m║       PLUGIN SYSTEM DIAGNOSTICS       ║\033[0m\n'
  printf '  \033[1m╚═══════════════════════════════════════╝\033[0m\n'

  # ── 1. Infrastructure ──────────────────────────────────────────────────────
  _diag_section "Infrastructure"

  if [ -d "$PLUGIN_DIR" ]; then
    _diag_pass "Plugin directory exists: $PLUGIN_DIR"
    pass=$((pass + 1))
  else
    _diag_fail "Plugin directory missing: $PLUGIN_DIR"
    fail=$((fail + 1))
  fi

  if [ -f "$PLUGIN_POLICY_FILE" ]; then
    if jq -e '.' "$PLUGIN_POLICY_FILE" >/dev/null 2>&1; then
      _diag_pass "Policy file valid JSON: $PLUGIN_POLICY_FILE"
      pass=$((pass + 1))
    else
      _diag_fail "Policy file is not valid JSON"
      fail=$((fail + 1))
    fi
  else
    _diag_fail "Policy file missing: $PLUGIN_POLICY_FILE"
    fail=$((fail + 1))
  fi

  if [ -d "$PLUGIN_TRUSTED_KEYS_DIR" ]; then
    local key_count
    key_count=$(find "$PLUGIN_TRUSTED_KEYS_DIR" -name '*.pub' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$key_count" -gt 0 ]; then
      _diag_pass "Trusted keys directory: $key_count public key(s) found"
      pass=$((pass + 1))
    else
      _diag_warn "Trusted keys directory exists but contains no .pub keys"
      _diag_info "Generate a keypair: see trusted_keys/README.md"
      warn=$((warn + 1))
    fi
  else
    _diag_fail "Trusted keys directory missing: $PLUGIN_TRUSTED_KEYS_DIR"
    fail=$((fail + 1))
  fi

  if [ -d "$PLUGIN_STATE_DIR" ] && [ -w "$PLUGIN_STATE_DIR" ]; then
    _diag_pass "State directory writable: $PLUGIN_STATE_DIR"
    pass=$((pass + 1))
  else
    _diag_fail "State directory not writable: $PLUGIN_STATE_DIR"
    fail=$((fail + 1))
  fi

  if command -v openssl &>/dev/null; then
    _diag_pass "openssl available: $(command -v openssl)"
    pass=$((pass + 1))
  else
    _diag_fail "openssl not found (required for signature verification)"
    fail=$((fail + 1))
  fi

  # ── 2. Plugin Discovery ────────────────────────────────────────────────────
  _diag_section "Plugin Discovery"

  local discovered=0 plugin_dirs
  plugin_dirs="$(plugin_discover)"
  if [ -n "$plugin_dirs" ]; then
    discovered=$(echo "$plugin_dirs" | wc -l | tr -d ' ')
    _diag_pass "Discovered $discovered plugin directory(ies)"
    pass=$((pass + 1))
    echo "$plugin_dirs" | while IFS= read -r d; do
      _diag_info "  $(basename "$d")/ → $d"
    done
  else
    _diag_warn "No plugin directories found in $PLUGIN_DIR"
    warn=$((warn + 1))
  fi

  # ── 3. Per-Plugin Verification ─────────────────────────────────────────────
  _diag_section "Plugin Verification"

  local dir manifest plugin_id version entrypoint runtime expected_hash key_id
  for dir in $plugin_dirs; do
    [ -z "$dir" ] && continue
    manifest="${dir}/manifest.json"

    if [ ! -f "$manifest" ]; then
      _diag_fail "$(basename "$dir"): missing manifest.json"
      fail=$((fail + 1))
      continue
    fi

    plugin_id="$(jq -r '.plugin_id // empty' "$manifest" 2>/dev/null)"
    version="$(jq -r '.version // empty' "$manifest" 2>/dev/null)"
    entrypoint="$(jq -r '.entrypoint // empty' "$manifest" 2>/dev/null)"
    runtime="$(jq -r '.runtime // empty' "$manifest" 2>/dev/null)"
    expected_hash="$(jq -r '.hash.executable // empty' "$manifest" 2>/dev/null)"
    key_id="$(jq -r '.publisher.key_id // empty' "$manifest" 2>/dev/null)"

    echo ""
    _diag_info "Plugin: $plugin_id (v$version)"

    # Manifest structure
    if [ -n "$plugin_id" ] && [ -n "$entrypoint" ] && [ -n "$version" ]; then
      _diag_pass "Manifest structure valid (id, entrypoint, version present)"
      pass=$((pass + 1))
    else
      _diag_fail "Manifest incomplete (missing plugin_id, entrypoint, or version)"
      fail=$((fail + 1))
    fi

    # Policy lookup
    local policy
    policy="$(plugin_policy_lookup "$plugin_id" 2>/dev/null)"
    if [ -n "$policy" ]; then
      _diag_pass "Policy registered for $plugin_id"
      pass=$((pass + 1))

      # Version range
      local min_v max_v
      min_v="$(echo "$policy" | jq -r '.min_version' 2>/dev/null)"
      max_v="$(echo "$policy" | jq -r '.max_version' 2>/dev/null)"
      if plugin_semver_in_range "$version" "$min_v" "$max_v"; then
        _diag_pass "Version $version within policy range [$min_v, $max_v]"
        pass=$((pass + 1))
      else
        _diag_fail "Version $version outside policy range [$min_v, $max_v]"
        fail=$((fail + 1))
      fi

      # Publisher key match
      local policy_key_id
      policy_key_id="$(echo "$policy" | jq -r '.publisher_key_id' 2>/dev/null)"
      if [ "$key_id" = "$policy_key_id" ]; then
        _diag_pass "Publisher key ID matches policy ($key_id)"
        pass=$((pass + 1))
      else
        _diag_fail "Publisher key ID mismatch (manifest=$key_id policy=$policy_key_id)"
        fail=$((fail + 1))
      fi
    else
      _diag_fail "No policy registered for $plugin_id"
      fail=$((fail + 1))
    fi

    # Entrypoint exists
    local ep_path="${dir}/${entrypoint#./}"
    if [ -f "$ep_path" ]; then
      _diag_pass "Entrypoint exists: $ep_path"
      pass=$((pass + 1))

      if [ -x "$ep_path" ]; then
        _diag_pass "Entrypoint is executable"
        pass=$((pass + 1))
      else
        _diag_warn "Entrypoint is not executable (chmod +x recommended)"
        warn=$((warn + 1))
      fi
    else
      _diag_fail "Entrypoint missing: $ep_path"
      fail=$((fail + 1))
    fi

    # Runtime
    if [ -n "$runtime" ]; then
      if command -v "$runtime" &>/dev/null; then
        _diag_pass "Runtime available: $runtime ($(command -v "$runtime"))"
        pass=$((pass + 1))
      else
        _diag_fail "Runtime not found: $runtime"
        fail=$((fail + 1))
      fi
    fi

    # Executable hash
    if [ -f "$ep_path" ]; then
      local actual_hash
      actual_hash="$(plugin_sha256 "$ep_path")"
      if [ "$expected_hash" = "PLACEHOLDER_HASH_RUN_SETUP_TO_GENERATE" ]; then
        _diag_warn "Executable hash is placeholder — not verified"
        _diag_info "Current hash: $actual_hash"
        _diag_info "Update manifest.json hash.executable, then re-sign"
        warn=$((warn + 1))
      elif [ "$actual_hash" = "$expected_hash" ]; then
        _diag_pass "Executable hash matches manifest"
        pass=$((pass + 1))
      else
        _diag_fail "Executable hash mismatch"
        _diag_info "Expected: $expected_hash"
        _diag_info "Actual:   $actual_hash"
        fail=$((fail + 1))
      fi
    fi

    # Signature
    local sig="${dir}/manifest.sig"
    local key_file="${PLUGIN_TRUSTED_KEYS_DIR}/${key_id}.pub"
    if [ -f "$sig" ]; then
      if [ -f "$key_file" ]; then
        if plugin_verify_manifest_signature "$manifest" "$sig" "$key_file"; then
          _diag_pass "Manifest signature verified"
          pass=$((pass + 1))
        else
          _diag_fail "Manifest signature INVALID"
          fail=$((fail + 1))
        fi
      else
        _diag_fail "Trusted key not found: $key_file"
        _diag_info "Place the publisher's public key at: $key_file"
        fail=$((fail + 1))
      fi
    else
      _diag_warn "No manifest.sig — signature not verified"
      _diag_info "Sign with: openssl dgst -sha256 -sign <key.pem> -out manifest.sig manifest.json"
      warn=$((warn + 1))
    fi

    # macOS code signature (informational for scripts)
    if [ -f "$ep_path" ]; then
      if file "$ep_path" 2>/dev/null | grep -qiE 'Mach-O|bundle'; then
        if codesign --verify --deep --strict "$ep_path" >/dev/null 2>&1; then
          _diag_pass "macOS code signature valid"
          pass=$((pass + 1))
        else
          _diag_fail "macOS code signature invalid"
          fail=$((fail + 1))
        fi
      else
        _diag_info "Entrypoint is a script — macOS code signing not applicable"
      fi
    fi
  done

  # ── 4. Capability & Path Enforcement ───────────────────────────────────────
  _diag_section "Policy Enforcement (capability + path rules)"

  if [ -n "$plugin_dirs" ]; then
    # Use the first discovered plugin for enforcement tests
    local test_plugin_dir test_manifest test_plugin_id
    test_plugin_dir="$(echo "$plugin_dirs" | head -n 1)"
    test_manifest="${test_plugin_dir}/manifest.json"
    test_plugin_id="$(jq -r '.plugin_id // empty' "$test_manifest" 2>/dev/null)"

    if [ -n "$test_plugin_id" ]; then
      local test_policy
      test_policy="$(plugin_policy_lookup "$test_plugin_id" 2>/dev/null)"
      if [ -n "$test_policy" ]; then
        local test_allowed_caps test_allowed_targets test_forbidden_targets
        test_allowed_caps="$(echo "$test_policy" | jq -c '.allowed_capabilities' 2>/dev/null)"
        test_allowed_targets="$(echo "$test_policy" | jq -c '.allowed_targets' 2>/dev/null)"
        test_forbidden_targets="$(echo "$test_policy" | jq -c '.forbidden_targets' 2>/dev/null)"

        # Capability allow
        if plugin_capability_allowed "write.patch_text" "$test_allowed_caps"; then
          _diag_pass "Capability ALLOW: write.patch_text (declared)"
          pass=$((pass + 1))
        else
          _diag_fail "Capability ALLOW: write.patch_text should be allowed"
          fail=$((fail + 1))
        fi

        # Capability deny
        if ! plugin_capability_allowed "write.delete_file" "$test_allowed_caps"; then
          _diag_pass "Capability DENY: write.delete_file (undeclared → blocked)"
          pass=$((pass + 1))
        else
          _diag_fail "Capability DENY: write.delete_file should be blocked"
          fail=$((fail + 1))
        fi

        # Path allow
        if plugin_path_allowed "$HOME/Documents/test.conf" "$test_allowed_targets" "$test_forbidden_targets"; then
          _diag_pass "Path ALLOW: ~/Documents/test.conf"
          pass=$((pass + 1))
        else
          _diag_fail "Path ALLOW: ~/Documents/test.conf should be allowed"
          fail=$((fail + 1))
        fi

        # Path deny — system
        if ! plugin_path_allowed "/System/Library/test" "$test_allowed_targets" "$test_forbidden_targets"; then
          _diag_pass "Path DENY: /System/Library/test (forbidden)"
          pass=$((pass + 1))
        else
          _diag_fail "Path DENY: /System/Library/test should be blocked"
          fail=$((fail + 1))
        fi

        # Path deny — ssh
        if ! plugin_path_allowed "$HOME/.ssh/authorized_keys" "$test_allowed_targets" "$test_forbidden_targets"; then
          _diag_pass "Path DENY: ~/.ssh/authorized_keys (forbidden)"
          pass=$((pass + 1))
        else
          _diag_fail "Path DENY: ~/.ssh/authorized_keys should be blocked"
          fail=$((fail + 1))
        fi

        # Path deny — unlisted
        if ! plugin_path_allowed "/tmp/random_file" "$test_allowed_targets" "$test_forbidden_targets"; then
          _diag_pass "Path DENY: /tmp/random_file (not in allowed list)"
          pass=$((pass + 1))
        else
          _diag_fail "Path DENY: /tmp/random_file should be blocked (default deny)"
          fail=$((fail + 1))
        fi
      fi
    fi
  fi

  # ── 5. Plugin Execution (live subprocess test) ─────────────────────────────
  _diag_section "Plugin Execution (live subprocess test)"

  if [ -n "$plugin_dirs" ]; then
    local test_plugin_dir test_manifest test_plugin_id
    test_plugin_dir="$(echo "$plugin_dirs" | head -n 1)"
    test_manifest="${test_plugin_dir}/manifest.json"
    test_plugin_id="$(jq -r '.plugin_id // empty' "$test_manifest" 2>/dev/null)"
    local test_runtime test_entrypoint
    test_runtime="$(jq -r '.runtime // empty' "$test_manifest" 2>/dev/null)"
    test_entrypoint="${test_plugin_dir}/$(jq -r '.entrypoint // empty' "$test_manifest" 2>/dev/null)"
    test_entrypoint="${test_entrypoint#./}"

    if [ -n "$test_runtime" ] && command -v "$test_runtime" &>/dev/null && [ -f "$test_entrypoint" ]; then
      # Create a temporary test file in ~/Documents (an allowed target path)
      test_dir="$HOME/Documents/.paranoid_diag_$$"
      mkdir -p "$test_dir"
      test_file="${test_dir}/test_config.conf"
      printf 'allow_legacy_tls=true\nmax_connections=100\ndebug_mode=false\n' > "$test_file"
      _diag_info "Created test file: $test_file"

      # 5a. Scan mode
      local scan_request scan_response scan_status
      scan_request="$(jq -n \
        --arg mode "scan" \
        --argjson targets "[\"$test_file\"]" \
        '{mode:$mode, request:{targets:$targets}, allowedTargets:["~/Documents/**"], forbiddenTargets:["/System/**"]}'
      )"

      scan_response="$(_diag_run_plugin "$test_runtime" "$test_entrypoint" "$scan_request")"
      if echo "$scan_response" | jq -e '.' >/dev/null 2>&1; then
        scan_status="$(echo "$scan_response" | jq -r '.status' 2>/dev/null)"
        if [ "$scan_status" = "ok" ]; then
          _diag_pass "Scan mode: valid JSON response, status=ok"
          pass=$((pass + 1))
          local scan_action_count
          scan_action_count="$(echo "$scan_response" | jq '.actions | length' 2>/dev/null)"
          _diag_info "Returned $scan_action_count action(s)"
        else
          _diag_fail "Scan mode: status=$scan_status (expected ok)"
          fail=$((fail + 1))
        fi
      else
        _diag_fail "Scan mode: plugin returned invalid JSON"
        fail=$((fail + 1))
      fi

      # 5b. Propose mode (dry run)
      local propose_request propose_response propose_status
      propose_request="$(jq -n \
        --arg mode "dry_run" \
        --arg target "$test_file" \
        '{mode:$mode,
          request:{proposals:[{
            target:$target,
            capability:"write.patch_text",
            find:"allow_legacy_tls=true",
            replace:"allow_legacy_tls=false",
            reason:"Disable insecure TLS (diagnostics test)",
            create_backup:true,
            dry_run:true
          }]},
          allowedTargets:["~/Documents/**"],
          forbiddenTargets:["/System/**"]}'
      )"

      propose_response="$(_diag_run_plugin "$test_runtime" "$test_entrypoint" "$propose_request")"
      if echo "$propose_response" | jq -e '.' >/dev/null 2>&1; then
        propose_status="$(echo "$propose_response" | jq -r '.status' 2>/dev/null)"
        if [ "$propose_status" = "ok" ]; then
          _diag_pass "Propose mode (dry run): valid JSON response, status=ok"
          pass=$((pass + 1))

          local action_type
          action_type="$(echo "$propose_response" | jq -r '.actions[0].type // empty' 2>/dev/null)"
          if [[ "$action_type" == dry_run_* ]]; then
            _diag_pass "Proposal is marked as dry_run ($action_type)"
            pass=$((pass + 1))
          else
            _diag_warn "Proposal type=$action_type (expected dry_run_ prefix)"
            warn=$((warn + 1))
          fi

          # Check required proposal fields
          local has_target has_capability has_reason has_rollback has_hash
          has_target="$(echo "$propose_response" | jq -r '.actions[0].target // empty' 2>/dev/null)"
          has_capability="$(echo "$propose_response" | jq -r '.actions[0].capability // empty' 2>/dev/null)"
          has_reason="$(echo "$propose_response" | jq -r '.actions[0].reason // empty' 2>/dev/null)"
          has_rollback="$(echo "$propose_response" | jq -r '.actions[0].rollback_hint // empty' 2>/dev/null)"
          has_hash="$(echo "$propose_response" | jq -r '.actions[0].before_hash // empty' 2>/dev/null)"

          if [ -n "$has_target" ] && [ -n "$has_capability" ] && [ -n "$has_reason" ]; then
            _diag_pass "Proposal has required fields (target, capability, reason)"
            pass=$((pass + 1))
          else
            _diag_fail "Proposal missing required fields"
            fail=$((fail + 1))
          fi

          if [ -n "$has_rollback" ]; then
            _diag_pass "Proposal includes rollback_hint"
            pass=$((pass + 1))
          else
            _diag_warn "Proposal missing rollback_hint"
            warn=$((warn + 1))
          fi

          if [ -n "$has_hash" ]; then
            _diag_pass "Proposal includes before_hash (race protection)"
            pass=$((pass + 1))
          else
            _diag_warn "Proposal missing before_hash"
            warn=$((warn + 1))
          fi
        else
          _diag_fail "Propose mode: status=$propose_status"
          fail=$((fail + 1))
        fi
      else
        _diag_fail "Propose mode: plugin returned invalid JSON"
        fail=$((fail + 1))
      fi

      # 5c. Validate mode
      local validate_request validate_response
      validate_request="$(jq -n \
        --arg target "$test_file" \
        '{mode:"validate",
          request:{action:{target:$target, capability:"write.patch_text"}},
          allowedTargets:["~/Documents/**"],
          forbiddenTargets:["/System/**"]}'
      )"

      validate_response="$(_diag_run_plugin "$test_runtime" "$test_entrypoint" "$validate_request")"
      if echo "$validate_response" | jq -e '.' >/dev/null 2>&1; then
        local val_passed
        val_passed="$(echo "$validate_response" | jq -r '.validation.passed // false' 2>/dev/null)"
        if [ "$val_passed" = "true" ]; then
          _diag_pass "Validate mode: all checks passed for test file"
          pass=$((pass + 1))
        else
          _diag_warn "Validate mode: some checks failed"
          _diag_info "$(echo "$validate_response" | jq -c '.validation.checks' 2>/dev/null)"
          warn=$((warn + 1))
        fi
      else
        _diag_fail "Validate mode: plugin returned invalid JSON"
        fail=$((fail + 1))
      fi

      # 5d. Forbidden path rejection
      local forbidden_request forbidden_response
      forbidden_request="$(jq -n \
        '{mode:"propose",
          request:{proposals:[{
            target:"/System/Library/test",
            capability:"write.patch_text",
            find:"x",replace:"y",
            reason:"test forbidden"
          }]},
          allowedTargets:["~/Documents/**"],
          forbiddenTargets:["/System/**"]}'
      )"

      forbidden_response="$(_diag_run_plugin "$test_runtime" "$test_entrypoint" "$forbidden_request")"
      if echo "$forbidden_response" | jq -e '.' >/dev/null 2>&1; then
        local forbidden_type
        forbidden_type="$(echo "$forbidden_response" | jq -r '.actions[0].type // empty' 2>/dev/null)"
        if [ "$forbidden_type" = "error" ]; then
          _diag_pass "Forbidden path: plugin correctly rejected /System target"
          pass=$((pass + 1))
        else
          _diag_fail "Forbidden path: plugin did NOT reject /System target (type=$forbidden_type)"
          fail=$((fail + 1))
        fi
      else
        _diag_fail "Forbidden path test: invalid JSON response"
        fail=$((fail + 1))
      fi

      # 5e. Idempotency check
      local idem_request idem_response
      idem_request="$(jq -n \
        --arg target "$test_file" \
        '{mode:"propose",
          request:{proposals:[{
            target:$target,
            capability:"write.patch_text",
            find:"nonexistent_string_xyz",
            replace:"replacement",
            reason:"test idempotency"
          }]},
          allowedTargets:["~/Documents/**"],
          forbiddenTargets:["/System/**"]}'
      )"

      idem_response="$(_diag_run_plugin "$test_runtime" "$test_entrypoint" "$idem_request")"
      if echo "$idem_response" | jq -e '.' >/dev/null 2>&1; then
        local idem_type
        idem_type="$(echo "$idem_response" | jq -r '.actions[0].type // empty' 2>/dev/null)"
        if [ "$idem_type" = "error" ]; then
          local idem_reason
          idem_reason="$(echo "$idem_response" | jq -r '.actions[0].reason // empty' 2>/dev/null)"
          _diag_pass "Idempotency: plugin correctly reports pattern not found"
          _diag_info "Reason: $idem_reason"
          pass=$((pass + 1))
        else
          _diag_warn "Idempotency: unexpected response type=$idem_type"
          warn=$((warn + 1))
        fi
      else
        _diag_fail "Idempotency test: invalid JSON response"
        fail=$((fail + 1))
      fi

      # 5f. Verify test file was NOT modified (read-only confirmation)
      local file_after
      file_after="$(cat "$test_file" 2>/dev/null)"
      if [ "$file_after" = "allow_legacy_tls=true
max_connections=100
debug_mode=false" ]; then
        _diag_pass "Test file was NOT modified (all tests were read-only/dry-run)"
        pass=$((pass + 1))
      else
        _diag_fail "Test file was unexpectedly modified"
        fail=$((fail + 1))
      fi

      # Clean up test directory
      rm -rf "$test_dir" 2>/dev/null
      _diag_info "Cleaned up test directory: $test_dir"
    else
      _diag_warn "Cannot run live execution tests (runtime or entrypoint unavailable)"
      warn=$((warn + 1))
    fi
  else
    _diag_warn "No plugins discovered — skipping execution tests"
    warn=$((warn + 1))
  fi

  # ── 6. Write Verification (Watermark) ────────────────────────────────────
  _diag_section "Write Verification (Watermark)"

  _diag_info "Watermark key: $PARANOID_WATERMARK_KEY"
  _diag_info "Tmp directory: $PARANOID_DIAG_TMP"

  if [ -n "$plugin_dirs" ]; then
    local wm_plugin_dir wm_manifest wm_plugin_id wm_runtime wm_entrypoint
    wm_plugin_dir="$(echo "$plugin_dirs" | head -n 1)"
    wm_manifest="${wm_plugin_dir}/manifest.json"
    wm_plugin_id="$(jq -r '.plugin_id // empty' "$wm_manifest" 2>/dev/null)"
    wm_runtime="$(jq -r '.runtime // empty' "$wm_manifest" 2>/dev/null)"
    wm_entrypoint="${wm_plugin_dir}/$(jq -r '.entrypoint // empty' "$wm_manifest" 2>/dev/null)"
    wm_entrypoint="${wm_entrypoint#./}"

    if [ -n "$wm_runtime" ] && command -v "$wm_runtime" &>/dev/null && [ -f "$wm_entrypoint" ]; then
      # Create the 3 test files in the diag tmp dir
      local wm_plist="${PARANOID_DIAG_TMP}/watermark_test.plist"
      local wm_sh="${PARANOID_DIAG_TMP}/watermark_test.sh"
      local wm_txt="${PARANOID_DIAG_TMP}/watermark_test.txt"

      printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n  <key>Label</key>\n  <string>com.paranoid.watermark.test</string>\n</dict>\n</plist>\n' > "$wm_plist"
      printf '#!/usr/bin/env bash\necho "watermark test"\n' > "$wm_sh"
      printf 'Paranoid Scanner — watermark verification file\n' > "$wm_txt"

      # Define watermark comments for each file type
      local wm_comment_plist="<!-- PARANOID_WATERMARK: ${PARANOID_WATERMARK_KEY} -->"
      local wm_comment_sh="# PARANOID_WATERMARK: ${PARANOID_WATERMARK_KEY}"
      local wm_comment_txt="# PARANOID_WATERMARK: ${PARANOID_WATERMARK_KEY}"

      # Allowed targets must include our tmp dir
      local wm_allowed_targets
      wm_allowed_targets="$(jq -n --arg d "${PARANOID_DIAG_TMP}/**" '[$d]')"
      local wm_forbidden_targets='["/System/**"]'

      local wm_all_passed=true

      # For each file: propose append via plugin, broker the write, verify watermark
      local wm_file wm_comment wm_label
      for wm_file in "$wm_plist" "$wm_sh" "$wm_txt"; do
        case "$wm_file" in
          *.plist) wm_comment="$wm_comment_plist"; wm_label=".plist" ;;
          *.sh)    wm_comment="$wm_comment_sh";    wm_label=".sh" ;;
          *.txt)   wm_comment="$wm_comment_txt";   wm_label=".txt" ;;
        esac

        # Build propose request for append_if_missing
        local wm_request
        wm_request="$(jq -n \
          --arg mode "propose" \
          --arg target "$wm_file" \
          --arg content "$wm_comment" \
          --arg reason "Watermark verification test" \
          --argjson allowed "$wm_allowed_targets" \
          --argjson forbidden "$wm_forbidden_targets" \
          '{mode:$mode,
            request:{proposals:[{
              target:$target,
              capability:"write.append_if_missing",
              content:$content,
              reason:$reason,
              create_backup:false
            }]},
            allowedTargets:$allowed,
            forbiddenTargets:$forbidden}'
        )"

        # Run plugin to get proposal
        local wm_response
        wm_response="$(_diag_run_plugin "$wm_runtime" "$wm_entrypoint" "$wm_request")"

        if ! echo "$wm_response" | jq -e '.' >/dev/null 2>&1; then
          _diag_fail "Watermark ${wm_label}: plugin returned invalid JSON"
          fail=$((fail + 1))
          wm_all_passed=false
          continue
        fi

        local wm_action_type
        wm_action_type="$(echo "$wm_response" | jq -r '.actions[0].type // empty' 2>/dev/null)"

        if [ "$wm_action_type" != "write_patch_text" ]; then
          _diag_fail "Watermark ${wm_label}: unexpected proposal type=${wm_action_type}"
          _diag_info "Response: $(echo "$wm_response" | jq -c '.actions[0]' 2>/dev/null)"
          fail=$((fail + 1))
          wm_all_passed=false
          continue
        fi

        _diag_pass "Watermark ${wm_label}: proposal received (append_if_missing)"
        pass=$((pass + 1))

        # Broker the write through core (actual write, not dry-run)
        # We need to temporarily set the active plugin state for brokering
        local saved_active_id="$ACTIVE_PLUGIN_ID"
        local saved_active_caps="$ACTIVE_PLUGIN_ALLOWED_CAPS"
        local saved_active_targets="$ACTIVE_PLUGIN_ALLOWED_TARGETS"
        local saved_active_forbidden="$ACTIVE_PLUGIN_FORBIDDEN_TARGETS"

        ACTIVE_PLUGIN_ID="$wm_plugin_id"
        ACTIVE_PLUGIN_ALLOWED_CAPS='["write.append_if_missing","write.patch_text","write.atomic_replace","read.scan"]'
        ACTIVE_PLUGIN_ALLOWED_TARGETS="$wm_allowed_targets"
        ACTIVE_PLUGIN_FORBIDDEN_TARGETS="$wm_forbidden_targets"

        local wm_broker_result
        wm_broker_result="$(plugin_broker_actions "$wm_plugin_id" "$wm_response")"

        # Restore active state
        ACTIVE_PLUGIN_ID="$saved_active_id"
        ACTIVE_PLUGIN_ALLOWED_CAPS="$saved_active_caps"
        ACTIVE_PLUGIN_ALLOWED_TARGETS="$saved_active_targets"
        ACTIVE_PLUGIN_FORBIDDEN_TARGETS="$saved_active_forbidden"

        local wm_brokered
        wm_brokered="$(echo "$wm_broker_result" | jq -r '.[0].brokered // empty' 2>/dev/null)"

        if [ "$wm_brokered" != "completed" ]; then
          _diag_fail "Watermark ${wm_label}: broker failed (status=${wm_brokered})"
          _diag_info "Result: $(echo "$wm_broker_result" | jq -c '.[0]' 2>/dev/null)"
          fail=$((fail + 1))
          wm_all_passed=false
          continue
        fi

        _diag_pass "Watermark ${wm_label}: write brokered successfully"
        pass=$((pass + 1))

        # Verify: read back file and check watermark is present
        if grep -qF "$PARANOID_WATERMARK_KEY" "$wm_file" 2>/dev/null; then
          _diag_pass "Watermark ${wm_label}: key verified in file"
          pass=$((pass + 1))
        else
          _diag_fail "Watermark ${wm_label}: key NOT found in file after write"
          fail=$((fail + 1))
          wm_all_passed=false
        fi
      done

      if [ "$wm_all_passed" = true ]; then
        _diag_pass "All 3 watermark files written and verified"
        pass=$((pass + 1))
      fi

      # Clean up watermark test files
      rm -f "$wm_plist" "$wm_sh" "$wm_txt" 2>/dev/null
      _diag_info "Cleaned up watermark test files"
    else
      _diag_warn "Cannot run watermark tests (runtime or entrypoint unavailable)"
      warn=$((warn + 1))
    fi
  else
    _diag_warn "No plugins discovered — skipping watermark tests"
    warn=$((warn + 1))
  fi

  # ── 7. Audit Log ───────────────────────────────────────────────────────────
  _diag_section "Audit Log"

  if [ -f "$PLUGIN_AUDIT_LOG" ]; then
    local log_lines
    log_lines="$(wc -l < "$PLUGIN_AUDIT_LOG" | tr -d ' ')"
    _diag_pass "Audit log exists: $PLUGIN_AUDIT_LOG ($log_lines entries)"
    pass=$((pass + 1))
    _diag_info "Last 3 entries:"
    tail -n 3 "$PLUGIN_AUDIT_LOG" 2>/dev/null | while IFS= read -r l; do
      _diag_info "  $l"
    done
  else
    _diag_info "Audit log not yet created (will be created on first plugin operation)"
  fi

  # ── Summary ────────────────────────────────────────────────────────────────
  echo ""
  printf '  \033[1m── Summary ──\033[0m\n'
  printf '  \033[32mPASS: %d\033[0m  \033[31mFAIL: %d\033[0m  \033[33mWARN: %d\033[0m\n' "$pass" "$fail" "$warn"
  echo ""

  if [ "$fail" -eq 0 ] && [ "$warn" -eq 0 ]; then
    printf '  \033[32m\033[1mAll checks passed. Plugin system is fully operational.\033[0m\n'
  elif [ "$fail" -eq 0 ]; then
    printf '  \033[33m\033[1mNo failures. Warnings indicate setup steps remaining.\033[0m\n'
  else
    printf '  \033[31m\033[1mFailures detected. Review above and fix before using plugins in scans.\033[0m\n'
  fi
  echo ""

  plugin_log "DIAGNOSTICS: pass=$pass fail=$fail warn=$warn"
}
