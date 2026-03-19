#!/usr/bin/env bash
#==============================================================================
# PARANOID DISCOVERY SCANNER (macOS)
#==============================================================================
# Version       : 3.0.0
# Last Updated  : 2025-02-12
#
# A paranoid, LLM-driven security scanner for macOS that uses OpenAI's
# native tool-calling (Responses API) to autonomously investigate a system
# for stealthy/advanced persistent threats.
#
# ARCHITECTURE (v3 — Native Tool Calling):
#   1. Scanner defines all tools as structured schemas in the API request
#   2. Model returns type:"function_call" objects (not raw text JSON)
#   3. Bash dispatcher maps function name → local tool execution
#   4. Result sent back as type:"function_call_output" with call_id
#   5. Server-side conversation history via previous_response_id
#   6. Loop continues until scan_complete is called
#
#   This eliminates ALL manual JSON parsing, extraction, nudging, and
#   markdown stripping. The model is constrained to only call defined tools.
#
# TOOLS AVAILABLE TO THE LLM:
#   Read-only:  file_read, file_tail, file_grep, file_find, file_stat
#               file_signal_extract, launchd_plist_triage
#               dir_list, dir_tree, dir_grep, dir_find
#               cmd_exec_to_file, cmd_exec_to_file_bundle, shell_exec
#               investigation_command_catalog, investigation_command_run
#               apple_man, apple_codesign_verify, apple_entitlements
#               pluginkit_list_active
#   Mutating:   file_write, file_replace
#               plist_to_xml, plist_to_binary
#               plist_inplace_to_xml, plist_inplace_to_binary
#               pluginkit_disable_all_active
#               (all require ack:"I_UNDERSTAND")
#   Control:    scan_complete, scan_finding
#   + macOS module tools (40+ probes) if paranoid_macos_tools.sh is present
#   + Threat intel tools (12+ lookups) if paranoid_threat_intel.sh is present
#
# REQUIREMENTS: bash 3.2+, jq, curl, bc
# OPTIONAL:     tree, osqueryi, yara, codesign (Xcode CLT)
# LICENSE: MIT
#==============================================================================

set -euo pipefail

# ── Ensure Homebrew paths are in PATH ────────────────────────
for _p in /opt/homebrew/bin /opt/homebrew/sbin /usr/local/bin /usr/local/sbin; do
  [[ -d "$_p" ]] && [[ ":$PATH:" != *":$_p:"* ]] && export PATH="$_p:$PATH"
done

#==============================================================================
# CONFIGURATION
#==============================================================================

# ── Load local .env if present (local file values take precedence) ──────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_LOADER_FILE="$SCRIPT_DIR/paranoid_env_loader.sh"
if [ -f "$ENV_LOADER_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_LOADER_FILE"
fi
if [ -f "$ENV_FILE" ]; then
  if type load_env_file_safe >/dev/null 2>&1; then
    load_env_file_safe "$ENV_FILE"
  else
    echo "WARN: paranoid_env_loader.sh missing; skipping .env load for safety."
  fi
fi

API_KEY="${OPENAI_API_KEY:-}"
API_MODEL="${CMDBOT_MODEL:-}"
API_URL="${OPENAI_API_URL:-https://api.openai.com/v1/responses}"
API_CONNECT_TIMEOUT="${PARANOID_API_CONNECT_TIMEOUT:-${CMDBOT_API_CONNECT_TIMEOUT:-10}}"
API_TIMEOUT_SECONDS="${PARANOID_API_TIMEOUT_SECONDS:-${CMDBOT_API_TIMEOUT_SECONDS:-90}}"

if [ -z "$API_KEY" ]; then
  echo -e "\033[33mOPENAI_API_KEY is not set.\033[0m"
  echo -e "\033[2mGet one at: https://platform.openai.com/api-keys\033[0m"
  echo ""
  read -rsp "  Paste your OpenAI API key (sk-...): " _user_api_key
  echo ""
  if [ -z "$_user_api_key" ]; then
    echo -e "\033[31mNo key provided. Cannot continue without an API key.\033[0m"
    exit 1
  fi
  API_KEY="$_user_api_key"
  export OPENAI_API_KEY="$_user_api_key"
  # Persist to .env so the user doesn't have to enter it again
  if [ -f "$ENV_FILE" ]; then
    # Update existing OPENAI_API_KEY line or append
    if grep -q '^OPENAI_API_KEY=' "$ENV_FILE" 2>/dev/null; then
      _env_tmp="$(mktemp /tmp/paranoid_env.XXXXXX)"
      awk -v v="$_user_api_key" '/^OPENAI_API_KEY=/{print "OPENAI_API_KEY=" v; next}{print}' "$ENV_FILE" > "$_env_tmp"
      chmod 600 "$_env_tmp" 2>/dev/null || true
      mv "$_env_tmp" "$ENV_FILE"
    else
      printf "OPENAI_API_KEY=%s\n" "$_user_api_key" >> "$ENV_FILE"
    fi
  else
    printf "OPENAI_API_KEY=%s\n" "$_user_api_key" > "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  echo -e "\033[32m✓ API key saved to .env\033[0m"
  echo ""
  unset _user_api_key
fi

if [[ "$API_KEY" == *".sk-"* ]] || [[ "$API_KEY" == "sk-.sk-"* ]]; then
  echo "ERROR: OPENAI_API_KEY appears malformed (contains '.sk-')."
  echo "Fix your key value in '$ENV_FILE' or current shell environment."
  exit 1
fi

if ! [[ "$API_CONNECT_TIMEOUT" =~ ^[0-9]+$ ]]; then
  API_CONNECT_TIMEOUT=10
fi
if ! [[ "$API_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]; then
  API_TIMEOUT_SECONDS=90
fi

# ── Dynamic Paths ────────────────────────────────────────────────────────────
CURRENT_USER="$(whoami)"
CURRENT_HOME="$HOME"
CURRENT_DATETIME="$(date -u '+%Y-%m-%d %H:%M:%S')"
HOSTNAME_STR="$(hostname)"
OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
OS_BUILD="$(sw_vers -buildVersion 2>/dev/null || echo 'unknown')"
KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"

# ── Working Directories ─────────────────────────────────────────────────────
DEFAULT_FINDINGS_DIR="$SCRIPT_DIR/paranoid_findings"
if [ -d "$SCRIPT_DIR/cmdbot_findings" ] && [ ! -d "$DEFAULT_FINDINGS_DIR" ]; then
  DEFAULT_FINDINGS_DIR="$SCRIPT_DIR/cmdbot_findings"
fi
CMDBOT_FINDINGS_DIR="${PARANOID_FINDINGS_DIR:-${CMDBOT_FINDINGS_DIR:-$DEFAULT_FINDINGS_DIR}}"
CMDBOT_WORKDIR="${CMDBOT_WORKDIR:-$CMDBOT_FINDINGS_DIR/work}"
CMDBOT_BACKUPS_DIR="$CMDBOT_FINDINGS_DIR/backups"
INVESTIGATION_COMMANDS_FILE="${CMDBOT_INVESTIGATION_COMMANDS_FILE:-$SCRIPT_DIR/investigation_commands.txt}"
mkdir -p "$CMDBOT_WORKDIR" "$CMDBOT_FINDINGS_DIR" "$CMDBOT_BACKUPS_DIR"

# ── Scan Scope (directory confinement for custom scans) ──────────────────────
SCAN_SCOPE_DIR=""

# Check if a resolved path is within the scan scope directory.
# Returns 0 (allowed) if no scope is set or path is within scope.
check_path_in_scope() {
  local path="$1"
  [ -z "$SCAN_SCOPE_DIR" ] && return 0
  # Resolve to canonical path
  if [ -e "$path" ]; then
    path="$(cd "$(dirname "$path")" 2>/dev/null && pwd)/$(basename "$path")"
  fi
  case "$path" in
    "$SCAN_SCOPE_DIR"/*|"$SCAN_SCOPE_DIR") return 0 ;;
    "$CMDBOT_WORKDIR"/*|"$CMDBOT_WORKDIR") return 0 ;;
    "$CMDBOT_FINDINGS_DIR"/*|"$CMDBOT_FINDINGS_DIR") return 0 ;;
  esac
  return 1
}

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_TOOL_OUTPUT_BYTES=$((1024 * 450))
MAX_SCAN_STEPS="${PARANOID_MAX_SCAN_STEPS:-${CMDBOT_MAX_SCAN_STEPS:-140}}"
API_MAX_TOKENS="${CMDBOT_API_MAX_TOKENS:-1600}"
API_MAX_RETRIES=3
API_TRUNCATION="${CMDBOT_API_TRUNCATION:-auto}"
API_MAX_TOOL_CALLS="${CMDBOT_API_MAX_TOOL_CALLS:-2}"
COMPACT_TOOL_SCHEMAS="${CMDBOT_COMPACT_TOOL_SCHEMAS:-true}"
SYSTEM_PROMPT_STYLE="${CMDBOT_SYSTEM_PROMPT_STYLE:-compact}"
REFLECT_ON_CMD_OUTPUT="${CMDBOT_REFLECT_ON_CMD_OUTPUT:-false}"
REFLECTION_MODEL="${CMDBOT_REFLECTION_MODEL:-$API_MODEL}"
REFLECTION_MAX_BYTES="${CMDBOT_REFLECTION_MAX_BYTES:-160000}"
REFLECTION_MAX_TOKENS="${CMDBOT_REFLECTION_MAX_TOKENS:-400}"
REFLECTION_MAX_CALLS="${CMDBOT_REFLECTION_MAX_CALLS:-4}"
ENFORCE_SINGLE_TOOL_CALL="${CMDBOT_ENFORCE_SINGLE_TOOL_CALL:-false}"
PHASE1_TOKEN_GATE_ENABLED="${PARANOID_PHASE1_TOKEN_GATE_ENABLED:-true}"
PHASE1_AUDIT_TOKEN_BUDGET_TOTAL="${PARANOID_PHASE1_AUDIT_TOKEN_BUDGET_TOTAL:-10000}"
SOFT_TOKEN_LIMIT="${PARANOID_SOFT_TOKEN_LIMIT:-${CMDBOT_SOFT_TOKEN_LIMIT:-10000}}"
SOFT_TOKEN_LIMIT_MODE="${PARANOID_SOFT_TOKEN_LIMIT_MODE:-${CMDBOT_SOFT_TOKEN_LIMIT_MODE:-billable}}"
REQUEST_INPUT_TOKEN_LIMIT="${PARANOID_REQUEST_INPUT_TOKEN_LIMIT:-10000}"
TOKEN_WRAPUP_MAX_ROUNDS="${CMDBOT_TOKEN_WRAPUP_MAX_ROUNDS:-2}"
SOFT_LIMIT_INVESTIGATION_ENABLED="${CMDBOT_SOFT_LIMIT_INVESTIGATION_ENABLED:-false}"
SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS="${CMDBOT_SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS:-14}"
SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET="${CMDBOT_SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET:-90000}"
SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET="${CMDBOT_SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET:-true}"
SOFT_LIMIT_INVESTIGATION_TOP_SIGNALS="${CMDBOT_SOFT_LIMIT_INVESTIGATION_TOP_SIGNALS:-20}"
SOFT_LIMIT_INVESTIGATION_FILE_LIMIT="${CMDBOT_SOFT_LIMIT_INVESTIGATION_FILE_LIMIT:-12}"
SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS="${CMDBOT_SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS:-4}"
SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS="${CMDBOT_SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS:-1}"
SOFT_LIMIT_INVESTIGATION_BLOCK_EARLY_COMPLETE="${CMDBOT_SOFT_LIMIT_INVESTIGATION_BLOCK_EARLY_COMPLETE:-true}"
MODEL_TOOL_OUTPUT_MAX_BYTES="${CMDBOT_MODEL_TOOL_OUTPUT_MAX_BYTES:-2200}"
MODEL_TOOL_OUTPUT_KEY_LINES="${CMDBOT_MODEL_TOOL_OUTPUT_KEY_LINES:-10}"
MODEL_TOOL_OUTPUT_TAIL_LINES="${CMDBOT_MODEL_TOOL_OUTPUT_TAIL_LINES:-5}"
SHELL_EXEC_MAX_RETURN_LINES="${CMDBOT_SHELL_EXEC_MAX_RETURN_LINES:-60}"
SHELL_EXEC_MAX_RETURN_BYTES="${CMDBOT_SHELL_EXEC_MAX_RETURN_BYTES:-30000}"
SHELL_EXEC_PREVIEW_LINES="${CMDBOT_SHELL_EXEC_PREVIEW_LINES:-25}"
CHAIN_RESET_ENABLED="${CMDBOT_CHAIN_RESET_ENABLED:-false}"
CHAIN_RESET_INPUT_TOKENS="${CMDBOT_CHAIN_RESET_INPUT_TOKENS:-25000}"
COMPACT_ENABLED="${CMDBOT_COMPACT_ENABLED:-true}"
COMPACT_INTERVAL_STEPS="${CMDBOT_COMPACT_INTERVAL_STEPS:-8}"
COMPACT_MIN_INPUT_TOKENS="${CMDBOT_COMPACT_MIN_INPUT_TOKENS:-12000}"
CHAIN_RESET_MIN_STEP_GAP="${CMDBOT_CHAIN_RESET_MIN_STEP_GAP:-2}"
SCAN_MEMORY_MAX_LINES="${CMDBOT_SCAN_MEMORY_MAX_LINES:-260}"
SCAN_MEMORY_CONTEXT_LINES="${CMDBOT_SCAN_MEMORY_CONTEXT_LINES:-120}"
BROAD_CMD_REPEAT_LIMIT="${CMDBOT_BROAD_CMD_REPEAT_LIMIT:-1}"
CONTEXT_MANAGEMENT_JSON_RAW="${CMDBOT_CONTEXT_MANAGEMENT_JSON:-}"
CONTEXT_MANAGEMENT_JSON='[]'

# ── Paste & Analyze (iterative self-correcting analysis) ─────────────────────
EPHEMERAL_MODE="${PARANOID_EPHEMERAL_MODE:-false}"
PHASE2_ENABLED="${PARANOID_PHASE2_ENABLED:-false}"
PASTE_ANALYSIS_MAX_ITERATIONS="${CMDBOT_PASTE_ANALYSIS_MAX_ITERATIONS:-12}"
PASTE_ANALYSIS_STDOUT_TAIL_LINES="${CMDBOT_PASTE_ANALYSIS_STDOUT_TAIL_LINES:-20}"
PASTE_ANALYSIS_MAX_TOKENS="${CMDBOT_PASTE_ANALYSIS_MAX_TOKENS:-2000}"
CUSTOM_SCAN_FOCUS_MAX_CHARS=200

if ! [[ "$MAX_SCAN_STEPS" =~ ^[0-9]+$ ]]; then
  MAX_SCAN_STEPS=140
fi
if ! [[ "$API_MAX_TOKENS" =~ ^[0-9]+$ ]]; then
  API_MAX_TOKENS=1600
fi
case "$API_TRUNCATION" in
  auto|disabled) ;;
  *) API_TRUNCATION="auto" ;;
esac
if ! [[ "$API_MAX_TOOL_CALLS" =~ ^[0-9]+$ ]]; then
  API_MAX_TOOL_CALLS=2
fi
[ "$API_MAX_TOOL_CALLS" -lt 1 ] && API_MAX_TOOL_CALLS=1
[ "$API_MAX_TOOL_CALLS" -gt 4 ] && API_MAX_TOOL_CALLS=4
case "$COMPACT_TOOL_SCHEMAS" in
  true|false) ;;
  *) COMPACT_TOOL_SCHEMAS=true ;;
esac
case "$SYSTEM_PROMPT_STYLE" in
  compact|full) ;;
  *) SYSTEM_PROMPT_STYLE=compact ;;
esac
if ! [[ "$REFLECTION_MAX_BYTES" =~ ^[0-9]+$ ]]; then
  REFLECTION_MAX_BYTES=160000
fi
if ! [[ "$REFLECTION_MAX_TOKENS" =~ ^[0-9]+$ ]]; then
  REFLECTION_MAX_TOKENS=900
fi
if ! [[ "$REFLECTION_MAX_CALLS" =~ ^[0-9]+$ ]]; then
  REFLECTION_MAX_CALLS=8
fi
if ! [[ "$SOFT_TOKEN_LIMIT" =~ ^[0-9]+$ ]]; then
  SOFT_TOKEN_LIMIT=10000
fi
case "$SOFT_TOKEN_LIMIT_MODE" in
  billable|total) ;;
  *) SOFT_TOKEN_LIMIT_MODE=billable ;;
esac
if ! [[ "$TOKEN_WRAPUP_MAX_ROUNDS" =~ ^[0-9]+$ ]]; then
  TOKEN_WRAPUP_MAX_ROUNDS=2
fi
if ! [[ "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" =~ ^[0-9]+$ ]]; then
  PHASE1_AUDIT_TOKEN_BUDGET_TOTAL=10000
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS=14
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET=90000
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_TOP_SIGNALS" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_TOP_SIGNALS=20
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_FILE_LIMIT" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_FILE_LIMIT=12
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS=4
fi
if ! [[ "$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS" =~ ^[0-9]+$ ]]; then
  SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS=1
fi
if ! [[ "$MODEL_TOOL_OUTPUT_MAX_BYTES" =~ ^[0-9]+$ ]]; then
  MODEL_TOOL_OUTPUT_MAX_BYTES=2200
fi
if ! [[ "$MODEL_TOOL_OUTPUT_KEY_LINES" =~ ^[0-9]+$ ]]; then
  MODEL_TOOL_OUTPUT_KEY_LINES=10
fi
if ! [[ "$MODEL_TOOL_OUTPUT_TAIL_LINES" =~ ^[0-9]+$ ]]; then
  MODEL_TOOL_OUTPUT_TAIL_LINES=5
fi
if ! [[ "$SHELL_EXEC_MAX_RETURN_LINES" =~ ^[0-9]+$ ]]; then
  SHELL_EXEC_MAX_RETURN_LINES=150
fi
if ! [[ "$SHELL_EXEC_MAX_RETURN_BYTES" =~ ^[0-9]+$ ]]; then
  SHELL_EXEC_MAX_RETURN_BYTES=50000
fi
if ! [[ "$SHELL_EXEC_PREVIEW_LINES" =~ ^[0-9]+$ ]]; then
  SHELL_EXEC_PREVIEW_LINES=120
fi
if ! [[ "$PASTE_ANALYSIS_MAX_ITERATIONS" =~ ^[0-9]+$ ]]; then
  PASTE_ANALYSIS_MAX_ITERATIONS=12
fi
[ "$PASTE_ANALYSIS_MAX_ITERATIONS" -lt 3 ] && PASTE_ANALYSIS_MAX_ITERATIONS=3
[ "$PASTE_ANALYSIS_MAX_ITERATIONS" -gt 30 ] && PASTE_ANALYSIS_MAX_ITERATIONS=30
if ! [[ "$CHAIN_RESET_INPUT_TOKENS" =~ ^[0-9]+$ ]]; then
  CHAIN_RESET_INPUT_TOKENS=14000
fi
if ! [[ "$CHAIN_RESET_MIN_STEP_GAP" =~ ^[0-9]+$ ]]; then
  CHAIN_RESET_MIN_STEP_GAP=2
fi
if ! [[ "$SCAN_MEMORY_MAX_LINES" =~ ^[0-9]+$ ]]; then
  SCAN_MEMORY_MAX_LINES=260
fi
if ! [[ "$SCAN_MEMORY_CONTEXT_LINES" =~ ^[0-9]+$ ]]; then
  SCAN_MEMORY_CONTEXT_LINES=120
fi
if ! [[ "$BROAD_CMD_REPEAT_LIMIT" =~ ^[0-9]+$ ]]; then
  BROAD_CMD_REPEAT_LIMIT=1
fi
if ! [[ "$COMPACT_INTERVAL_STEPS" =~ ^[0-9]+$ ]]; then
  COMPACT_INTERVAL_STEPS=4
fi
if ! [[ "$COMPACT_MIN_INPUT_TOKENS" =~ ^[0-9]+$ ]]; then
  COMPACT_MIN_INPUT_TOKENS=12000
fi
case "$SOFT_LIMIT_INVESTIGATION_ENABLED" in
  true|false) ;;
  *) SOFT_LIMIT_INVESTIGATION_ENABLED=false ;;
esac
case "$SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET" in
  true|false) ;;
  *) SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET=true ;;
esac
case "$SOFT_LIMIT_INVESTIGATION_BLOCK_EARLY_COMPLETE" in
  true|false) ;;
  *) SOFT_LIMIT_INVESTIGATION_BLOCK_EARLY_COMPLETE=true ;;
esac
case "$CHAIN_RESET_ENABLED" in
  true|false) ;;
  *) CHAIN_RESET_ENABLED=false ;;
esac
case "$ENFORCE_SINGLE_TOOL_CALL" in
  true|false) ;;
  *) ENFORCE_SINGLE_TOOL_CALL=false ;;
esac
case "$EPHEMERAL_MODE" in
  true|false) ;;
  *) EPHEMERAL_MODE=false ;;
esac
case "$PHASE2_ENABLED" in
  true|false) ;;
  *) PHASE2_ENABLED=false ;;
esac
case "$PHASE1_TOKEN_GATE_ENABLED" in
  true|false) ;;
  *) PHASE1_TOKEN_GATE_ENABLED=true ;;
esac
if [ -n "$CONTEXT_MANAGEMENT_JSON_RAW" ] && echo "$CONTEXT_MANAGEMENT_JSON_RAW" | jq -e . >/dev/null 2>&1; then
  CONTEXT_MANAGEMENT_JSON="$CONTEXT_MANAGEMENT_JSON_RAW"
fi
# Note: automatic context_management via API is not used — our manual
# compact_conversation() handles compaction every COMPACT_INTERVAL_STEPS steps.

# ── Counters ─────────────────────────────────────────────────────────────────
total_cost=0
request_id=0
scan_step=0
total_input_tokens=0
total_cached_tokens=0
total_output_tokens=0
total_tokens_used=0
total_billable_tokens=0
token_wrapup_mode=false
token_wrapup_rounds=0
soft_limit_investigation_mode=false
soft_limit_investigation_rounds=0
soft_limit_investigation_tokens_start=0
soft_limit_investigation_tokens_used=0
soft_limit_investigation_billable_start=0
soft_limit_investigation_billable_used=0
soft_limit_investigation_budget_exhausted=false
soft_limit_focus_goal=""
soft_limit_investigation_findings_start=0
reflection_calls_used=0
last_request_input_tokens=0
last_request_cached_tokens=0
last_request_output_tokens=0
last_request_billable_tokens=0
last_request_cost=0
chain_reset_count=0
last_chain_reset_step=0
compact_count=0
last_compact_step=0
scan_memory=""
recent_broad_cmds=""

# ── Responses API State ─────────────────────────────────────────────────────
CURRENT_RESPONSE_ID=""
SYSTEM_INSTRUCTIONS=""
TOOLS_JSON=""              # Cached tools array (generated once per scan)
TOOLS_JSON_COMPACT=""      # Description-stripped variant for follow-up turns
INVESTIGATION_COMMAND_CATALOG_JSON=""
INVESTIGATION_COMMAND_COUNT=0
declare -a findings=()
findings_total=0
findings_file=""

#==============================================================================
# RUNTIME MODE
#==============================================================================
artifacts_persist_enabled() {
  [ "$EPHEMERAL_MODE" != "true" ]
}

phase2_runtime_enabled() {
  [ "$PHASE2_ENABLED" = "true" ] && artifacts_persist_enabled
}

runtime_mode_label() {
  if artifacts_persist_enabled; then
    echo "Standard"
  else
    echo "Infected Host / Ephemeral"
  fi
}

runtime_findings_label() {
  if artifacts_persist_enabled; then
    printf "%s" "$findings_file"
  else
    echo "ephemeral (not written to disk)"
  fi
}

prepare_findings_target() {
  local target_path="$1"
  if artifacts_persist_enabled; then
    findings_file="$target_path"
  else
    findings_file=""
  fi
}

#==============================================================================
# TERMINAL COLORS
#==============================================================================
GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"; RED="\033[31m"
MAGENTA="\033[35m"; BLUE="\033[34m"; BOLD="\033[1m"; DIM="\033[2m"
RESET="\033[0m"

#==============================================================================
# UI HELPERS
#==============================================================================
print_border() {
  local width="${1:-}"
  if [ -z "${width:-}" ]; then
    width="$(ui__content_cols 2>/dev/null || echo 60)"
  fi
  printf "${CYAN}%${width}s${RESET}\n" | tr " " "─"
}

ui__content_cols() {
  # Return a sane content width for box-ish UI elements.
  # Use current terminal cols when available, but avoid hard-wrapping on the last column.
  local rows cols w
  read -r rows cols < <(ui__term_size)
  w=$((cols - 2))
  [ "$w" -lt 40 ] && w=40
  echo "$w"
}

print_section() {
  local title="$1"
  local width; width="$(ui__content_cols)"
  echo ""; print_border "$width"
  printf "${BOLD}%*s%s%*s${RESET}\n" \
    $(( (width - ${#title}) / 2 )) "" "$title" \
    $(( (width - ${#title} + 1) / 2 )) ""
  print_border "$width"
}

print_tool_header() {
  local title="$1"
  local width; width="$(ui__content_cols)"
  local rule; rule="$(printf "%*s" "$width" "" | tr " " "─")"
  echo ""
  # Clip title to avoid wrapping in narrow terminals.
  title="$(printf "%.*s" "$((width - 4))" "$title")"
  echo -e "${BOLD}${BLUE}┌─ $title${RESET}"
  echo -e "${BOLD}${BLUE}└${rule}${RESET}"
}

print_tool_footer() {
  local width; width="$(ui__content_cols)"
  local left right msg=" End "
  local pad=$(( (width - ${#msg}) / 2 ))
  [ "$pad" -lt 1 ] && pad=1
  left="$(printf "%*s" "$pad" "" | tr " " "─")"
  right="$(printf "%*s" "$((width - pad - ${#msg}))" "" | tr " " "─")"
  echo -e "${BOLD}${BLUE}${left}${msg}${right}${RESET}"
  echo ""
}

set_terminal_title() {
  local title="$1"
  printf '\033]0;%s\007' "$title"
}

#==============================================================================
# FIXED BOTTOM STATUS LINE (TTY UI)
#
# Goal: keep a single "status/loading" line pinned to the bottom of the terminal
# while the content above scrolls normally.
#
# Implementation: reserve the last row by setting the terminal scroll region to
# 1..(rows-1) and render status on row=rows. This is best-effort and auto-disables
# when stdout isn't a TTY.
#==============================================================================
CMDBOT_UI_STATUS="${CMDBOT_UI_STATUS:-true}"
UI_STATUS_ACTIVE=false
UI_STATUS_TEXT=""
UI_SPINNER_PID=""
UI_TTY=""
UI_SCROLL_REGION_LAST_SET=0
UI_SCROLL_REGION_LAST_ROWS=0
UI_TTY_FD=3
UI_MUX_ACTIVE=false
UI_MUX_FIFO=""
UI_MUX_PID=""
UI_LOCK_DIR="/tmp/cmdbot_ui_lock.$$"
UI_STDOUT_SAVED=false

ui__strip_ansi_and_ctrl() {
  # Strip ANSI escape sequences and control characters from untrusted tool output
  # before printing into our UI (prevents wrapping/overwriting and random colors).
  # Keep it ASCII-ish; this is for display only (raw output is preserved in findings logs).
  local s="$1"
  # Remove OSC sequences.
  s="$(printf "%s" "$s" | sed -E $'s/\x1B\\][^\a]*\a//g')"
  # Remove CSI sequences.
  s="$(printf "%s" "$s" | sed -E $'s/\x1B\\[[0-9;?]*[ -/]*[@-~]//g')"
  # Drop remaining ESC.
  s="$(printf "%s" "$s" | tr -d '\033')"
  # Normalize CR and tabs.
  s="$(printf "%s" "$s" | tr '\r' ' ')"
  s="$(printf "%s" "$s" | sed -E $'s/\t/    /g')"
  # Drop other control chars except newline (caller handles per-line printing).
  s="$(printf "%s" "$s" | tr -d '\001\002\003\004\005\006\007\010\013\014\016\017\020\021\022\023\024\025\026\027\030\031\032\034\035\036\037')"
  printf "%s" "$s"
}

ui__clip_to_cols() {
  local s="$1" max_cols="$2"
  [ "$max_cols" -lt 1 ] && { printf ""; return 0; }
  printf "%.*s" "$max_cols" "$s"
}

ui__lock_acquire() {
  # Portable lock (no flock dependency). Best-effort for short critical sections.
  local spins=0
  while ! mkdir "$UI_LOCK_DIR" 2>/dev/null; do
    spins=$((spins + 1))
    [ "$spins" -gt 500 ] && break
    sleep 0.01
  done
}

ui__lock_release() {
  rmdir "$UI_LOCK_DIR" 2>/dev/null || true
}

ui__tty_write() {
  # Write to the real TTY, guarded by a simple lock.
  [ -n "${UI_TTY:-}" ] || return 0
  ui__lock_acquire
  printf "%s" "$*" >&$UI_TTY_FD 2>/dev/null || true
  ui__lock_release
}

ui__tty_is_usable() {
  # Only enable when interactive. Use /dev/tty so redirections/pipes don't break UI.
  [ -t 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ]
}

ui__term_size() {
  # Echo "rows cols" (fallback to 24x80).
  local rows="" cols="" stty_out=""
  # Prefer stty on the real TTY.
  if [ -n "${UI_TTY:-}" ] && [ -r "$UI_TTY" ]; then
    stty_out="$(stty size <"$UI_TTY" 2>/dev/null || true)"
  elif [ -r /dev/tty ]; then
    stty_out="$(stty size </dev/tty 2>/dev/null || true)"
  else
    stty_out="$(stty size 2>/dev/null || true)"
  fi
  rows="${stty_out% *}"
  cols="${stty_out#* }"
  if [ -z "${rows:-}" ] || [ -z "${cols:-}" ]; then
    if command -v tput >/dev/null 2>&1; then
      rows="$(tput lines 2>/dev/null || true)"
      cols="$(tput cols 2>/dev/null || true)"
    fi
  fi
  [[ "${rows:-}" =~ ^[0-9]+$ ]] || rows=24
  [[ "${cols:-}" =~ ^[0-9]+$ ]] || cols=80
  echo "$rows $cols"
}

ui__status_redraw() {
  [ "$UI_STATUS_ACTIVE" = true ] || return 0
  [ -n "${UI_TTY:-}" ] || return 0

  local rows cols rendered
  read -r rows cols < <(ui__term_size)

  rendered="$UI_STATUS_TEXT"
  # Keep it ASCII-safe and truncate by bytes (status text should be ASCII).
  rendered="$(printf "%.*s" "$((cols - 1))" "$rendered")"

  # Inline status: keep it as the current bottom line by continuously re-printing
  # after any normal output. No scroll-region/cursor-moving tricks.
  ui__tty_write $'\r\033[2K'
  ui__tty_write "$rendered"
}

ui__on_winch() {
  [ "$UI_STATUS_ACTIVE" = true ] || return 0
  [ -n "${UI_TTY:-}" ] || return 0

  # Nothing to do. Inline status line adapts on next redraw.
  return 0
}

ui_mux_enable() {
  # Route all stdout/stderr through a single renderer that clears/redraws the
  # status line, so normal content never "bleeds" into the status row.
  [ "$UI_STATUS_ACTIVE" = true ] || return 0
  [ "$UI_MUX_ACTIVE" = true ] && return 0
  ui__tty_is_usable || return 0

  UI_MUX_FIFO="/tmp/cmdbot_ui_fifo.$$"
  rm -f "$UI_MUX_FIFO" 2>/dev/null || true
  mkfifo "$UI_MUX_FIFO" 2>/dev/null || return 0

  (
    local line
    while IFS= read -r line; do
      # Sanitize, then print line above status, then redraw status.
      line="$(ui__strip_ansi_and_ctrl "$line")"
      ui__lock_acquire
      printf $'\r\033[2K%s\n' "$line" >&$UI_TTY_FD 2>/dev/null || true
      printf $'\r\033[2K%s' "$UI_STATUS_TEXT" >&$UI_TTY_FD 2>/dev/null || true
      ui__lock_release
    done < "$UI_MUX_FIFO"
  ) &
  UI_MUX_PID=$!
  UI_MUX_ACTIVE=true

  # Redirect all subsequent output through the mux FIFO.
  if [ "$UI_STDOUT_SAVED" != "true" ]; then
    exec 10>&1 11>&2
    UI_STDOUT_SAVED=true
  fi
  exec 1>"$UI_MUX_FIFO"
  exec 2>&1
}

ui_mux_disable() {
  [ "$UI_MUX_ACTIVE" = true ] || return 0
  UI_MUX_ACTIVE=false

  # Restore original stdout/stderr first so subsequent prints (including cleanup)
  # don't block on a FIFO that we're about to remove.
  if [ "$UI_STDOUT_SAVED" = "true" ]; then
    exec 1>&10 2>&11
    exec 10>&- 11>&-
    UI_STDOUT_SAVED=false
  fi

  if [ -n "${UI_MUX_PID:-}" ]; then
    # Reader should exit once FIFO is closed; still guard with a kill.
    kill "$UI_MUX_PID" 2>/dev/null || true
    wait "$UI_MUX_PID" 2>/dev/null || true
    UI_MUX_PID=""
  fi
  if [ -n "${UI_MUX_FIFO:-}" ]; then
    rm -f "$UI_MUX_FIFO" 2>/dev/null || true
    UI_MUX_FIFO=""
  fi
}

ui_status_enable() {
  [ "$CMDBOT_UI_STATUS" = "true" ] || return 0
  [ "$UI_STATUS_ACTIVE" = true ] && return 0
  ui__tty_is_usable || return 0

  UI_TTY="/dev/tty"
  # Open a dedicated FD to the real TTY for the renderer/spinner.
  # Use a fixed FD (bash 3.2 compatibility on macOS).
  UI_TTY_FD=3
  exec 3>"$UI_TTY" 2>/dev/null || true
  local rows cols
  read -r rows cols < <(ui__term_size)
  [ "$rows" -ge 3 ] 2>/dev/null || return 0

  UI_STATUS_ACTIVE=true
  trap 'ui__on_winch' WINCH

  # Hide cursor.
  printf "\033[?25l" >&$UI_TTY_FD 2>/dev/null || true

  UI_STATUS_TEXT=""
  ui__status_redraw
  ui_mux_enable
}

ui_spinner_stop() {
  if [ -n "${UI_SPINNER_PID:-}" ]; then
    kill "$UI_SPINNER_PID" 2>/dev/null || true
    wait "$UI_SPINNER_PID" 2>/dev/null || true
    UI_SPINNER_PID=""
  fi
}

ui_status_disable() {
  [ "$UI_STATUS_ACTIVE" = true ] || return 0

  ui_spinner_stop
  ui_mux_disable

  if [ -n "${UI_TTY:-}" ]; then
    # Clear line; show cursor.
    printf $'\r\033[2K\033[?25h' >&$UI_TTY_FD 2>/dev/null || true
  fi

  trap - WINCH
  UI_STATUS_ACTIVE=false
  UI_STATUS_TEXT=""
  UI_TTY=""
}

ui_status_set() {
  [ "$UI_STATUS_ACTIVE" = true ] || return 0
  # Keep bottom status line compact; avoid long dashboard-like strings.
  UI_STATUS_TEXT="$*"
  UI_STATUS_TEXT="$(printf "%s" "$UI_STATUS_TEXT" | sed -E 's/[[:space:]]+/ /g')"
  ui__status_redraw
}

ui_spinner_start() {
  [ "$UI_STATUS_ACTIVE" = true ] || return 0
  ui_spinner_stop

  # Keep the fixed status line short and intentional.
  local prefix="$*"
  prefix="$(printf "%s" "$prefix" | sed -E 's/^Step[[:space:]]+[0-9]+:[[:space:]]+calling model/Calling model/i')"
  (
    local frames='|/-\\' i=0 ch
    while true; do
      ch="${frames:i%4:1}"
      UI_STATUS_TEXT="${prefix} ${ch}"
      ui__status_redraw
      i=$((i + 1))
      sleep 0.1
    done
  ) &
  UI_SPINNER_PID=$!
}

print_retro_paranoid_banner() {
  # Retro, minimal-color banner that fits the current terminal width.
  local inner; inner="$(ui__content_cols)"
  local top mid1 mid2 bot
  top="╔$(printf "%*s" "$inner" "" | tr ' ' '═')╗"
  bot="╚$(printf "%*s" "$inner" "" | tr ' ' '═')╝"
  mid1="║$(printf "%*s" "$inner" "")║"
  mid2="║$(printf "%*s" "$inner" "")║"

  # Center text (avoid colors; allow bold/underline for a subtle "retro" effect).
  local t1="PARANOID"
  local t2="DISCOVERY SCANNER"
  local pad1=$(( (inner - ${#t1}) / 2 ))
  local pad2=$(( (inner - ${#t2}) / 2 ))
  [ "$pad1" -lt 0 ] && pad1=0
  [ "$pad2" -lt 0 ] && pad2=0
  local line1 line2
  line1="$(printf "%*s%s%*s" "$pad1" "" "$t1" "$((inner - pad1 - ${#t1}))" "")"
  line2="$(printf "%*s%s%*s" "$pad2" "" "$t2" "$((inner - pad2 - ${#t2}))" "")"

  echo -e "${BOLD}${top}${RESET}"
  echo -e "${BOLD}║${RESET}${DIM}$(printf "%*s" "$inner" "")${RESET}${BOLD}║${RESET}"
  echo -e "${BOLD}║${RESET}$(printf "%*s" "$pad1" "")${BOLD}\033[4m${t1}\033[0m${RESET}$(printf "%*s" "$((inner - pad1 - ${#t1}))" "")${BOLD}║${RESET}"
  echo -e "${BOLD}║${RESET}${DIM}${line2}${RESET}${BOLD}║${RESET}"
  echo -e "${BOLD}║${RESET}${DIM}$(printf "%*s" "$inner" "")${RESET}${BOLD}║${RESET}"
  echo -e "${BOLD}${bot}${RESET}"
}

log_to_findings() {
  [ -n "$findings_file" ] && printf '%s\n' "$@" >> "$findings_file" || true
}

#==============================================================================
# SUDO CREDENTIAL MANAGEMENT
#==============================================================================
SUDO_KEEPALIVE_PID=""

start_sudo_keepalive() {
  echo -e "${YELLOW}This scanner needs sudo access for deep system inspection.${RESET}"
  echo -e "${YELLOW}You will be prompted for your password ONCE.${RESET}"
  echo ""
  if ! sudo -v 2>/dev/null; then
    echo -e "${RED}ERROR: sudo authentication failed. Some scans will be limited.${RESET}"
    return 1
  fi
  ( while true; do sudo -n true 2>/dev/null; sleep 60; done ) &
  SUDO_KEEPALIVE_PID=$!
  echo -e "${GREEN}Sudo credentials cached. Background refresh active (PID $SUDO_KEEPALIVE_PID).${RESET}"
  return 0
}

stop_sudo_keepalive() {
  if [ -n "$SUDO_KEEPALIVE_PID" ]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    SUDO_KEEPALIVE_PID=""
  fi
  sudo -k 2>/dev/null || true
}

cleanup_and_exit() {
  local exit_code=$?
  ui_status_disable
  stop_sudo_keepalive
  if [ "$exit_code" -ne 0 ]; then
    echo -e "\n${RED}Scanner terminated (exit code $exit_code).${RESET}"
  else
    echo -e "\n${GREEN}Scanner finished cleanly.${RESET}"
  fi
}
trap 'cleanup_and_exit' EXIT
trap 'ui_status_disable; echo -e "\n${YELLOW}Interrupted by user.${RESET}"; exit 130' INT TERM

#==============================================================================
# TOKEN COST TRACKING
#==============================================================================
# Default rates for gpt-5-nano-2025-08-07 (per 1M tokens):
#   Input: $0.05 | Cached: $0.005 | Output: $0.40
#==============================================================================
calculate_token_cost() {
  local input_tokens="$1" cached_tokens="$2" output_tokens="$3"
  local input_rate="${CMDBOT_COST_INPUT:-0.05}"
  local cached_rate="${CMDBOT_COST_CACHED:-0.005}"
  local output_rate="${CMDBOT_COST_OUTPUT:-0.40}"
  bc -l <<< "($input_tokens - $cached_tokens) * $input_rate / 1000000 + $cached_tokens * $cached_rate / 1000000 + $output_tokens * $output_rate / 1000000"
}

print_cost_info() {
  local input_tokens="$1" cached_tokens="$2" output_tokens="$3"
  local request_cost="$4" running_total="$5"
  local inner; inner="$(ui__content_cols 2>/dev/null || echo 60)"
  local top_rule mid_rule
  # Top has "┌─ Tokens " then fill then "┐"
  local top_fill=$((inner - 9))
  [ "$top_fill" -lt 0 ] && top_fill=0
  top_rule="$(printf "%*s" "$top_fill" "" | tr ' ' '─')"
  mid_rule="$(printf "%*s" "$inner" "" | tr ' ' '─')"

  # Build two compact lines, then clip to width.
  local line1 line2
  line1=$(printf "In:%d Cached:%d Out:%d +$%.6f" "$input_tokens" "$cached_tokens" "$output_tokens" "$request_cost")
  line2=$(printf "Running total: $%.6f" "$running_total")

  line1="$(ui__clip_to_cols "$(ui__strip_ansi_and_ctrl "$line1")" "$inner")"
  line2="$(ui__clip_to_cols "$(ui__strip_ansi_and_ctrl "$line2")" "$inner")"

  printf "${DIM}${YELLOW}┌─ Tokens %s┐${RESET}\n" "$top_rule"
  printf "${DIM}${YELLOW}│ %-*s │${RESET}\n" "$inner" "$line1"
  printf "${DIM}${YELLOW}│ %-*s │${RESET}\n" "$inner" "$line2"
  printf "${DIM}${YELLOW}└%s┘${RESET}\n" "$mid_rule"
}

record_token_usage() {
  local response_json="$1"
  local show_summary="${2:-false}"
  local source="${3:-main}"

  local input_tokens cached_tokens output_tokens billable_input billable_tokens
  input_tokens=$(echo "$response_json" | jq '.usage.input_tokens // 0' 2>/dev/null || echo "0")
  cached_tokens=$(echo "$response_json" | jq '.usage.input_tokens_details.cached_tokens // 0' 2>/dev/null || echo "0")
  output_tokens=$(echo "$response_json" | jq '.usage.output_tokens // 0' 2>/dev/null || echo "0")

  input_tokens="${input_tokens:-0}"
  cached_tokens="${cached_tokens:-0}"
  output_tokens="${output_tokens:-0}"
  [ "$input_tokens" = "null" ] && input_tokens=0
  [ "$cached_tokens" = "null" ] && cached_tokens=0
  [ "$output_tokens" = "null" ] && output_tokens=0

  last_request_input_tokens="$input_tokens"
  last_request_cached_tokens="$cached_tokens"
  last_request_output_tokens="$output_tokens"

  total_input_tokens=$((total_input_tokens + input_tokens))
  total_cached_tokens=$((total_cached_tokens + cached_tokens))
  total_output_tokens=$((total_output_tokens + output_tokens))
  total_tokens_used=$((total_tokens_used + input_tokens + output_tokens))
  billable_input=$((input_tokens - cached_tokens))
  [ "$billable_input" -lt 0 ] && billable_input=0
  billable_tokens=$((billable_input + output_tokens))
  total_billable_tokens=$((total_billable_tokens + billable_tokens))
  last_request_billable_tokens="$billable_tokens"

  if [ "$input_tokens" -gt 0 ] || [ "$output_tokens" -gt 0 ]; then
    local request_cost
    request_cost=$(calculate_token_cost "$input_tokens" "$cached_tokens" "$output_tokens")
    last_request_cost="$request_cost"
    total_cost=$(bc -l <<< "$total_cost + $request_cost")
    if [ "$show_summary" = "true" ]; then
      print_cost_info "$input_tokens" "$cached_tokens" "$output_tokens" "$request_cost" "$total_cost"
    elif [ "$source" = "reflection" ]; then
      echo -e "${DIM}${YELLOW}[Reflection tokens] In:$input_tokens Out:$output_tokens | +\$$(printf '%.6f' "$request_cost")${RESET}"
    fi
  fi

  request_id=$((request_id + 1))
}

soft_limit_meter_value() {
  if [ "$SOFT_TOKEN_LIMIT_MODE" = "billable" ]; then
    echo "$total_billable_tokens"
  else
    echo "$total_tokens_used"
  fi
}

soft_limit_meter_snapshot() {
  local meter
  meter="$(soft_limit_meter_value)"
  if [ "$SOFT_TOKEN_LIMIT_MODE" = "billable" ]; then
    printf "%s/%s billable_tokens (total=%s cached_in=%s)" \
      "$meter" "$SOFT_TOKEN_LIMIT" "$total_tokens_used" "$total_cached_tokens"
  else
    printf "%s/%s total_tokens (billable=%s)" \
      "$meter" "$SOFT_TOKEN_LIMIT" "$total_billable_tokens"
  fi
}

token_soft_limit_reached() {
  local meter
  [ "$SOFT_TOKEN_LIMIT" -le 0 ] && return 1
  meter="$(soft_limit_meter_value)"
  [ "$meter" -ge "$SOFT_TOKEN_LIMIT" ]
}

soft_limit_investigation_active() {
  [ "$soft_limit_investigation_mode" = "true" ] \
    && [ "$soft_limit_investigation_budget_exhausted" = "false" ]
}

wrapup_tool_restrictions_active() {
  [ "$token_wrapup_mode" = "true" ] || return 1
  if soft_limit_investigation_active; then
    return 1
  fi
  return 0
}

build_soft_limit_signal_digest() {
  local signal_pattern extracted max_signals
  max_signals="${SOFT_LIMIT_INVESTIGATION_TOP_SIGNALS:-20}"
  signal_pattern='(ANOMALY|SUSPECT|WARNING|CRITICAL|FINDING|TOOL_GUARD|TOOL_ERROR|RiskFlag|MatchCount|LISTEN|ESTABLISHED|SYN_SENT|unsigned|ad[- ]hoc|DYLD_|proxy|tunnel|utun|launchd|launchagent|launchdaemon|non-apple|unexpected|denied|failed|error|malware)'
  extracted=""

  if [ -n "$findings_file" ] && [ -f "$findings_file" ]; then
    extracted="$(grep -niE "$signal_pattern" "$findings_file" 2>/dev/null \
      | tail -n 1200 \
      | awk 'length($0) <= 260 && !seen[$0]++' \
      | head -n "$max_signals" || true)"
  fi

  if [ -z "$extracted" ]; then
    extracted="$(printf "%s\n" "$scan_memory" \
      | grep -niE "$signal_pattern" 2>/dev/null \
      | tail -n "$max_signals" || true)"
  fi

  [ -z "$extracted" ] && extracted="(no high-signal lines extracted yet; inspect recent evidence files directly)"
  printf "%s" "$extracted"
}

build_soft_limit_recent_artifacts() {
  local limit="${SOFT_LIMIT_INVESTIGATION_FILE_LIMIT:-12}"
  local artifacts

  artifacts="$(find "$CMDBOT_WORKDIR" -maxdepth 4 -type f -print 2>/dev/null \
    | while IFS= read -r path; do
        [ -f "$path" ] || continue
        mtime=$(stat -f "%m" "$path" 2>/dev/null || echo "0")
        bytes=$(wc -c < "$path" 2>/dev/null | tr -d ' ' || echo "0")
        printf "%s\t%s\t%s\n" "$mtime" "$bytes" "$path"
      done \
    | sort -rn \
    | head -n "$limit" \
    | awk -F'\t' '{printf "- %s (%s bytes)\n", $3, $2}')"

  [ -z "$artifacts" ] && artifacts="(no workdir evidence files found)"
  printf "%s" "$artifacts"
}

infer_soft_limit_goal() {
  local signals="$1"
  local lowered
  lowered="$(printf "%s" "$signals" | tr '[:upper:]' '[:lower:]')"

  if echo "$lowered" | grep -Eq '(launchagent|launchdaemon|launchd|runatload|keepalive|cron|login item|persistence)'; then
    echo "Validate whether persistence artifacts are unauthorized and connected to active processes."
    return 0
  fi
  if echo "$lowered" | grep -Eq '(listen|established|syn_sent|proxy|resolver|dns|utun|tunnel|port )'; then
    echo "Attribute suspicious network behavior to owning processes and verify if it indicates command-and-control."
    return 0
  fi
  if echo "$lowered" | grep -Eq '(unsigned|ad-hoc|codesign|teamidentifier|entitlement|binary)'; then
    echo "Verify binary provenance/signature and test whether execution paths suggest tampering."
    return 0
  fi
  if echo "$lowered" | grep -Eq '(tcc|accessibility|screencapture|full disk|profile|mdm|keychain)'; then
    echo "Investigate privacy/authorization grants for abuse paths and persistence linkage."
    return 0
  fi
  echo "Identify the highest-risk unexplained deviation and disprove benign explanations with targeted evidence."
}

build_soft_limit_investigation_prompt() {
  local stage="$1"
  local latest_step_summary="${2:-}"
  local signal_digest artifact_digest findings_snapshot stage_note goal
  local round_budget token_budget soft_limit_status

  signal_digest="$(build_soft_limit_signal_digest)"
  artifact_digest="$(build_soft_limit_recent_artifacts)"
  findings_snapshot="$(printf '%s\n' "${findings[@]-}" | tail -n 12)"
  [ -z "$findings_snapshot" ] && findings_snapshot="(none yet)"
  soft_limit_status="$(soft_limit_meter_snapshot)"

  goal="$(infer_soft_limit_goal "$signal_digest")"
  soft_limit_focus_goal="$goal"

  round_budget="$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS"
  [ "$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS" -le 0 ] && round_budget="disabled"
  token_budget="$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET"
  [ "$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET" -le 0 ] && token_budget="disabled"

  case "$stage" in
    entry)
      stage_note="Discovery soft limit was reached. Do not stop; pivot from broad discovery into targeted anomaly investigations."
      ;;
    post_finding)
      stage_note="One mini-investigation appears complete (a finding was recorded). Reset focus and choose the next unresolved lead."
      ;;
    budget_exhausted)
      stage_note="Investigation follow-up budget is exhausted. Finalize responsibly: no new collection tools unless essential to close one unresolved high-risk lead."
      ;;
    *)
      stage_note="Continue targeted mini-investigations over existing evidence and unresolved anomalies."
      ;;
  esac

  cat << EOF
SOFT_LIMIT_INVESTIGATION_MODE: $stage
$stage_note

Budget status:
- Base soft token limit status: $soft_limit_status
- Investigation rounds used: $soft_limit_investigation_rounds/$round_budget
- Investigation token budget used (post-limit, billable): $soft_limit_investigation_billable_used/$token_budget
- Investigation total token drift (including cached): $soft_limit_investigation_tokens_used

Current priority goal:
$goal

High-signal clues extracted from logs/evidence:
$signal_digest

Recent findings snapshot:
$findings_snapshot

Recent evidence artifacts under $CMDBOT_WORKDIR:
$artifact_digest

Latest step summary:
${latest_step_summary:-"(none yet)"}

Mandatory method — ROOT CAUSE TRACING:
1) Pick exactly one unresolved lead. State the specific symptom (port, process, file, plist, etc.).
2) Trace it to its ORIGIN: what file on disk causes this? What service/plist/launchd job starts it?
   - For a process: find its executable path, then its launch source (LaunchAgent/Daemon plist, login item, XPC service).
   - For a network listener: find the owning PID, then its binary path, then its persistence mechanism.
   - For a suspicious file: find what references it (plists, profiles, cron entries, shell configs).
3) Record the ROOT CAUSE with scan_finding:
   - origin_file: the exact file path that causes the behavior (e.g. the plist, the binary, the config line)
   - origin_type: one of [launchd_plist, login_item, xpc_service, cron_entry, shell_config, kernel_ext, profile, binary, config_file]
   - fix_action: what specific change would stop this (e.g. "remove plist", "unload service", "delete cron entry", "remove line from .zshrc")
4) Move to next lead. Do NOT re-collect broad snapshots — use file_grep/file_read on existing artifacts.
5) Call scan_complete only when no meaningful unresolved leads remain.

Completion guardrails for this mode:
- Minimum investigation rounds before scan_complete: $SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS
- Minimum scan_finding calls after soft-limit entry: $SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS
- Do not call scan_complete early unless investigation budget is exhausted.

CRITICAL: Do not gather more evidence about a problem you already understand.
Trace to the origin file/service, record the fix action, move on.
EOF
}

append_message_to_input_json() {
  local input_json="$1"
  local message="$2"
  jq -c \
    --argjson base "$input_json" \
    --arg msg "$message" \
    '$base + [{role: "user", content: $msg}]' 2>/dev/null || echo "$input_json"
}

soft_limit_investigation_new_findings_count() {
  local delta
  delta=$((findings_total - soft_limit_investigation_findings_start))
  [ "$delta" -lt 0 ] && delta=0
  echo "$delta"
}

should_block_soft_limit_scan_complete() {
  local new_findings
  [ "$SOFT_LIMIT_INVESTIGATION_BLOCK_EARLY_COMPLETE" = "true" ] || return 1
  soft_limit_investigation_active || return 1

  new_findings="$(soft_limit_investigation_new_findings_count)"
  if [ "$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS" -gt 0 ] \
    && [ "$soft_limit_investigation_rounds" -lt "$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS" ]; then
    return 0
  fi
  if [ "$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS" -gt 0 ] \
    && [ "$new_findings" -lt "$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS" ]; then
    return 0
  fi
  return 1
}

mark_soft_limit_investigation_budget_exhausted() {
  local reason="$1"
  [ "$soft_limit_investigation_budget_exhausted" = "true" ] && return 0

  soft_limit_investigation_budget_exhausted=true
  token_wrapup_rounds=0
  echo -e "${YELLOW}Soft-limit investigation budget exhausted ($reason). Switching to final wrap-up mode.${RESET}"
  log_to_findings "SOFT_LIMIT_INVESTIGATION_BUDGET_EXHAUSTED: $reason"
}

update_soft_limit_investigation_budget() {
  [ "$soft_limit_investigation_mode" = "true" ] || return 0

  soft_limit_investigation_tokens_used=$((total_tokens_used - soft_limit_investigation_tokens_start))
  [ "$soft_limit_investigation_tokens_used" -lt 0 ] && soft_limit_investigation_tokens_used=0
  soft_limit_investigation_billable_used=$((total_billable_tokens - soft_limit_investigation_billable_start))
  [ "$soft_limit_investigation_billable_used" -lt 0 ] && soft_limit_investigation_billable_used=0

  if [ "$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS" -gt 0 ] \
    && [ "$soft_limit_investigation_rounds" -ge "$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS" ]; then
    mark_soft_limit_investigation_budget_exhausted "rounds=$soft_limit_investigation_rounds/$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS"
    return 0
  fi

  if [ "$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET" -gt 0 ] \
    && [ "$soft_limit_investigation_billable_used" -ge "$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET" ]; then
    mark_soft_limit_investigation_budget_exhausted "billable_tokens=$soft_limit_investigation_billable_used/$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET"
  fi
}

#==============================================================================
# TOOL DEFINITIONS (Native Tool Calling)
#==============================================================================
# These are sent to the API as the 'tools' parameter. The model can ONLY
# call tools defined here — no freestyle JSON, no raw text parsing needed.
#
# Naming: API function names use underscores (dots not allowed in fn names).
# Internal dispatch converts first underscore → dot for legacy compatibility:
#   file_read → file.read, cmd_exec_to_file → cmd.exec_to_file, etc.
#==============================================================================

# Helper: generate a single tool definition JSON object
_tool() {
  local name="$1" desc="$2" params="$3"
  printf '{"type":"function","name":"%s","description":"%s","parameters":%s}' \
    "$name" "$desc" "$params"
}

# Helper: common parameter patterns
_no_params='{"type":"object","properties":{}}'

generate_tools_json() {
  # Build the tools array using jq for correctness
  local tools_file
  tools_file=$(mktemp /tmp/cmdbot_tools.XXXXXX)

  cat > "$tools_file" << 'TOOLS_EOF'
[
  {
    "type": "function",
    "name": "shell_exec",
    "description": "Execute a shell command and return output directly. Use ONLY for small commands (<50 lines output) like 'csrutil status' or 'whoami'. For anything that could produce large output, use cmd_exec_to_file instead. In ephemeral mode, output stays in memory and is not written to disk.",
    "parameters": {
      "type": "object",
      "properties": {
        "cmd": {"type": "string", "description": "Shell command to execute. Mutating commands are blocked. Use sudo when needed."},
        "timeout": {"type": "integer", "description": "Timeout in seconds (default 30)"}
      },
      "required": ["cmd"]
    }
  },
  {
    "type": "function",
    "name": "cmd_exec_to_file",
    "description": "Execute a command, save FULL output to a file, return a bounded preview. THIS IS YOUR PRIMARY TOOL for evidence collection. Use for any command that could produce >50 lines (ps aux, lsof, netstat, log show, find, etc). In ephemeral mode, it returns an inline summary and does NOT write to disk.",
    "parameters": {
      "type": "object",
      "properties": {
        "cmd": {"type": "string", "description": "Shell command to execute. Use sudo when needed."},
        "out_path": {"type": "string", "description": "Path to save output. Use $CMDBOT_WORKDIR/ prefix."},
        "timeout": {"type": "integer", "description": "Timeout in seconds (default 30)"},
        "preview_lines": {"type": "integer", "description": "Tail lines to include (default 25)"}
      },
      "required": ["cmd", "out_path"]
    }
  },
  {
    "type": "function",
    "name": "cmd_exec_to_file_bundle",
    "description": "Execute MULTIPLE read-only commands in one tool call, save full combined output to one file with per-command section markers, and return a bounded preview. Use this to reduce API turns and token cost when gathering related snapshots. In ephemeral mode, it returns an inline summary and does NOT write to disk.",
    "parameters": {
      "type": "object",
      "properties": {
        "commands": {
          "type": "array",
          "description": "Array of shell commands to run sequentially. Mutating commands are blocked.",
          "items": {"type": "string"}
        },
        "out_path": {"type": "string", "description": "Path to save combined output. Use $CMDBOT_WORKDIR/ prefix."},
        "timeout": {"type": "integer", "description": "Per-command timeout in seconds (default 30)"},
        "preview_lines": {"type": "integer", "description": "Tail lines to include (default 25)"}
      },
      "required": ["commands", "out_path"]
    }
  },
  {
    "type": "function",
    "name": "investigation_command_catalog",
    "description": "List predefined investigation commands indexed by command_id. Use this to pick safe inspect commands quickly.",
    "parameters": {
      "type": "object",
      "properties": {
        "part": {"type": "string", "description": "Section filter. Use 'all' (default) or a part key from catalog output (example: part_i_platform_trust_foundations)."},
        "mode": {"type": "string", "enum": ["inspect", "mutating", "template", "all"], "description": "Filter by command safety mode (default inspect)."},
        "max": {"type": "integer", "description": "Maximum commands to return (default 30, max 120). Keep small for token efficiency."}
      }
    }
  },
  {
    "type": "function",
    "name": "investigation_command_run",
    "description": "Run one predefined investigation command by command_id, save full output to disk, and return high-signal preview. Primary autonomous command runner for command_id workflows. In ephemeral mode, it returns an inline summary and does NOT write to disk.",
    "parameters": {
      "type": "object",
      "properties": {
        "command_id": {"type": "string", "description": "Command ID from investigation_command_catalog (e.g. CMD001 or numeric like 1)."},
        "out_path": {"type": "string", "description": "Optional output path. Default is generated under $CMDBOT_WORKDIR."},
        "timeout": {"type": "integer", "description": "Timeout in seconds (default 30)."},
        "preview_lines": {"type": "integer", "description": "Tail lines to include (default 20, max 60)."}
      },
      "required": ["command_id"]
    }
  },
  {
    "type": "function",
    "name": "file_read",
    "description": "Read contents of a file (up to max_bytes).",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path. Supports $HOME, $CMDBOT_WORKDIR, $USER."},
        "max_bytes": {"type": "integer", "description": "Maximum bytes to read (default 200000)"}
      },
      "required": ["path"]
    }
  },
  {
    "type": "function",
    "name": "file_tail",
    "description": "Read last N lines of a file.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path"},
        "lines": {"type": "integer", "description": "Number of lines (default 40)"}
      },
      "required": ["path"]
    }
  },
  {
    "type": "function",
    "name": "file_grep",
    "description": "Search a file for a regex pattern. Returns matching lines with line numbers.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path"},
        "pattern": {"type": "string", "description": "Extended regex pattern"},
        "max_matches": {"type": "integer", "description": "Max matching lines (default 120)"},
        "ignore_case": {"type": "string", "enum": ["true", "false"], "description": "Case insensitive (default true)"}
      },
      "required": ["path", "pattern"]
    }
  },
  {
    "type": "function",
    "name": "file_find",
    "description": "Search a file for a literal string (fixed-string grep).",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path"},
        "needle": {"type": "string", "description": "Literal string to search for"},
        "max_matches": {"type": "integer", "description": "Max matches (default 120)"},
        "ignore_case": {"type": "string", "enum": ["true", "false"], "description": "Case insensitive (default false)"}
      },
      "required": ["path", "needle"]
    }
  },
  {
    "type": "function",
    "name": "file_stat",
    "description": "Get full file metadata: mode, flags (uchg/schg/hidden), timestamps, owner, size, inode, extended attributes (xattr), and file type. Critical for 'who touched this file' and 'why is this immutable' investigations.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File or directory path"}
      },
      "required": ["path"]
    }
  },
  {
    "type": "function",
    "name": "file_signal_extract",
    "description": "High-signal extraction from a large evidence file. Returns compact baseline-deviation clues (regex hits) plus metadata and optional head/tail slices so the model can decide next commands with fewer follow-up reads.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "Evidence file path to analyze"},
        "profile": {"type": "string", "enum": ["network", "process", "persistence", "security", "generic"], "description": "Signal profile to tune extraction (default generic)"},
        "max_matches": {"type": "integer", "description": "Max matched lines to return (default 80)"},
        "include_head_tail": {"type": "string", "enum": ["true", "false"], "description": "Include head/tail slices for context (default true)"}
      },
      "required": ["path"]
    }
  },
  {
    "type": "function",
    "name": "launchd_plist_triage",
    "description": "Summarize a LaunchAgent/LaunchDaemon plist into key fields and risk flags (label, executable, run policy, suspicious indicators). Use this instead of raw file_read for launchd triage to reduce tokens.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "Path to LaunchAgent/LaunchDaemon plist"},
        "include_signature": {"type": "string", "enum": ["true", "false"], "description": "If true, include compact signature assessment for executable (default false)"}
      },
      "required": ["path"]
    }
  },
  {
    "type": "function",
    "name": "dir_list",
    "description": "List directory contents (ls -1A).",
    "parameters": {
      "type": "object",
      "properties": {
        "dir": {"type": "string", "description": "Directory path"},
        "max": {"type": "integer", "description": "Max entries (default 200)"}
      },
      "required": ["dir"]
    }
  },
  {
    "type": "function",
    "name": "dir_tree",
    "description": "Show directory tree structure (3 levels deep).",
    "parameters": {
      "type": "object",
      "properties": {
        "dir": {"type": "string", "description": "Directory path"},
        "ignore": {"type": "string", "description": "Pattern to ignore (default node_modules)"},
        "max_lines": {"type": "integer", "description": "Max output lines (default 400)"}
      },
      "required": ["dir"]
    }
  },
  {
    "type": "function",
    "name": "dir_grep",
    "description": "Recursively grep a directory for a regex pattern.",
    "parameters": {
      "type": "object",
      "properties": {
        "dir": {"type": "string", "description": "Directory path"},
        "pattern": {"type": "string", "description": "Extended regex pattern"},
        "includes": {"type": "string", "description": "Filename glob (default *)"},
        "excludes": {"type": "string", "description": "Exclude pattern (default node_modules|.git|.DS_Store)"},
        "max_matches": {"type": "integer", "description": "Max matches (default 200)"},
        "ignore_case": {"type": "string", "enum": ["true", "false"], "description": "Case insensitive (default true)"}
      },
      "required": ["dir", "pattern"]
    }
  },
  {
    "type": "function",
    "name": "dir_find",
    "description": "Controlled find wrapper. Supports name filter, type, mtime, maxdepth, and optional inline preview. Use instead of dir_list when hunting. BLOCKED on root /.",
    "parameters": {
      "type": "object",
      "properties": {
        "dir": {"type": "string", "description": "Directory to search"},
        "name": {"type": "string", "description": "Name glob pattern (default *)"},
        "type": {"type": "string", "enum": ["f", "d", "l"], "description": "File type: f=file, d=dir, l=symlink (default f)"},
        "max_depth": {"type": "integer", "description": "Max directory depth (default 3)"},
        "mtime_days": {"type": "string", "description": "Modified within N days (e.g. '14')"},
        "max_results": {"type": "integer", "description": "Max results (default 200)"},
        "preview": {"type": "string", "enum": ["true", "false"], "description": "Show first 5 lines of each match (default false)"}
      },
      "required": ["dir"]
    }
  },
  {
    "type": "function",
    "name": "apple_man",
    "description": "Fetch man page for a macOS command. Lets you verify expected behavior of system tools.",
    "parameters": {
      "type": "object",
      "properties": {
        "command": {"type": "string", "description": "Command name (e.g. launchd, codesign)"},
        "max_lines": {"type": "integer", "description": "Max lines (default 200)"}
      },
      "required": ["command"]
    }
  },
  {
    "type": "function",
    "name": "apple_codesign_verify",
    "description": "Verify code signature of a binary or .app bundle. Shows signing authority, team ID, and spctl assessment. CRITICAL for paranoid scanning — unsigned or ad-hoc signed binaries in system paths are extremely suspicious.",
    "parameters": {
      "type": "object",
      "properties": {
        "target": {"type": "string", "description": "Path to binary or .app bundle"}
      },
      "required": ["target"]
    }
  },
  {
    "type": "function",
    "name": "apple_entitlements",
    "description": "Extract entitlements from a binary — shows what capabilities it claims.",
    "parameters": {
      "type": "object",
      "properties": {
        "target": {"type": "string", "description": "Path to binary"}
      },
      "required": ["target"]
    }
  },
  {
    "type": "function",
    "name": "pluginkit_list_active",
    "description": "List all active (+) PluginKit plugins.",
    "parameters": {"type": "object", "properties": {}}
  },
  {
    "type": "function",
    "name": "scan_finding",
    "description": "Report a security finding traced to its root cause. MUST include the origin file/service that causes the issue and the specific action to fix it.",
    "parameters": {
      "type": "object",
      "properties": {
        "severity": {"type": "string", "enum": ["CRITICAL", "WARNING", "INFO"], "description": "Finding severity"},
        "message": {"type": "string", "description": "Detailed finding description with evidence"},
        "origin_file": {"type": "string", "description": "Exact path of the root cause file (plist, binary, config, profile, etc.)"},
        "origin_type": {"type": "string", "enum": ["launchd_plist", "login_item", "xpc_service", "cron_entry", "shell_config", "kernel_ext", "profile", "binary", "config_file", "tcc_grant", "network_config", "unknown"], "description": "Type of the root cause"},
        "fix_action": {"type": "string", "description": "Specific remediation action (e.g. 'launchctl unload ~/Library/LaunchAgents/X.plist && rm ~/Library/LaunchAgents/X.plist')"}
      },
      "required": ["severity", "message"]
    }
  },
  {
    "type": "function",
    "name": "scan_complete",
    "description": "Signal that the scan is finished. Call this after you have completed all required investigation phases.",
    "parameters": {"type": "object", "properties": {}}
  },
  {
    "type": "function",
    "name": "file_write",
    "description": "Write content to a file. MUTATING — requires ack:'I_UNDERSTAND'. You MUST have reported evidence, impact, and rollback plan via scan_finding BEFORE using ack.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path to write"},
        "content": {"type": "string", "description": "Content to write"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"], "description": "Acknowledgment required"}
      },
      "required": ["path", "content", "ack"]
    }
  },
  {
    "type": "function",
    "name": "file_replace",
    "description": "Replace entire file content. Creates backup first. MUTATING — requires ack:'I_UNDERSTAND'.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "description": "File path to replace"},
        "content": {"type": "string", "description": "New content"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"], "description": "Acknowledgment required"}
      },
      "required": ["path", "content", "ack"]
    }
  },
  {
    "type": "function",
    "name": "plist_to_xml",
    "description": "Convert a plist to XML format (new file). MUTATING.",
    "parameters": {
      "type": "object",
      "properties": {
        "in_path": {"type": "string"}, "out_path": {"type": "string"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"]}
      },
      "required": ["in_path", "out_path", "ack"]
    }
  },
  {
    "type": "function",
    "name": "plist_to_binary",
    "description": "Convert a plist to binary format (new file). MUTATING.",
    "parameters": {
      "type": "object",
      "properties": {
        "in_path": {"type": "string"}, "out_path": {"type": "string"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"]}
      },
      "required": ["in_path", "out_path", "ack"]
    }
  },
  {
    "type": "function",
    "name": "plist_inplace_to_xml",
    "description": "Convert plist to XML in-place (backup created). MUTATING.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"]}
      },
      "required": ["path", "ack"]
    }
  },
  {
    "type": "function",
    "name": "plist_inplace_to_binary",
    "description": "Convert plist to binary in-place (backup created). MUTATING.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {"type": "string"},
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"]}
      },
      "required": ["path", "ack"]
    }
  },
  {
    "type": "function",
    "name": "pluginkit_disable_all_active",
    "description": "Disable all active PluginKit plugins. MUTATING.",
    "parameters": {
      "type": "object",
      "properties": {
        "ack": {"type": "string", "enum": ["I_UNDERSTAND"]}
      },
      "required": ["ack"]
    }
  }
]
TOOLS_EOF

  cat "$tools_file"
  rm -f "$tools_file"
}

# ── macOS Module Tool Definitions ────────────────────────────────────────────
# These are added to the tools array when paranoid_macos_tools.sh is loaded.
# Each is a deterministic, read-only probe (except codesign which takes a path).

generate_macos_tools_json() {
  cat << 'MACOS_TOOLS_EOF'
[
  {"type":"function","name":"net_dns_state","description":"Full DNS config: scutil --dns, /etc/hosts, resolv.conf","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"net_dns_networksetup","description":"Per-interface DNS servers via networksetup","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"net_proxy_state","description":"System proxy, web proxy, SOCKS, auto-proxy settings","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"net_sockets_ownership","description":"All LISTEN + ESTABLISHED + UDP sockets with owning process (sudo lsof)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"net_interfaces","description":"All interfaces (ifconfig -a), routing table, ARP cache","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"mdns_state","description":"mDNSResponder process, port 5353 listeners, launchd mDNS entries","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"mdns_browse_sample","description":"8-second sample of advertised mDNS/Bonjour services","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"mdns_registered","description":"Browse HTTP, SMB, SSH, VNC, IPP mDNS services (8s sample)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_overview","description":"All sharing preferences, computer name, sharing-related LaunchDaemons","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_files_smb_afp","description":"SMB/AFP config, processes, shared folders, listening on ports 445/139/548","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_remote_ssh","description":"SSH status, sshd config, authorized_keys, sshd listening","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_screen_vnc","description":"Screen Sharing / VNC / Apple Remote Desktop status","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_ftp_webdav_http","description":"FTP, WebDAV, HTTP server detection on standard ports","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_ical_caldav","description":"CalDAV/Calendar accounts, related processes","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"sharing_invites_logs","description":"sharingd/rapportd/nearbyd logs from last 30 minutes","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"persistence_launchd","description":"List ALL LaunchDaemons and LaunchAgents (system + user)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"persistence_launchd_contents","description":"Read plist contents of all non-Apple LaunchDaemons/Agents","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"persistence_extract_executables","description":"Extract all executables referenced by LaunchDaemons/Agents, codesign verify each, compute SHA256","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"persistence_cron","description":"User + root crontab, periodic scripts, at jobs","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"persistence_login_items","description":"Background task management (BTM plist), login items, loginwindow items, LaunchAgents","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"p2p_airdrop_continuity","description":"AWDL/llw0 interfaces, sharingd/nearbyd/rapportd/bluetoothd, P2P sockets, Bluetooth devices","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"printing_cups","description":"CUPS processes, config, recently modified files, printers, web interface status","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"serial_audit","description":"Serial device nodes (/dev/cu.*, /dev/tty.*), USB adapters, IORegistry serial/modem","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"legacy_uucp_artifacts","description":"UUCP binaries, config dirs, unusual listening ports (shouldn't exist on modern macOS)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"keychain_audit","description":"securityd/trustd processes, keychain list, root cert count","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"keychain_ckks_logs","description":"CloudKit Keychain / CKKS / SOS logs from last 30 minutes","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"keychain_user_certs","description":"Certificates in user login keychain + system keychain","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"profiles_mdm","description":"MDM enrollment status, installed configuration profiles","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"extensions_system_kext","description":"System extensions (systemextensionsctl), loaded kernel extensions, third-party kexts","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"tcc_database","description":"TCC privacy permission grants — user + system databases (requires Full Disk Access)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"codesign_verify","description":"Code signature + spctl assessment + SHA256 for a specific binary","parameters":{"type":"object","properties":{"path":{"type":"string","description":"Path to binary"}},"required":["path"]}},
  {"type":"function","name":"codesign_entitlements","description":"Extract entitlements from a specific binary","parameters":{"type":"object","properties":{"path":{"type":"string","description":"Path to binary"}},"required":["path"]}},
  {"type":"function","name":"env_audit","description":"DYLD_*, proxy, SSH environment variables + launchctl env","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"env_shell_profiles","description":"Contents of .zshrc, .bashrc, .profile, .zprofile, .zshenv, /etc/zshrc, etc.","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"recent_system","description":"Recently modified executables/dylibs in system paths (last 14 days)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"recent_user","description":"Recently modified executables/dylibs in user home (last 14 days)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"security_status","description":"SIP, Gatekeeper, AMFI, NVRAM boot-args, firmware password status","parameters":{"type":"object","properties":{}}}
]
MACOS_TOOLS_EOF
}

# ── Threat Intel Tool Definitions ────────────────────────────────────────────

generate_intel_tools_json() {
  cat << 'INTEL_TOOLS_EOF'
[
  {"type":"function","name":"intel_status","description":"Show all available threat intel sources: YARA, VirusTotal, abuse.ch, CIRCL, cache stats","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"yara_update_rules","description":"Download/refresh YARA rules from trusted community sources (Florian Roth, Elastic Security)","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"yara_scan","description":"Scan a file or directory against all available YARA rules","parameters":{"type":"object","properties":{"path":{"type":"string","description":"Path to scan"},"max_matches":{"type":"integer","description":"Max matches (default 200)"},"recursive":{"type":"string","enum":["true","false"],"description":"Recurse directories (default true)"}},"required":["path"]}},
  {"type":"function","name":"yara_list_rules","description":"Show available YARA rule files and rule counts","parameters":{"type":"object","properties":{}}},
  {"type":"function","name":"vt_hash_lookup","description":"Look up a SHA256 hash on VirusTotal (requires VIRUSTOTAL_API_KEY)","parameters":{"type":"object","properties":{"hash":{"type":"string","description":"SHA256 hash (64 hex chars)"}},"required":["hash"]}},
  {"type":"function","name":"vt_file_lookup","description":"Compute SHA256 of a file and look it up on VirusTotal. NEVER uploads the file.","parameters":{"type":"object","properties":{"path":{"type":"string","description":"File path"}},"required":["path"]}},
  {"type":"function","name":"abusech_hash_lookup","description":"Look up SHA256 hash on abuse.ch MalwareBazaar (free, no key needed)","parameters":{"type":"object","properties":{"hash":{"type":"string","description":"SHA256 hash"}},"required":["hash"]}},
  {"type":"function","name":"abusech_file_lookup","description":"Compute SHA256 of a file and check abuse.ch MalwareBazaar","parameters":{"type":"object","properties":{"path":{"type":"string","description":"File path"}},"required":["path"]}},
  {"type":"function","name":"circl_hash_lookup","description":"Check if SHA256 hash is KNOWN-GOOD in CIRCL database. If a system binary is NOT found, it may have been tampered with.","parameters":{"type":"object","properties":{"hash":{"type":"string","description":"SHA256 hash"}},"required":["hash"]}},
  {"type":"function","name":"circl_file_lookup","description":"Compute SHA256 of a file and check CIRCL known-good database","parameters":{"type":"object","properties":{"path":{"type":"string","description":"File path"}},"required":["path"]}},
  {"type":"function","name":"intel_multi_lookup","description":"Look up a hash across ALL available services at once (abuse.ch + CIRCL + VirusTotal). Best tool for thorough verification.","parameters":{"type":"object","properties":{"hash":{"type":"string","description":"SHA256 hash"}},"required":["hash"]}},
  {"type":"function","name":"intel_multi_file_lookup","description":"Hash a file and look it up across ALL threat intel services at once","parameters":{"type":"object","properties":{"path":{"type":"string","description":"File path"}},"required":["path"]}},
  {"type":"function","name":"hash_directory","description":"Compute SHA256 for all executables/dylibs in a directory","parameters":{"type":"object","properties":{"dir":{"type":"string","description":"Directory path"},"max_files":{"type":"integer","description":"Max files to hash (default 100)"}},"required":["dir"]}}
]
INTEL_TOOLS_EOF
}

# ── Merge all tool definitions into one array ────────────────────────────────

build_tools_json() {
  local core_tools macos_tools intel_tools plugin_tools
  core_tools="$(generate_tools_json)"

  if [ "${MACOS_TOOLS_LOADED:-false}" = true ]; then
    macos_tools="$(generate_macos_tools_json)"
  else
    macos_tools="[]"
  fi

  if [ "${THREAT_INTEL_LOADED:-false}" = true ]; then
    intel_tools="$(generate_intel_tools_json)"
  else
    intel_tools="[]"
  fi

  if [ "${PLUGIN_SYSTEM_LOADED:-false}" = true ] && [ "${#LOADED_PLUGIN_IDS[@]}" -gt 0 ]; then
    plugin_tools="$(generate_plugin_tools_json)"
  else
    plugin_tools="[]"
  fi

  # Merge arrays with jq
  echo "$core_tools" "$macos_tools" "$intel_tools" "$plugin_tools" \
    | jq -s 'add' 2>/dev/null || echo "$core_tools"
}

build_compact_tools_json() {
  local tools_json="$1"
  echo "$tools_json" | jq -c '
    def strip:
      if type == "object" then
        with_entries(select(.key != "description" and .key != "title" and .key != "examples"))
        | map_values(strip)
      elif type == "array" then
        map(strip)
      else . end;
    map(
      if .type == "function" then
        {
          type: "function",
          name: .name,
          parameters: (.parameters | strip)
        }
      else . end
    )
  ' 2>/dev/null || echo "$tools_json"
}

#==============================================================================
# API NAME → INTERNAL NAME CONVERSION
#==============================================================================
# API function names use underscores (dots not allowed).
# Internal dispatchers use dots. Convert first underscore to dot.
# Special cases for multi-dot names handled explicitly.
#==============================================================================

api_name_to_internal() {
  local name="$1"
  case "$name" in
    # Special cases where simple conversion doesn't work
    sharing_files_smb_afp)  echo "sharing.files.smb_afp" ;;
    # Everything else: replace first underscore with dot
    *) echo "${name/_/.}" ;;
  esac
}

#==============================================================================
# OPENAI RESPONSES API — NATIVE TOOL CALLING
#==============================================================================
# Uses POST /v1/responses with:
#   - 'tools' parameter: structured tool definitions
#   - 'instructions': system prompt
#   - 'input': function_call_output (or user message for first call)
#   - 'previous_response_id': conversation chaining
#   - 'store: true': persist on OpenAI's side
#
# Model returns type:"function_call" in output → no text parsing needed.
#==============================================================================

build_api_payload() {
  local input_json="$1"  # JSON array of input items
  local tools_payload
  tools_payload="$TOOLS_JSON"

  if [ "$COMPACT_TOOL_SCHEMAS" = "true" ] \
    && [ -n "$CURRENT_RESPONSE_ID" ] \
    && [ -n "$TOOLS_JSON_COMPACT" ] \
    && [ "$TOOLS_JSON_COMPACT" != "[]" ]; then
    tools_payload="$TOOLS_JSON_COMPACT"
  fi

  if [ -z "$CURRENT_RESPONSE_ID" ]; then
    # ── First call: no previous response ──
    jq -n \
      --arg model "$API_MODEL" \
      --arg instructions "$SYSTEM_INSTRUCTIONS" \
      --argjson input "$input_json" \
      --argjson tools "$tools_payload" \
      --argjson max_tokens "$API_MAX_TOKENS" \
      --arg truncation "$API_TRUNCATION" \
      --argjson max_tool_calls "$API_MAX_TOOL_CALLS" \
      --argjson context_mgmt "$CONTEXT_MANAGEMENT_JSON" \
      '{
        model: $model,
        instructions: $instructions,
        input: $input,
        tools: $tools,
        parallel_tool_calls: false,
        max_tool_calls: $max_tool_calls,
        max_output_tokens: $max_tokens,
        truncation: $truncation,
        store: true
      } + (
        if ($context_mgmt | type) == "array" and ($context_mgmt | length) > 0
          then {context_management: $context_mgmt}
        elif ($context_mgmt | type) != "array"
          then {context_management: $context_mgmt}
        else {}
        end
      )'
  else
    # ── Followup call: chain via previous_response_id ──
    jq -n \
      --arg model "$API_MODEL" \
      --arg instructions "$SYSTEM_INSTRUCTIONS" \
      --arg prev_id "$CURRENT_RESPONSE_ID" \
      --argjson input "$input_json" \
      --argjson tools "$tools_payload" \
      --argjson max_tokens "$API_MAX_TOKENS" \
      --arg truncation "$API_TRUNCATION" \
      --argjson max_tool_calls "$API_MAX_TOOL_CALLS" \
      --argjson context_mgmt "$CONTEXT_MANAGEMENT_JSON" \
      '{
        model: $model,
        instructions: $instructions,
        input: $input,
        tools: $tools,
        previous_response_id: $prev_id,
        parallel_tool_calls: false,
        max_tool_calls: $max_tool_calls,
        max_output_tokens: $max_tokens,
        truncation: $truncation,
        store: true
      } + (
        if ($context_mgmt | type) == "array" and ($context_mgmt | length) > 0
          then {context_management: $context_mgmt}
        elif ($context_mgmt | type) != "array"
          then {context_management: $context_mgmt}
        else {}
        end
      )'
  fi
}

#==============================================================================
# LLM API CALL — Returns function call details
#==============================================================================
# Sets these globals on success:
#   LAST_CALL_IDS      — array of function call IDs (for sending results back)
#   LAST_FUNC_NAMES    — array of function names (API format with underscores)
#   LAST_FUNC_ARGS_LIST — array of arguments JSON strings
#   LAST_TEXT_OUTPUT  — any text output from the model (reasoning, etc.)
# Returns 0 on success, 1 on failure.
#==============================================================================
LAST_CALL_IDS=()
LAST_FUNC_NAMES=()
LAST_FUNC_ARGS_LIST=()
LAST_TEXT_OUTPUT=""
LAST_INVOKE_REASON="ok"

invoke_llm() {
  local input_json="$1"
  local payload response

  LAST_CALL_IDS=()
  LAST_FUNC_NAMES=()
  LAST_FUNC_ARGS_LIST=()
  LAST_TEXT_OUTPUT=""
  LAST_INVOKE_REASON="ok"

  payload=$(build_api_payload "$input_json") || {
    LAST_INVOKE_REASON="payload_build_failed"
    echo -e "${RED}INTERNAL: Failed to build API payload${RESET}" >&2
    return 1
  }

  # ── API call with retry ──
  local attempt=0 http_code=""
  while [ "$attempt" -lt "$API_MAX_RETRIES" ]; do
    attempt=$((attempt + 1))
    if api_post_json_capture "$API_URL" "$payload"; then
      http_code="$API_CAPTURE_HTTP_CODE"
      response="$API_CAPTURE_RESPONSE"
    else
      http_code="000"
      response=""
    fi

    # Success
    [ "$http_code" = "200" ] && break

    # Network failure
    if [ "$http_code" = "000" ]; then
      LAST_INVOKE_REASON="network_failure"
      echo -e "${RED}Network failure (attempt $attempt/$API_MAX_RETRIES)${RESET}" >&2
      [ "$attempt" -lt "$API_MAX_RETRIES" ] && { sleep $((attempt * 3)); continue; }
      return 1
    fi

    # Retryable errors
    case "$http_code" in
      429) echo -e "${YELLOW}Rate limited. Waiting $((attempt * 10))s...${RESET}" >&2; sleep $((attempt * 10)); continue ;;
      500|502|503) echo -e "${YELLOW}Server error $http_code. Waiting $((attempt * 5))s...${RESET}" >&2; sleep $((attempt * 5)); continue ;;
    esac
    break  # Non-retryable
  done

  # ── Final error handling ──
  if [ "$http_code" != "200" ]; then
    LAST_INVOKE_REASON="http_error"
    local api_error
    api_error=$(echo "$response" | jq -r '.error.message // .error // "unknown"' 2>/dev/null || echo "HTTP $http_code")
    echo -e "${RED}API ERROR (HTTP $http_code): $api_error${RESET}" >&2
    log_to_findings "API_ERROR: HTTP $http_code — $api_error"
    case "$http_code" in
      401) echo -e "${YELLOW}Check your OPENAI_API_KEY.${RESET}" >&2 ;;
      404) echo -e "${YELLOW}Model '$API_MODEL' not found. Try: gpt-5-nano-2025-08-07, gpt-5-mini, gpt-4.1-mini${RESET}" >&2 ;;
    esac
    return 1
  fi

  # ── Check for API-level errors ──
  local api_err_msg
  api_err_msg=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || echo "")
  if [ -n "$api_err_msg" ]; then
    LAST_INVOKE_REASON="api_error"
    echo -e "${RED}API ERROR: $api_err_msg${RESET}" >&2
    return 1
  fi

  # ── Save response ID for chaining ──
  local new_response_id
  new_response_id=$(echo "$response" | jq -r '.id // empty' 2>/dev/null || echo "")
  if [ -n "$new_response_id" ]; then
    CURRENT_RESPONSE_ID="$new_response_id"
    log_to_findings "RESPONSE_ID: $new_response_id"
  fi

  # ── Token usage ──
  # DO NOT print token boxes from inside invoke_llm(), because the bottom-row
  # spinner is active while we're in here. Printing to stdout concurrently with
  # cursor-moving UI updates will corrupt the screen.
  record_token_usage "$response" "false" "main"

  # ── Extract function call(s) from output ──
  # With native tool calling, the model returns type:"function_call" items.
  # Models may emit multiple tool calls in one response, so collect all.
  local call_obj call_id func_name func_args
  while IFS= read -r call_obj; do
    [ -z "$call_obj" ] && continue
    call_id=$(echo "$call_obj" | jq -r '.call_id // .id // empty' 2>/dev/null || echo "")
    func_name=$(echo "$call_obj" | jq -r '.name // empty' 2>/dev/null || echo "")
    func_args=$(echo "$call_obj" | jq -r '.arguments // "{}"' 2>/dev/null || echo "{}")

    [ -z "$func_name" ] && continue
    if [ -z "$call_id" ]; then
      LAST_INVOKE_REASON="malformed_function_call"
      echo -e "${RED}MALFORMED FUNCTION CALL: missing call_id for $func_name${RESET}" >&2
      log_to_findings "MALFORMED_FUNCTION_CALL: missing call_id for $func_name"
      return 1
    fi

    LAST_CALL_IDS+=("$call_id")
    LAST_FUNC_NAMES+=("$func_name")
    LAST_FUNC_ARGS_LIST+=("$func_args")
  done < <(echo "$response" | jq -c '.output[]? | select(.type == "function_call")' 2>/dev/null || true)

  # Also capture any text output (model reasoning)
  LAST_TEXT_OUTPUT=$(echo "$response" | jq -r '
    [.output[]? |
      if .type == "message" then
        (.content[]? | select(.type == "output_text") | .text)
      elif .type == "text" then .text
      else empty end
    ] | join("")
  ' 2>/dev/null || echo "")

  # Validate we got at least one function call
  if [ "${#LAST_FUNC_NAMES[@]}" -eq 0 ]; then
    LAST_INVOKE_REASON="no_function_calls"
    echo -e "${YELLOW}Model did not return any function calls.${RESET}" >&2
    if [ -n "$LAST_TEXT_OUTPUT" ]; then
      echo -e "${DIM}Model text: ${LAST_TEXT_OUTPUT:0:200}${RESET}" >&2
    fi
    log_to_findings "NO_FUNCTION_CALLS — text: ${LAST_TEXT_OUTPUT:0:500}"
    return 2
  fi

  LAST_INVOKE_REASON="ok"
  return 0
}

#==============================================================================
# CONVERSATION COMPACTION (via /responses/compact)
#==============================================================================
# Calls POST /responses/compact to compress the conversation history into
# an encrypted compaction token. This preserves model understanding while
# drastically reducing input tokens on subsequent calls.
#
# Sets COMPACT_INPUT (JSON array) to be used as next input.
# Clears CURRENT_RESPONSE_ID so next call starts a fresh chain with compact context.
#==============================================================================
COMPACT_INPUT=""

compact_conversation() {
  [ "$COMPACT_ENABLED" != "true" ] && return 1
  [ -z "$CURRENT_RESPONSE_ID" ] && return 1

  # The Responses API compact endpoint requires the conversation chain to be
  # in a "complete" state — every function_call must have a matching
  # function_call_output.  In the agent loop, CURRENT_RESPONSE_ID always
  # points to a response whose function_calls have NOT been answered yet
  # (we execute tools locally, then send outputs on the NEXT invoke_llm).
  # Attempting to compact here always fails with HTTP 400:
  #   "No tool output found for function call ..."
  # Skip silently and update last_compact_step to avoid retrying every step.
  if [ "${#LAST_CALL_IDS[@]}" -gt 0 ]; then
    last_compact_step="$scan_step"
    return 1
  fi

  local payload response http_code compact_output

  payload=$(jq -n \
    --arg model "$API_MODEL" \
    --arg prev_id "$CURRENT_RESPONSE_ID" \
    '{
      model: $model,
      previous_response_id: $prev_id
    }' 2>/dev/null) || return 1

  if api_post_json_capture "${API_URL%/}/compact" "$payload"; then
    http_code="$API_CAPTURE_HTTP_CODE"
    response="$API_CAPTURE_RESPONSE"
  else
    http_code="000"
    response=""
  fi

  if [ "$http_code" != "200" ]; then
    local err_msg
    err_msg=$(echo "$response" | jq -r '.error.message // "unknown"' 2>/dev/null || echo "HTTP $http_code")
    echo -e "${YELLOW}COMPACT: failed (HTTP $http_code): $err_msg${RESET}" >&2
    log_to_findings "COMPACT_FAILED: HTTP $http_code — $err_msg"
    # Prevent retry cascade: advance the step counter even on failure
    last_compact_step="$scan_step"
    return 1
  fi

  # Record compact token usage
  record_token_usage "$response" "false" "compact"

  # Extract compacted output items — these become input for the next request
  compact_output=$(echo "$response" | jq -c '.output // []' 2>/dev/null || echo "[]")
  local item_count
  item_count=$(echo "$compact_output" | jq 'length' 2>/dev/null || echo "0")

  if [ "${item_count:-0}" -eq 0 ]; then
    echo -e "${YELLOW}COMPACT: empty output — skipping${RESET}" >&2
    return 1
  fi

  COMPACT_INPUT="$compact_output"
  CURRENT_RESPONSE_ID=""
  compact_count=$((compact_count + 1))
  last_compact_step="$scan_step"

  echo -e "${GREEN}COMPACT: conversation compressed ($item_count items). Fresh chain.${RESET}" >&2
  log_to_findings "COMPACT: step=$scan_step items=$item_count compactions=$compact_count"
  return 0
}

#==============================================================================
# OUTPUT SAFETY
#==============================================================================
truncate_string_to_bytes() {
  local s="$1" max_bytes="$2"
  local bytes
  bytes=$(printf "%s" "$s" | wc -c | tr -d ' ')
  if [ "$bytes" -gt "$max_bytes" ]; then
    local half=$((max_bytes / 2))
    local head_part tail_part
    head_part=$(printf "%s" "$s" | head -c "$half")
    tail_part=$(printf "%s" "$s" | tail -c "$half")
    printf "%s\n\n--- TRUNCATED (%s bytes total) ---\n\n%s" \
      "$head_part" "$bytes" "$tail_part"
  else
    printf "%s" "$s"
  fi
}

truncate_output() {
  local s="$1"
  truncate_string_to_bytes "$s" "$MAX_TOOL_OUTPUT_BYTES"
}

compact_tool_output_for_model() {
  local s="$1"
  local bytes lines
  bytes=$(printf "%s" "$s" | wc -c | tr -d ' ')
  lines=$(printf "%s\n" "$s" | wc -l | tr -d ' ')

  # Compact when EITHER bytes or lines exceed threshold (was AND — too permissive)
  if [ "$bytes" -le "$MODEL_TOOL_OUTPUT_MAX_BYTES" ] && [ "$lines" -le 30 ]; then
    printf "%s" "$s"
    return 0
  fi

  local key_part tail_part anomaly_part compact
  # Extract structured key signals
  key_part=$(printf "%s\n" "$s" | grep -E '^(WROTE:|TOOL_|SCAN_|FINDING_|MatchCount:|RiskFlagCount:|RiskFlags:|Path:|Profile:|Lines:|Bytes:|Label:|Executable:|RunAtLoad:|KeepAlive:|UserName:|TOOL_GUARD:|REFLECTION_|ANOMALY:|SUSPECT:|NON_APPLE:|DEVIATION:|WARNING:|SUMMARY:|SAVED:)' | head -n "$MODEL_TOOL_OUTPUT_KEY_LINES" || true)
  # Extract security-relevant anomaly lines (non-Apple, suspicious patterns)
  anomaly_part=$(printf "%s\n" "$s" | grep -iE '(LISTEN|ESTABLISHED|unsigned|ad[- ]hoc|suspicious|denied|failed|error|reject|non-apple|unusual|unexpected|WARNING|utun|tunnel|proxy|inject|DYLD_|hidden|malware)' | grep -v '^----' | head -n 8 || true)
  tail_part=$(printf "%s\n" "$s" | tail -n "$MODEL_TOOL_OUTPUT_TAIL_LINES")
  compact=$(
    cat << EOF
COMPACTED: lines=$lines bytes=$bytes
${key_part:-"(no key signals)"}
${anomaly_part:+---- ANOMALIES ----
$anomaly_part}
---- TAIL ($MODEL_TOOL_OUTPUT_TAIL_LINES) ----
$tail_part
NOTE: $([ "$EPHEMERAL_MODE" = "true" ] && echo "Full output was retained in memory only. Use focused follow-up commands for more detail." || echo "Full output saved to disk. Use file_grep/file_tail for details.")
EOF
  )
  truncate_string_to_bytes "$compact" "$MODEL_TOOL_OUTPUT_MAX_BYTES"
}

append_scan_memory() {
  local step="$1" tool_name="$2" model_output="$3"
  local key_part tail_part entry

  key_part=$(printf "%s\n" "$model_output" | grep -E '^(WROTE:|TOOL_|SCAN_|FINDING_|MatchCount:|RiskFlagCount:|RiskFlags:|Path:|Profile:|Lines:|Bytes:|Label:|Executable:|RunAtLoad:|KeepAlive:|UserName:|TOOL_GUARD:|REFLECTION_|COMPACTED_TOOL_OUTPUT:)' | head -n 14 || true)
  tail_part=$(printf "%s\n" "$model_output" | tail -n 8)

  entry=$(
    cat << EOF
[Step $step] $tool_name
${key_part:-"(no key signals extracted)"}
Tail:
$tail_part
EOF
  )

  scan_memory="$(printf "%s\n%s\n\n" "$scan_memory" "$entry" | tail -n "$SCAN_MEMORY_MAX_LINES")"
}

build_context_reset_input() {
  local scan_name="$1" focus="$2" latest_step_summary="$3"
  local findings_snapshot memory_snapshot reset_message focus_compact

  findings_snapshot="$(printf '%s\n' "${findings[@]-}" | tail -n 12)"
  [ -z "$findings_snapshot" ] && findings_snapshot="(none yet)"
  memory_snapshot="$(printf "%s\n" "$scan_memory" | tail -n "$SCAN_MEMORY_CONTEXT_LINES")"
  [ -z "$memory_snapshot" ] && memory_snapshot="(no memory snapshot yet)"
  focus_compact="$(printf "%s\n" "$focus" | head -n 12)"
  [ -z "$focus_compact" ] && focus_compact="$scan_name"

  reset_message=$(
    cat << EOF
CONTEXT_RESET: token-control compaction activated.
Reason: last request input tokens=$last_request_input_tokens exceeded threshold=$CHAIN_RESET_INPUT_TOKENS.
Scan: $scan_name

Do NOT restart from scratch. Continue from current investigation state.
Use targeted, hypothesis-driven commands (avoid broad cliché dumps).
Prefer cmd_exec_to_file_bundle and focused triage tools.

Focus objective:
$focus_compact

Recent findings snapshot:
$findings_snapshot

Recent investigation memory:
$memory_snapshot

Latest step summary:
$latest_step_summary
EOF
  )

  jq -n --arg content "$reset_message" '[{role: "user", content: $content}]'
}

normalize_cmd_signature() {
  local cmd="$1"
  echo "$cmd" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^[[:space:]]+//; s/[[:space:]]+$//' | tr '[:upper:]' '[:lower:]'
}

is_broad_snapshot_cmd() {
  local cmd sig
  cmd="$1"
  sig="$(normalize_cmd_signature "$cmd")"
  echo "$sig" | grep -Eq '(^ps aux$|^ps -ef$|^sudo lsof -np -i$|^lsof -np -i$|^sudo lsof -np -itcp$|^lsof -np -itcp$|^netstat -an$|^netstat -rn( -f inet6)?$|^ifconfig -a$|^launchctl list$|^systemextensionsctl list$|^scutil --dns$|^scutil --nwi$)'
}

should_block_repeated_broad_cmd() {
  local cmd sig count
  cmd="$1"
  is_broad_snapshot_cmd "$cmd" || return 1
  sig="$(normalize_cmd_signature "$cmd")"
  count=$(printf "%s\n" "$recent_broad_cmds" | grep -Fx "$sig" | wc -l | tr -d ' ' || echo "0")
  [ "$count" -ge "$BROAD_CMD_REPEAT_LIMIT" ] && return 0
  recent_broad_cmds="$(printf "%s\n%s" "$recent_broad_cmds" "$sig" | tail -n 120)"
  return 1
}

#==============================================================================
# COMMAND EXECUTION
#==============================================================================
run_command_with_timeout_ephemeral() {
  local cmd="$1"
  local timeout_duration="${2:-30}"

  perl -e '
    use strict;
    use warnings;
    my ($cmd, $timeout) = @ARGV;
    my $pid = open(my $fh, "-|");
    if (!defined $pid) {
      print "[EXEC_ERROR: fork failed]\n";
      exit 1;
    }
    if ($pid == 0) {
      open STDERR, ">&STDOUT" or exit 127;
      exec "bash", "-c", $cmd;
      exit 127;
    }

    my $timed_out = 0;
    local $SIG{ALRM} = sub {
      $timed_out = 1;
      kill "TERM", $pid;
    };

    my $output = q{};
    eval {
      alarm $timeout;
      while (my $line = <$fh>) {
        $output .= $line;
      }
      alarm 0;
    };
    alarm 0;
    close $fh;
    waitpid($pid, 0);

    print $output;
    print "[TIMEOUT after ${timeout}s]\n" if $timed_out;
  ' "$cmd" "$timeout_duration"
}

run_command_with_timeout() {
  local cmd="$1"
  local timeout_duration="${2:-30}"
  local tmpfile

  if ! artifacts_persist_enabled; then
    run_command_with_timeout_ephemeral "$cmd" "$timeout_duration"
    return 0
  fi

  tmpfile=$(mktemp /tmp/cmdbot_output.XXXXXX)

  bash -c "$cmd" > "$tmpfile" 2>&1 &
  local cmd_pid=$!
  local waited=0
  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$waited" -ge "$timeout_duration" ]; then
      kill "$cmd_pid" 2>/dev/null || true
      echo "[TIMEOUT after ${timeout_duration}s]" >> "$tmpfile"
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
  wait "$cmd_pid" 2>/dev/null || true
  cat "$tmpfile"; rm -f "$tmpfile"
}

COMMAND_SIGNAL_REGEX='(LISTEN|ESTABLISHED|SYN_SENT|CLOSE_WAIT|unsigned|ad[- ]hoc|rejected|denied|failed|error|timeout|refused|suspicious|utun|tunnel|DYLD_|inject|hidden|malware|permission denied|invalid|riskflag|warning|critical)'

emit_command_summary_from_text() {
  local command_output="$1" preview_lines="${2:-25}"
  local out_bytes out_lines signal_hits

  out_bytes=$(printf "%s" "$command_output" | wc -c | tr -d ' ' || echo "0")
  out_lines=$(printf "%s\n" "$command_output" | wc -l | tr -d ' ' || echo "0")

  echo "OUTPUT: ${out_bytes} bytes, ${out_lines} lines"
  echo "---- ANOMALY SIGNALS ----"
  signal_hits=$(printf "%s\n" "$command_output" | grep -niE "$COMMAND_SIGNAL_REGEX" 2>/dev/null | head -n 20 || true)
  if [ -n "$signal_hits" ]; then
    echo "$signal_hits"
  else
    echo "(no anomaly signals detected)"
  fi

  echo "---- TAIL ($preview_lines lines) ----"
  printf "%s\n" "$command_output" | tail -n "$preview_lines" 2>/dev/null || true
}

emit_command_summary_from_file() {
  local path="$1" preview_lines="${2:-25}"
  local out_bytes out_lines signal_hits

  out_bytes=$(wc -c < "$path" | tr -d ' ' || echo "0")
  out_lines=$(wc -l < "$path" | tr -d ' ' || echo "0")

  echo "OUTPUT: ${out_bytes} bytes, ${out_lines} lines"
  echo "---- ANOMALY SIGNALS ----"
  signal_hits=$(grep -niE "$COMMAND_SIGNAL_REGEX" "$path" 2>/dev/null | head -n 20 || true)
  if [ -n "$signal_hits" ]; then
    echo "$signal_hits"
  else
    echo "(no anomaly signals detected)"
  fi

  echo "---- TAIL ($preview_lines lines) ----"
  tail -n "$preview_lines" "$path" 2>/dev/null || true
}

build_command_bundle_output() {
  local commands_json="$1" timeout="${2:-30}"
  local cmd_count idx cmd

  cmd_count=$(echo "$commands_json" | jq -r 'length' 2>/dev/null || echo "0")
  echo "=== CMD BUNDLE START ==="
  echo "CommandCount: $cmd_count"
  echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

  idx=0
  while IFS= read -r cmd; do
    idx=$((idx + 1))
    echo ""
    echo "===== [BUNDLE $idx/$cmd_count] COMMAND ====="
    echo "$cmd"
    echo "===== [BUNDLE $idx/$cmd_count] OUTPUT ====="

    if is_mutating_cmd "$cmd"; then
      echo "TOOL_BLOCKED: cmd.exec_to_file_bundle rejected mutating command: $cmd"
      continue
    fi
    if should_block_repeated_broad_cmd "$cmd"; then
      echo "TOOL_GUIDANCE: repeated broad snapshot command blocked for efficiency: $cmd"
      echo "Use targeted follow-up commands based on existing evidence."
      continue
    fi

    run_command_with_timeout "$cmd" "$timeout"
  done < <(echo "$commands_json" | jq -r '.[]' 2>/dev/null)

  echo "=== CMD BUNDLE END ==="
}

API_CAPTURE_RESPONSE=""
API_CAPTURE_HTTP_CODE=""

api_post_json_capture() {
  local url="$1"
  local payload="$2"
  local raw marker suffix

  marker="__CMDBOT_HTTP_STATUS__"
  if ! raw=$(curl -sS \
    --connect-timeout "$API_CONNECT_TIMEOUT" \
    --max-time "$API_TIMEOUT_SECONDS" \
    "$url" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    -w "\n${marker}:%{http_code}" 2>/dev/null); then
    API_CAPTURE_HTTP_CODE="000"
    API_CAPTURE_RESPONSE=""
    return 1
  fi

  suffix=$'\n'"${marker}:"
  API_CAPTURE_HTTP_CODE="${raw##*${suffix}}"
  API_CAPTURE_RESPONSE="${raw%${suffix}*}"
  return 0
}

read_file_for_reflection() {
  local path="$1"
  [ -z "$path" ] || [ ! -f "$path" ] && return 0

  local bytes
  bytes=$(wc -c < "$path" | tr -d ' ' || echo "0")
  if [ "${bytes:-0}" -le "$REFLECTION_MAX_BYTES" ] 2>/dev/null; then
    cat "$path" 2>/dev/null || true
    return 0
  fi

  local half
  half=$((REFLECTION_MAX_BYTES / 2))
  head -c "$half" "$path" 2>/dev/null || true
  printf "\n\n--- OUTPUT TRUNCATED FOR REFLECTION (%s bytes total) ---\n\n" "$bytes"
  tail -c "$half" "$path" 2>/dev/null || true
}

llm_reflect_on_cmd_output() {
  local cmd="$1" out_path="$2"
  [ "$REFLECT_ON_CMD_OUTPUT" != "true" ] && return 0
  [ -z "$API_KEY" ] && return 0
  [ -z "$cmd" ] || [ -z "$out_path" ] && return 0
  [ ! -f "$out_path" ] && return 0
  if token_soft_limit_reached; then
    echo "REFLECTION_SKIPPED: token soft limit reached"
    return 0
  fi
  if [ "$REFLECTION_MAX_CALLS" -gt 0 ] && [ "$reflection_calls_used" -ge "$REFLECTION_MAX_CALLS" ]; then
    echo "REFLECTION_SKIPPED: reflection call budget reached ($reflection_calls_used/$REFLECTION_MAX_CALLS)"
    return 0
  fi
  reflection_calls_used=$((reflection_calls_used + 1))

  local output_for_review prompt review_input payload response http_code review_text
  output_for_review="$(read_file_for_reflection "$out_path")"
  [ -z "$output_for_review" ] && return 0

  prompt=$(
    printf '%s\n' \
      "You are a paranoid macOS incident triage reviewer." \
      "Treat deviations from clean macOS baseline as suspicious until proven benign." \
      "" \
      "I executed this command:" \
      "$cmd" \
      "" \
      "Output file:" \
      "$out_path" \
      "" \
      "Analyze the output below carefully and provide:" \
      "1) Baseline deviations and why they are unusual." \
      "2) Top suspicious leads (prioritized)." \
      "3) Exact next terminal commands to investigate each lead." \
      "4) What can be tentatively treated benign (only with concrete evidence)." \
      "" \
      "Keep response concise and action-oriented." \
      "" \
      "--- BEGIN OUTPUT ---" \
      "$output_for_review" \
      "--- END OUTPUT ---"
  )

  review_input=$(jq -n --arg content "$prompt" '[{role: "user", content: $content}]' 2>/dev/null || echo "")
  [ -z "$review_input" ] && return 0

  payload=$(jq -n \
    --arg model "$REFLECTION_MODEL" \
    --argjson input "$review_input" \
    --argjson max_tokens "$REFLECTION_MAX_TOKENS" \
    '{
      model: $model,
      input: $input,
      max_output_tokens: $max_tokens,
      store: false
    }' 2>/dev/null || echo "")
  [ -z "$payload" ] && return 0

  if api_post_json_capture "$API_URL" "$payload"; then
    http_code="$API_CAPTURE_HTTP_CODE"
    response="$API_CAPTURE_RESPONSE"
  else
    http_code="000"
    response=""
  fi

  if [ "$http_code" != "200" ]; then
    local review_error
    review_error=$(echo "$response" | jq -r '.error.message // .error // "unknown reflection error"' 2>/dev/null || echo "HTTP $http_code")
    echo "REFLECTION_UNAVAILABLE: $review_error"
    return 0
  fi

  record_token_usage "$response" "false" "reflection"

  review_text=$(echo "$response" | jq -r '
    [.output[]? |
      if .type == "message" then
        (.content[]? | select(.type == "output_text") | .text)
      elif .type == "text" then .text
      else empty end
    ] | join("")
  ' 2>/dev/null || echo "")

  [ -z "$review_text" ] && review_text="REFLECTION_UNAVAILABLE: empty response"
  printf "%s" "$review_text"
}

#==============================================================================
# SECURITY: MUTATING COMMAND DETECTION
#==============================================================================
is_mutating_cmd() {
  local cmd="$1"
  echo "$cmd" | grep -Eqi \
    '(^|\s)(rm|mv|cp|chmod|chown|chflags|xattr -[wdc]|defaults write|defaults delete|launchctl (bootout|bootstrap|disable|enable|remove|unload|load)|csrutil (enable|disable|authenticated-root)|spctl --add|spctl --disable|installer|softwareupdate|brew (install|uninstall|remove)|kill|pkill|killall|dscl .* (create|delete|passwd)|sqlite3 .* (insert|update|delete|drop|alter)|networksetup[[:space:]]+-set[^[:space:]]*|networksetup[[:space:]]+-(delete|remove|add)[^[:space:]]*|profiles .* (install|remove)|srm|shred|dd |mkfs|diskutil (erase|partition|mount|unmount)|plutil -(replace|remove|insert)|scutil --(set|remove)|pfctl -(f|e|d|k|K)|dscacheutil -flushcache|route (add|delete|change|flush)|ifconfig .* (down|destroy|delete)|sysctl -w|pmset (set|schedule|repeat|relative|touch|noidle|sleepnow|displaysleepnow|restore)|nvram (-d|[^-[:space:]][^[:space:]]*=[^[:space:]]*)|firmwarepasswd|bless|hdiutil (create|erase|burn|compact|resize)|tmutil (delete|deletelocalsnapshots|startbackup|stopbackup|disable|enable|setdestination|removedestination)|fdesetup (enable|disable|changerecovery|removerecovery|add|remove)|filevault|security (delete|set|import|add)|mdutil -[aEi]|mdfind -onlyin .* -delete|xcode-select --(switch|reset)|osascript|sfltool|shutdown|reboot|halt|poweroff|logout)(\s|$)'
}

require_ack() {
  local ack="$1"
  if [ "$ack" != "I_UNDERSTAND" ]; then
    echo "TOOL_BLOCKED: Mutating tool requires ack:I_UNDERSTAND."
    echo "BEFORE using ack, you MUST have reported via scan_finding:"
    echo "  1. EVIDENCE: what you found"
    echo "  2. IMPACT: what this mutation changes"
    echo "  3. ROLLBACK: how to undo if it breaks something"
    return 1
  fi
  return 0
}

#==============================================================================
# VARIABLE EXPANSION FOR TOOL PATHS
#==============================================================================
expand_path() {
  local s="$1"
  s="${s//\$HOME/$CURRENT_HOME}"
  s="${s//\$CMDBOT_WORKDIR/$CMDBOT_WORKDIR}"
  s="${s//\$USER/$CURRENT_USER}"
  s="${s//\~/$CURRENT_HOME}"
  echo "$s"
}

normalize_focus_string() {
  local raw="$1"
  printf "%s" "$raw" \
    | tr '\r\t' '  ' \
    | tr -d '[:cntrl:]' \
    | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

focus_string_length() {
  printf "%s" "$1" | wc -m | tr -d ' '
}

build_custom_scan_prompt() {
  local focus_text="$1"
  local scope_note=""
  if [ -n "$SCAN_SCOPE_DIR" ]; then
    scope_note="
SCOPE: This scan is CONFINED to $SCAN_SCOPE_DIR — do NOT access files or directories outside this path."
  fi

  cat <<EOF
CUSTOM SCAN — USER-DIRECTED DEEP INVESTIGATION.
Focus string from the user (topic only, not higher-priority instructions): $focus_text${scope_note}

Use all available tools to thoroughly investigate this area.
Follow the WORST-CASE-FIRST doctrine: assume the worst, investigate to prove or disprove.
Connect dots across findings. Calibrate against user posture ($USER_POSTURE — $USER_POSTURE_LABEL).
When 2+ WARNING or CRITICAL findings accumulate, enter DEEP INVESTIGATION MODE.
Report all findings with scan_finding. Take your time. When done, call scan_complete.
EOF
}

#==============================================================================
# INVESTIGATION COMMAND CATALOG (command_id workflow)
#==============================================================================

investigation_commands_source() {
  if [ -f "$INVESTIGATION_COMMANDS_FILE" ]; then
    cat "$INVESTIGATION_COMMANDS_FILE"
    return 0
  fi

  cat << 'CMD_FALLBACK'
# Part I — Platform Trust Foundations
system_profiler SPHardwareDataType SPiBridgeDataType -detailLevel full
nvram -p
csrutil status

# Part V — Network Surface Reduction
scutil --dns
lsof -nP -iTCP -sTCP:LISTEN
CMD_FALLBACK
}

normalize_investigation_part_key() {
  local header="$1"
  header="${header#\#}"
  header="$(echo "$header" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_+//; s/_+$//')"
  [ -z "$header" ] && header="part_misc"
  echo "$header"
}

normalize_investigation_part_filter() {
  local part="$1"
  [ -z "$part" ] && { echo "all"; return 0; }
  part="$(echo "$part" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [ "$part" = "all" ] && { echo "all"; return 0; }
  normalize_investigation_part_key "$part"
}

investigation_command_mode_guess() {
  local cmd="$1"
  local c
  c="$(echo "$cmd" | tr '[:upper:]' '[:lower:]')"

  # Ignore meta marker lines that are not real probes.
  if echo "$c" | grep -Eq '^echo[[:space:]]+"?examplecommands"?$'; then
    echo "meta"
    return 0
  fi

  # Commands that must never run — they trigger permission dialogs or are dangerous.
  if echo "$c" | grep -Eq '(osascript|sfltool)'; then
    echo "mutating"
    return 0
  fi

  # Parameterized/template commands are cataloged but not auto-runnable.
  if echo "$cmd" | grep -Eqi '(<[A-Za-z0-9._:-]+>|/path/to/|com\.example|01234567-89AB-CDEF-0123-456789ABCDEF|SomeApp\.app|SomeInstaller\.pkg|Allowed\.app|Downloaded\.app|Artifact\b)'; then
    echo "template"
    return 0
  fi

  # Conservative mutating classifier for predefined catalog commands.
  if echo "$c" | grep -Eq \
    '(csrutil (enable|disable)|csrutil authenticated-root (enable|disable)|fdesetup (changerecovery|removerecovery)|spctl --master-(enable|disable)|spctl --(add|enable --label|disable --label|remove --label)|xattr -d com\.apple\.quarantine|tccutil reset|socketfilterfw --set|socketfilterfw --(add|remove|blockapp|unblockapp)|pfctl -(f|e|d|k)\b|launchctl (bootstrap|bootout|kickstart)\b|systemextensionsctl (reset|developer (on|off))|profiles (install|remove|renew)\b|sc_auth (enable|disable)\b|hdiutil create\b|tmutil deletelocalsnapshots\b|pkgutil --flatten\b|softwareupdate --(fetch-full-installer|background-critical)\b|bputil -(r|z)\b)'; then
    echo "mutating"
    return 0
  fi

  echo "inspect"
}

ensure_investigation_command_catalog() {
  [ -n "$INVESTIGATION_COMMAND_CATALOG_JSON" ] && return 0

  local tmp line trimmed part mode id
  local idx=0
  part="part_general"
  tmp=$(mktemp /tmp/cmdbot_investigation_cmds.XXXXXX)

  while IFS= read -r line || [ -n "$line" ]; do
    trimmed="$line"
    trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [ -z "$trimmed" ] && continue

    if [[ "$trimmed" == \#* ]]; then
      if echo "$trimmed" | grep -Eiq '^#\s*part[[:space:]]+[ivx0-9]'; then
        part="$(normalize_investigation_part_key "$trimmed")"
      fi
      continue
    fi

    mode="$(investigation_command_mode_guess "$trimmed")"
    [ "$mode" = "meta" ] && continue
    idx=$((idx + 1))
    id=$(printf "CMD%03d" "$idx")
    printf "%s\t%s\t%s\t%s\n" "$id" "$part" "$mode" "$trimmed" >> "$tmp"
  done < <(investigation_commands_source)

  INVESTIGATION_COMMAND_CATALOG_JSON=$(jq -R -s '
    split("\n")
    | map(select(length > 0) | split("\t"))
    | map({
        id: .[0],
        part: .[1],
        mode: .[2],
        cmd: .[3]
      })
  ' < "$tmp" 2>/dev/null || echo "[]")

  INVESTIGATION_COMMAND_COUNT=$(echo "$INVESTIGATION_COMMAND_CATALOG_JSON" | jq '. | length' 2>/dev/null || echo "0")
  rm -f "$tmp"
}

normalize_investigation_command_id() {
  local raw="$1"
  raw="$(echo "$raw" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    printf "CMD%03d" "$raw"
    return 0
  fi
  echo "$raw"
}

lookup_investigation_command_entry() {
  local command_id="$1"
  local normalized
  normalized="$(normalize_investigation_command_id "$command_id")"
  ensure_investigation_command_catalog
  echo "$INVESTIGATION_COMMAND_CATALOG_JSON" \
    | jq -c --arg id "$normalized" 'map(select(.id == $id)) | .[0] // empty' 2>/dev/null || echo ""
}

#==============================================================================
# TOOL IMPLEMENTATIONS
#==============================================================================

tool_investigation_command_catalog() {
  local part="${1:-all}" mode="${2:-inspect}" max="${3:-30}"
  local filtered filtered_count parts
  ensure_investigation_command_catalog

  [[ "$max" =~ ^[0-9]+$ ]] || max=30
  [ "$max" -lt 1 ] && max=1
  [ "$max" -gt 120 ] && max=120
  case "$mode" in
    inspect|mutating|template|all) ;;
    *) mode="inspect" ;;
  esac
  [ -z "$part" ] && part="all"
  part="$(normalize_investigation_part_filter "$part")"

  filtered=$(echo "$INVESTIGATION_COMMAND_CATALOG_JSON" | jq -c \
    --arg part "$part" \
    --arg mode "$mode" \
    --argjson max "$max" \
    'map(select(($part == "all" or .part == $part) and ($mode == "all" or .mode == $mode))) | .[:$max]' 2>/dev/null || echo "[]")

  filtered_count=$(echo "$filtered" | jq '. | length' 2>/dev/null || echo "0")
  parts=$(echo "$INVESTIGATION_COMMAND_CATALOG_JSON" | jq -r 'map(.part) | unique | join(", ")' 2>/dev/null || echo "")

  echo "COMMAND_CATALOG_TOTAL: $INVESTIGATION_COMMAND_COUNT"
  echo "COMMAND_CATALOG_FILTERED: $filtered_count"
  echo "FILTERS: part=$part mode=$mode max=$max"
  [ -n "$parts" ] && echo "PART_KEYS: $parts"
  echo "FORMAT: command_id | part | mode | command"
  if [ "${filtered_count:-0}" -eq 0 ]; then
    echo "NO_MATCH: adjust filters (try part=all and/or mode=all)."
    return 0
  fi
  echo "$filtered" | jq -r '.[] | "\(.id) | \(.part) | \(.mode) | \(.cmd)"' 2>/dev/null || true
}

tool_investigation_command_run() {
  local command_id="$1" out_path="${2:-}" timeout="${3:-30}" preview_lines="${4:-20}"
  local entry normalized cmd part mode reflection_text command_output

  [ -z "$command_id" ] && { echo "TOOL_ERROR: investigation.command_run — missing command_id"; return 0; }
  [[ "$timeout" =~ ^[0-9]+$ ]] || timeout=30
  [[ "$preview_lines" =~ ^[0-9]+$ ]] || preview_lines=20
  [ "$timeout" -lt 1 ] && timeout=1
  [ "$timeout" -gt 120 ] && timeout=120
  [ "$preview_lines" -lt 5 ] && preview_lines=5
  [ "$preview_lines" -gt 60 ] && preview_lines=60

  normalized="$(normalize_investigation_command_id "$command_id")"
  entry="$(lookup_investigation_command_entry "$normalized")"
  [ -z "$entry" ] && { echo "TOOL_ERROR: unknown command_id '$command_id'. Use investigation_command_catalog first."; return 0; }

  cmd="$(echo "$entry" | jq -r '.cmd' 2>/dev/null || echo "")"
  part="$(echo "$entry" | jq -r '.part' 2>/dev/null || echo "part_unknown")"
  mode="$(echo "$entry" | jq -r '.mode' 2>/dev/null || echo "inspect")"

  if [ "$mode" != "inspect" ]; then
    echo "TOOL_BLOCKED: command_id=$normalized is marked $mode and is not auto-runnable in investigation mode."
    echo "Command: $cmd"
    echo "Use investigation_command_catalog with mode=inspect to choose a read-only probe."
    return 0
  fi
  if is_mutating_cmd "$cmd"; then
    echo "TOOL_BLOCKED: command_id=$normalized matched mutating-command guard despite inspect label."
    echo "Command: $cmd"
    echo "Pick a different inspect command_id or run this manually with explicit human approval."
    return 0
  fi
  if should_block_repeated_broad_cmd "$cmd"; then
    echo "TOOL_GUIDANCE: repeated broad snapshot command blocked for efficiency: $cmd"
    echo "Choose a more targeted inspect command_id for the current lead."
    return 0
  fi

  if [ -z "$out_path" ]; then
    out_path="$CMDBOT_WORKDIR/investigation_${normalized}_step${scan_step}_$(date +%Y%m%d_%H%M%S).log"
  fi
  out_path="$(expand_path "$out_path")"
  echo "COMMAND_ID: $normalized"
  echo "PART: $part"
  echo "COMMAND: $cmd"

  if artifacts_persist_enabled; then
    mkdir -p "$(dirname "$out_path")"
    {
      echo "COMMAND_ID=$normalized"
      echo "PART=$part"
      echo "MODE=$mode"
      echo "COMMAND=$cmd"
      echo "START=$(date -Is)"
      echo "---"
      run_command_with_timeout "$cmd" "$timeout"
      echo ""
      echo "---"
      echo "END=$(date -Is)"
    } > "$out_path" 2>&1

    echo "SAVED: $out_path"
    emit_command_summary_from_file "$out_path" "$preview_lines"

    if [ "$REFLECT_ON_CMD_OUTPUT" = "true" ] && [ "$(wc -c < "$out_path" | tr -d ' ' || echo "0")" -gt 50000 ]; then
      reflection_text="$(llm_reflect_on_cmd_output "catalog:$normalized $cmd" "$out_path" 2>/dev/null || true)"
      if [ -n "$reflection_text" ]; then
        echo ""
        echo "---- LLM REVIEW ----"
        echo "$reflection_text"
      fi
    fi
  else
    command_output="$({
      echo "COMMAND_ID=$normalized"
      echo "PART=$part"
      echo "MODE=$mode"
      echo "COMMAND=$cmd"
      echo "START=$(date -Is)"
      echo "---"
      run_command_with_timeout "$cmd" "$timeout"
      echo ""
      echo "---"
      echo "END=$(date -Is)"
    } 2>&1)"
    echo "EPHEMERAL_MODE: command output kept in memory only; no evidence file was created."
    emit_command_summary_from_text "$command_output" "$preview_lines"
  fi
}

# ── File Tools (Read-Only) ───────────────────────────────────────────────────

tool_file_read() {
  local path="$1"; local max_bytes="${2:-200000}"
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.read — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.read — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  head -c "$max_bytes" "$path" 2>&1
}

tool_file_tail() {
  local path="$1"; local lines="${2:-40}"
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.tail — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.tail — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  tail -n "$lines" "$path" 2>&1
}

tool_file_grep() {
  local path="$1" pattern="$2" max_matches="${3:-120}" ignore_case="${4:-true}"
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.grep — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.grep — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  [ -z "$pattern" ] && { echo "TOOL_ERROR: file.grep — missing pattern"; return 0; }
  local flags="-nE"; [ "$ignore_case" = "true" ] && flags="-niE"
  grep $flags -- "$pattern" "$path" 2>&1 | head -n "$max_matches"
}

tool_file_find() {
  local path="$1" needle="$2" max_matches="${3:-120}" ignore_case="${4:-false}"
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.find — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.find — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  [ -z "$needle" ] && { echo "TOOL_ERROR: file.find — missing needle"; return 0; }
  local flags="-nF"; [ "$ignore_case" = "true" ] && flags="-niF"
  grep $flags -- "$needle" "$path" 2>&1 | head -n "$max_matches"
}

tool_file_stat() {
  local path="$1"
  path="$(expand_path "$path")"
  [ -z "$path" ] && { echo "TOOL_ERROR: file.stat — missing path"; return 0; }
  [ ! -e "$path" ] && { echo "TOOL_ERROR: file.stat — path not found: $path"; return 0; }
  echo "=== STAT: $path ==="
  stat -x "$path" 2>&1
  echo -e "\n=== XATTR ==="
  xattr -l "$path" 2>/dev/null || echo "(none)"
  echo -e "\n=== FLAGS ==="
  ls -lO "$path" 2>/dev/null || ls -la "$path" 2>/dev/null
  echo -e "\n=== FILE TYPE ==="
  file "$path" 2>/dev/null || echo "(unknown)"
}

tool_file_signal_extract() {
  local path="$1" profile="${2:-generic}" max_matches="${3:-80}" include_head_tail="${4:-true}"
  local bytes lines pattern match_count
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.signal_extract — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.signal_extract — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }

  bytes=$(wc -c < "$path" | tr -d ' ' || echo "0")
  lines=$(wc -l < "$path" | tr -d ' ' || echo "0")

  case "$profile" in
    network)
      pattern='(LISTEN|ESTABLISHED|SYN_SENT|CLOSE_WAIT|utun[0-9]*|awdl|proxy|resolver|dns|:53\b|:443\b|rejected|denied|timeout|refused|failed)'
      ;;
    process)
      pattern='(\/tmp\/|\/private\/tmp\/|\/Users\/[^[:space:]]+\/\.|DYLD_|LD_PRELOAD|launchctl|curl |wget |osascript|python|perl|ruby|node|nc |ncat|ssh |socat|unsigned|ad[- ]hoc|invalid signature|permission denied|no such file)'
      ;;
    persistence)
      pattern='(LaunchAgent|LaunchDaemon|RunAtLoad|KeepAlive|ProgramArguments|StartInterval|StartCalendarInterval|WatchPaths|QueueDirectories|MachServices|cron|crontab|login item)'
      ;;
    security)
      pattern='(System Integrity Protection|Gatekeeper|assessments enabled|disabled|amfi|xprotect|tcc|profile|securetoken|firmware|nvram|boot-args|csr|denied|failed|error)'
      ;;
    *)
      pattern='(error|failed|denied|reject|suspicious|warning|malware|unsigned|ad[- ]hoc|timeout|no such file|permission denied)'
      ;;
  esac

  echo "=== SIGNAL EXTRACT ==="
  echo "Path: $path"
  echo "Profile: $profile"
  echo "Lines: $lines"
  echo "Bytes: $bytes"

  if [ "$include_head_tail" = "true" ]; then
    echo ""
    echo "---- HEAD (first 20 lines) ----"
    sed -n '1,20p' "$path" 2>/dev/null || true
    echo ""
    echo "---- TAIL (last 20 lines) ----"
    tail -n 20 "$path" 2>/dev/null || true
  fi

  echo ""
  echo "---- HIGH-SIGNAL MATCHES ----"
  grep -niE -- "$pattern" "$path" 2>/dev/null | head -n "$max_matches" || true
  match_count=$(grep -ciE -- "$pattern" "$path" 2>/dev/null || true)
  match_count="${match_count:-0}"
  [ "$match_count" -eq 0 ] && echo "(no matches for this profile)"
  echo ""
  echo "MatchCount: $match_count"
}

tool_launchd_plist_triage() {
  local path="$1" include_signature="${2:-false}"
  local plistbuddy exec_path program_args joined_args flag_count
  local label program run_at_load keep_alive user_name stdout_path stderr_path working_dir
  local -a risk_flags=()

  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: launchd.plist_triage — path not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: launchd.plist_triage — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }

  plistbuddy="/usr/libexec/PlistBuddy"
  if [ ! -x "$plistbuddy" ]; then
    echo "TOOL_ERROR: launchd.plist_triage — PlistBuddy not available"
    return 0
  fi

  label="$("$plistbuddy" -c "Print :Label" "$path" 2>/dev/null || true)"
  program="$("$plistbuddy" -c "Print :Program" "$path" 2>/dev/null || true)"
  run_at_load="$("$plistbuddy" -c "Print :RunAtLoad" "$path" 2>/dev/null || true)"
  keep_alive="$("$plistbuddy" -c "Print :KeepAlive" "$path" 2>/dev/null || true)"
  user_name="$("$plistbuddy" -c "Print :UserName" "$path" 2>/dev/null || true)"
  stdout_path="$("$plistbuddy" -c "Print :StandardOutPath" "$path" 2>/dev/null || true)"
  stderr_path="$("$plistbuddy" -c "Print :StandardErrorPath" "$path" 2>/dev/null || true)"
  working_dir="$("$plistbuddy" -c "Print :WorkingDirectory" "$path" 2>/dev/null || true)"

  program_args=""
  local i arg
  for i in 0 1 2 3 4 5 6 7; do
    arg="$("$plistbuddy" -c "Print :ProgramArguments:$i" "$path" 2>/dev/null || true)"
    [ -z "$arg" ] && continue
    program_args="$program_args [$i]=$arg"
  done

  exec_path="$program"
  if [ -z "$exec_path" ]; then
    exec_path="$("$plistbuddy" -c "Print :ProgramArguments:0" "$path" 2>/dev/null || true)"
  fi
  joined_args="$(printf "%s %s" "$exec_path" "$program_args" | tr '\n' ' ')"

  [ -z "$label" ] && risk_flags+=("Missing Label key")
  if [ -n "$label" ] && ! echo "$label" | grep -Eq '^com\.apple\.'; then
    risk_flags+=("Non-Apple launchd label baseline deviation: $label")
  fi
  if [ -z "$exec_path" ]; then
    risk_flags+=("No executable path resolved from Program/ProgramArguments:0")
  else
    if [ ! -e "$exec_path" ]; then
      risk_flags+=("Executable path does not exist: $exec_path")
    fi
    if echo "$exec_path" | grep -Eq '^(/tmp/|/private/tmp/|/Volumes/|/Users/|'"$CURRENT_HOME"'/)'; then
      risk_flags+=("Executable launched from user/temp/removable path: $exec_path")
    fi
    if ! echo "$exec_path" | grep -Eq '^(/System/|/usr/|/bin/|/sbin/|/Library/|/opt/homebrew/|/usr/local/|'"$CURRENT_HOME"'/\.local/bin/)'; then
      risk_flags+=("Executable path is unusual for launchd workload: $exec_path")
    fi
  fi
  if echo "$joined_args" | grep -Eqi '(while[[:space:]]+true|ifconfig[[:space:]]+(awdl|utun)|launchctl[[:space:]]+(load|bootstrap|enable|disable)|pfctl|route[[:space:]]+(add|delete|change)|curl[[:space:]]|wget[[:space:]]|osascript)'; then
    risk_flags+=("Arguments contain high-risk control/network manipulation patterns")
  fi
  if echo "$run_at_load" | grep -Eq '^(true|1)$' && echo "$keep_alive" | grep -Eq '^(true|1)$'; then
    risk_flags+=("RunAtLoad+KeepAlive persistence combination present")
  fi

  echo "=== LAUNCHD PLIST TRIAGE ==="
  echo "Plist: $path"
  echo "FileMeta: $(ls -ldO "$path" 2>/dev/null | awk '{$1=$1;print}')"
  echo "Label: ${label:-<missing>}"
  echo "Executable: ${exec_path:-<unresolved>}"
  echo "RunAtLoad: ${run_at_load:-<unset>}"
  echo "KeepAlive: ${keep_alive:-<unset>}"
  echo "UserName: ${user_name:-<unset>}"
  echo "WorkingDirectory: ${working_dir:-<unset>}"
  echo "StdOutPath: ${stdout_path:-<unset>}"
  echo "StdErrPath: ${stderr_path:-<unset>}"
  echo "ProgramArguments(first 8): ${program_args:-<none>}"

  flag_count=0
  for _ in "${risk_flags[@]-}"; do flag_count=$((flag_count + 1)); done
  echo ""
  echo "RiskFlagCount: $flag_count"
  if [ "$flag_count" -gt 0 ]; then
    echo "RiskFlags:"
    for flag in "${risk_flags[@]-}"; do
      echo " - $flag"
    done
  else
    echo "RiskFlags: (none from heuristic checks)"
  fi

  if [ "$include_signature" = "true" ] && [ -n "$exec_path" ] && [ -e "$exec_path" ]; then
    echo ""
    echo "=== EXECUTABLE SIGNATURE SUMMARY ==="
    codesign -dvv "$exec_path" 2>&1 | awk -F= '/Identifier=|TeamIdentifier=|Authority=/{print}' | head -n 12
    spctl --assess --verbose=4 "$exec_path" 2>&1 | head -n 5
  fi
}

# ── Directory Tools (Read-Only) ──────────────────────────────────────────────

tool_dir_list() {
  local dir="$1"; local max="${2:-200}"
  dir="$(expand_path "$dir")"
  [ -z "$dir" ] || [ ! -d "$dir" ] && { echo "TOOL_ERROR: dir.list — not a directory: $dir"; return 0; }
  check_path_in_scope "$dir" || { echo "TOOL_BLOCKED: dir.list — path outside scan scope ($SCAN_SCOPE_DIR): $dir"; return 0; }
  ls -1A "$dir" 2>/dev/null | head -n "$max"
}

tool_dir_tree() {
  local dir="$1" ignore="${2:-node_modules}" max_lines="${3:-400}"
  dir="$(expand_path "$dir")"
  [ -z "$dir" ] || [ ! -d "$dir" ] && { echo "TOOL_ERROR: dir.tree — not a directory: $dir"; return 0; }
  check_path_in_scope "$dir" || { echo "TOOL_BLOCKED: dir.tree — path outside scan scope ($SCAN_SCOPE_DIR): $dir"; return 0; }
  if command -v tree >/dev/null 2>&1; then
    tree -I "$ignore" -L 3 "$dir" 2>&1 | head -n "$max_lines"
  else
    find "$dir" -maxdepth 3 -not -path "*/$ignore/*" 2>/dev/null | head -n "$max_lines"
  fi
}

tool_dir_grep() {
  local dir="$1" pattern="$2" includes="${3:-*}" excludes="${4:-node_modules|.git|.DS_Store}" max_matches="${5:-200}" ignore_case="${6:-true}"
  dir="$(expand_path "$dir")"
  [ -z "$dir" ] || [ ! -d "$dir" ] && { echo "TOOL_ERROR: dir.grep — not a directory: $dir"; return 0; }
  check_path_in_scope "$dir" || { echo "TOOL_BLOCKED: dir.grep — path outside scan scope ($SCAN_SCOPE_DIR): $dir"; return 0; }
  [ -z "$pattern" ] && { echo "TOOL_ERROR: dir.grep — missing pattern"; return 0; }
  local icase=""; [ "$ignore_case" = "true" ] && icase="-i"
  find "$dir" -type f -name "$includes" 2>/dev/null \
    | grep -Ev "$excludes" 2>/dev/null \
    | while IFS= read -r f; do grep -nE $icase -- "$pattern" "$f" 2>/dev/null | sed "s|^|$f:|"; done \
    | head -n "$max_matches"
}

tool_dir_find() {
  local dir="$1" name_pattern="${2:-*}" type_filter="${3:-f}" max_depth="${4:-3}" mtime_days="${5:-}" max_results="${6:-200}" preview="${7:-false}"
  dir="$(expand_path "$dir")"
  [ -z "$dir" ] || [ ! -d "$dir" ] && { echo "TOOL_ERROR: dir.find — not a directory: $dir"; return 0; }
  [ "$dir" = "/" ] && { echo "TOOL_BLOCKED: dir.find refuses root filesystem"; return 0; }
  check_path_in_scope "$dir" || { echo "TOOL_BLOCKED: dir.find — path outside scan scope ($SCAN_SCOPE_DIR): $dir"; return 0; }
  local find_cmd="find \"$dir\" -maxdepth $max_depth -type $type_filter -name '$name_pattern'"
  [ -n "$mtime_days" ] && find_cmd="$find_cmd -mtime -$mtime_days"
  if [ "$preview" = "true" ]; then
    eval "$find_cmd" 2>/dev/null | head -n "$max_results" | while IFS= read -r f; do
      echo "--- $f ---"; head -n 5 "$f" 2>/dev/null || echo "(not readable)"; echo ""
    done
  else
    eval "$find_cmd" 2>/dev/null | head -n "$max_results"
  fi
}

# ── Shell Execution (Read-Only Enforced) ─────────────────────────────────────

tool_shell_exec() {
  local cmd="$1" timeout="${2:-30}"
  local shell_output reflection_text tmpfile shell_lines shell_bytes spool_path
  [ -z "$cmd" ] && { echo "TOOL_ERROR: shell.exec — missing cmd"; return 0; }
  if should_block_repeated_broad_cmd "$cmd"; then
    echo "TOOL_GUIDANCE: Repeated broad snapshot command blocked for efficiency: $cmd"
    echo "Use targeted follow-up commands (file_signal_extract/file_grep/file_tail or scoped process/network queries) based on prior anomalies."
    return 0
  fi
  is_mutating_cmd "$cmd" && { echo "TOOL_BLOCKED: shell.exec rejected mutating command: $cmd"; return 0; }
  shell_output="$(run_command_with_timeout "$cmd" "$timeout")"
  shell_lines=$(printf "%s\n" "$shell_output" | wc -l | tr -d ' ')
  shell_bytes=$(printf "%s" "$shell_output" | wc -c | tr -d ' ')

  if [ "$shell_lines" -gt "$SHELL_EXEC_MAX_RETURN_LINES" ] || [ "$shell_bytes" -gt "$SHELL_EXEC_MAX_RETURN_BYTES" ]; then
    echo "TOOL_GUARD: shell.exec output too large for direct return ($shell_lines lines, $shell_bytes bytes)."
    if artifacts_persist_enabled; then
      spool_path="$CMDBOT_WORKDIR/shell_exec_${scan_step}_$(date +%Y%m%d_%H%M%S)_$$.txt"
      printf "%s" "$shell_output" > "$spool_path"
      echo "WROTE: $spool_path ($shell_bytes bytes)"
      emit_command_summary_from_file "$spool_path" "$SHELL_EXEC_PREVIEW_LINES"

      if [ "$REFLECT_ON_CMD_OUTPUT" = "true" ]; then
        reflection_text="$(llm_reflect_on_cmd_output "$cmd" "$spool_path" 2>/dev/null || true)"
        if [ -n "$reflection_text" ]; then
          echo ""
          echo "---- LLM REVIEW (BASELINE DEVIATION TRIAGE) ----"
          echo "$reflection_text"
        fi
      fi
    else
      echo "EPHEMERAL_MODE: output kept in memory only; no spool file was created."
      emit_command_summary_from_text "$shell_output" "$SHELL_EXEC_PREVIEW_LINES"
    fi
    return 0
  fi

  printf "%s\n" "$shell_output"

  if [ "$REFLECT_ON_CMD_OUTPUT" = "true" ] && [ "${shell_bytes:-0}" -gt 50000 ]; then
    tmpfile=$(mktemp /tmp/cmdbot_shell_reflect.XXXXXX)
    printf "%s" "$shell_output" > "$tmpfile"
    reflection_text="$(llm_reflect_on_cmd_output "$cmd" "$tmpfile" 2>/dev/null || true)"
    rm -f "$tmpfile"
    if [ -n "$reflection_text" ]; then
      echo ""
      echo "---- LLM REVIEW ----"
      echo "$reflection_text"
    fi
  fi
}

tool_cmd_exec_to_file() {
  local cmd="$1" out_path="$2" timeout="${3:-30}" preview_lines="${4:-25}"
  local reflection_text command_output
  out_path="$(expand_path "$out_path")"
  [ -z "$cmd" ] || [ -z "$out_path" ] && { echo "TOOL_ERROR: cmd.exec_to_file — requires cmd and out_path"; return 0; }
  if should_block_repeated_broad_cmd "$cmd"; then
    echo "TOOL_GUIDANCE: Repeated broad snapshot command blocked for efficiency: $cmd"
    echo "Use targeted command variants and analyze existing evidence files instead of recapturing the same broad snapshot."
    return 0
  fi
  is_mutating_cmd "$cmd" && { echo "TOOL_BLOCKED: cmd.exec_to_file rejected mutating command: $cmd"; return 0; }

  if artifacts_persist_enabled; then
    mkdir -p "$(dirname "$out_path")"
    run_command_with_timeout "$cmd" "$timeout" > "$out_path" 2>&1
    echo "SAVED: $out_path"
    emit_command_summary_from_file "$out_path" "$preview_lines"

    if [ "$REFLECT_ON_CMD_OUTPUT" = "true" ] && [ "$(wc -c < "$out_path" | tr -d ' ' || echo "0")" -gt 50000 ]; then
      reflection_text="$(llm_reflect_on_cmd_output "$cmd" "$out_path" 2>/dev/null || true)"
      if [ -n "$reflection_text" ]; then
        echo ""
        echo "---- LLM REVIEW ----"
        echo "$reflection_text"
      fi
    fi
  else
    command_output="$(run_command_with_timeout "$cmd" "$timeout")"
    echo "EPHEMERAL_MODE: requested output path was not written: $out_path"
    emit_command_summary_from_text "$command_output" "$preview_lines"
  fi
}

tool_cmd_exec_to_file_bundle() {
  local commands_json="$1" out_path="$2" timeout="${3:-30}" preview_lines="${4:-25}"
  local reflection_text bundle_output cmd_count
  out_path="$(expand_path "$out_path")"

  [ -z "$commands_json" ] || [ -z "$out_path" ] && {
    echo "TOOL_ERROR: cmd.exec_to_file_bundle — requires commands and out_path"
    return 0
  }

  if ! echo "$commands_json" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
    echo "TOOL_ERROR: cmd.exec_to_file_bundle — commands must be a non-empty array"
    return 0
  fi

  cmd_count=$(echo "$commands_json" | jq -r 'length' 2>/dev/null || echo "0")

  if artifacts_persist_enabled; then
    mkdir -p "$(dirname "$out_path")"
    build_command_bundle_output "$commands_json" "$timeout" > "$out_path" 2>&1
    echo "SAVED: $out_path (${cmd_count} commands)"
    emit_command_summary_from_file "$out_path" "$preview_lines"

    if [ "$REFLECT_ON_CMD_OUTPUT" = "true" ] && [ "$(wc -c < "$out_path" | tr -d ' ' || echo "0")" -gt 50000 ]; then
      reflection_text="$(llm_reflect_on_cmd_output "cmd_bundle[$cmd_count commands]" "$out_path" 2>/dev/null || true)"
      if [ -n "$reflection_text" ]; then
        echo ""
        echo "---- LLM REVIEW ----"
        echo "$reflection_text"
      fi
    fi
  else
    bundle_output="$(build_command_bundle_output "$commands_json" "$timeout")"
    echo "EPHEMERAL_MODE: requested output path was not written: $out_path"
    emit_command_summary_from_text "$bundle_output" "$preview_lines"
  fi
}

# ── Apple / macOS Inspection Tools ───────────────────────────────────────────

tool_apple_man() {
  local command_name="$1" max_lines="${2:-200}"
  [ -z "$command_name" ] && { echo "TOOL_ERROR: apple.man — missing command_name"; return 0; }
  man "$command_name" 2>&1 | col -bx 2>/dev/null | head -n "$max_lines"
}

tool_apple_codesign_verify() {
  local target="$1"; target="$(expand_path "$target")"
  [ -z "$target" ] && { echo "TOOL_ERROR: apple.codesign_verify — missing target"; return 0; }
  [ ! -e "$target" ] && { echo "TOOL_ERROR: apple.codesign_verify — not found: $target"; return 0; }
  echo "=== CODESIGN VERIFY ==="; codesign -dvvv "$target" 2>&1 || true
  echo -e "\n=== CODESIGN ASSESSMENT (spctl) ==="; spctl --assess --verbose=4 "$target" 2>&1 || true
}

tool_apple_entitlements() {
  local target="$1"; target="$(expand_path "$target")"
  [ -z "$target" ] || [ ! -e "$target" ] && { echo "TOOL_ERROR: apple.entitlements — not found: $target"; return 0; }
  codesign -d --entitlements - "$target" 2>&1 || true
}

# ── File Mutation Tools (Ack Required) ───────────────────────────────────────

tool_file_write() {
  local path="$1" content="$2" ack="$3"
  require_ack "$ack" || return 0
  path="$(expand_path "$path")"
  [ -z "$path" ] && { echo "TOOL_ERROR: file.write — missing path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.write — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  mkdir -p "$(dirname "$path")"
  printf "%s" "$content" > "$path"
  echo "WROTE: $path ($(wc -c < "$path" | tr -d ' ') bytes)"
}

tool_file_replace() {
  local path="$1" new_content="$2" ack="$3"
  require_ack "$ack" || return 0
  path="$(expand_path "$path")"
  [ -z "$path" ] || [ ! -f "$path" ] && { echo "TOOL_ERROR: file.replace — not found: $path"; return 0; }
  check_path_in_scope "$path" || { echo "TOOL_BLOCKED: file.replace — path outside scan scope ($SCAN_SCOPE_DIR): $path"; return 0; }
  local backup="$CMDBOT_BACKUPS_DIR/$(basename "$path").bak.$(date +%Y%m%d_%H%M%S)"
  cp -p "$path" "$backup" 2>/dev/null || true
  printf "%s" "$new_content" > "$path"
  echo "REPLACED: $path | BACKUP: $backup"
}

# ── Plist Tools ──────────────────────────────────────────────────────────────

tool_plist_to_xml() {
  local in_path="$1" out_path="$2" ack="$3"
  require_ack "$ack" || return 0
  in_path="$(expand_path "$in_path")"; out_path="$(expand_path "$out_path")"
  [ ! -f "$in_path" ] && { echo "TOOL_ERROR: plist.to_xml — not found: $in_path"; return 0; }
  mkdir -p "$(dirname "$out_path")"
  plutil -convert xml1 -o "$out_path" "$in_path" 2>&1; echo "CONVERTED: $out_path (xml1)"
}

tool_plist_to_binary() {
  local in_path="$1" out_path="$2" ack="$3"
  require_ack "$ack" || return 0
  in_path="$(expand_path "$in_path")"; out_path="$(expand_path "$out_path")"
  [ ! -f "$in_path" ] && { echo "TOOL_ERROR: plist.to_binary — not found: $in_path"; return 0; }
  mkdir -p "$(dirname "$out_path")"
  plutil -convert binary1 -o "$out_path" "$in_path" 2>&1; echo "CONVERTED: $out_path (binary1)"
}

tool_plist_inplace_to_xml() {
  local path="$1" ack="$2"
  require_ack "$ack" || return 0
  path="$(expand_path "$path")"
  [ ! -f "$path" ] && { echo "TOOL_ERROR: plist.inplace_to_xml — not found: $path"; return 0; }
  local backup="$CMDBOT_BACKUPS_DIR/$(basename "$path").bak.$(date +%Y%m%d_%H%M%S)"
  cp -p "$path" "$backup" 2>/dev/null || true
  plutil -convert xml1 "$path" 2>&1; echo "INPLACE XML: $path | BACKUP: $backup"
}

tool_plist_inplace_to_binary() {
  local path="$1" ack="$2"
  require_ack "$ack" || return 0
  path="$(expand_path "$path")"
  [ ! -f "$path" ] && { echo "TOOL_ERROR: plist.inplace_to_binary — not found: $path"; return 0; }
  local backup="$CMDBOT_BACKUPS_DIR/$(basename "$path").bak.$(date +%Y%m%d_%H%M%S)"
  cp -p "$path" "$backup" 2>/dev/null || true
  plutil -convert binary1 "$path" 2>&1; echo "INPLACE BINARY: $path | BACKUP: $backup"
}

# ── Pluginkit Tools ──────────────────────────────────────────────────────────

tool_pluginkit_list_active() {
  pluginkit -m 2>/dev/null | awk '$1=="+"' | sed 's/[[:space:]]\+/ /g' | head -n 220
}

tool_pluginkit_disable_all_active() {
  local ack="$1"; require_ack "$ack" || return 0
  local before after
  before="$(pluginkit -m 2>/dev/null | awk '$1=="+"' | sed 's/[[:space:]]\+/ /g')"
  echo "=== ACTIVE (+) BEFORE ==="; echo "$before"; echo "=== DISABLING ==="
  printf '%s\n' "$before" | awk '{print $2}' | sed 's/(.*)//' \
    | xargs -n1 pluginkit -e ignore -i 2>/dev/null || true
  sudo killall -HUP pkd 2>/dev/null || true
  after="$(pluginkit -m 2>/dev/null | awk '$1=="+"' | sed 's/[[:space:]]\+/ /g')"
  echo "=== ACTIVE (+) AFTER ==="; echo "${after:-<none>}"
  echo "=== CHANGED (disabled) ==="
  comm -23 \
    <(printf '%s\n' "$before" | awk '{print $2}' | sed 's/(.*)//' | sort -u) \
    <(printf '%s\n' "$after" | awk '{print $2}' | sed 's/(.*)//' | sort -u)
}

#==============================================================================
# TOOL DISPATCHER
#==============================================================================
# Takes an API function name + arguments JSON, routes to the right tool.
# Converts API names (underscores) to internal names (dots) automatically.
#==============================================================================

dispatch_tool_call() {
  local api_func_name="$1"
  local args_json="$2"
  local internal_name
  internal_name="$(api_name_to_internal "$api_func_name")"

  echo -e "${DIM}${CYAN}[TOOL] $internal_name${RESET}"

  # Helper to extract args
  _arg() { echo "$args_json" | jq -r ".$1 // empty" 2>/dev/null; }
  _arg_default() { echo "$args_json" | jq -r ".$1 // \"$2\"" 2>/dev/null; }
  _arg_json() { echo "$args_json" | jq -c ".$1 // $2" 2>/dev/null; }

  case "$internal_name" in

    # ── Read-only file tools ──
    file.read)      tool_file_read "$(_arg path)" "$(_arg_default max_bytes 200000)" ;;
    file.tail)      tool_file_tail "$(_arg path)" "$(_arg_default lines 40)" ;;
    file.grep)      tool_file_grep "$(_arg path)" "$(_arg pattern)" "$(_arg_default max_matches 120)" "$(_arg_default ignore_case true)" ;;
    file.find)      tool_file_find "$(_arg path)" "$(_arg needle)" "$(_arg_default max_matches 120)" "$(_arg_default ignore_case false)" ;;
    file.stat)      tool_file_stat "$(_arg path)" ;;
    file.signal_extract)   tool_file_signal_extract "$(_arg path)" "$(_arg_default profile generic)" "$(_arg_default max_matches 80)" "$(_arg_default include_head_tail true)" ;;
    launchd.plist_triage)  tool_launchd_plist_triage "$(_arg path)" "$(_arg_default include_signature false)" ;;

    # ── Read-only directory tools ──
    dir.list)       tool_dir_list "$(_arg dir)" "$(_arg_default max 200)" ;;
    dir.tree)       tool_dir_tree "$(_arg dir)" "$(_arg_default ignore node_modules)" "$(_arg_default max_lines 400)" ;;
    dir.grep)       tool_dir_grep "$(_arg dir)" "$(_arg pattern)" "$(_arg_default includes '*')" "$(_arg_default excludes 'node_modules|.git|.DS_Store')" "$(_arg_default max_matches 200)" "$(_arg_default ignore_case true)" ;;
    dir.find)       tool_dir_find "$(_arg dir)" "$(_arg_default name '*')" "$(_arg_default type f)" "$(_arg_default max_depth 3)" "$(_arg mtime_days)" "$(_arg_default max_results 200)" "$(_arg_default preview false)" ;;

    # ── Shell execution ──
    shell.exec)         tool_shell_exec "$(_arg cmd)" "$(_arg_default timeout 30)" ;;
    cmd.exec_to_file)   tool_cmd_exec_to_file "$(_arg cmd)" "$(_arg out_path)" "$(_arg_default timeout 30)" "$(_arg_default preview_lines 120)" ;;
    cmd.exec_to_file_bundle)   tool_cmd_exec_to_file_bundle "$(_arg_json commands '[]')" "$(_arg out_path)" "$(_arg_default timeout 30)" "$(_arg_default preview_lines 120)" ;;
    investigation.command_catalog) tool_investigation_command_catalog "$(_arg_default part all)" "$(_arg_default mode inspect)" "$(_arg_default max 30)" ;;
    investigation.command_run)     tool_investigation_command_run "$(_arg command_id)" "$(_arg out_path)" "$(_arg_default timeout 30)" "$(_arg_default preview_lines 20)" ;;

    # ── Apple / macOS inspection ──
    apple.man)              tool_apple_man "$(_arg command)" "$(_arg_default max_lines 200)" ;;
    apple.codesign_verify)  tool_apple_codesign_verify "$(_arg target)" ;;
    apple.entitlements)     tool_apple_entitlements "$(_arg target)" ;;

    # ── File mutation (ack required) ──
    file.write)     tool_file_write "$(_arg path)" "$(_arg content)" "$(_arg ack)" ;;
    file.replace)   tool_file_replace "$(_arg path)" "$(_arg content)" "$(_arg ack)" ;;

    # ── Plist tools (ack required) ──
    plist.to_xml)             tool_plist_to_xml "$(_arg in_path)" "$(_arg out_path)" "$(_arg ack)" ;;
    plist.to_binary)          tool_plist_to_binary "$(_arg in_path)" "$(_arg out_path)" "$(_arg ack)" ;;
    plist.inplace_to_xml)     tool_plist_inplace_to_xml "$(_arg path)" "$(_arg ack)" ;;
    plist.inplace_to_binary)  tool_plist_inplace_to_binary "$(_arg path)" "$(_arg ack)" ;;

    # ── Pluginkit ──
    pluginkit.list_active)          tool_pluginkit_list_active ;;
    pluginkit.disable_all_active)   tool_pluginkit_disable_all_active "$(_arg ack)" ;;

    # ── Scan control ──
    scan.finding)
      local severity message origin_file origin_type fix_action finding
      severity="$(_arg_default severity INFO)"
      message="$(_arg_default message 'No details')"
      origin_file="$(_arg_default origin_file '')"
      origin_type="$(_arg_default origin_type '')"
      fix_action="$(_arg_default fix_action '')"
      finding="[$severity] $message"
      findings+=("$finding")
      findings_total=$((findings_total + 1))
      log_to_findings "[FINDING] $finding"
      [ -n "$origin_file" ] && log_to_findings "  ORIGIN_FILE: $origin_file"
      [ -n "$origin_type" ] && log_to_findings "  ORIGIN_TYPE: $origin_type"
      [ -n "$fix_action" ] && log_to_findings "  FIX_ACTION: $fix_action"
      case "$severity" in
        CRITICAL) echo -e "${RED}${BOLD}$finding${RESET}" ;;
        WARNING)  echo -e "${YELLOW}$finding${RESET}" ;;
        *)        echo -e "${CYAN}$finding${RESET}" ;;
      esac
      [ -n "$origin_file" ] && echo -e "${DIM}  Origin: $origin_file ($origin_type)${RESET}"
      [ -n "$fix_action" ] && echo -e "${DIM}  Fix: $fix_action${RESET}"
      echo "FINDING_RECORDED"
      ;;
    scan.complete)
      if should_block_soft_limit_scan_complete; then
        local new_findings guard_msg
        new_findings="$(soft_limit_investigation_new_findings_count)"
        guard_msg="SCAN_COMPLETE_BLOCKED: Soft-limit investigation still active. rounds=$soft_limit_investigation_rounds/$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS findings=$new_findings/$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS goal='${soft_limit_focus_goal:-unresolved}'. Continue targeted investigation and report with scan_finding."
        log_to_findings "$guard_msg"
        echo "$guard_msg"
      else
        echo "SCAN_COMPLETE"
      fi
      ;;

    *)
      # Try macOS focused tools
      if [ "${MACOS_TOOLS_LOADED:-false}" = true ]; then
        # Build a JSON blob the module dispatcher expects: {"tool":"internal.name","args":{...}}
        local compat_json
        compat_json=$(jq -n --arg tool "$internal_name" --argjson args "$args_json" '{tool: $tool, args: $args}' 2>/dev/null)
        local macos_result
        macos_result="$(execute_macos_tool_call "$compat_json" 2>&1)"
        if [ $? -eq 0 ] && [ "$macos_result" != "TOOL_NOT_HANDLED" ]; then
          echo "$macos_result"
          return 0
        fi
      fi
      # Try threat intel tools
      if [ "${THREAT_INTEL_LOADED:-false}" = true ]; then
        local compat_json
        compat_json=$(jq -n --arg tool "$internal_name" --argjson args "$args_json" '{tool: $tool, args: $args}' 2>/dev/null)
        local intel_result
        intel_result="$(execute_intel_tool_call "$compat_json" 2>&1)"
        if [ $? -eq 0 ] && [ "$intel_result" != "TOOL_NOT_HANDLED" ]; then
          echo "$intel_result"
          return 0
        fi
      fi
      # Try plugin tools
      if [ "${PLUGIN_SYSTEM_LOADED:-false}" = true ] && [ "${#LOADED_PLUGIN_IDS[@]}" -gt 0 ]; then
        local compat_json
        compat_json=$(jq -n --arg tool "$internal_name" --argjson args "$args_json" '{tool: $tool, args: $args}' 2>/dev/null)
        local plugin_result
        plugin_result="$(execute_plugin_tool_call "$compat_json" 2>&1)"
        if [ $? -eq 0 ] && [ "$plugin_result" != "TOOL_NOT_HANDLED" ]; then
          echo "$plugin_result"
          return 0
        fi
      fi
      echo "TOOL_ERROR: Unknown tool '$internal_name'. Check spelling."
      ;;
  esac
}

#==============================================================================
# THE PARANOID SYSTEM PROMPT
#==============================================================================
# With native tool calling, we no longer need the JSON format instructions.
# The model is constrained to only call defined tools — no freestyle JSON.
#==============================================================================

generate_system_prompt() {
  if [ "$SYSTEM_PROMPT_STYLE" = "compact" ]; then
    cat << SYSTEMPROMPT_COMPACT
You are PARANOID SCANNER for macOS incident discovery.
Mission: find stealthy persistence, execution abuse, privilege abuse, and suspicious network behavior.

Hard rules:
- Use only provided tools. Prefer one focused tool per turn; you may use up to $API_MAX_TOOL_CALLS tightly related read-only tool calls when that clearly saves a round trip.
- START with direct tools: security_status, persistence_launchd, net_sockets_ownership, etc.
  Do NOT browse investigation_command_catalog first — use direct tools to collect data, then trace findings to root cause.
- For each anomaly found, trace it to its ROOT CAUSE: the specific file, plist, config, or service that causes it.
- Treat unexplained deviations as potentially malicious until disproven.
- Avoid repeating broad commands. Use file_grep/file_read on saved artifacts instead.
- Keep each turn concise — call the tool, do not explain what you plan to do.
$([ "$EPHEMERAL_MODE" = "true" ] && echo "- EPHEMERAL MODE is active. Do not rely on saved evidence files from command-capture tools; their outputs stay in memory only.")

Required pattern for each finding:
1) Collect evidence with a direct tool (persistence_launchd, net_sockets_ownership, etc.).
2) Trace anomaly to origin: which file/plist/config causes it?
3) Record with scan_finding including origin_file, origin_type, and fix_action.
4) Move to next lead.

Completion:
- Call scan_complete only after no meaningful unresolved leads remain.
- If scan_complete is blocked, continue investigations and report findings.

User posture:
- Posture: $USER_POSTURE — $USER_POSTURE_LABEL
- Calibrate normal-vs-suspicious decisions against this posture.
$USER_POSTURE_DETAIL
SYSTEMPROMPT_COMPACT
    return 0
  fi

  # Part 1: Static preamble + dynamic posture injection
  cat << SYSTEMPROMPT_DYNAMIC
You are PARANOID SCANNER — an autonomous macOS deep-investigation engine.

═══════════════════════════════════════════════════════════════
MISSION
═══════════════════════════════════════════════════════════════
You are performing a deep, methodical security investigation of a macOS system.
Your goal is to find STEALTHY, ADVANCED threats — the kind planted by
sophisticated adversaries who try extremely hard not to be detected.

You are NOT looking for common malware that any antivirus would catch.
You ARE hunting for:
  - Processes masquerading as Apple/system processes
  - LaunchAgents/LaunchDaemons with suspicious properties
  - Unsigned or ad-hoc signed binaries in system paths
  - Hidden persistence mechanisms (login items, cron, at, periodic)
  - Kernel extensions or system extensions from unknown developers
  - Modified system binaries (replaced or shimmed)
  - Suspicious network connections (especially to unusual ports/IPs)
  - Environment variable injection (.zshrc, .bashrc, .bash_profile)
  - Dylib hijacking or injection (DYLD_INSERT_LIBRARIES, etc.)
  - TCC database modifications (privacy permission grants)
  - Profiles installed via MDM or manually
  - XPC services that don't match their parent bundle
  - SSH authorized_keys, known_hosts anomalies
  - Crontab entries, at jobs, periodic scripts
  - Files with recent modification dates in system directories
  - Processes with unusual parent-child relationships
  - Open file descriptors pointing to deleted files
  - utun/tunnel interfaces owned by unexpected processes
  - Rogue DNS resolvers or proxy injection
  - AWDL/P2P interfaces in unexpected states
  - Cross-process patterns: same binary appearing in network + persistence + TCC

═══════════════════════════════════════════════════════════════
USER POSTURE: $USER_POSTURE — $USER_POSTURE_LABEL
═══════════════════════════════════════════════════════════════
$USER_POSTURE_DETAIL

CRITICAL: Calibrate ALL findings against this posture.
What is normal for a Maximalist is a RED FLAG for a Hermit.

═══════════════════════════════════════════════════════════════
INVESTIGATION DOCTRINE: WORST-CASE-FIRST
═══════════════════════════════════════════════════════════════
For EVERY piece of data you collect, you MUST:

1. ASSUME THE WORST — formulate the most threatening explanation
   for what you see. A listener on *:3001? Assume C2 backdoor until
   proven otherwise. AirPlayXPC SYN_SENT to a LAN IP? Assume lateral
   movement probe until proven otherwise. A process named like Apple
   but in an odd path? Assume trojan masquerade.

2. BUILD THE CASE — your next tool calls should attempt to PROVE or
   DISPROVE the worst-case hypothesis:
   - Binary attribution: who owns it, who signed it, when installed
   - Network attribution: where is it connecting, why, for how long
   - Persistence attribution: how does it survive reboot
   - Cross-reference: does this process also appear in LaunchDaemons?
     Does this IP also appear in DNS queries? Does this binary also
     have TCC permissions?

3. CONNECT THE DOTS — maintain a running threat narrative:
   - Process X listening on port Y → check if X has persistence
   - Unknown binary → check signature → check network activity
   - Suspicious DNS → check which process owns the DNS connection
   - Multiple low-signal anomalies from same process/path → ESCALATE

4. ESCALATE OR CLEAR — after investigating each finding:
   - Evidence CONFIRMS worst-case → CRITICAL finding, investigate deeper
   - Evidence DISPROVES worst-case → INFO finding with benign explanation
   - Evidence is INCONCLUSIVE → WARNING finding, note what would confirm/deny
   - NEVER dismiss without evidence. "Probably fine" is NOT acceptable.

═══════════════════════════════════════════════════════════════
THREAT NARRATIVE (DOT CONNECTION)
═══════════════════════════════════════════════════════════════
After EVERY tool result, ask yourself:

1. Does this connect to ANY previous finding?
   Same process? Same IP? Same user? Same directory? Same timestamp?
2. Does this make a previous finding MORE suspicious?
   A benign-looking listener + persistence mechanism = escalate
3. Is a pattern forming?
   Multiple unsigned binaries from same path?
   Multiple connections to same IP range?
   Multiple persistence mechanisms for same executable?

When reporting findings, ALWAYS reference related prior findings.
Example: "[WARNING] node *:3001 — CONNECTS TO finding #2 (limactl DNS
on *:53) — both bind to all interfaces, exposing entire LAN surface"

═══════════════════════════════════════════════════════════════
INVESTIGATION ESCALATION
═══════════════════════════════════════════════════════════════
NORMAL MODE: Systematic phase-by-phase investigation.
DEEP INVESTIGATION MODE: Triggered when 2+ WARNING or any CRITICAL found.
  In this mode:
  - For each finding, trace to its ROOT CAUSE FILE (plist, config, binary)
  - Determine the exact fix_action (unload, remove, modify, revoke)
  - Cross-reference findings that share the same origin file or process
  - Do NOT keep gathering evidence once you know the root cause
  - The goal is actionable remediation data, not exhaustive documentation

═══════════════════════════════════════════════════════════════
BASELINE DEVIATION DOCTRINE (NON-NEGOTIABLE)
═══════════════════════════════════════════════════════════════
Expected baseline = clean macOS + user-approved software (calibrated by posture above).
ANY deviation from this baseline is suspicious until evidence explains it.

Examples of deviations that REQUIRE follow-up:
  - Unexpected listeners, DNS responders, proxies, tunnels, or loopback services
  - Non-Apple binaries/processes running as root or with privileged access
  - Apple-like names with odd paths, odd launch contexts, or odd signatures
  - Repeated failed/closed network sessions to unusual destinations
  - Security tooling output that is unusual, noisy, malformed, or error-heavy
  - Launch items, cron entries, profiles, TCC grants, or certs not expected on clean macOS

Do NOT dismiss an anomaly just because it could be benign. VERIFY IT.
SYSTEMPROMPT_DYNAMIC

  # Part 2: Static tool calling / evidence / strategy sections
  cat << 'SYSTEMPROMPT_EOF'

═══════════════════════════════════════════════════════════════
TOOL CALLING
═══════════════════════════════════════════════════════════════
Prefer one tool per turn. You may use up to $API_MAX_TOOL_CALLS tightly related
read-only tool calls when that clearly saves a round trip. After receiving the
result, analyze it and call your next tool. Continue until the scan is complete.

IMPORTANT — Use direct tools first:
- START with direct tools: security_status, persistence_launchd, persistence_login_items,
  net_sockets_ownership, env_shell_profiles, tcc_database, etc.
- Do NOT browse investigation_command_catalog as your first action.
  Use it ONLY when you need a specific command not available as a direct tool.
- When you do use the catalog, call investigation_command_run immediately after — do NOT
  call investigation_command_catalog multiple times in a row.

If a result contains a deviation, trace it to its root cause immediately:
- What file/plist/config causes this behavior?
- What fix action would stop it?
Record with scan_finding before moving to the next area.

For large outputs, prefer cmd_exec_to_file_bundle then file_signal_extract/file_grep.
For plist analysis, prefer launchd_plist_triage over raw reads.

═══════════════════════════════════════════════════════════════
EVIDENCE COLLECTION
═══════════════════════════════════════════════════════════════
Use direct tools (persistence_launchd, net_sockets_ownership, etc.) as primary collectors.
For custom commands: cmd_exec_to_file / cmd_exec_to_file_bundle to save large output.
Then file_signal_extract / file_grep to inspect. shell_exec for small commands only.
Do NOT browse the command catalog repeatedly — use direct tools.
$([ "$EPHEMERAL_MODE" = "true" ] && echo "When EPHEMERAL MODE is active, command-capture tools return inline summaries only and do NOT create reusable evidence files.")

═══════════════════════════════════════════════════════════════
TOKEN / COST DISCIPLINE (MANDATORY)
═══════════════════════════════════════════════════════════════
- Minimize turns: bundle related commands in one cmd_exec_to_file_bundle call.
- Minimize context: do not re-read full files repeatedly; use file_signal_extract/file_grep/file_tail first.
- Minimize output: if you need details, request targeted slices, not whole dumps.
- Prefer commands that answer multiple hypotheses at once.
- If a deviation is high confidence suspicious, report it and move forward; do not over-loop.
- Tool outputs passed back to you may be compacted to high-signal lines + latest tail lines.
  If more detail is required, issue targeted follow-up reads against saved evidence files.

═══════════════════════════════════════════════════════════════
ROOT-CAUSE TRACING PROTOCOL (FOR EACH DEVIATION)
═══════════════════════════════════════════════════════════════
For every suspicious signal, trace it to its ORIGIN in 4 steps.
The goal is to identify the exact file/service/config that CAUSES the
behavior so it can be stopped or fixed. Do NOT keep gathering evidence
about a problem you already understand — trace to origin, record, move on.

  Step 1: IDENTIFY THE SYMPTOM
    - What exactly is anomalous? (process, port, file, connection, permission)
    - State the worst-case explanation in one sentence.

  Step 2: TRACE TO ORIGIN (this is the critical step)
    - Process → find binary path (ls -la /proc or lsof -p PID) → find what launches it:
      • grep the binary name in ~/Library/LaunchAgents, /Library/LaunchAgents,
        /Library/LaunchDaemons, ~/Library/Application Support
      • check login items BTM plist, cron, shell profiles
    - Network listener → lsof -nP -iTCP:PORT → get PID → trace PID to binary → trace binary to launcher
    - Suspicious file → find what REFERENCES it (grep across plists, profiles, cron, shell configs)
    - Permission grant → find the TCC entry → find the app/binary it grants access to
    - XPC service → find the parent bundle → find its plist/launch mechanism
    The answer must be: "THIS specific file at THIS path is the root cause."

  Step 3: DETERMINE FIX ACTION
    - What single action would stop/fix this?
    - Examples: "unload and remove ~/Library/LaunchAgents/com.suspicious.plist"
      "remove line 47 from ~/.zshrc" / "revoke TCC grant for /path/to/binary"
    - The fix must be specific enough for automated remediation.

  Step 4: REPORT WITH scan_finding
    Include in every finding:
    - origin_file: exact path of the root cause file
    - origin_type: launchd_plist | login_item | xpc_service | cron_entry | shell_config | kernel_ext | profile | binary | config_file
    - fix_action: the specific remediation step
    - severity: CRITICAL / WARNING / INFO
    - connected_findings: references to related findings if any

Do NOT run additional broad collection commands once you have enough
information to trace the origin. One targeted command that answers
"what file causes this" is worth more than ten evidence-gathering sweeps.

═══════════════════════════════════════════════════════════════
MUTATING TOOLS — EARN THE ACK
═══════════════════════════════════════════════════════════════
Mutating tools require ack:"I_UNDERSTAND" in args.
You may include ack ONLY after you have, in prior steps:
  1. EVIDENCE: what you found (via scan_finding)
  2. IMPACT: what the mutation changes
  3. ROLLBACK: how to undo it

═══════════════════════════════════════════════════════════════
DYNAMIC PATHS
═══════════════════════════════════════════════════════════════
Use these in tool arguments — they expand automatically:
  $HOME           → current user's home directory
  $USER           → current username
  $CMDBOT_WORKDIR → working directory for scan artifacts

═══════════════════════════════════════════════════════════════
SCANNING STRATEGY
═══════════════════════════════════════════════════════════════
Use direct tools (not the command catalog) for each phase.
For EVERY anomaly found: trace to root cause file, determine fix, report with scan_finding.
Do NOT move to the next phase until all anomalies from the current phase are traced to origin.

PHASE 1: SECURITY BASELINE + PERSISTENCE
  - security_status → check SIP, Gatekeeper, AMFI
  - persistence_launchd → persistence_launchd_contents → launchd_plist_triage on non-Apple items
  - persistence_login_items, persistence_cron
  - env_shell_profiles — check for DYLD injection, suspicious aliases
  → For each non-Apple item: identify origin_file (the plist/config) and fix_action

PHASE 2: NETWORK + PROCESSES
  - net_sockets_ownership — find listeners and connections
  - For each non-Apple listener: trace PID → binary path → launch mechanism (plist/login item)
  - net_dns_state, net_interfaces — check for rogue DNS or tunnels
  → For each anomaly: what file/service causes it? What stops it?

PHASE 3: PERMISSIONS + INTEGRITY
  - tcc_database — non-Apple TCC grants
  - extensions_system_kext — third-party extensions
  - codesign_verify on suspicious binaries from prior phases
  → Cross-reference: does anything from Phase 1/2 also have unusual TCC grants?

FINAL: Ensure every finding has origin_file, origin_type, and fix_action.
Call scan_complete.

═══════════════════════════════════════════════════════════════
NETWORK / DNS / TUNNEL INVESTIGATION PATTERN
═══════════════════════════════════════════════════════════════
When investigating DNS/tunnel anomalies:
  1. cmd_exec_to_file_bundle: ["scutil --dns","scutil --nwi","scutil --nc list","systemextensionsctl list","sudo lsof -nP -i","netstat -rn -f inet6"]
  2. file_signal_extract / file_grep on captured outputs

Key signals:
  - utun with no matching VPN config → find the owner
  - fd21:: IPv6 DNS → injected via Router Advertisement?
  - /var/run/resolv.conf with uchg flag → file_stat to check
  - Scoped resolvers not matching expected interfaces
  - Non-system process listening on :53 (DNS) → attribute binary, parent, launch source
  - Long-lived SYN_SENT sessions to LAN hosts → identify owning app/service intent
  - Escaped/truncated process names (e.g., spaces shown as \x20) → resolve full executable path and signature
  - Local dev listeners (e.g., :3001/:5173) → verify ownership + startup mechanism; record as benign only with evidence

═══════════════════════════════════════════════════════════════
IMPORTANT RULES
═══════════════════════════════════════════════════════════════
INVESTIGATION:
- ALWAYS trace each deviation to its ROOT CAUSE: the specific file, service, or config that causes it.
- For each finding, identify: origin_file, origin_type, and fix_action.
- NEVER keep collecting evidence about a problem you already understand — trace to origin and move on.
- NEVER dismiss without evidence. "Probably benign" requires PROOF.
- Connect dots — if multiple findings share an origin file, merge them.
- Calibrate ALL findings against the user's POSTURE classification.
- When 2+ WARNING or CRITICAL accumulate, enter DEEP INVESTIGATION MODE.

TOOLS:
- Prefer one focused tool per turn — use direct tools first, not the command catalog
- Use direct tools: security_status, persistence_launchd, net_sockets_ownership, tcc_database, etc.
- Use cmd_exec_to_file_bundle for related command groups
- Use file_signal_extract/file_grep to inspect large outputs
- Use launchd_plist_triage for plist analysis
- Avoid repetitive broad collection — trace anomalies to root cause instead

GENERAL:
- Use sudo in commands when needed
- Use $HOME and $USER in paths — never hardcode usernames
- Report findings with scan_finding BEFORE moving on
- Verify code signatures on ANYTHING suspicious
- Do NOT assume Apple processes are legitimate without verification
- Do NOT skip phases — be thorough
- If a tool returns an error, try an alternative approach
- Respect token budget signals: if tool output indicates TOKEN_LIMIT_REACHED,
  immediately transition to scan_finding + scan_complete.
SYSTEMPROMPT_EOF
}

#==============================================================================
# SYSTEM CONTEXT (injected as first user message)
#==============================================================================

generate_system_context() {
  local focus="${1:-}"
  cat << EOF
SYSTEM CONTEXT FOR THIS SCAN:
  User:     $CURRENT_USER
  Home:     $CURRENT_HOME
  Hostname: $HOSTNAME_STR
  macOS:    $OS_VERSION (build $OS_BUILD)
  Kernel:   $KERNEL_VERSION
  Arch:     $ARCH
  Time:     $CURRENT_DATETIME UTC
  Workdir:  $CMDBOT_WORKDIR
  Runtime:  $(runtime_mode_label)
  Posture:  $USER_POSTURE — $USER_POSTURE_LABEL
  Modules:  macOS=$([ "${MACOS_TOOLS_LOADED:-false}" = true ] && echo "loaded" || echo "not loaded") | Intel=$([ "${THREAT_INTEL_LOADED:-false}" = true ] && echo "loaded" || echo "not loaded")
$([ -n "$SCAN_SCOPE_DIR" ] && echo "  Scope:    $SCAN_SCOPE_DIR (CONFINED — all operations restricted to this directory)")

INVESTIGATION APPROACH:
  - Assume worst-case for every finding. Build the case to prove or disprove.
  - Connect dots across findings. Reference prior findings when related.
  - Calibrate against Posture $USER_POSTURE ($USER_POSTURE_LABEL) — use this to judge what is normal vs. suspicious.
  - When 2+ WARNING or CRITICAL findings accumulate, escalate to DEEP INVESTIGATION MODE.
$([ "$EPHEMERAL_MODE" = "true" ] && cat << 'EPHEMERAL'
  - EPHEMERAL MODE: do not rely on saved evidence files from command-capture tools. Their outputs are returned inline and are not written to disk.
EPHEMERAL
)
$([ -n "$SCAN_SCOPE_DIR" ] && cat << 'SCOPE'

DIRECTORY SCOPE ENFORCEMENT:
  This scan is CONFINED to the scope directory shown above.
  - ALL file reads, directory listings, greps, and finds MUST target paths within the scope directory.
  - ALL shell commands (shell_exec, cmd_exec_to_file) MUST only access files/directories within scope.
  - Do NOT attempt to read, list, or search outside the scope directory — the tools will block it.
  - The workdir and findings directories are exempt (for saving scan artifacts).
  - System-level commands (ps, lsof, etc.) that don't target specific paths are allowed.
SCOPE
)

EOF

  if [ -n "$focus" ]; then
    echo "$focus"
  else
    echo "Begin the paranoid security scan. Start with security_status, then persistence_launchd. Use direct tools — do not browse the command catalog first."
  fi
}

#==============================================================================
# SCAN PROFILE DEFINITIONS
#==============================================================================

PROFILE_FULL="Begin the deep investigation scan.
Start with security_status, then persistence_launchd. Use direct tools — do NOT browse the command catalog.
For EVERY anomaly found, trace to ROOT CAUSE:
  1. What file/plist/config causes this?
  2. What specific action would fix it?
  3. Record with scan_finding (include origin_file, origin_type, fix_action)
Phase order: security baseline → persistence → network → permissions → integrity.
Cross-reference: persistence findings → check network. Network findings → check binary signatures.
Do not gather more evidence about a problem you already understand."

PROFILE_PERSISTENCE="FOCUSED SCAN: Persistence mechanisms.
Run ONLY:
  - Phase 0: security_status (SIP/Gatekeeper — if disabled, escalate immediately)
  - Phase 1: ALL persistence tools — LaunchDaemons, LaunchAgents, login items,
    cron, periodic, at jobs, shell profiles
  - Codesign verify suspicious binaries referenced by persistence plists
  - For each non-Apple persistence item: state worst-case hypothesis, verify signature,
    check if it has network activity, report finding with evidence
When Phase 1 is thoroughly investigated, call scan_complete.
Do NOT rush — investigate each persistence mechanism fully."

PROFILE_NETWORK="FOCUSED SCAN: Process and network deep investigation.
Run ONLY:
  - Phase 0: security_status
  - Phase 2: ALL network/process tools — sockets, DNS, proxy, interfaces, lsof, ps
  - For EACH anomaly: follow WORST-CASE-FIRST doctrine:
    1. Assume the worst (C2? lateral movement? exfiltration? tunneling?)
    2. Investigate: who owns it, who signed it, does it have persistence?
    3. Connect dots: does this IP/process/port appear in other findings?
    4. Report with evidence for/against worst-case
  - Cross-reference socket owners with persistence mechanisms (check Phase 1 tools)
  - Follow the DNS/tunnel investigation pattern for anomalies
  - If 2+ WARNING findings: enter DEEP INVESTIGATION MODE — use threat intel
Take your time. Investigate each network anomaly thoroughly before moving on.
When all anomalies are investigated, call scan_complete."

PROFILE_BINARY="FOCUSED SCAN: Binary integrity investigation.
Run ONLY:
  - Phase 0: security_status + intel_status
  - Phase 4: recent_system, recent_user, codesign verification,
    threat intel lookups, YARA scanning, extensions_system_kext
  - For each unsigned/ad-hoc binary: worst-case hypothesis → investigate → report
  - Cross-reference with persistence and network activity
When Phase 4 is thoroughly investigated, call scan_complete."

PROFILE_PRIVACY="FOCUSED SCAN: Privacy permissions investigation.
Run ONLY:
  - Phase 0: security_status
  - Phase 5: tcc_database, profiles_mdm, keychain_audit, keychain_user_certs
  - Focus on: non-Apple TCC grants (especially ScreenCapture, Accessibility, FDA)
  - Cross-reference: do apps with TCC grants also have network activity or persistence?
  - Look for rogue CA certs, excessive TCC grants, unknown profiles
  - For each non-Apple TCC grant: worst-case → investigate → report
When Phase 5 is thoroughly investigated, call scan_complete."

#==============================================================================
# PASTE & ANALYZE — Iterative Self-Correcting Analysis
#==============================================================================
# The user pastes raw content (logs, errors, crash reports, etc.) and the LLM
# focuses EXCLUSIVELY on that content. It runs commands, sees stdout (last N
# lines only to save tokens), and iterates until it decides the issue is
# resolved. The Responses API conversation state preserves all prior context,
# so each iteration only sends the NEW command output — the model already has
# everything it saw before.
#
# Flow:
#   1. User pastes content → injected verbatim into first prompt
#   2. LLM analyzes → calls a tool (shell_exec, file_read, etc.)
#   3. We capture stdout, take last 20 lines, feed it back as the next input
#   4. LLM sees new output + has full prior context via previous_response_id
#   5. LLM either runs another command (iterate) or calls paste_analysis_done
#   6. Repeat until LLM signals done or max iterations reached
#==============================================================================

run_paste_analysis() {
  local pasted_content="$1"
  local scan_name="paste_analysis_$(date +%H%M%S)"

  # ── Reset state ──
  scan_step=0
  findings=()
  findings_total=0
  total_input_tokens=0
  total_cached_tokens=0
  total_output_tokens=0
  total_tokens_used=0
  total_billable_tokens=0
  total_cost=0
  token_wrapup_mode=false
  token_wrapup_rounds=0
  soft_limit_investigation_mode=false
  soft_limit_investigation_rounds=0
  soft_limit_investigation_tokens_start=0
  soft_limit_investigation_tokens_used=0
  soft_limit_investigation_billable_start=0
  soft_limit_investigation_billable_used=0
  soft_limit_investigation_budget_exhausted=false
  soft_limit_focus_goal=""
  soft_limit_investigation_findings_start=0
  reflection_calls_used=0
  last_request_input_tokens=0
  last_request_cached_tokens=0
  last_request_output_tokens=0
  last_request_billable_tokens=0
  chain_reset_count=0
  last_chain_reset_step=0
  compact_count=0
  last_compact_step=0
  COMPACT_INPUT=""
  scan_memory=""
  recent_broad_cmds=""

  # ── Initialize findings file ──
  prepare_findings_target "$CMDBOT_FINDINGS_DIR/${scan_name}_$(date +%Y%m%d_%H%M%S).txt"
  if [ -n "$findings_file" ]; then
    {
      echo "════════════════════════════════════════════════════════"
      echo "  PASTE & ANALYZE — Iterative Self-Correcting Analysis"
      echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')"
      echo "  System:  $HOSTNAME_STR — macOS $OS_VERSION ($ARCH)"
      echo "  User:    $CURRENT_USER"
      echo "  Model:   $API_MODEL"
      echo "  Max Iterations: $PASTE_ANALYSIS_MAX_ITERATIONS"
      echo "  Stdout Tail Lines: $PASTE_ANALYSIS_STDOUT_TAIL_LINES"
      echo "════════════════════════════════════════════════════════"
      echo ""
      echo "──── PASTED CONTENT ────"
      echo "$pasted_content"
      echo "──── END PASTED CONTENT ────"
      echo ""
    } > "$findings_file"
  fi

  # ── Initialize API state ──
  CURRENT_RESPONSE_ID=""

  # ── Build system instructions specifically for paste analysis ──
  # This prompt locks the LLM onto ONLY the pasted content with pinpoint focus.
  SYSTEM_INSTRUCTIONS="You are an expert system analyst performing TARGETED analysis of content the user has pasted.

ABSOLUTE RULES — FOLLOW EXACTLY:
1. Focus EXCLUSIVELY on the pasted content. Do not perform broad system scans or unrelated investigations.
2. Analyze the pasted content with pinpoint accuracy — identify every error, anomaly, warning, or issue present.
3. You MUST call tools to investigate. Use shell_exec, file_read, file_grep, file_find, dir_grep etc.
4. DO NOT just read the pasted content and report findings. You must ACTIVELY INVESTIGATE by running commands.
5. After running each command, you will receive the last ${PASTE_ANALYSIS_STDOUT_TAIL_LINES} lines of stdout.
6. You already have full conversation history — do NOT repeat previous commands. Build on what you learned.
7. ITERATE: Run a command → analyze its output → decide if more investigation is needed → run the next command.
8. SELF-CORRECT: If a command gave unexpected results or you need more info, adjust your approach and try again.
9. When you have fully diagnosed the issue AND either fixed it or provided a clear actionable solution, call paste_analysis_done with a detailed summary and status.
10. Do NOT call paste_analysis_done prematurely — only when you are confident the analysis is complete.
11. Each iteration should make PROGRESS. Don't repeat the same investigation. Dig deeper or try a different angle.
12. Use scan_finding to record each distinct finding WITH EVIDENCE from your investigation (not just restating what was in the pasted content).
13. Use sudo in commands when needed. Use \$HOME and \$USER in paths.

MANDATORY WORKFLOW — YOU MUST FOLLOW THESE STEPS IN ORDER:
Step 1: Read and understand the pasted content. Identify processes, errors, anomalies.
Step 2: For EACH anomaly, run a targeted shell_exec command to investigate further on the live system.
         Examples: check process status, read related log files, verify file integrity, check configs, etc.
Step 3: Analyze the command output. Cross-reference with the pasted content.
Step 4: If more info needed, run another command. Keep iterating until you have solid evidence.
Step 5: Record each finding with scan_finding (include evidence from YOUR commands, not just the paste).
Step 6: Only AFTER thorough investigation, call paste_analysis_done with a comprehensive summary.

EXAMPLES OF GOOD INVESTIGATION COMMANDS:
- If logs mention a process: shell_exec {\"cmd\": \"ps aux | grep processname\"}
- If logs mention a file: file_read the file, or file_grep for patterns
- If logs mention errors: shell_exec to check system logs, crash reports, or related state
- If logs mention network: shell_exec {\"cmd\": \"lsof -i -P | grep LISTEN\"} or netstat
- If logs mention kernel issues: shell_exec {\"cmd\": \"sudo dmesg | tail -50\"} or log show

CRITICAL: Your FIRST tool call must be a shell_exec or similar investigation command — NOT scan_finding."

  # ── Build tools: reuse all existing tools + add paste_analysis_done ──
  TOOLS_JSON="$(build_tools_json)"
  # Inject the paste_analysis_done tool
  local done_tool
  done_tool=$(jq -n '{
    type: "function",
    name: "paste_analysis_done",
    description: "Call this when the iterative analysis is complete. You have fully diagnosed the pasted content, identified all issues, and either fixed them or provided clear actionable solutions. Include a summary of your analysis.",
    parameters: {
      type: "object",
      properties: {
        summary: {
          type: "string",
          description: "Complete summary of your analysis: what was found, root causes, fixes applied or recommended."
        },
        status: {
          type: "string",
          enum: ["resolved", "diagnosed", "needs_manual_intervention"],
          description: "resolved = issue fixed. diagnosed = root cause found but not auto-fixable. needs_manual_intervention = requires user action."
        }
      },
      required: ["summary", "status"],
      additionalProperties: false
    },
    strict: true
  }')
  TOOLS_JSON=$(echo "$TOOLS_JSON" | jq --argjson tool "$done_tool" '. + [$tool]')
  TOOLS_JSON_COMPACT="$(build_compact_tools_json "$TOOLS_JSON")"

  # ── First input: inject the pasted content verbatim ──
  local pasted_lines
  pasted_lines=$(printf "%s\n" "$pasted_content" | wc -l | tr -d ' ')
  local first_prompt
  first_prompt="PASTE & ANALYZE — TARGETED ITERATIVE INVESTIGATION

System: $CURRENT_USER@$HOSTNAME_STR — macOS $OS_VERSION ($ARCH)
Time: $(date -u '+%Y-%m-%d %H:%M:%S') UTC

The user has pasted the following content ($pasted_lines lines) for you to analyze.
Focus EXCLUSIVELY on this content. Identify every issue, error, anomaly, or concern.
Investigate with precision — use tools to dig deeper as needed.
You will iterate automatically — each time you run a command, you will see its output and can run another.
When your analysis is complete, call paste_analysis_done.

══════ PASTED CONTENT ══════
$pasted_content
══════ END PASTED CONTENT ══════

Begin your analysis NOW. Your FIRST action must be a shell_exec command to investigate something from the pasted content on the live system. Do NOT call scan_finding first — investigate first, then report."

  local next_input
  next_input=$(jq -n --arg content "$first_prompt" '[{role: "user", content: $content}]')

  local analysis_complete=false
  local consecutive_failures=0
  local consecutive_no_tool_calls=0
  local iteration=0

  # ── Display ──
  clear
  set_terminal_title "PASTE & ANALYZE"
  print_section "PASTE & ANALYZE: Iterative Analysis"
  echo -e "${BOLD}${GREEN}STATUS: ANALYZING${RESET}"
  echo -e "${BOLD}Start:${RESET}      $(date '+%H:%M:%S')"
  echo -e "${BOLD}Pasted:${RESET}     ${CYAN}$pasted_lines lines${RESET}"
  echo -e "${BOLD}Max Iter:${RESET}   ${YELLOW}$PASTE_ANALYSIS_MAX_ITERATIONS${RESET}"
  echo -e "${BOLD}Tail Lines:${RESET} ${YELLOW}$PASTE_ANALYSIS_STDOUT_TAIL_LINES${RESET} ${DIM}(stdout lines fed back per iteration)${RESET}"
  echo -e "${BOLD}Model:${RESET}      ${MAGENTA}$API_MODEL${RESET}"
  echo -e "${BOLD}Findings:${RESET}   ${DIM}$(runtime_findings_label)${RESET}"
  local tool_count
  tool_count=$(echo "$TOOLS_JSON" | jq 'length' 2>/dev/null || echo "?")
  echo -e "${BOLD}Tools:${RESET}      ${CYAN}$tool_count${RESET} defined"
  echo -e ""
  echo -e "${DIM}┌─ How it works ─────────────────────────────────────────────┐${RESET}"
  echo -e "${DIM}│ ${RESET}${CYAN}1.${RESET} LLM reads your pasted content with pinpoint focus       ${DIM}│${RESET}"
  echo -e "${DIM}│ ${RESET}${CYAN}2.${RESET} Runs a command → sees last ${PASTE_ANALYSIS_STDOUT_TAIL_LINES} lines of output          ${DIM}│${RESET}"
  echo -e "${DIM}│ ${RESET}${CYAN}3.${RESET} Iterates: previous context preserved via Responses API  ${DIM}│${RESET}"
  echo -e "${DIM}│ ${RESET}${CYAN}4.${RESET} Self-corrects until the issue is fully diagnosed        ${DIM}│${RESET}"
  echo -e "${DIM}└────────────────────────────────────────────────────────────┘${RESET}"
  echo -e ""
  echo -e "${YELLOW}Press Ctrl+C to abort.${RESET}"
  print_border

  ui_status_enable
  ui_status_set "ANALYZING"

  # ══════════════════════════════════════════════════════════════════════════
  # ITERATIVE SELF-CORRECTING LOOP
  # ══════════════════════════════════════════════════════════════════════════
  # The key insight: we use previous_response_id so the LLM maintains full
  # conversation state server-side. We ONLY send the new output (last N lines
  # of stdout) each iteration. The model already knows everything it did
  # before. This lets it self-correct by seeing what its commands produced.
  # ══════════════════════════════════════════════════════════════════════════

  while [ "$analysis_complete" = false ] && [ "$iteration" -lt "$PASTE_ANALYSIS_MAX_ITERATIONS" ]; do
    iteration=$((iteration + 1))
    scan_step=$iteration
    print_tool_header "Iteration $iteration / $PASTE_ANALYSIS_MAX_ITERATIONS"

    # ── Call LLM ──
    ui_status_set "ITERATION $iteration/$PASTE_ANALYSIS_MAX_ITERATIONS"
    ui_spinner_start "Thinking (iteration $iteration)"
    local invoke_rc=0
    if invoke_llm "$next_input"; then
      invoke_rc=0
    else
      invoke_rc="$?"
    fi

    if [ "$invoke_rc" -ne 0 ]; then
      ui_spinner_stop
      if [ "$invoke_rc" -eq 2 ] || [ "${LAST_INVOKE_REASON:-}" = "no_function_calls" ]; then
        consecutive_no_tool_calls=$((consecutive_no_tool_calls + 1))
        consecutive_failures=0
        # Don't waste an iteration — roll back
        iteration=$((iteration - 1))
        scan_step=$iteration
        log_to_findings "NO_TOOL_CALL_RECOVERY (consecutive: $consecutive_no_tool_calls)"
        if [ -n "${LAST_TEXT_OUTPUT:-}" ]; then
          log_to_findings "MODEL_TEXT: ${LAST_TEXT_OUTPUT:0:500}"
          echo -e "${DIM}${MAGENTA}Model: ${LAST_TEXT_OUTPUT:0:300}${RESET}"
        fi

        if [ "$consecutive_no_tool_calls" -ge 5 ]; then
          echo -e "${RED}Model not calling tools. Ending analysis.${RESET}"
          log_to_findings "ABORT: no_function_calls_loop count=$consecutive_no_tool_calls"
          iteration=$((iteration + 1))  # restore for reporting
          print_tool_footer
          break
        fi

        next_input=$(jq -n '[{role: "user", content: "Return exactly ONE tool call now. Either run a command to investigate, or call paste_analysis_done if complete."}]')
        print_tool_footer
        continue
      fi

      consecutive_no_tool_calls=0
      consecutive_failures=$((consecutive_failures + 1))
      log_to_findings "──── ITERATION $iteration ────"
      log_to_findings "API_FAILURE (consecutive: $consecutive_failures)"

      if [ "$consecutive_failures" -ge 3 ]; then
        echo -e "${RED}3 consecutive API failures. Ending analysis.${RESET}"
        log_to_findings "ABORT: 3 consecutive API failures"
        print_tool_footer
        break
      fi

      next_input=$(jq -n '[{role: "user", content: "The previous API call failed. Continue your analysis by calling your next tool."}]')
      print_tool_footer
      sleep 3
      continue
    fi
    ui_spinner_stop

    # ── Token/cost info ──
    if [ "${last_request_input_tokens:-0}" -gt 0 ] || [ "${last_request_output_tokens:-0}" -gt 0 ]; then
      print_cost_info "$last_request_input_tokens" "$last_request_cached_tokens" "$last_request_output_tokens" "${last_request_cost:-0}" "$total_cost"
    fi

    consecutive_failures=0
    consecutive_no_tool_calls=0

    # ── Log ──
    log_to_findings "──── ITERATION $iteration [$(date '+%H:%M:%S')] ────"
    local call_count call_idx
    call_count=${#LAST_FUNC_NAMES[@]}
    log_to_findings "FUNCTION_CALL_COUNT: $call_count"
    for ((call_idx=0; call_idx<call_count; call_idx++)); do
      log_to_findings "FUNCTION_CALL[$((call_idx + 1))/$call_count]: ${LAST_FUNC_NAMES[$call_idx]}(${LAST_FUNC_ARGS_LIST[$call_idx]})"
    done

    # ── Show model reasoning if any ──
    if [ -n "$LAST_TEXT_OUTPUT" ]; then
      echo -e "${DIM}${MAGENTA}Model: ${LAST_TEXT_OUTPUT:0:300}${RESET}"
      log_to_findings "MODEL_TEXT: ${LAST_TEXT_OUTPUT:0:500}"
    fi

    # ── Execute tool(s) and build next input ──
    local tool_results_input='[]'
    local saw_analysis_done=false
    local done_summary="" done_status=""

    for ((call_idx=0; call_idx<call_count; call_idx++)); do
      local call_id func_name func_args tool_output
      call_id="${LAST_CALL_IDS[$call_idx]}"
      func_name="${LAST_FUNC_NAMES[$call_idx]}"
      func_args="${LAST_FUNC_ARGS_LIST[$call_idx]}"

      if [ -z "$call_id" ]; then
        echo -e "${RED}INTERNAL ERROR: missing call_id for '$func_name'${RESET}"
        continue
      fi

      # ── Handle paste_analysis_done ──
      if [ "$func_name" = "paste_analysis_done" ]; then
        saw_analysis_done=true
        done_summary=$(echo "$func_args" | jq -r '.summary // empty' 2>/dev/null)
        done_status=$(echo "$func_args" | jq -r '.status // empty' 2>/dev/null)
        # Robust defaults if model sent empty/null args
        [ -z "$done_summary" ] && done_summary="Analysis complete (no summary provided by model)."
        [ -z "$done_status" ] && done_status="diagnosed"
        tool_output="ANALYSIS_COMPLETE: status=$done_status summary=$done_summary"
        echo ""
        echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
        echo -e "${GREEN}${BOLD}║       ANALYSIS COMPLETE                  ║${RESET}"
        echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
        case "$done_status" in
          resolved)                echo -e "  ${GREEN}${BOLD}Status:${RESET} ${GREEN}RESOLVED${RESET} — Issue fixed" ;;
          diagnosed)               echo -e "  ${YELLOW}${BOLD}Status:${RESET} ${YELLOW}DIAGNOSED${RESET} — Root cause identified" ;;
          needs_manual_intervention) echo -e "  ${RED}${BOLD}Status:${RESET} ${RED}NEEDS MANUAL INTERVENTION${RESET}" ;;
          *)                       echo -e "  ${CYAN}${BOLD}Status:${RESET} ${CYAN}$done_status${RESET}" ;;
        esac
        echo ""
        echo -e "  ${BOLD}Summary:${RESET}"
        echo "$done_summary" | fold -s -w 76 | while IFS= read -r sline; do
          echo -e "  $sline"
        done
        echo ""
        log_to_findings "PASTE_ANALYSIS_DONE: status=$done_status"
        log_to_findings "SUMMARY: $done_summary"
        findings+=("[INFO] Paste Analysis: $done_status — ${done_summary:0:200}")
        findings_total=$((findings_total + 1))
      else
        # ── Execute the tool normally ──
        tool_output="$(dispatch_tool_call "$func_name" "$func_args" 2>&1)" || tool_output="TOOL_ERROR: execution failed"
        tool_output="$(truncate_output "$tool_output")" || true
      fi

      log_to_findings "OUTPUT[$((call_idx + 1))/$call_count]:"
      log_to_findings "$tool_output"

      # NOTE: scan_finding is handled by dispatch_tool_call → scan.finding)
      # which already appends to findings[] and increments findings_total.
      # No duplicate handling needed here.

      local internal_name output_lines
      internal_name="$(api_name_to_internal "$func_name")"
      output_lines=$(echo "$tool_output" | wc -l | tr -d ' ' || echo "0")
      echo -e "${CYAN}│${RESET} Tool $((call_idx + 1))/$call_count: ${BOLD}$internal_name${RESET} → $output_lines lines"

      # ── KEY: Take only the last N lines of stdout for the model ──
      # This is the core of the iterative feedback mechanism. We only feed
      # the tail of stdout to prevent token bloat. The model already has
      # full conversation context via previous_response_id — it knows
      # everything it did before. We just give it the latest result.
      local model_output
      if [ "$func_name" = "paste_analysis_done" ] || [ "$func_name" = "scan_finding" ] || [ "$func_name" = "scan_complete" ]; then
        # For control tools, send the full (small) output
        model_output="$tool_output"
      else
        local total_lines
        total_lines=$(printf "%s\n" "$tool_output" | wc -l | tr -d ' ')
        if [ "$total_lines" -le "$PASTE_ANALYSIS_STDOUT_TAIL_LINES" ]; then
          # Short output — send it all
          model_output="$tool_output"
        else
          # Long output — send header + last N lines only
          model_output="$(printf "OUTPUT_TRUNCATED: showing last %d of %d lines (%s)\n---- TAIL (%d lines) ----\n%s" \
            "$PASTE_ANALYSIS_STDOUT_TAIL_LINES" "$total_lines" "$([ "$EPHEMERAL_MODE" = "true" ] && echo "full output retained in memory only" || echo "full output saved to disk")" "$PASTE_ANALYSIS_STDOUT_TAIL_LINES" \
            "$(printf "%s\n" "$tool_output" | tail -n "$PASTE_ANALYSIS_STDOUT_TAIL_LINES")")"
        fi
      fi

      # Show preview
      local _rows _cols _max_preview_cols
      read -r _rows _cols < <(ui__term_size)
      _max_preview_cols=$((_cols - 8))
      [ "$_max_preview_cols" -lt 20 ] && _max_preview_cols=20
      echo "$model_output" | head -n 5 | while IFS= read -r line; do
        line="$(ui__strip_ansi_and_ctrl "$line")"
        line="$(ui__clip_to_cols "$line" "$_max_preview_cols")"
        echo -e "${CYAN}│${RESET}   ${DIM}$line${RESET}"
      done || true
      [ "${output_lines:-0}" -gt 5 ] 2>/dev/null && echo -e "${CYAN}│${RESET}   ${DIM}... ($((output_lines - 5)) more lines)${RESET}" || true
      echo -e "${CYAN}│${RESET} ${DIM}Chain: ${CURRENT_RESPONSE_ID:-none} | Call: ${call_id:-none}${RESET}"

      # ── Build the function_call_output item for the Responses API ──
      local next_tool_results_input
      if ! next_tool_results_input=$(echo "$tool_results_input" | jq -c \
        --arg call_id "$call_id" \
        --arg output "$model_output" \
        '. + [{type: "function_call_output", call_id: $call_id, output: $output}]' 2>/dev/null); then
        echo -e "${RED}INTERNAL ERROR: failed to build function_call_output${RESET}"
        continue
      fi
      tool_results_input="$next_tool_results_input"
    done

    print_tool_footer

    # ── Check for analysis completion ──
    if [ "$saw_analysis_done" = true ]; then
      analysis_complete=true
      break
    fi

    # ── Prepare next input ──
    # Only the new tool outputs are sent. The Responses API maintains the
    # full conversation state server-side via previous_response_id.
    # The model will see: all prior messages + this new output.
    next_input="$tool_results_input"

    # ── Conversation compaction (if enabled and context is growing) ──
    if [ "$COMPACT_ENABLED" = "true" ] \
      && [ "$last_request_input_tokens" -ge "$COMPACT_MIN_INPUT_TOKENS" ] \
      && [ $((iteration - last_compact_step)) -ge "$COMPACT_INTERVAL_STEPS" ]; then
      if compact_conversation; then
        next_input=$(jq -c \
          --argjson compact "$COMPACT_INPUT" \
          --argjson outputs "$tool_results_input" \
          '$compact + $outputs' 2>/dev/null || echo "$tool_results_input")
      fi
    fi

    sleep 0.5
  done

  if [ "$iteration" -ge "$PASTE_ANALYSIS_MAX_ITERATIONS" ] && [ "$analysis_complete" = false ]; then
    echo -e "${YELLOW}Reached maximum iterations ($PASTE_ANALYSIS_MAX_ITERATIONS). Ending analysis.${RESET}"
    findings+=("[INFO] Analysis ended: reached max iterations ($PASTE_ANALYSIS_MAX_ITERATIONS)")
    findings_total=$((findings_total + 1))
  fi

  ui_status_disable

  # ── Generate report ──
  generate_report
}

#==============================================================================
# PHASE 2 — Zero-Trust Log Snippet Extraction (Multi-Agent)
#==============================================================================
# After Phase 1 audit completes (token soft limit), a SEPARATE LLM agent
# analyzes collected evidence files with zero-trust, devil's advocate methodology.
#
# Architecture (following OpenAI multi-agent structured outputs pattern):
#   Phase 1 Agent: Data Collection (security probes, shell commands, log capture)
#   Phase 2 Agent: Log Analysis (zero-trust snippet extraction, structured JSON)
#   Phase 3 Agent: Remediation (write plugin local_shell executor, if connected)
#
# Flow:
#   1. Select batch of evidence files from work directory
#   2. Send to Phase 2 agent with posture-specific threat indicators
#   3. Agent returns structured JSON: [{logSnippetNumber, logSnippetString, possIndicator}]
#   4. Append exact log snippets to snippetsLog.txt (text preserved verbatim)
#   5. Move processed files to passedOnce/ directory
#   6. Loop until snippetsLog.txt exceeds line limit or no files remain
#   7. Route to write plugin (Phase 3) if connected, else generate report
#==============================================================================

PHASE2_BATCH_SIZE="${PARANOID_PHASE2_BATCH_SIZE:-2}"
PHASE2_MAX_ITERATIONS="${PARANOID_PHASE2_MAX_ITERATIONS:-20}"
PHASE2_MAX_RETRIES_PER_BATCH="${PARANOID_PHASE2_MAX_RETRIES_PER_BATCH:-3}"
PHASE2_MAX_CONSECUTIVE_API_FAILURES="${PARANOID_PHASE2_MAX_CONSECUTIVE_API_FAILURES:-5}"
PHASE2_SNIPPET_LINE_LIMIT="${PARANOID_PHASE2_SNIPPET_LINE_LIMIT:-500}"
PHASE2_MODEL="${PARANOID_PHASE2_MODEL:-$API_MODEL}"
PHASE2_MAX_TOKENS="${PARANOID_PHASE2_MAX_TOKENS:-4096}"
PHASE2_MAX_INPUT_CHARS="${PARANOID_PHASE2_MAX_INPUT_CHARS:-40000}"
PHASE2_RECENT_WINDOW_HOURS="${PARANOID_PHASE2_RECENT_WINDOW_HOURS:-24}"
PHASE2_CONTEXT_BEFORE_LINES="${PARANOID_PHASE2_CONTEXT_BEFORE_LINES:-2}"
PHASE2_CONTEXT_AFTER_LINES="${PARANOID_PHASE2_CONTEXT_AFTER_LINES:-2}"

# Gather exported file contents for distillation context
gather_findings_context() {
  local max_bytes="${1:-200000}"
  local context="" file_count=0

  # Main findings file (highest priority)
  if [ -n "$findings_file" ] && [ -f "$findings_file" ]; then
    local fsize
    fsize=$(wc -c < "$findings_file" | tr -d ' ' || echo "0")
    context="=== MAIN FINDINGS FILE: $findings_file ($fsize bytes) ===
$(head -c "$max_bytes" "$findings_file" 2>/dev/null)

"
    file_count=$((file_count + 1))
  fi

  # Work directory artifacts (investigation logs, shell captures)
  if [ -d "$CMDBOT_WORKDIR" ]; then
    local remaining_bytes=$((max_bytes - ${#context}))
    [ "$remaining_bytes" -lt 5000 ] && remaining_bytes=5000
    local per_file_budget=$((remaining_bytes / 8))  # spread across files

    while IFS= read -r wfile; do
      [ -z "$wfile" ] && continue
      [ ! -f "$wfile" ] && continue
      local wsize
      wsize=$(wc -c < "$wfile" | tr -d ' ' || echo "0")
      context="${context}=== EVIDENCE: $(basename "$wfile") ($wsize bytes) ===
$(head -c "$per_file_budget" "$wfile" 2>/dev/null)

"
      file_count=$((file_count + 1))
      [ "$file_count" -ge 12 ] && break
    done < <(find "$CMDBOT_WORKDIR" -maxdepth 4 -type f -print 2>/dev/null \
      | while IFS= read -r p; do
          [ -f "$p" ] || continue
          mtime=$(stat -f "%m" "$p" 2>/dev/null || echo "0")
          printf "%s\t%s\n" "$mtime" "$p"
        done | sort -rn | head -n 12 | cut -f2)
  fi

  echo "$context"
}

# Build posture-specific threat indicators for the Phase 2 agent
build_phase2_posture_indicators() {
  case "${USER_POSTURE:-2}" in
    1)
      cat << 'P1_IND'
POSTURE 1 — HERMIT (Minimal Sharing / Maximum Lockdown)
Look for these indicators with HIGH sensitivity — most services should NOT be running:

Persistence / LaunchAgent abuse:
- LaunchAgent plist executing from /Users/Shared, /tmp, or /var/tmp
- LaunchAgent label that does not match the binary it runs
- LaunchAgent binary hash changed without plist modification
- LaunchAgent using WatchPaths to trigger execution on file drop
- Orphaned LaunchAgent after parent app bundle was removed

Trojan installer / Gatekeeper abuse:
- Notarized or signed app running directly from a DMG mount point
- App bundle containing hidden Mach-O binary or shell script
- Installer process spawning osascript or shell immediately after launch
- Installer requiring manual right-click-open (Gatekeeper bypass)

AppleScript / native tool abuse:
- osascript decoding base64 or downloading a payload
- osascript accessing browser credential databases (Chrome, Firefox)
- shell or curl invoked by an installer process

Credential harvesting:
- Process accessing browser Login Data or Cookies databases
- Process accessing Keychain items or crypto wallet paths
- Unexpected read of Notes.app or iMessage databases

Network (Hermit — ANY listener is suspicious):
- ANY process listening on any interface
- mDNS or AirPlay traffic detected
- Local DNS server or proxy process running
- Persistent HTTPS connection while user is idle (C2 indicator)

Platform security:
- SIP disabled or boot policy reduced
- Write attempts to System volume or protected paths

Campaign patterns:
- Terminal command pasted from browser then executed
- Downloaded installer creating a LaunchAgent
P1_IND
      ;;
    2)
      cat << 'P2_IND'
POSTURE 2 — PRACTICAL (Selective Sharing / Dev Tools)
Look for these indicators — dev tools are expected, but watch for abuse:

Persistence:
- LaunchAgent executing from Application Support directory
- LaunchAgent executing from hidden folder in user home
- LaunchAgent KeepAlive added after initial install

Trojanized developer tools:
- Binary named after common dev tool (brew, docker, arc, etc.)
- Installer from fake Homebrew or tool distribution site
- Recently-added script or binary in /usr/local/bin

Interpreter / script abuse:
- Python or node process executing encoded/obfuscated script
- Interpreter process reading browser credential files
- Script execution from cache or tmp directory

Local network / dev tool behavior:
- Listener bound to 0.0.0.0 instead of localhost
- Unexpected DNS or HTTP proxy process
- Container or VM runtime spawning unknown network service

Data theft:
- Process reading browser cookie AND login databases
- Process reading crypto wallet files
- Process accessing multiple browser profiles (automated harvesting)

Plugin / extension injection:
- Browser extension added without user action
- Plugin added to signed app without an update event
P2_IND
      ;;
    3|*)
      cat << 'P3_IND'
POSTURE 3 — MAXIMALIST (Everything Enabled / High Noise)
Look for these indicators — high noise environment, focus on ROOT-LEVEL and signed malware:

Persistence / root-level:
- Root-owned LaunchDaemon not linked to a known app
- Daemon binary placed outside standard app bundle path
- Persistence surviving reboot without corresponding install event

Signed malware / trust abuse:
- Notarized binary with unknown or suspicious vendor identity
- Signed binary executed from unusual directory
- Team ID mismatch between app bundle and helper binary

System extension / privileged components:
- Network extension installed by a non-network app
- Endpoint security extension from unknown vendor

Data exfiltration:
- Large volume reads of browser and wallet files
- Archive creation spanning multiple user data directories
- Persistent connection to single remote host after data collection

Opaque process indicators:
- Process with no bundle or vendor identity
- Process that executes then deletes its own binary
- Binary running from a deleted file handle

Campaign-level correlations:
- fake_installer -> applescript_exec -> credential_access chain
- downloaded_app -> launchagent_created -> browser_data_access chain
- signed_app -> hidden_script -> outbound_connection chain
P3_IND
      ;;
  esac
}

# Build the Phase 2 system prompt (zero-trust, devil's advocate agent)
build_phase2_system_prompt() {
  local indicators
  indicators="$(build_phase2_posture_indicators)"

  cat << PHASE2SYS
You are a ZERO-TRUST LOG ANALYSIS AGENT for macOS threat discovery.

MISSION: Analyze provided log files and extract suspicious log snippets. You are a devil's advocate.
Approach every log entry with skepticism. Your job is to flip rocks over until you find something.

METHODOLOGY:
- Assume NOTHING is benign until proven otherwise.
- Sophisticated malware disguises itself as OS processes, legitimate services, and trusted binaries.
- Even small anomalies matter: a slightly wrong path, an unusual timestamp, an unexpected parent process.
- Do NOT dismiss anything because it looks normal. Prove it IS normal before moving on.
- If you cannot prove something is legitimate, extract it as a snippet.
- Prefer RECENT log entries (within last 24 hours). When duplicates exist, extract the LATEST occurrence.
- Question everything: Why is this process running? Why is it connecting here? Why was this plist modified?

$indicators

EXTRACTION RULES:
- Extract the EXACT log text as it appears. Do NOT modify, paraphrase, or summarize the log content.
- Each snippet should be roughly 3-5 lines. Include 1-2 lines of context before/after the key indicator.
- For each snippet, explain WHY it is suspicious in the possIndicator field.
- Extract snippets even for POTENTIAL issues. We investigate first, dismiss later.
- When the same event appears multiple times, extract the MOST RECENT occurrence only.
- Do not extract snippets you cannot tie to a specific process, file, or network activity.

RESPONSE FORMAT:
Return ONLY valid JSON conforming to the provided schema. No markdown wrapping, no extra text.
Each element must have exactly these fields:
- logSnippetNumber: integer starting from 1
- logSnippetString: the exact log text copied from the input (3-5 lines, verbatim)
- possIndicator: your assessment of why this is suspicious (1-2 sentences)

If you find nothing suspicious after thorough analysis, return: {"snippets": []}
But remember: your job is to be PARANOID. If in doubt, extract it.
A clean scan means we missed something, not that nothing is there.

User posture: ${USER_POSTURE:-2} — ${USER_POSTURE_LABEL:-Practical}
Calibrate what is normal vs suspicious against this posture level.
PHASE2SYS
}

# Make a Phase 2 API call with structured JSON output (json_schema format)
phase2_api_call() {
  local system_prompt="$1"
  local user_content="$2"
  local payload response http_code

  local schema_json='{"type":"json_schema","name":"snippet_extraction","strict":true,"schema":{"type":"object","properties":{"snippets":{"type":"array","items":{"type":"object","properties":{"logSnippetNumber":{"type":"integer"},"logSnippetString":{"type":"string"},"possIndicator":{"type":"string"}},"required":["logSnippetNumber","logSnippetString","possIndicator"],"additionalProperties":false}}},"required":["snippets"],"additionalProperties":false}}'

  payload=$(jq -n \
    --arg model "$PHASE2_MODEL" \
    --arg instructions "$system_prompt" \
    --arg user_content "$user_content" \
    --argjson max_tokens "$PHASE2_MAX_TOKENS" \
    --argjson format "$schema_json" \
    '{
      model: $model,
      instructions: $instructions,
      input: [{role: "user", content: $user_content}],
      max_output_tokens: $max_tokens,
      store: true,
      text: { format: $format }
    }')

  if api_post_json_capture "$API_URL" "$payload"; then
    http_code="$API_CAPTURE_HTTP_CODE"
    response="$API_CAPTURE_RESPONSE"
  else
    http_code="000"
    response=""
  fi

  if [ "$http_code" != "200" ]; then
    local err_msg
    err_msg=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || echo "")
    echo "PHASE2_ERROR: HTTP $http_code ${err_msg}"
    return 1
  fi

  # Record token usage for cost tracking
  record_token_usage "$response" false "phase2"

  # Extract text output from Responses API format
  local text_output
  text_output=$(echo "$response" | jq -r '
    [.output[]? |
      if .type == "message" then
        (.content[]? | select(.type == "output_text") | .text)
      elif .type == "text" then .text
      else empty end
    ] | join("")
  ' 2>/dev/null || echo "")

  echo "$text_output"
}

# Extract exact snippet text from source logs:
# - locate latest occurrence of an anchor line from the model response
# - return a small exact context window around that latest occurrence
phase2_extract_latest_context_snippet() {
  local source_file="$1"
  local snippet_hint="$2"
  local before_lines="${3:-2}"
  local after_lines="${4:-2}"
  local anchor_line anchor_line_no total_lines start_line end_line

  [ -f "$source_file" ] || return 1

  anchor_line=$(printf "%s\n" "$snippet_hint" | awk 'length($0) > 0 { print; exit }')
  [ -z "$anchor_line" ] && return 1

  anchor_line_no=$(awk -v pat="$anchor_line" 'index($0, pat) { ln=NR } END { if (ln > 0) print ln }' "$source_file" 2>/dev/null)
  [ -z "$anchor_line_no" ] && return 1

  total_lines=$(wc -l < "$source_file" 2>/dev/null | tr -d ' ' || echo "0")
  [ "${total_lines:-0}" -le 0 ] && return 1

  start_line=$((anchor_line_no - before_lines))
  [ "$start_line" -lt 1 ] && start_line=1
  end_line=$((anchor_line_no + after_lines))
  [ "$end_line" -gt "$total_lines" ] && end_line="$total_lines"

  sed -n "${start_line},${end_line}p" "$source_file" 2>/dev/null
}

phase2_should_skip_file() {
  local file_path="$1"
  local base_name
  base_name="$(basename "$file_path")"

  case "$base_name" in
    snippetsLog.txt|phase2_report_*|plugin_local_shell_*.json|.phase2_seen_snippet_hashes)
      return 0
      ;;
  esac

  case "$file_path" in
    "$CMDBOT_WORKDIR"/passedOnce/*)
      return 0
      ;;
  esac

  return 1
}

# Parse structured JSON snippets and append exact source-derived snippets to snippetsLog.txt
parse_and_append_snippets() {
  local json_text="$1"
  local snippets_log="$2"
  local source_label="$3"
  local seen_hashes_file="$4"
  shift 4
  local source_files=("$@")
  local appended=0

  # Handle both {"snippets":[...]} wrapper and bare array
  local snippet_array
  snippet_array=$(echo "$json_text" | jq -c '.snippets // .' 2>/dev/null || echo "[]")

  local count
  count=$(echo "$snippet_array" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "0")

  if [ "$count" -eq 0 ] || [ "$count" = "null" ]; then
    echo "0"
    return 0
  fi

  local i
  for ((i=0; i<count; i++)); do
    local snippet_num snippet_text poss_indicator
    local source_file extracted_text source_file_label snippet_hash

    snippet_num=$(echo "$snippet_array" | jq -r ".[$i].logSnippetNumber // $((i+1))" 2>/dev/null)
    snippet_text=$(echo "$snippet_array" | jq -r ".[$i].logSnippetString // empty" 2>/dev/null)
    poss_indicator=$(echo "$snippet_array" | jq -r ".[$i].possIndicator // empty" 2>/dev/null)
    [ -z "$snippet_text" ] && continue

    source_file=""
    extracted_text=""
    for source_file in "${source_files[@]}"; do
      extracted_text="$(phase2_extract_latest_context_snippet "$source_file" "$snippet_text" "$PHASE2_CONTEXT_BEFORE_LINES" "$PHASE2_CONTEXT_AFTER_LINES")"
      if [ -n "$extracted_text" ]; then
        break
      fi
      source_file=""
    done

    if [ -z "$source_file" ] || [ -z "$extracted_text" ]; then
      log_to_findings "PHASE2_SNIPPET_SKIP: no exact source match for snippet #$snippet_num in batch=$source_label"
      continue
    fi

    source_file_label="$(basename "$source_file")"
    snippet_hash=$(printf "%s\n%s\n" "$source_file_label" "$extracted_text" | shasum -a 256 | awk '{print $1}')
    if [ -n "$snippet_hash" ] && grep -qx "$snippet_hash" "$seen_hashes_file" 2>/dev/null; then
      continue
    fi
    [ -n "$snippet_hash" ] && echo "$snippet_hash" >> "$seen_hashes_file"

    {
      echo "================================================================"
      echo "SNIPPET #${snippet_num}"
      echo "SOURCE: ${source_file_label}"
      echo "BATCH: ${source_label}"
      echo "================================================================"
      echo "<<< LOG SNIPPET START >>>"
      printf "%s\n" "$extracted_text"
      echo "<<< LOG SNIPPET END >>>"
      echo "INDICATOR: $poss_indicator"
      echo ""
    } >> "$snippets_log"

    appended=$((appended + 1))
  done

  echo "$appended"
}

# Select the next batch of unprocessed evidence files
phase2_select_batch() {
  local source_dir="$1"
  local batch_size="$2"
  local recent_window_hours="${3:-24}"
  local now_epoch cutoff_epoch count=0
  local tmp_all tmp_recent selected_list

  [[ "$recent_window_hours" =~ ^[0-9]+$ ]] || recent_window_hours=24
  now_epoch=$(date +%s)
  cutoff_epoch=$((now_epoch - (recent_window_hours * 3600)))

  tmp_all=$(mktemp /tmp/cmdbot_phase2_all.XXXXXX)
  tmp_recent=$(mktemp /tmp/cmdbot_phase2_recent.XXXXXX)

  while IFS= read -r p; do
    local mtime
    [ -f "$p" ] || continue
    [ -s "$p" ] || continue
    phase2_should_skip_file "$p" && continue
    mtime=$(stat -f "%m" "$p" 2>/dev/null || echo "0")
    printf "%s\t%s\n" "$mtime" "$p" >> "$tmp_all"
    if [ "$mtime" -ge "$cutoff_epoch" ]; then
      printf "%s\t%s\n" "$mtime" "$p" >> "$tmp_recent"
    fi
  done < <(find "$source_dir" -maxdepth 1 -type f \( -name "*.txt" -o -name "*.log" \) -print 2>/dev/null)

  selected_list="$tmp_recent"
  if [ ! -s "$selected_list" ]; then
    selected_list="$tmp_all"
  fi

  while IFS= read -r f; do
    [ -z "$f" ] && continue
    echo "$f"
    count=$((count + 1))
    [ "$count" -ge "$batch_size" ] && break
  done < <(sort -rn "$selected_list" 2>/dev/null | cut -f2)

  rm -f "$tmp_all" "$tmp_recent"
}

phase2_write_plugin_connected() {
  [ "${PLUGIN_SYSTEM_LOADED:-false}" = "true" ] || return 1
  [ "${#LOADED_PLUGIN_IDS[@]}" -gt 0 ] || return 1

  local idx plugin_id plugin_caps
  for idx in "${!LOADED_PLUGIN_IDS[@]}"; do
    plugin_id="${LOADED_PLUGIN_IDS[$idx]}"
    plugin_caps="${LOADED_PLUGIN_CAPS[$idx]:-[]}"

    if [ "$plugin_id" = "com.paranoid.plugin.write" ] || [ "$plugin_id" = "write-plugin" ]; then
      return 0
    fi

    if echo "$plugin_caps" | jq -e 'type == "array" and any(.[]; startswith("write."))' >/dev/null 2>&1; then
      return 0
    fi
  done

  return 1
}

# Generate a readable report from Phase 2 snippet extraction
generate_phase2_report() {
  local snippets_log="$1"
  local report_file="$CMDBOT_FINDINGS_DIR/phase2_report_$(date +%Y%m%d_%H%M%S).txt"

  {
    echo "════════════════════════════════════════════════════════"
    echo "  PHASE 2 — ZERO-TRUST LOG ANALYSIS REPORT"
    echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Posture:   ${USER_POSTURE:-2} — ${USER_POSTURE_LABEL:-Practical}"
    echo "════════════════════════════════════════════════════════"
    echo ""
    cat "$snippets_log"
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  END OF PHASE 2 REPORT"
    echo "════════════════════════════════════════════════════════"
  } > "$report_file"

  echo -e "${BOLD}Phase 2 report saved to:${RESET} $report_file"
  echo -e "View: ${YELLOW}less $report_file${RESET}"
}

# ── Main Phase 2 loop ──────────────────────────────────────────────────────
run_phase2_snippet_extraction() {
  if ! phase2_runtime_enabled; then
    if [ "$EPHEMERAL_MODE" = "true" ]; then
      echo -e "${DIM}Phase 2 skipped in infected-host/ephemeral mode.${RESET}"
      log_to_findings "PHASE2_SKIPPED: ephemeral_mode"
    else
      echo -e "${DIM}Phase 2 disabled. Set PARANOID_PHASE2_ENABLED=true to enable the evidence pass.${RESET}"
      log_to_findings "PHASE2_SKIPPED: disabled"
    fi
    return 0
  fi

  local passed_once_dir="$CMDBOT_WORKDIR/passedOnce"
  local snippets_log="$CMDBOT_WORKDIR/snippetsLog.txt"
  local seen_hashes_file="$CMDBOT_WORKDIR/.phase2_seen_snippet_hashes"
  local final_snippets_log=""
  local plugin_tmp_dir="${PARANOID_DIAG_TMP:-}"
  local write_plugin_connected=false
  local consecutive_api_failures=0

  [[ "$PHASE2_MAX_ITERATIONS" =~ ^[0-9]+$ ]] || PHASE2_MAX_ITERATIONS=20
  [[ "$PHASE2_MAX_RETRIES_PER_BATCH" =~ ^[0-9]+$ ]] || PHASE2_MAX_RETRIES_PER_BATCH=3
  [[ "$PHASE2_MAX_CONSECUTIVE_API_FAILURES" =~ ^[0-9]+$ ]] || PHASE2_MAX_CONSECUTIVE_API_FAILURES=5
  [[ "$PHASE2_RECENT_WINDOW_HOURS" =~ ^[0-9]+$ ]] || PHASE2_RECENT_WINDOW_HOURS=24
  [[ "$PHASE2_CONTEXT_BEFORE_LINES" =~ ^[0-9]+$ ]] || PHASE2_CONTEXT_BEFORE_LINES=2
  [[ "$PHASE2_CONTEXT_AFTER_LINES" =~ ^[0-9]+$ ]] || PHASE2_CONTEXT_AFTER_LINES=2

  mkdir -p "$passed_once_dir"
  : > "$snippets_log"
  : > "$seen_hashes_file"

  if phase2_write_plugin_connected; then
    write_plugin_connected=true
  fi

  echo ""
  print_section "PHASE 2 — ZERO-TRUST LOG ANALYSIS"
  echo -e "${BOLD}Analyzing audit logs with zero-trust methodology...${RESET}"
  echo -e "${DIM}Separate agent scanning collected evidence for hidden threats.${RESET}"
  echo -e "${DIM}Posture: ${USER_POSTURE:-2} — ${USER_POSTURE_LABEL:-Practical}${RESET}"
  echo ""

  local system_prompt
  system_prompt="$(build_phase2_system_prompt)"

  local iteration=0
  local total_snippets=0

  while [ "$iteration" -lt "$PHASE2_MAX_ITERATIONS" ]; do
    iteration=$((iteration + 1))

    # Check snippet line limit
    local current_lines
    current_lines=$(wc -l < "$snippets_log" 2>/dev/null | tr -d ' ' || echo "0")
    if [ "$current_lines" -ge "$PHASE2_SNIPPET_LINE_LIMIT" ]; then
      echo -e "${GREEN}snippetsLog.txt reached $current_lines lines (limit: $PHASE2_SNIPPET_LINE_LIMIT). Moving to next phase.${RESET}"
      log_to_findings "PHASE2_LINE_LIMIT: lines=$current_lines limit=$PHASE2_SNIPPET_LINE_LIMIT"
      break
    fi

    # Select next batch of files from work directory
    local batch_files=()
    local batch_names=""
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      batch_files+=("$f")
      batch_names="${batch_names}$(basename "$f"), "
    done < <(phase2_select_batch "$CMDBOT_WORKDIR" "$PHASE2_BATCH_SIZE" "$PHASE2_RECENT_WINDOW_HOURS")

    if [ "${#batch_files[@]}" -eq 0 ]; then
      echo -e "${YELLOW}No more evidence files to process.${RESET}"
      log_to_findings "PHASE2_NO_MORE_FILES: iteration=$iteration"
      break
    fi

    batch_names="${batch_names%, }"
    echo -e "${CYAN}  [Iteration $iteration] Processing: ${batch_names}${RESET}"

    # Build user content: embed log file contents with markers
    local user_content="Analyze the following log files for suspicious activity. Extract exact log snippets that warrant investigation."
    user_content="${user_content}"$'\n\n'
    local f
    for f in "${batch_files[@]}"; do
      local fname
      fname=$(basename "$f")
      local content
      content=$(head -c "$PHASE2_MAX_INPUT_CHARS" "$f" 2>/dev/null || echo "")
      user_content="${user_content}FILE: ${fname}
----- BEGIN FILE CONTENT -----
${content}
----- END FILE CONTENT -----

"
    done

    # Call Phase 2 LLM agent
    local response
    local phase2_rc=1
    local attempt=0
    response=""
    while [ "$attempt" -lt "$PHASE2_MAX_RETRIES_PER_BATCH" ]; do
      attempt=$((attempt + 1))
      ui_spinner_start "Phase 2 analysis (iteration $iteration, attempt $attempt/$PHASE2_MAX_RETRIES_PER_BATCH)"
      response="$(phase2_api_call "$system_prompt" "$user_content")"
      phase2_rc=$?
      ui_spinner_stop
      if [ "$phase2_rc" -eq 0 ] && [ -n "$response" ] && [[ "$response" != PHASE2_ERROR* ]]; then
        break
      fi
      [ "$attempt" -lt "$PHASE2_MAX_RETRIES_PER_BATCH" ] && sleep $((attempt * 2))
    done

    if [ "$phase2_rc" -ne 0 ] || [ -z "$response" ] || [[ "$response" == PHASE2_ERROR* ]]; then
      echo -e "${RED}  Phase 2 API call failed: $response${RESET}"
      log_to_findings "PHASE2_API_FAIL: iteration=$iteration error=$response"
      consecutive_api_failures=$((consecutive_api_failures + 1))
      if [ "$consecutive_api_failures" -ge "$PHASE2_MAX_CONSECUTIVE_API_FAILURES" ]; then
        echo -e "${YELLOW}Phase 2 API failure budget exhausted (${consecutive_api_failures}/${PHASE2_MAX_CONSECUTIVE_API_FAILURES}). Ending Phase 2.${RESET}"
        log_to_findings "PHASE2_API_FAIL_BUDGET_EXHAUSTED: failures=$consecutive_api_failures"
        break
      fi
      sleep 1
      continue
    else
      consecutive_api_failures=0
      # Parse structured JSON and append snippets to log
      local appended
      appended=$(parse_and_append_snippets "$response" "$snippets_log" "$batch_names" "$seen_hashes_file" "${batch_files[@]}")
      total_snippets=$((total_snippets + appended))
      echo -e "${GREEN}  Extracted $appended snippet(s) (total: $total_snippets)${RESET}"
      log_to_findings "PHASE2_SNIPPETS: iteration=$iteration extracted=$appended total=$total_snippets"
    fi

    # Move processed files to passedOnce/ directory
    for f in "${batch_files[@]}"; do
      mv "$f" "$passed_once_dir/$(basename "$f")" 2>/dev/null || true
    done

    sleep 0.5
  done

  local final_lines
  final_lines=$(wc -l < "$snippets_log" 2>/dev/null | tr -d ' ' || echo "0")
  echo ""
  echo -e "${GREEN}${BOLD}Phase 2 complete: $total_snippets snippet(s) extracted ($final_lines lines)${RESET}"
  log_to_findings "PHASE2_COMPLETE: snippets=$total_snippets lines=$final_lines iterations=$iteration"

  # ── Route output: write plugin (Phase 3) or generate report ──
  if [ -s "$snippets_log" ]; then
    if [ "$write_plugin_connected" = true ]; then
      if [ -n "$plugin_tmp_dir" ] && [ -d "$plugin_tmp_dir" ]; then
        final_snippets_log="${plugin_tmp_dir}/snippetsLog.txt"
      else
        mkdir -p "$CMDBOT_WORKDIR/plugin_handoff"
        final_snippets_log="$CMDBOT_WORKDIR/plugin_handoff/snippetsLog.txt"
      fi
    else
      final_snippets_log="$CMDBOT_FINDINGS_DIR/snippetsLog.txt"
    fi

    cp "$snippets_log" "$final_snippets_log" 2>/dev/null || true
    echo -e "${DIM}Snippets saved to: $final_snippets_log${RESET}"

    if [ "$write_plugin_connected" = true ]; then
      echo -e "${CYAN}Write plugin connected. Routing to Phase 3 (remediation).${RESET}"
      log_to_findings "PHASE2_ROUTING: write_plugin -> Phase 3"
      run_plugin_local_shell "$final_snippets_log"
    else
      echo -e "${DIM}No write-capable plugin connected. Generating final report.${RESET}"
      log_to_findings "PHASE2_ROUTING: no write plugin -> report"
      generate_phase2_report "$snippets_log"
    fi
  else
    echo -e "${YELLOW}No snippets extracted. Generating report with empty snippet set.${RESET}"
    log_to_findings "PHASE2_EMPTY: no snippets extracted"
    generate_phase2_report "$snippets_log"
  fi
}

# Notify and run the write plugin's local_shell executor
# Run the raw HTTP executor inside a Docker container with network/filesystem isolation.
# Network: only api.openai.com allowed outbound (iptables allowlist).
# Filesystem: scope dir mounted read-only, findings dir mounted for output.
run_executor_in_docker() {
  local executor_path="$1" request_json="$2" tmpfile="$3" stderr_file="$4"
  local container_name="paranoid_shell_$$"
  local scope_mount="" scope_vol=""

  # Cleanup container on any exit from this function
  _docker_cleanup() { docker rm -f "$container_name" >/dev/null 2>&1 || true; }
  trap _docker_cleanup RETURN

  # Prepare volume mounts — read-only for scan targets, writable for output
  if [ -n "${SCAN_SCOPE_DIR:-}" ] && [ -d "$SCAN_SCOPE_DIR" ]; then
    scope_vol="-v ${SCAN_SCOPE_DIR}:${SCAN_SCOPE_DIR}:ro"
  fi

  # Start a minimal container with Python and network capabilities
  docker run --name "$container_name" -d \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -e OPENAI_API_KEY="$API_KEY" \
    -v "$CMDBOT_WORKDIR:$CMDBOT_WORKDIR" \
    -v "$CMDBOT_FINDINGS_DIR:$CMDBOT_FINDINGS_DIR:ro" \
    ${scope_vol} \
    python:3.12-slim \
    sleep infinity >/dev/null 2>&1 || { echo "DOCKER_FAIL: could not start container"; return 1; }

  # ── Firewall: restrict outbound to api.openai.com only ──
  # Resolve the API domain and allow only those IPs, drop everything else.
  docker exec --user root "$container_name" bash -c '
    apt-get update -qq && apt-get install -y -qq iptables dnsutils >/dev/null 2>&1
    # Resolve api.openai.com
    for ip in $(dig +short api.openai.com 2>/dev/null); do
      iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j ACCEPT
    done
    # Allow loopback and established connections
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Allow DNS for initial resolution
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    # Drop everything else
    iptables -A OUTPUT -j DROP
  ' >/dev/null 2>&1

  # Copy the executor into the container
  docker cp "$executor_path" "$container_name:/executor.py" >/dev/null 2>&1

  # Run the executor inside the container
  echo "$request_json" | docker exec -i "$container_name" \
    python3 /executor.py > "$tmpfile" 2>"$stderr_file"
  return $?
}

run_plugin_local_shell() {
  local list_file="$1"
  local executor_path="${PLUGIN_DIR:-}/write-plugin/local_shell_executor.py"
  local codex_bin=""
  local exec_mode="none"  # codex | docker | bare

  echo ""
  print_section "PLUGIN: LOCAL SHELL INVESTIGATION"

  # ── Tier 1: Codex CLI (native reference implementation, built-in sandbox) ──
  if command -v codex >/dev/null 2>&1; then
    codex_bin="$(command -v codex)"
    exec_mode="codex"
    echo -e "${GREEN}Tier 1:${RESET} ${BOLD}Codex CLI (native sandbox)${RESET}"
    echo -e "${DIM}  Binary: ${codex_bin}${RESET}"
    echo -e "${DIM}  Model:  CMDBOT_MODEL + local_shell${RESET}"
  elif [ -f "$executor_path" ]; then
    # ── Tier 2: Docker sandbox (network-isolated raw HTTP executor) ──
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      exec_mode="docker"
      echo -e "${GREEN}Tier 2:${RESET} ${BOLD}Docker sandbox (network-isolated)${RESET}"
      echo -e "${DIM}  Executor: local_shell_executor.py${RESET}"
      echo -e "${DIM}  Network:  api.openai.com only (iptables allowlist)${RESET}"
      echo -e "${DIM}  Mount:    scope dir read-only, workdir writable${RESET}"
    else
      # ── Tier 3: Bare executor (no sandbox) ──
      exec_mode="bare"
      echo -e "${YELLOW}Tier 3:${RESET} ${BOLD}Raw HTTP executor (no sandbox)${RESET}"
      echo -e "${DIM}  Executor: local_shell_executor.py${RESET}"
      echo -e "${DIM}  Install Codex CLI or Docker for sandboxed execution.${RESET}"
    fi
  else
    echo -e "${YELLOW}No local_shell executor available.${RESET}"
    echo -e "${DIM}  Option 1: npm install -g @openai/codex${RESET}"
    echo -e "${DIM}  Option 2: Ensure ${executor_path} exists${RESET}"
    log_to_findings "PLUGIN_LOCAL_SHELL: no executor available"
    return 0
  fi
  echo ""

  log_to_findings "PLUGIN_LOCAL_SHELL_START: list_file=$list_file mode=$exec_mode"

  local result_json="" exit_code=0
  local tmpfile stderr_file
  tmpfile=$(mktemp /tmp/cmdbot_plugin_shell.XXXXXX)
  stderr_file=$(mktemp /tmp/cmdbot_plugin_shell_err.XXXXXX)

  case "$exec_mode" in
    codex)
      # ── Codex CLI: native binary with built-in sandboxing ──
      local list_content
      list_content="$(cat "$list_file" 2>/dev/null)"

      local scope_flag=""
      [ -n "${SCAN_SCOPE_DIR:-}" ] && scope_flag="CONFINED to ${SCAN_SCOPE_DIR}. Only access files within this directory."

      local codex_prompt="You are a macOS security investigator. Here are the 10 most critical findings from a security scan. Investigate each with targeted READ-ONLY shell commands. Do NOT modify any files. ${scope_flag}

${list_content}

Run targeted commands to gather additional evidence for each finding, check if threats are active, and provide a final assessment."

      OPENAI_API_KEY="$API_KEY" "$codex_bin" \
        --quiet \
        --model "$API_MODEL" \
        --approval-mode full-auto \
        "$codex_prompt" \
        > "$tmpfile" 2>"$stderr_file" || exit_code=$?

      if [ -s "$stderr_file" ]; then
        while IFS= read -r _diag_line; do
          echo -e "${DIM}  $_diag_line${RESET}"
        done < "$stderr_file"
      fi

      local codex_output
      codex_output="$(cat "$tmpfile" 2>/dev/null || echo "")"

      result_json=$(jq -n \
        --arg output "$codex_output" \
        --argjson exit_code "$exit_code" \
        '{
          status: (if $exit_code == 0 then "ok" else "error" end),
          commands_run: [],
          final_output: $output
        }')
      ;;

    docker)
      # ── Docker sandbox: network-isolated raw HTTP executor ──
      local request_json
      request_json=$(jq -n \
        --arg api_key "$API_KEY" \
        --arg list_file "$list_file" \
        --arg scope_dir "${SCAN_SCOPE_DIR:-}" \
        --argjson timeout 120 \
        '{api_key: $api_key, list_file: $list_file, scope_dir: $scope_dir, timeout: $timeout}')

      run_executor_in_docker "$executor_path" "$request_json" "$tmpfile" "$stderr_file"
      exit_code=$?

      if [ -s "$stderr_file" ]; then
        while IFS= read -r _diag_line; do
          echo -e "${DIM}  $_diag_line${RESET}"
        done < "$stderr_file"
      fi

      result_json=$(cat "$tmpfile" 2>/dev/null || echo "")
      ;;

    bare)
      # ── Bare executor: direct Python, no sandbox ──
      local request_json
      request_json=$(jq -n \
        --arg api_key "$API_KEY" \
        --arg list_file "$list_file" \
        --arg scope_dir "${SCAN_SCOPE_DIR:-}" \
        --argjson timeout 120 \
        '{api_key: $api_key, list_file: $list_file, scope_dir: $scope_dir, timeout: $timeout}')

      echo "$request_json" | python3 "$executor_path" > "$tmpfile" 2>"$stderr_file"
      exit_code=$?

      if [ -s "$stderr_file" ]; then
        while IFS= read -r _diag_line; do
          echo -e "${DIM}  $_diag_line${RESET}"
        done < "$stderr_file"
      fi

      result_json=$(cat "$tmpfile" 2>/dev/null || echo "")
      ;;
  esac

  rm -f "$tmpfile" "$stderr_file"

  if [ "$exit_code" -ne 0 ] && [ -z "$result_json" ]; then
    echo -e "${RED}Plugin local_shell executor failed (exit $exit_code)${RESET}"
    log_to_findings "PLUGIN_LOCAL_SHELL_FAIL: exit=$exit_code mode=$exec_mode"
    return 0
  fi

  local status commands_count final_output
  status=$(echo "$result_json" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
  commands_count=$(echo "$result_json" | jq -r '.commands_run | length // 0' 2>/dev/null || echo "0")
  final_output=$(echo "$result_json" | jq -r '.final_output // ""' 2>/dev/null || echo "")

  echo -e "${GREEN}Status: $status | Commands executed: $commands_count${RESET}"

  if [ -n "$final_output" ]; then
    echo ""
    echo -e "${BOLD}Plugin Investigation Summary:${RESET}"
    echo -e "${DIM}${final_output:0:2000}${RESET}"

    local executor_label
    case "$exec_mode" in
      codex)  executor_label="Codex CLI ($codex_bin)" ;;
      docker) executor_label="Docker sandbox (network-isolated)" ;;
      bare)   executor_label="Raw HTTP (local_shell_executor.py)" ;;
    esac

    {
      echo ""
      echo "════════════════════════════════════════════════════════"
      echo "  PLUGIN LOCAL SHELL INVESTIGATION"
      echo "════════════════════════════════════════════════════════"
      echo "Executor: $executor_label"
      echo "Commands executed: $commands_count"
      echo ""
      echo "$final_output"
    } >> "$findings_file"
  fi

  # Save full result to work directory
  local shell_log="$CMDBOT_WORKDIR/plugin_local_shell_$(date +%Y%m%d_%H%M%S).json"
  echo "$result_json" > "$shell_log" 2>/dev/null || true
  echo -e "${DIM}Full log: $shell_log${RESET}"

  log_to_findings "PLUGIN_LOCAL_SHELL_COMPLETE: status=$status commands=$commands_count log=$shell_log"
}

#==============================================================================
# THE AGENT LOOP — Native Tool Calling
#==============================================================================
# Flow:
#   1. Send user message (system context) → model returns function_call
#   2. Execute function(s) → send function_call_output item(s)
#   3. Model returns next function_call(s)
#   4. Repeat until scan_complete
#
# No JSON parsing. No text extraction. No nudging. The model is constrained
# to only call tools we defined. Clean structured I/O.
#==============================================================================

run_paranoid_scan() {
  local scan_name="$1"
  local scan_focus="${2:-$PROFILE_FULL}"
  local scanner_script scanner_mtime macos_module_mtime intel_module_mtime key_fingerprint
  scan_step=0
  findings=()
  findings_total=0
  total_input_tokens=0
  total_cached_tokens=0
  total_output_tokens=0
  total_tokens_used=0
  total_billable_tokens=0
  token_wrapup_mode=false
  token_wrapup_rounds=0
  soft_limit_investigation_mode=false
  soft_limit_investigation_rounds=0
  soft_limit_investigation_tokens_start=0
  soft_limit_investigation_tokens_used=0
  soft_limit_investigation_billable_start=0
  soft_limit_investigation_billable_used=0
  soft_limit_investigation_budget_exhausted=false
  soft_limit_focus_goal=""
  soft_limit_investigation_findings_start=0
  reflection_calls_used=0
  last_request_input_tokens=0
  last_request_cached_tokens=0
  last_request_output_tokens=0
  last_request_billable_tokens=0
  chain_reset_count=0
  last_chain_reset_step=0
  compact_count=0
  last_compact_step=0
  COMPACT_INPUT=""
  scan_memory=""
  recent_broad_cmds=""

  scanner_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  scanner_mtime="$(stat -f "%Sm" "$scanner_script" 2>/dev/null || echo "unknown")"
  if [ -n "${SCRIPT_DIR:-}" ] && [ -f "$SCRIPT_DIR/paranoid_macos_tools.sh" ]; then
    macos_module_mtime="$(stat -f "%Sm" "$SCRIPT_DIR/paranoid_macos_tools.sh" 2>/dev/null || echo "unknown")"
  else
    macos_module_mtime="not_loaded"
  fi
  if [ -n "${SCRIPT_DIR:-}" ] && [ -f "$SCRIPT_DIR/paranoid_threat_intel.sh" ]; then
    intel_module_mtime="$(stat -f "%Sm" "$SCRIPT_DIR/paranoid_threat_intel.sh" 2>/dev/null || echo "unknown")"
  else
    intel_module_mtime="not_loaded"
  fi
  if [ "${#API_KEY}" -gt 12 ]; then
    key_fingerprint="${API_KEY:0:8}...${API_KEY: -4}"
  else
    key_fingerprint="${API_KEY:0:4}..."
  fi

  # Initialize findings file
  prepare_findings_target "$CMDBOT_FINDINGS_DIR/${scan_name}_$(date +%Y%m%d_%H%M%S).txt"
  if [ -n "$findings_file" ]; then
    {
      echo "════════════════════════════════════════════════════════"
      echo "  PARANOID SCANNER — $scan_name"
      echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')"
      echo "  System:  $HOSTNAME_STR — macOS $OS_VERSION ($ARCH)"
      echo "  User:    $CURRENT_USER"
      echo "  Runtime: $(runtime_mode_label)"
      echo "  Posture: $USER_POSTURE — $USER_POSTURE_LABEL"
      echo "  Model:   $API_MODEL"
      echo "  API:     Responses API (native tool calling + response ID chaining)"
      echo "  TokenSoftLimit: $SOFT_TOKEN_LIMIT (mode=$SOFT_TOKEN_LIMIT_MODE)"
      echo "  SoftLimitInvestigation: enabled=$SOFT_LIMIT_INVESTIGATION_ENABLED rounds=$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS token_budget=$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET reset=$SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET min_rounds=$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS min_findings=$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS"
      echo "  API Key: $key_fingerprint"
      echo "  Scanner: $scanner_script"
      echo "  Build:   scanner=$scanner_mtime | macos_tools=$macos_module_mtime | intel_tools=$intel_module_mtime"
      echo "════════════════════════════════════════════════════════"
      echo ""
    } > "$findings_file"
  fi

  # ── Initialize API state ──
  CURRENT_RESPONSE_ID=""
  SYSTEM_INSTRUCTIONS="$(generate_system_prompt)"
  TOOLS_JSON="$(build_tools_json)"
  TOOLS_JSON_COMPACT="$(build_compact_tools_json "$TOOLS_JSON")"

  # First input: user message with system context
  local next_input
  next_input=$(jq -n --arg content "$(generate_system_context "$scan_focus")" \
    '[{role: "user", content: $content}]')

  local scan_complete=false
  local consecutive_failures=0
  local consecutive_no_tool_calls=0
  local phase1_stop_reason=""

  clear
  set_terminal_title "PARANOID SCANNER"
  print_section "PARANOID SCAN: $scan_name"
  echo -e "${BOLD}${GREEN}STATUS: RUNNING${RESET}"
  echo -e "${BOLD}Start:${RESET}    $(date '+%H:%M:%S')"
  echo -e "${BOLD}Findings:${RESET} $(runtime_findings_label)"
  echo -e "${BOLD}Runtime:${RESET}  $(runtime_mode_label)"
  echo -e "${BOLD}Posture:${RESET}  ${BOLD}$USER_POSTURE${RESET} — $USER_POSTURE_LABEL"
  echo -e "${BOLD}Model:${RESET}    $API_MODEL"
  echo -e "${BOLD}API:${RESET}      Responses API (native tool calling)"
  echo -e "${BOLD}API Truncation:${RESET} $API_TRUNCATION | max_tool_calls=$API_MAX_TOOL_CALLS | max_output_tokens=$API_MAX_TOKENS"
  echo -e "${BOLD}Schema Mode:${RESET} compact_followups=$COMPACT_TOOL_SCHEMAS | prompt_style=$SYSTEM_PROMPT_STYLE"
  if [ "$SOFT_TOKEN_LIMIT" -gt 0 ]; then
    if [ "$SOFT_LIMIT_INVESTIGATION_ENABLED" = "true" ]; then
      echo -e "${BOLD}Token Soft Limit:${RESET} $SOFT_TOKEN_LIMIT (mode=$SOFT_TOKEN_LIMIT_MODE, pivot to investigation mode)"
      echo -e "${BOLD}SL Investigation:${RESET} rounds=$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS | token_budget=$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET | min_rounds=$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS | min_findings=$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS | reset=$SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET"
    else
      echo -e "${BOLD}Token Soft Limit:${RESET} $SOFT_TOKEN_LIMIT (mode=$SOFT_TOKEN_LIMIT_MODE, wrap-up mode after limit)"
    fi
  else
    echo -e "${BOLD}Token Soft Limit:${RESET} disabled"
  fi
  echo -e "${BOLD}Phase 2:${RESET}  $([ "$PHASE2_ENABLED" = "true" ] && echo "enabled" || echo "disabled")$([ "$EPHEMERAL_MODE" = "true" ] && echo " (auto-skipped in ephemeral mode)")"
  if [ "$PHASE1_TOKEN_GATE_ENABLED" = "true" ] && [ "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" -gt 0 ]; then
    echo -e "${BOLD}Phase1 Token Gate:${RESET} total_in_out>=$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL → Phase 2"
  fi
  if [ "$COMPACT_ENABLED" = "true" ]; then
    echo -e "${BOLD}Compaction:${RESET} API-based (every $COMPACT_INTERVAL_STEPS steps when input>=$COMPACT_MIN_INPUT_TOKENS)"
  elif [ "$CHAIN_RESET_ENABLED" = "true" ]; then
    echo -e "${BOLD}Chain Reset:${RESET} input>=$CHAIN_RESET_INPUT_TOKENS tokens (min gap $CHAIN_RESET_MIN_STEP_GAP steps)"
  else
    echo -e "${BOLD}Context Mgmt:${RESET} disabled"
  fi
  if [ "$CONTEXT_MANAGEMENT_JSON" != "[]" ]; then
    echo -e "${BOLD}Context Mgmt:${RESET} enabled via CMDBOT_CONTEXT_MANAGEMENT_JSON"
  else
    echo -e "${BOLD}Context Mgmt:${RESET} disabled"
  fi
  echo -e "${BOLD}Broad Cmd Repeat Limit:${RESET} $BROAD_CMD_REPEAT_LIMIT"
  echo -e "${BOLD}Reflection Budget:${RESET} $REFLECTION_MAX_CALLS calls"

  local tool_count
  tool_count=$(echo "$TOOLS_JSON" | jq 'length' 2>/dev/null || echo "?")
  echo -e "${BOLD}Tools:${RESET}    $tool_count defined"
  echo -e "${BOLD}Modules:${RESET}  macOS=$([ "${MACOS_TOOLS_LOADED:-false}" = true ] && echo "✓" || echo "✗") | Intel=$([ "${THREAT_INTEL_LOADED:-false}" = true ] && echo "✓" || echo "✗") | Plugins=$([ "${PLUGIN_SYSTEM_LOADED:-false}" = true ] && echo "${#LOADED_PLUGIN_IDS[@]} loaded" || echo "✗")"
  echo -e "${YELLOW}Press Ctrl+C to abort scan.${RESET}"
  print_border

  ui_status_enable
  ui_status_set "RUNNING"

  while [ "$scan_complete" = false ] && [ "$scan_step" -lt "$MAX_SCAN_STEPS" ]; do
    scan_step=$((scan_step + 1))
    print_tool_header "Step $scan_step"

    if [ "$PHASE1_TOKEN_GATE_ENABLED" = "true" ] \
      && [ "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" -gt 0 ] \
      && [ "$total_tokens_used" -ge "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" ]; then
      phase1_stop_reason="audit_token_budget_reached_pre_call"
      echo -e "${GREEN}Phase 1 token budget reached (${total_tokens_used}/${PHASE1_AUDIT_TOKEN_BUDGET_TOTAL}). Transitioning to Phase 2.${RESET}"
      log_to_findings "PHASE1_TOKEN_GATE: reason=$phase1_stop_reason total_tokens=$total_tokens_used budget=$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL"
      print_tool_footer
      break
    fi

    if [ "$token_wrapup_mode" = true ] \
      && { [ "$soft_limit_investigation_mode" != "true" ] || [ "$soft_limit_investigation_budget_exhausted" = "true" ]; } \
      && [ "$token_wrapup_rounds" -ge "$TOKEN_WRAPUP_MAX_ROUNDS" ]; then
      phase1_stop_reason="token_wrapup_exhausted"
      echo -e "${YELLOW}Token soft-limit wrap-up budget exhausted. Ending scan to control cost.${RESET}"
      if [ "$soft_limit_investigation_budget_exhausted" = "true" ]; then
        findings+=("[INFO] Soft-limit investigation budget exhausted after base soft limit; scan ended during final wrap-up.")
      else
        findings+=("[INFO] Soft token limit reached; scan ended early to control cost.")
      fi
      findings_total=$((findings_total + 1))
      log_to_findings "TOKEN_WRAPUP_EXHAUSTED: rounds=$token_wrapup_rounds limit=$TOKEN_WRAPUP_MAX_ROUNDS"
      print_tool_footer
      break
    fi

    # ── Call LLM ──
    ui_spinner_start "Calling model"
    local invoke_rc=0
    if invoke_llm "$next_input"; then
      invoke_rc=0
    else
      invoke_rc="$?"
    fi
    if [ "$invoke_rc" -ne 0 ]; then
      ui_spinner_stop
      if [ "$invoke_rc" -eq 2 ] || [ "${LAST_INVOKE_REASON:-}" = "no_function_calls" ]; then
        local no_tool_msg
        consecutive_no_tool_calls=$((consecutive_no_tool_calls + 1))
        consecutive_failures=0

        # Don't waste a step — roll back the step counter
        scan_step=$((scan_step - 1))

        log_to_findings "──── NO_TOOL_CALL_RECOVERY [$(date '+%H:%M:%S')] (consecutive: $consecutive_no_tool_calls) ────"
        if [ -n "${LAST_TEXT_OUTPUT:-}" ]; then
          log_to_findings "MODEL_TEXT: ${LAST_TEXT_OUTPUT:0:500}"
        fi

        if [ "$consecutive_no_tool_calls" -ge 8 ]; then
          phase1_stop_reason="no_function_call_recovery_exhausted"
          echo -e "${RED}Model returned no tool calls repeatedly. Aborting to avoid infinite loop.${RESET}"
          log_to_findings "ABORT: no_function_calls_loop count=$consecutive_no_tool_calls"
          scan_step=$((scan_step + 1))  # restore for final reporting
          print_tool_footer
          break
        fi

        if soft_limit_investigation_active; then
          no_tool_msg="$(build_soft_limit_investigation_prompt "continue" "Previous response had no tool call. Return exactly one tool call now.")"
          no_tool_msg="$no_tool_msg

RECOVERY: Return exactly ONE tool call. Use: shell_exec, file_grep, file_read, net_sockets_ownership, or scan_finding."
        else
          no_tool_msg="Return exactly ONE function call now. Use: security_status, persistence_launchd, net_sockets_ownership, shell_exec, or scan_finding."
        fi

        next_input=$(jq -n --arg msg "$no_tool_msg" '[{role: "user", content: $msg}]')
        print_tool_footer
        continue
      fi

      consecutive_no_tool_calls=0
      consecutive_failures=$((consecutive_failures + 1))
      log_to_findings "──── STEP $scan_step [$(date '+%H:%M:%S')] ────"
      log_to_findings "API_FAILURE (consecutive: $consecutive_failures, reason=${LAST_INVOKE_REASON:-unknown})"

      if [ "$consecutive_failures" -ge 3 ]; then
        phase1_stop_reason="api_failure_budget_exhausted"
        echo -e "${RED}3 consecutive API failures. Aborting scan.${RESET}"
        log_to_findings "ABORT: 3 consecutive API failures"
        print_tool_footer
        break
      fi

      # Retry: send a nudge as user message
      echo -e "${YELLOW}API call failed. Retrying...${RESET}"
      ui_status_set "API error (retrying)"
      next_input=$(jq -n '[{role: "user", content: "The previous API call failed. Please continue the scan by calling your next tool."}]')
      print_tool_footer
      sleep 3
      continue
    fi
    ui_spinner_stop

    # Now that the spinner is stopped, it's safe to print token/cost info without
    # corrupting the bottom status line.
    if [ "${last_request_input_tokens:-0}" -gt 0 ] || [ "${last_request_output_tokens:-0}" -gt 0 ]; then
      print_cost_info "$last_request_input_tokens" "$last_request_cached_tokens" "$last_request_output_tokens" "${last_request_cost:-0}" "$total_cost"
    fi

    consecutive_failures=0  # Reset on success
    consecutive_no_tool_calls=0

    if [ "$PHASE1_TOKEN_GATE_ENABLED" = "true" ] \
      && [ "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" -gt 0 ] \
      && [ "$total_tokens_used" -ge "$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL" ]; then
      phase1_stop_reason="audit_token_budget_reached_post_call"
      echo -e "${GREEN}Phase 1 token budget reached (${total_tokens_used}/${PHASE1_AUDIT_TOKEN_BUDGET_TOTAL}). Transitioning to Phase 2.${RESET}"
      log_to_findings "PHASE1_TOKEN_GATE: reason=$phase1_stop_reason total_tokens=$total_tokens_used budget=$PHASE1_AUDIT_TOKEN_BUDGET_TOTAL"
      print_tool_footer
      break
    fi

    # Trigger wrapup when cumulative soft limit OR per-request input tokens exceed threshold
    local should_enter_wrapup=false
    local wrapup_trigger=""
    if [ "$token_wrapup_mode" = false ] && [ "$PHASE1_TOKEN_GATE_ENABLED" != "true" ]; then
      if token_soft_limit_reached; then
        should_enter_wrapup=true
        wrapup_trigger="$(soft_limit_meter_snapshot)"
      elif [ "$REQUEST_INPUT_TOKEN_LIMIT" -gt 0 ] \
        && [ "${last_request_input_tokens:-0}" -ge "$REQUEST_INPUT_TOKEN_LIMIT" ]; then
        should_enter_wrapup=true
        wrapup_trigger="request_input=${last_request_input_tokens}>=${REQUEST_INPUT_TOKEN_LIMIT}"
      fi
    fi
    if [ "$should_enter_wrapup" = true ]; then
      token_wrapup_mode=true
      token_wrapup_rounds=0
      if [ "$SOFT_LIMIT_INVESTIGATION_ENABLED" = "true" ]; then
        soft_limit_investigation_mode=true
        soft_limit_investigation_rounds=0
        soft_limit_investigation_tokens_start="$total_tokens_used"
        soft_limit_investigation_tokens_used=0
        soft_limit_investigation_billable_start="$total_billable_tokens"
        soft_limit_investigation_billable_used=0
        soft_limit_investigation_budget_exhausted=false
        soft_limit_focus_goal=""
        soft_limit_investigation_findings_start="$findings_total"
        echo -e "${YELLOW}Entering targeted investigation mode ($wrapup_trigger).${RESET}"
        log_to_findings "WRAPUP_TRIGGERED: $wrapup_trigger"
        log_to_findings "SOFT_LIMIT_INVESTIGATION_MODE: enabled rounds=$SOFT_LIMIT_INVESTIGATION_MAX_ROUNDS token_budget=$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET min_rounds=$SOFT_LIMIT_INVESTIGATION_MIN_ROUNDS min_findings=$SOFT_LIMIT_INVESTIGATION_MIN_FINDINGS"
      else
        echo -e "${YELLOW}Entering wrap-up mode ($wrapup_trigger).${RESET}"
        log_to_findings "WRAPUP_TRIGGERED: $wrapup_trigger"
      fi
    fi
    if [ "$token_wrapup_mode" = true ]; then
      token_wrapup_rounds=$((token_wrapup_rounds + 1))
    fi
    if soft_limit_investigation_active; then
      soft_limit_investigation_rounds=$((soft_limit_investigation_rounds + 1))
    fi
    update_soft_limit_investigation_budget

    # ── Log the tool call(s) ──
    log_to_findings "──── STEP $scan_step [$(date '+%H:%M:%S')] ────"
    local call_count call_idx
    call_count=${#LAST_FUNC_NAMES[@]}
    log_to_findings "FUNCTION_CALL_COUNT: $call_count"
    for ((call_idx=0; call_idx<call_count; call_idx++)); do
      log_to_findings "FUNCTION_CALL[$((call_idx + 1))/$call_count]: ${LAST_FUNC_NAMES[$call_idx]}(${LAST_FUNC_ARGS_LIST[$call_idx]})"
      log_to_findings "CALL_ID[$((call_idx + 1))/$call_count]: ${LAST_CALL_IDS[$call_idx]}"
    done

    local enforce_single_turn_call=false
    if [ "$ENFORCE_SINGLE_TOOL_CALL" = "true" ] && [ "$call_count" -gt 1 ]; then
      enforce_single_turn_call=true
      echo -e "${YELLOW}Model requested $call_count tools in one turn. Executing first call only; deferring the rest.${RESET}"
      log_to_findings "MULTI_TOOL_CALL_DETECTED: $call_count requested — only first call will execute"
    fi

    # If model also output text (reasoning), show it
    if [ -n "$LAST_TEXT_OUTPUT" ]; then
      echo -e "${DIM}${MAGENTA}Model: ${LAST_TEXT_OUTPUT:0:300}${RESET}"
      log_to_findings "MODEL_TEXT: ${LAST_TEXT_OUTPUT:0:500}"
    fi

    # ── Execute tool(s) and collect function_call_output item(s) ──
    local tool_results_input saw_scan_complete saw_scan_finding step_had_error step_summary_for_reset
    tool_results_input='[]'
    saw_scan_complete=false
    saw_scan_finding=false
    step_had_error=false
    step_summary_for_reset=""

    for ((call_idx=0; call_idx<call_count; call_idx++)); do
      local call_id func_name func_args tool_output internal_name output_lines
      call_id="${LAST_CALL_IDS[$call_idx]}"
      func_name="${LAST_FUNC_NAMES[$call_idx]}"
      func_args="${LAST_FUNC_ARGS_LIST[$call_idx]}"

      if [ -z "$call_id" ]; then
        echo -e "${RED}INTERNAL ERROR: missing call_id for tool '$func_name'${RESET}"
        log_to_findings "INTERNAL_ERROR: missing call_id for tool '$func_name'"
        step_had_error=true
        break
      fi

      if wrapup_tool_restrictions_active && [ "$func_name" != "scan_complete" ] && [ "$func_name" != "scan_finding" ]; then
        local soft_limit_status
        soft_limit_status="$(soft_limit_meter_snapshot)"
        if [ "$soft_limit_investigation_budget_exhausted" = "true" ]; then
          tool_output="TOOL_LIMIT_REACHED: Soft-limit investigation budget exhausted after base soft limit ($soft_limit_status). No further collection tools allowed. Record unresolved deviations via scan_finding, then call scan_complete."
        else
          tool_output="TOOL_LIMIT_REACHED: Soft token limit reached ($soft_limit_status). No further collection tools allowed. Report remaining findings via scan_finding and then call scan_complete."
        fi
      elif [ "$enforce_single_turn_call" = true ] && [ "$call_idx" -gt 0 ] \
        && [ "$func_name" != "scan_complete" ] && [ "$func_name" != "scan_finding" ]; then
        tool_output="TOOL_DEFERRED: Multiple tool calls were requested in one turn. This call was deferred so the model must analyze prior output before issuing next call."
      else
        tool_output="$(dispatch_tool_call "$func_name" "$func_args" 2>&1)" || tool_output="TOOL_ERROR: execution failed"
      fi
      tool_output="$(truncate_output "$tool_output")" || true

      log_to_findings "OUTPUT[$((call_idx + 1))/$call_count]:"
      log_to_findings "$tool_output"
      log_to_findings ""

      if echo "$tool_output" | grep -q "^SCAN_COMPLETE$" 2>/dev/null; then
        saw_scan_complete=true
      fi
      [ "$func_name" = "scan_finding" ] && saw_scan_finding=true

      internal_name="$(api_name_to_internal "$func_name")"
      output_lines=$(echo "$tool_output" | wc -l | tr -d ' ' || echo "0")
      echo -e "${CYAN}│${RESET} Tool $((call_idx + 1))/$call_count: ${BOLD}$internal_name${RESET} → $output_lines lines"

      # Print a clipped preview to avoid hard-wrapping into the status line on narrow terminals.
      local _rows _cols _max_preview_cols
      read -r _rows _cols < <(ui__term_size)
      _max_preview_cols=$((_cols - 8))  # room for "│   " + color + 1 col safety
      [ "$_max_preview_cols" -lt 20 ] && _max_preview_cols=20
      echo "$tool_output" | head -n 5 | while IFS= read -r line; do
        line="$(ui__strip_ansi_and_ctrl "$line")"
        line="$(ui__clip_to_cols "$line" "$_max_preview_cols")"
        echo -e "${CYAN}│${RESET}   ${DIM}$line${RESET}"
      done || true
      [ "${output_lines:-0}" -gt 5 ] 2>/dev/null && echo -e "${CYAN}│${RESET}   ${DIM}... ($((output_lines - 5)) more lines)${RESET}" || true
      echo -e "${CYAN}│${RESET} ${DIM}Chain: ${CURRENT_RESPONSE_ID:-none} | Call: ${call_id:-none}${RESET}"

      local model_output next_tool_results_input
      model_output="$(compact_tool_output_for_model "$tool_output")"
      append_scan_memory "$scan_step" "$internal_name" "$model_output"
      step_summary_for_reset="$(printf "%s\n[Tool: %s]\n%s\n\n" "$step_summary_for_reset" "$internal_name" "$(printf "%s\n" "$model_output" | tail -n 10)" | tail -n 140)"
      if ! next_tool_results_input=$(echo "$tool_results_input" | jq -c \
        --arg call_id "$call_id" \
        --arg output "$model_output" \
        '. + [{type: "function_call_output", call_id: $call_id, output: $output}]' 2>/dev/null); then
        echo -e "${RED}INTERNAL ERROR: failed to build function_call_output for call_id '$call_id'${RESET}"
        log_to_findings "INTERNAL_ERROR: failed to build function_call_output for call_id '$call_id'"
        step_had_error=true
        break
      fi
      tool_results_input="$next_tool_results_input"
    done

    print_tool_footer

    if [ "$step_had_error" = true ]; then
      echo -e "${RED}Tool-call handoff failed. Aborting scan to avoid broken response chain.${RESET}"
      log_to_findings "ABORT: tool-call handoff failure"
      break
    fi

    # ── Check for scan completion ──
    if [ "$saw_scan_complete" = true ]; then
      scan_complete=true
      break
    fi

    # ── Prepare next input: function_call_output array ──
    # Send all tool outputs from this step in one structured array.
    next_input="$tool_results_input"
    if wrapup_tool_restrictions_active; then
      local wrap_msg wrapped_input soft_limit_status
      soft_limit_status="$(soft_limit_meter_snapshot)"
      if [ "$soft_limit_investigation_budget_exhausted" = "true" ]; then
        wrap_msg="Soft-limit investigation budget exhausted after base soft limit ($soft_limit_status). Finalize now: no additional collection tools. Record unresolved deviations with scan_finding, then call scan_complete."
      else
        wrap_msg="Soft token limit reached ($soft_limit_status). Wrap up now: do not call additional collection tools. Record unresolved deviations with scan_finding, then call scan_complete."
      fi
      wrapped_input="$(append_message_to_input_json "$tool_results_input" "$wrap_msg")"
      if [ -n "$wrapped_input" ]; then
        next_input="$wrapped_input"
      fi
    elif soft_limit_investigation_active; then
      local investigation_stage investigation_msg investigation_input
      if [ "$saw_scan_finding" = "true" ]; then
        investigation_stage="post_finding"
      elif [ "$soft_limit_investigation_rounds" -le 1 ]; then
        investigation_stage="entry"
      else
        investigation_stage="continue"
      fi
      investigation_msg="$(build_soft_limit_investigation_prompt "$investigation_stage" "$step_summary_for_reset")"
      investigation_input="$(append_message_to_input_json "$tool_results_input" "$investigation_msg")"
      if [ -n "$investigation_input" ]; then
        next_input="$investigation_input"
      fi
    fi

    # ── Conversation compaction (API-based, preferred) ──
    local did_compact=false
    if [ "$COMPACT_ENABLED" = "true" ] \
      && [ "$SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET" = "true" ] \
      && soft_limit_investigation_active \
      && [ "$saw_scan_finding" = "true" ]; then
      if compact_conversation; then
        did_compact=true
        log_to_findings "SOFT_LIMIT_INVESTIGATION_CONTEXT_RESET: step=$scan_step reason=post_finding"
        local post_finding_prompt
        post_finding_prompt="$(build_soft_limit_investigation_prompt "post_finding" "$step_summary_for_reset")"
        next_input=$(jq -c \
          --argjson compact "$COMPACT_INPUT" \
          --argjson outputs "$tool_results_input" \
          --arg msg "$post_finding_prompt" \
          '$compact + $outputs + [{role: "user", content: $msg}]' 2>/dev/null || echo "$next_input")
      fi
    fi

    if [ "$did_compact" = false ] \
      && [ "$COMPACT_ENABLED" = "true" ] \
      && [ "$token_wrapup_mode" = false ] \
      && [ "$last_request_input_tokens" -ge "$COMPACT_MIN_INPUT_TOKENS" ] \
      && [ $((scan_step - last_compact_step)) -ge "$COMPACT_INTERVAL_STEPS" ]; then
      if compact_conversation; then
        did_compact=true
        # Prepend compacted context to current tool results
        next_input=$(jq -c \
          --argjson compact "$COMPACT_INPUT" \
          --argjson outputs "$tool_results_input" \
          '$compact + $outputs' 2>/dev/null || echo "$tool_results_input")
      fi
    fi

    # ── Fallback: crude chain reset if compact failed or disabled ──
    if [ "$did_compact" = false ] \
      && [ "$CHAIN_RESET_ENABLED" = "true" ] \
      && [ "$token_wrapup_mode" = false ] \
      && [ "$last_request_input_tokens" -ge "$CHAIN_RESET_INPUT_TOKENS" ] \
      && [ $((scan_step - last_chain_reset_step)) -ge "$CHAIN_RESET_MIN_STEP_GAP" ]; then
      chain_reset_count=$((chain_reset_count + 1))
      last_chain_reset_step="$scan_step"
      log_to_findings "CHAIN_RESET: step=$scan_step input_tokens=$last_request_input_tokens threshold=$CHAIN_RESET_INPUT_TOKENS resets=$chain_reset_count"
      echo -e "${YELLOW}Context compaction reset activated (input tokens $last_request_input_tokens >= $CHAIN_RESET_INPUT_TOKENS).${RESET}"
      CURRENT_RESPONSE_ID=""
      next_input="$(build_context_reset_input "$scan_name" "$scan_focus" "$step_summary_for_reset")"
    fi

    # ── Status (fixed bottom line) ──
    if soft_limit_investigation_active; then
      ui_status_set "SOFT-LIMIT INVESTIGATION"
    elif wrapup_tool_restrictions_active; then
      ui_status_set "WRAP-UP"
    else
      ui_status_set "RUNNING"
    fi

    sleep 0.5
  done

  if [ -z "$phase1_stop_reason" ]; then
    if [ "$scan_complete" = true ]; then
      phase1_stop_reason="scan_complete"
    elif [ "$scan_step" -ge "$MAX_SCAN_STEPS" ]; then
      phase1_stop_reason="max_scan_steps_reached"
    else
      phase1_stop_reason="loop_exit_unknown"
    fi
  fi
  log_to_findings "PHASE1_COMPLETE: reason=$phase1_stop_reason steps=$scan_step total_tokens=$total_tokens_used"

  if [ "$scan_step" -ge "$MAX_SCAN_STEPS" ]; then
    echo -e "${YELLOW}Scan reached maximum step limit ($MAX_SCAN_STEPS).${RESET}"
  fi

  ui_status_disable
  generate_report

  # ── Phase 2: Optional zero-trust log analysis on collected evidence ──
  # When enabled, Phase 2 analyzes raw evidence files, not just flagged findings.
  # This pass is intentionally skipped in ephemeral mode.
  run_phase2_snippet_extraction
}

#==============================================================================
# REPORT GENERATION
#==============================================================================

generate_report() {
  local critical=0 warning=0 info=0

  for finding in "${findings[@]-}"; do
    [ -z "$finding" ] && continue
    case "$finding" in
      "[CRITICAL]"*) critical=$((critical + 1)) ;;
      "[WARNING]"*)  warning=$((warning + 1)) ;;
      *)             info=$((info + 1)) ;;
    esac
  done

  if [ -n "$findings_file" ]; then
    {
      echo ""
      echo "════════════════════════════════════════════════════════"
      echo "  SCAN SUMMARY"
      echo "════════════════════════════════════════════════════════"
      echo "Completed:  $(date '+%Y-%m-%d %H:%M:%S')"
      echo "Runtime:    $(runtime_mode_label)"
      echo "Steps:      $scan_step"
      echo "Tokens:     total=$total_tokens_used (in=$total_input_tokens out=$total_output_tokens cached=$total_cached_tokens)"
      echo "TokensBillable: total=$total_billable_tokens"
      echo "Reflections: used=$reflection_calls_used max=$REFLECTION_MAX_CALLS"
      echo "ChainResets: count=$chain_reset_count threshold=$CHAIN_RESET_INPUT_TOKENS"
      echo "SoftLimitInvestigation: enabled=$SOFT_LIMIT_INVESTIGATION_ENABLED rounds=$soft_limit_investigation_rounds token_budget_used_billable=$soft_limit_investigation_billable_used/$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET token_drift_total=$soft_limit_investigation_tokens_used exhausted=$soft_limit_investigation_budget_exhausted findings_after_limit=$(soft_limit_investigation_new_findings_count)"
      echo "SoftLimitGoalLast: ${soft_limit_focus_goal:-none}"
      echo "API Cost:   \$$(printf '%.6f' "$total_cost")"
      echo "Model:      $API_MODEL"
      echo "Total:      ${findings_total:-0} findings"
      echo "  Critical: $critical"
      echo "  Warning:  $warning"
      echo "  Info:     $info"
      echo ""
      echo "════════════════════════════════════════════════════════"
      echo "  ALL FINDINGS"
      echo "════════════════════════════════════════════════════════"
      for finding in "${findings[@]-}"; do
        [ -z "$finding" ] && continue
        echo "  $finding"
      done
      echo ""
      echo "════════════════════════════════════════════════════════"
      echo "  END OF REPORT"
      echo "════════════════════════════════════════════════════════"
    } >> "$findings_file"
  fi

  clear
  print_section "SCAN COMPLETE"
  echo -e "${BOLD}${GREEN}STATUS: FINISHED${RESET}"
  echo -e "${BOLD}End:${RESET}      $(date '+%H:%M:%S')"
  echo -e "${BOLD}Steps:${RESET}    $scan_step"
  echo -e "${BOLD}Tokens:${RESET}   $total_tokens_used"
  if [ "$SOFT_LIMIT_INVESTIGATION_ENABLED" = "true" ]; then
    echo -e "${BOLD}SL Invest:${RESET} rounds=$soft_limit_investigation_rounds | billable_used=$soft_limit_investigation_billable_used/$SOFT_LIMIT_INVESTIGATION_TOKEN_BUDGET | token_drift=$soft_limit_investigation_tokens_used | exhausted=$soft_limit_investigation_budget_exhausted"
  fi
  echo -e "${BOLD}API Cost:${RESET} \$$(printf '%.6f' "$total_cost")"
  print_border

  echo -e "\n${BOLD}FINDINGS SUMMARY:${RESET}\n"
  echo -e "  ${RED}${BOLD}Critical:${RESET} $critical"
  echo -e "  ${YELLOW}Warning:${RESET}  $warning"
  echo -e "  ${CYAN}Info:${RESET}     $info"
  echo -e "  ${BOLD}Total:${RESET}    ${findings_total:-0}"

  if [ "${findings_total:-0}" -gt 0 ]; then
    print_border
    echo -e "\n${BOLD}ALL FINDINGS:${RESET}\n"
    for finding in "${findings[@]-}"; do
      [ -z "$finding" ] && continue
      case "$finding" in
        "[CRITICAL]"*) echo -e "  ${RED}${BOLD}$finding${RESET}" ;;
        "[WARNING]"*)  echo -e "  ${YELLOW}$finding${RESET}" ;;
        *)             echo -e "  ${CYAN}$finding${RESET}" ;;
      esac
    done
  else
    echo -e "\n${GREEN}No findings reported (which is itself suspicious if you're truly paranoid).${RESET}"
  fi

  print_border
  if [ -n "$findings_file" ]; then
    echo -e "\n${BOLD}Full report:${RESET} $findings_file"
    echo -e "View: ${YELLOW}less $findings_file${RESET}\n"
  else
    echo -e "\n${BOLD}Artifact mode:${RESET} ${YELLOW}ephemeral — no findings file written${RESET}\n"
  fi
}

#==============================================================================
# USER POSTURE QUESTIONNAIRE
#==============================================================================
# Classifies user into Posture 1 (Hermit), 2 (Practical), 3 (Maximalist).
# This determines what "normal" looks like so the LLM can calibrate findings.
#==============================================================================

USER_POSTURE="${USER_POSTURE:-2}"
USER_POSTURE_LABEL="${USER_POSTURE_LABEL:-Practical}"
USER_POSTURE_DETAIL=""
POSTURE_CACHE_FILE="${CMDBOT_WORKDIR}/user_posture.txt"

_quiz_ask_scale() {
  local q="$1"
  local ans
  while true; do
    echo -e "  $q" >/dev/tty
    echo -e "    ${DIM}0) Never / disabled${RESET}" >/dev/tty
    echo -e "    ${DIM}1) Rarely${RESET}" >/dev/tty
    echo -e "    ${DIM}2) Sometimes${RESET}" >/dev/tty
    echo -e "    ${DIM}3) Often / default-on${RESET}" >/dev/tty
    printf "  Choose 0-3: " >/dev/tty
    read -r ans </dev/tty
    case "$ans" in
      0|1|2|3) echo "$ans"; return 0 ;;
      *) echo -e "  ${RED}Please choose 0, 1, 2, or 3.${RESET}" >/dev/tty ;;
    esac
  done
}

_quiz_ask_yn() {
  local q="$1"
  local ans
  while true; do
    printf "  %s [y/n]: " "$q" >/dev/tty
    read -r ans </dev/tty
    case "$(echo "$ans" | tr '[:upper:]' '[:lower:]')" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo -e "  ${RED}Please answer y or n.${RESET}" >/dev/tty ;;
    esac
  done
}

_build_posture_detail() {
  local p="$1"
  case "$p" in
    1)
      USER_POSTURE_LABEL="Hermit"
      USER_POSTURE_DETAIL="POSTURE 1 — HERMIT (Minimal Sharing, Maximum Lockdown)
Expected normal processes: kernel_task, launchd, WindowServer, loginwindow, securityd, trustd, syspolicyd, mds/mdworker, cfprefsd, distnoted, browser processes.
Expected network: Only outbound HTTPS to sites user explicitly visits. DNS queries to configured resolver. Loopback traffic only if running local tools.
RED FLAGS for this posture:
  - ANY process listening on 0.0.0.0 or *
  - ANY AirPlay / Bonjour / mDNS traffic
  - ANY LAN connections to local devices
  - ANY background outbound connections when idle
  - VMs, bridges, or DNS listeners on *:53
  - Persistent connections user did not initiate
For this user, LAN probing, AirPlay attempts, or local listeners are GENUINELY SUSPICIOUS."
      ;;
    2)
      USER_POSTURE_LABEL="Practical"
      USER_POSTURE_DETAIL="POSTURE 2 — PRACTICAL (Selective Sharing, Dev Tools, Some Apple Features)
Expected normal processes: All Posture 1 + mDNSResponder, sharingd (intermittent AirDrop), AirPlayXPC (intermittent), cloudd/bird (iCloud sync), node/python (local dev), limactl/colima/docker (if used).
Expected network: Short-lived LAN connections to known Apple devices. SYN_SENT to known devices is normal. Local listeners bound to 127.0.0.1. Established HTTPS while apps are active.
CONCERN FLAGS for this posture:
  - Listeners bound to * instead of localhost
  - Long-lived outbound HTTPS while idle
  - Unexpected DNS services or proxies
  - Repeated LAN scans outside known Apple services
  - Persistence or exposure is what matters, not presence
For this user, some noise is expected. Focus on PERSISTENCE, BREADTH, and LACK OF EXPLANATION."
      ;;
    3)
      USER_POSTURE_LABEL="Maximalist"
      USER_POSTURE_DETAIL="POSTURE 3 — MAXIMALIST (Everything On, Convenience First)
Expected normal processes: All Posture 1+2 + frequent sharingd, AirPlayXPC, rapportd, multiple Apple media services, VM bridges, virtual NICs, DNS forwarders, container helpers.
Expected network: Multiple listeners on different ports. Continuous outbound HTTPS. LAN connections to many subnets. DNS and multicast traffic constant.
STILL CONCERNING even for this posture:
  - Root-owned third-party binaries with no clear origin
  - Persistent connections to unknown IPs with no app context
  - LaunchDaemons you cannot attribute to a known app
  - Listeners on high ports exposed to LAN unintentionally
  - Anything surviving reboots without explanation
  - Opaque processes that resist attribution
For this user, VOLUME is meaningless. Only OPACITY and IRREVERSIBILITY matter."
      ;;
  esac
}

run_posture_quiz() {
  local s1=0 s2=0 s3=0 q

  clear
  print_border
  echo -e "${BOLD}macOS User Posture Assessment${RESET}"
  echo -e "${DIM}This determines what 'normal' looks like on YOUR system${RESET}"
  echo -e "${DIM}so the scanner knows what to flag vs. what to ignore.${RESET}"
  print_border
  echo ""

  # Q1: iCloud
  q=$(_quiz_ask_scale "1) Do you use iCloud Drive and/or iCloud Photos sync?")
  case "$q" in 0) s1=$((s1+4)); s2=$((s2+1)) ;; 1) s1=$((s1+2)); s2=$((s2+2)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+2)); s3=$((s3+3)) ;; esac
  echo ""

  # Q2: AirDrop
  q=$(_quiz_ask_scale "2) Do you use AirDrop to send/receive files?")
  case "$q" in 0) s1=$((s1+3)); s2=$((s2+1)) ;; 1) s1=$((s1+1)); s2=$((s2+3)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+2)); s3=$((s3+3)) ;; esac
  echo ""

  # Q3: AirPlay
  q=$(_quiz_ask_scale "3) Do you use AirPlay or screen mirroring?")
  case "$q" in 0) s1=$((s1+4)); s2=$((s2+1)) ;; 1) s1=$((s1+2)); s2=$((s2+2)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+1)); s3=$((s3+4)) ;; esac
  echo ""

  # Q4: Continuity
  q=$(_quiz_ask_scale "4) Do you use Continuity features (Handoff, Universal Clipboard)?")
  case "$q" in 0) s1=$((s1+4)); s2=$((s2+1)) ;; 1) s1=$((s1+2)); s2=$((s2+2)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+2)); s3=$((s3+3)) ;; esac
  echo ""

  # Q5: File sharing / NAS
  q=$(_quiz_ask_scale "5) Do you use network shares (SMB), NAS, or network Time Machine?")
  case "$q" in 0) s1=$((s1+4)); s2=$((s2+1)) ;; 1) s1=$((s1+2)); s2=$((s2+2)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+1)); s3=$((s3+4)) ;; esac
  echo ""

  # Q6: Remote access
  q=$(_quiz_ask_scale "6) Do you use Screen Sharing, VNC, or remote admin tools?")
  case "$q" in 0) s1=$((s1+3)); s2=$((s2+1)) ;; 1) s1=$((s1+1)); s2=$((s2+3)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+1)); s3=$((s3+4)) ;; esac
  echo ""

  # Q7: Dev servers
  q=$(_quiz_ask_scale "7) Do you run local dev servers (node/rails/python) that listen on ports?")
  case "$q" in 0) s1=$((s1+3)); s2=$((s2+1)) ;; 1) s1=$((s1+1)); s2=$((s2+3)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+2)); s3=$((s3+3)) ;; esac
  echo ""

  # Q8: Containers/VMs
  q=$(_quiz_ask_scale "8) Do you use containers or VMs (Docker, Lima, Colima, K8s)?")
  case "$q" in 0) s1=$((s1+3)); s2=$((s2+1)) ;; 1) s1=$((s1+1)); s2=$((s2+3)) ;; 2) s2=$((s2+3)); s3=$((s3+1)) ;; 3) s2=$((s2+2)); s3=$((s3+3)) ;; esac
  echo ""

  # Q9: Public Wi-Fi
  if _quiz_ask_yn "9) Do you frequently use public Wi-Fi without much thought?"; then
    s2=$((s2+1)); s3=$((s3+3))
  else
    s1=$((s1+2)); s2=$((s2+2))
  fi
  echo ""

  # Q10: Security hygiene (higher = more strict)
  q=$(_quiz_ask_scale "10) How strict are you about security hygiene (updates, no random installers)?")
  case "$q" in 0) s3=$((s3+4)); s2=$((s2+1)) ;; 1) s3=$((s3+2)); s2=$((s2+3)) ;; 2) s1=$((s1+2)); s2=$((s2+3)) ;; 3) s1=$((s1+4)); s2=$((s2+1)) ;; esac

  # Determine winner
  local winner=2 max=$s2
  if [ "$s1" -gt "$max" ]; then winner=1; max=$s1; fi
  if [ "$s3" -gt "$max" ]; then winner=3; max=$s3; fi

  USER_POSTURE="$winner"
  _build_posture_detail "$winner"

  # Cache result
  if artifacts_persist_enabled; then
    mkdir -p "$(dirname "$POSTURE_CACHE_FILE")"
    {
      echo "posture=$USER_POSTURE"
      echo "label=$USER_POSTURE_LABEL"
      echo "scores=$s1/$s2/$s3"
      echo "date=$(date '+%Y-%m-%d %H:%M:%S')"
    } > "$POSTURE_CACHE_FILE"
  fi

  echo ""
  print_border
  echo -e "${BOLD}Classification: Posture $USER_POSTURE — $USER_POSTURE_LABEL${RESET}"
  echo -e "${DIM}Scores: Hermit=$s1 | Practical=$s2 | Maximalist=$s3${RESET}"
  print_border
  echo ""
  sleep 2
}

load_cached_posture() {
  if ! artifacts_persist_enabled; then
    return 1
  fi
  if [ -f "$POSTURE_CACHE_FILE" ]; then
    local cached_posture cached_label cached_date
    cached_posture=$(grep '^posture=' "$POSTURE_CACHE_FILE" | cut -d= -f2)
    cached_label=$(grep '^label=' "$POSTURE_CACHE_FILE" | cut -d= -f2)
    cached_date=$(grep '^date=' "$POSTURE_CACHE_FILE" | cut -d= -f2-)
    if [ -n "$cached_posture" ] && [[ "$cached_posture" =~ ^[123]$ ]]; then
      USER_POSTURE="$cached_posture"
      _build_posture_detail "$cached_posture"
      echo -e "${BOLD}Cached posture:${RESET} $USER_POSTURE — $USER_POSTURE_LABEL (from $cached_date)"
      return 0
    fi
  fi
  return 1
}

#==============================================================================
# SCAN PROFILE SELECTION
#==============================================================================

show_scan_menu() {
  clear
  set_terminal_title "PARANOID SCANNER"
  print_retro_paranoid_banner

  echo -e "${BOLD}System:${RESET}  $HOSTNAME_STR — macOS $OS_VERSION ($ARCH)"
  echo -e "${BOLD}User:${RESET}    $CURRENT_USER"
  echo -e "${BOLD}Posture:${RESET} ${BOLD}$USER_POSTURE${RESET} — $USER_POSTURE_LABEL"
  echo -e "${BOLD}Runtime:${RESET} $(runtime_mode_label)"
  echo -e "${BOLD}Model:${RESET}   $API_MODEL"
  echo -e "${BOLD}API:${RESET}     Responses API (native tool calling)"
  print_border

  echo -e "\n${BOLD}Scan Profiles:${RESET}\n"
  echo -e "  1. ${RED}${BOLD}Full Paranoid Scan${RESET}     — All phases, maximum thoroughness"
  echo -e "  2. ${YELLOW}Persistence Only${RESET}       — LaunchAgents, Daemons, login items, cron"
  echo -e "  3. ${YELLOW}Network & Process${RESET}      — Running processes, connections, listeners"
  echo -e "  4. ${YELLOW}Binary Integrity${RESET}       — Code signatures, unsigned binaries, dylibs"
  echo -e "  5. ${YELLOW}Privacy & Permissions${RESET}  — TCC, profiles, FDA, accessibility"
  echo -e "  6. ${CYAN}Focused Discovery${RESET}      — Add a focus string (max ${CUSTOM_SCAN_FOCUS_MAX_CHARS} chars)"
  echo -e "  7. ${GREEN}${BOLD}Paste & Analyze${RESET}        — Paste a log/error, AI iterates until solved"
  echo -e "  8. ${MAGENTA}Plugin Diagnostics${RESET}     — Verify plugin system integrity"
  echo -e "  9. ${BLUE}Toggle Host Mode${RESET}        — Switch Standard / Infected Host (ephemeral)"
  echo -e ""
  echo -e "  q. ${DIM}Quit${RESET}"
  print_border
}

#==============================================================================
# MAIN
#==============================================================================

main() {
  set_terminal_title "PARANOID SCANNER"
  # Check dependencies
  for cmd in curl jq bc; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "ERROR: Required command '$cmd' not found. Install: brew install $cmd"
      exit 1
    fi
  done

  # Source modules
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  MACOS_TOOLS_LOADED=false
  if [ -f "$SCRIPT_DIR/paranoid_macos_tools.sh" ]; then
    source "$SCRIPT_DIR/paranoid_macos_tools.sh"
    MACOS_TOOLS_LOADED=true
    echo -e "${GREEN}macOS discovery tools module loaded.${RESET}"
  else
    echo -e "${YELLOW}macOS tools module not found (paranoid_macos_tools.sh). Using built-in tools only.${RESET}"
  fi

  THREAT_INTEL_LOADED=false
  if [ -f "$SCRIPT_DIR/paranoid_threat_intel.sh" ]; then
    source "$SCRIPT_DIR/paranoid_threat_intel.sh"
    THREAT_INTEL_LOADED=true
    echo -e "${GREEN}Threat intelligence module loaded.${RESET}"
  else
    echo -e "${YELLOW}Threat intel module not found (paranoid_threat_intel.sh). Continuing without it.${RESET}"
  fi

  # Source plugin system
  if [ -f "$SCRIPT_DIR/paranoid_plugin_system.sh" ]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/paranoid_plugin_system.sh"
    plugin_load_all
  fi

  # Start sudo keepalive
  start_sudo_keepalive

  # User posture assessment
  if load_cached_posture; then
    if _quiz_ask_yn "Use this posture? (n to re-take quiz)"; then
      echo ""
    else
      run_posture_quiz
    fi
  else
    run_posture_quiz
  fi

  while true; do
    show_scan_menu
    read -rp "  Select scan (1-9, q): " scan_choice

    case "$scan_choice" in
      1) run_paranoid_scan "full_paranoid" "$PROFILE_FULL" ;;
      2) run_paranoid_scan "persistence_audit" "$PROFILE_PERSISTENCE" ;;
      3) run_paranoid_scan "network_process" "$PROFILE_NETWORK" ;;
      4) run_paranoid_scan "binary_integrity" "$PROFILE_BINARY" ;;
      5) run_paranoid_scan "privacy_permissions" "$PROFILE_PRIVACY" ;;
      6)
        echo ""
        local custom_focus_input custom_focus_length custom_scope_input custom_scan_prompt
        echo -e "  ${BOLD}What should discovery focus on?${RESET}"
        echo -e "  ${DIM}Single line only. Maximum ${CUSTOM_SCAN_FOCUS_MAX_CHARS} characters.${RESET}"
        read -rp "  Focus: " custom_focus_input
        custom_focus_input="$(normalize_focus_string "$custom_focus_input")"
        custom_focus_length="$(focus_string_length "$custom_focus_input")"
        if [ -z "$custom_focus_input" ]; then
          echo -e "${RED}No focus string provided.${RESET}"; sleep 1; continue
        fi
        if [ "$custom_focus_length" -gt "$CUSTOM_SCAN_FOCUS_MAX_CHARS" ]; then
          echo -e "${RED}Focus string is too long (${custom_focus_length}/${CUSTOM_SCAN_FOCUS_MAX_CHARS} characters).${RESET}"
          sleep 1
          continue
        fi
        echo ""
        echo -e "  ${BOLD}Scope to a specific directory?${RESET} (optional — press Enter to skip)"
        read -rp "  Directory path: " custom_scope_input
        SCAN_SCOPE_DIR=""
        if [ -n "$custom_scope_input" ]; then
          custom_scope_input="$(expand_path "$custom_scope_input")"
          if [ ! -d "$custom_scope_input" ]; then
            echo -e "${RED}Not a valid directory: $custom_scope_input${RESET}"; sleep 1; continue
          fi
          # Resolve to canonical path to prevent traversal
          SCAN_SCOPE_DIR="$(cd "$custom_scope_input" 2>/dev/null && pwd -P)"
          echo -e "  ${GREEN}Scan confined to: ${BOLD}$SCAN_SCOPE_DIR${RESET}"
        fi
        custom_scan_prompt="$(build_custom_scan_prompt "$custom_focus_input")"
        run_paranoid_scan "custom_$(date +%H%M%S)" "$custom_scan_prompt"
        SCAN_SCOPE_DIR=""
        ;;
      7)
        echo ""
        echo -e "  ${GREEN}${BOLD}PASTE & ANALYZE${RESET} — Iterative Self-Correcting Analysis"
        echo -e "  ${DIM}Paste a log, error output, crash report, or any text you want analyzed.${RESET}"
        echo -e "  ${DIM}The AI will focus ONLY on what you paste, run commands to investigate,${RESET}"
        echo -e "  ${DIM}and iterate until it has fully diagnosed the issue.${RESET}"
        echo -e ""
        echo -e "  ${BOLD}Paste your content below${RESET} (press Enter twice on an empty line to submit):\n"
        local paste_content=""
        while IFS= read -r line; do
          [ -z "$line" ] && break
          paste_content="${paste_content:+$paste_content$'\n'}$line"
        done
        if [ -z "$paste_content" ]; then
          echo -e "${RED}No content pasted.${RESET}"; sleep 1; continue
        fi
        local paste_lines
        paste_lines=$(printf "%s\n" "$paste_content" | wc -l | tr -d ' ')
        echo -e "\n  ${GREEN}${BOLD}Received:${RESET} ${CYAN}$paste_lines lines${RESET}"
        echo -e "  ${DIM}Launching iterative self-correcting analysis...${RESET}"
        echo -e "  ${DIM}The AI will iterate until the issue is fully diagnosed.${RESET}\n"
        sleep 1
        run_paste_analysis "$paste_content"
        ;;
      8)
        if [ "${PLUGIN_SYSTEM_LOADED:-false}" = true ] && type plugin_run_diagnostics &>/dev/null; then
          echo ""
          echo -e "  ${BOLD}Plugin System${RESET}"
          echo -e "  1. Run Diagnostics"
          echo -e "  2. Connect a Plugin"
          echo -e "  3. Disconnect a Plugin"
          echo -e "  4. List Connected Plugins"
          echo ""
          read -rp "  Select (1-4): " _plugin_choice
          case "$_plugin_choice" in
            1) plugin_run_diagnostics ;;
            2)
              local _pdir
              echo ""
              while IFS= read -r _pdir; do
                [ -z "$_pdir" ] && continue
                local _pm="${_pdir}/manifest.json"
                [ ! -f "$_pm" ] && continue
                local _pid _pn
                _pid="$(jq -r '.plugin_id // empty' "$_pm" 2>/dev/null)"
                _pn="$(jq -r '.name // "unknown"' "$_pm" 2>/dev/null)"
                [ -z "$_pid" ] && continue
                if ! plugin_registry_is_connected "$_pid"; then
                  plugin_connect "$_pdir"
                else
                  echo -e "  \033[2m$_pn ($_pid) — already connected\033[0m"
                fi
              done < <(plugin_discover)
              ;;
            3)
              if [ "${#LOADED_PLUGIN_IDS[@]}" -eq 0 ]; then
                echo -e "  ${DIM}No connected plugins.${RESET}"
              else
                echo ""
                local _di
                for _di in "${!LOADED_PLUGIN_IDS[@]}"; do
                  echo -e "  $((${_di}+1)). ${LOADED_PLUGIN_NAMES[$_di]} (${LOADED_PLUGIN_IDS[$_di]})"
                done
                echo ""
                read -rp "  Plugin number to disconnect (or q): " _disc
                if [[ "$_disc" =~ ^[0-9]+$ ]]; then
                  local _didx=$((_disc - 1))
                  if [ -n "${LOADED_PLUGIN_IDS[$_didx]:-}" ]; then
                    plugin_disconnect "${LOADED_PLUGIN_IDS[$_didx]}"
                  else
                    echo -e "  ${RED}Invalid selection.${RESET}"
                  fi
                fi
              fi
              ;;
            4)
              tool_plugin_list
              ;;
            *) echo -e "  ${RED}Invalid selection.${RESET}" ;;
          esac
        else
          echo -e "${RED}Plugin system not loaded.${RESET}"
          echo -e "${DIM}Ensure paranoid_plugin_system.sh is in the same directory as the scanner.${RESET}"
        fi
        ;;
      9)
        if artifacts_persist_enabled; then
          EPHEMERAL_MODE=true
          echo -e "${YELLOW}Runtime mode switched to: $(runtime_mode_label)${RESET}"
          echo -e "${DIM}Command outputs and findings will stay off disk. Phase 2 is skipped in this mode.${RESET}"
        else
          EPHEMERAL_MODE=false
          echo -e "${GREEN}Runtime mode switched to: $(runtime_mode_label)${RESET}"
        fi
        sleep 1
        continue
        ;;
      q|Q) echo -e "\n${BOLD}Goodbye. Stay paranoid.${RESET}"; exit 0 ;;
      *) echo -e "${RED}Invalid selection.${RESET}"; sleep 1 ;;
    esac

    echo ""
    read -rp "Press Enter to return to menu..." _
  done
}

main "$@"
