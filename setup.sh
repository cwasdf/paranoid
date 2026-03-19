#!/usr/bin/env bash
#==============================================================================
# PARANOID SCANNER — SETUP & LAUNCH
#==============================================================================
# Run this once. It checks dependencies, helps set API keys, then launches.
# Usage: ./setup.sh
#==============================================================================

set -euo pipefail

# ── Ensure Homebrew paths are in PATH ────────────────────────
# macOS doesn't source .zshrc/.bashrc for scripts, so brew binaries
# in /opt/homebrew/bin (Apple Silicon) or /usr/local/bin (Intel)
# won't be found unless we add them explicitly.
for p in /opt/homebrew/bin /opt/homebrew/sbin /usr/local/bin /usr/local/sbin; do
  [[ -d "$p" ]] && [[ ":$PATH:" != *":$p:"* ]] && export PATH="$p:$PATH"
done

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"
BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_LOADER_FILE="$SCRIPT_DIR/paranoid_env_loader.sh"

if [ -f "$ENV_LOADER_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_LOADER_FILE"
fi

upsert_env_var() {
  local key="$1" value="$2" file="$3"
  local tmp

  # Dotenv values should stay single-line.
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"

  tmp="$(mktemp /tmp/paranoid_env.XXXXXX)"

  if [ -f "$file" ]; then
    awk -v k="$key" -v v="$value" '
      BEGIN { done = 0 }
      $0 ~ ("^" k "=") {
        if (done == 0) {
          print k "=" v
          done = 1
        }
        next
      }
      { print }
      END {
        if (done == 0) {
          print k "=" v
        }
      }
    ' "$file" > "$tmp"
  else
    printf "%s=%s\n" "$key" "$value" > "$tmp"
  fi

  chmod 600 "$tmp" 2>/dev/null || true
  mv "$tmp" "$file"
  chmod 600 "$file" 2>/dev/null || true
}

echo -e "${BOLD}${RED}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║      PARANOID SCANNER — SETUP         ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${RESET}"

#──────────────────────────────────────────────────────────────
# 1. Check required files
#──────────────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Checking scanner files...${RESET}"

ok=true
for f in paranoid_scanner.sh paranoid_macos_tools.sh paranoid_threat_intel.sh paranoid_env_loader.sh; do
  if [ -f "$SCRIPT_DIR/$f" ]; then
    echo -e "  ${GREEN}✓${RESET} $f"
  else
    echo -e "  ${RED}✗${RESET} $f — MISSING"
    ok=false
  fi
done

if [ "$ok" = false ]; then
  echo -e "\n${RED}Place all required .sh files in the same folder, then re-run.${RESET}"
  exit 1
fi

# Make executable
chmod +x "$SCRIPT_DIR"/*.sh

#──────────────────────────────────────────────────────────────
# 2. Check system dependencies
#──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Checking dependencies...${RESET}"

check_dep() {
  local cmd="$1" required="$2" install_hint="$3"
  local found_path
  found_path="$(command -v "$cmd" 2>/dev/null || true)"
  if [ -n "$found_path" ]; then
    # Try to get version info (many macOS tools don't support --version)
    local ver=""
    ver=$("$cmd" --version 2>/dev/null | head -1 || true)
    [ -z "$ver" ] && ver=$("$cmd" -v 2>/dev/null | head -1 || true)
    [ -z "$ver" ] && ver=$("$cmd" -V 2>/dev/null | head -1 || true)
    [ -z "$ver" ] && ver="$found_path"
    echo -e "  ${GREEN}✓${RESET} $cmd ($ver)"
    return 0
  else
    if [ "$required" = "required" ]; then
      echo -e "  ${RED}✗${RESET} $cmd — REQUIRED. Install: $install_hint"
      return 1
    else
      echo -e "  ${YELLOW}○${RESET} $cmd — optional. Install: $install_hint"
      return 0
    fi
  fi
}

missing=false
check_dep bash   required "built-in"              || missing=true
check_dep curl   required "built-in / brew install curl" || missing=true
check_dep jq     required "brew install jq"        || missing=true
check_dep bc     required "built-in"               || missing=true
check_dep python3 required "built-in / xcode-select --install" || missing=true
check_dep codesign required "xcode-select --install" || missing=true

# Optional
check_dep tree     optional "brew install tree"
check_dep yara     optional "brew install yara"
check_dep osqueryi optional "brew install osquery"
check_dep sqlite3  optional "built-in"

if [ "$missing" = true ]; then
  echo -e "\n${RED}Install missing required dependencies, then re-run.${RESET}"
  echo -e "${YELLOW}Most can be installed with:${RESET}"
  echo "  brew install jq"
  echo "  xcode-select --install   # for codesign, python3"
  exit 1
fi

#──────────────────────────────────────────────────────────────
# 3. API Keys
#──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Configuring API keys...${RESET}"

# Load existing .env if present
if [ -f "$ENV_FILE" ]; then
  echo -e "  ${GREEN}Found .env file — loading...${RESET}"
  if type load_env_file_safe >/dev/null 2>&1; then
    load_env_file_safe "$ENV_FILE"
  else
    echo -e "  ${YELLOW}Could not load .env safely (env loader missing).${RESET}"
  fi
fi

# OpenAI (required)
if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo -e "  ${YELLOW}OPENAI_API_KEY not set.${RESET}"
  echo -e "  Get one at: https://platform.openai.com/api-keys"
  echo ""
  read -rsp "  Paste your OpenAI API key (sk-...): " user_key
  echo ""
  if [ -n "$user_key" ]; then
    upsert_env_var "OPENAI_API_KEY" "$user_key" "$ENV_FILE"
    export OPENAI_API_KEY="$user_key"
    echo -e "  ${GREEN}✓ Saved to .env${RESET}"
  else
    echo -e "  ${RED}No key provided. You'll need to set it manually.${RESET}"
  fi
else
  echo -e "  ${GREEN}✓${RESET} OPENAI_API_KEY is set (${OPENAI_API_KEY:0:8}...)"
fi

# VirusTotal (optional)
if [ -z "${VIRUSTOTAL_API_KEY:-}" ]; then
  echo -e "  ${YELLOW}○${RESET} VIRUSTOTAL_API_KEY not set (optional)"
  echo -e "    Free signup: https://www.virustotal.com/gui/join-us"
  read -rsp "  Paste your VirusTotal API key (or press Enter to skip): " vt_key
  echo ""
  if [ -n "$vt_key" ]; then
    upsert_env_var "VIRUSTOTAL_API_KEY" "$vt_key" "$ENV_FILE"
    export VIRUSTOTAL_API_KEY="$vt_key"
    echo -e "  ${GREEN}✓ Saved to .env${RESET}"
  fi
else
  echo -e "  ${GREEN}✓${RESET} VIRUSTOTAL_API_KEY is set"
fi

# Model selection
if [ -z "${PARANOID_MODEL:-${CMDBOT_MODEL:-}}" ]; then
  echo ""
  echo -e "  ${BOLD}LLM Model (default: gpt-5-nano-2025-08-07):${RESET}"
  echo -e "    gpt-5-nano-2025-08-07  — lowest-cost default"
  echo -e "    gpt-5-mini             — stronger reasoning"
  echo -e "    gpt-4.1-mini           — compatibility fallback"
  read -rp "  Model name (or Enter for gpt-5-nano-2025-08-07): " model_choice
  if [ -n "$model_choice" ]; then
    upsert_env_var "PARANOID_MODEL" "$model_choice" "$ENV_FILE"
    export PARANOID_MODEL="$model_choice"
  fi
fi

#──────────────────────────────────────────────────────────────
# 4. YARA rules (optional)
#──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] YARA rules...${RESET}"

YARA_DIR="$HOME/.paranoid/threat_intel/yara_rules"
if command -v yara &>/dev/null; then
  if ls "$YARA_DIR"/*.yar &>/dev/null 2>&1; then
    rule_count=$(ls "$YARA_DIR"/*.yar 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}✓${RESET} $rule_count YARA rule files in $YARA_DIR"
  else
    echo -e "  ${YELLOW}No YARA rules found.${RESET}"
    echo -e "  The scanner can download community rules automatically."
    echo -e "  Select 'Full Paranoid Scan' and the LLM will call yara.update_rules."
    echo -e "  Or download manually later."
  fi
else
  echo -e "  ${DIM}YARA not installed — skipping. (brew install yara)${RESET}"
fi

#──────────────────────────────────────────────────────────────
# 5. Launch
#──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Ready to launch!${RESET}"
echo ""
echo -e "  ${BOLD}Files:${RESET}"
echo -e "    Scanner:      $SCRIPT_DIR/paranoid_scanner.sh"
echo -e "    macOS Tools:  $SCRIPT_DIR/paranoid_macos_tools.sh"
echo -e "    Threat Intel: $SCRIPT_DIR/paranoid_threat_intel.sh"
echo -e "    Env Loader:   $SCRIPT_DIR/paranoid_env_loader.sh"
echo -e "    Environment:  ${ENV_FILE}"
echo -e "    Findings:     $SCRIPT_DIR/paranoid_findings/"
echo ""
echo -e "  ${BOLD}To run later without setup:${RESET}"
echo -e "    $SCRIPT_DIR/paranoid_scanner.sh"
echo ""

read -rp "  Launch scanner now? (y/n): " launch
if [ "$launch" = "y" ] || [ "$launch" = "Y" ]; then
  echo ""
  # Source .env for keys
  if [ -f "$ENV_FILE" ]; then
    if type load_env_file_safe >/dev/null 2>&1; then
      load_env_file_safe "$ENV_FILE"
    else
      echo -e "  ${YELLOW}Could not load .env safely (env loader missing).${RESET}"
    fi
  fi
  exec bash "$SCRIPT_DIR/paranoid_scanner.sh"
else
  echo -e "\n  ${BOLD}Run manually:${RESET}"
  echo "    ./paranoid_scanner.sh"
  echo ""
  echo -e "  ${BOLD}Stay paranoid.${RESET}"
fi
