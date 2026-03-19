#!/usr/bin/env bash
#==============================================================================
# Paranoid environment loader
#==============================================================================
# Loads simple KEY=VALUE pairs from a dotenv-style file without executing shell
# code. Supported lines:
#   KEY=value
#   KEY="value"
#   KEY='value'
#   export KEY=value
# Comments and blank lines are ignored.
#==============================================================================

load_env_file_safe() {
  local env_file="${1:-}"
  local line key value

  [ -n "$env_file" ] || return 0
  [ -f "$env_file" ] || return 0

  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [ -z "$line" ] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" == export[[:space:]]* ]] && line="${line#export }"

    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"

      if [[ "$value" =~ ^\"(.*)\"$ ]]; then
        value="${BASH_REMATCH[1]}"
      elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
        value="${BASH_REMATCH[1]}"
      fi

      printf -v "$key" '%s' "$value"
      export "$key"
    fi
  done < "$env_file"
}
