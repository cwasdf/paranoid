#!/usr/bin/env bash
set -euo pipefail

if ! command -v shellcheck >/dev/null 2>&1; then
  if [ "${CI:-}" = "true" ]; then
    echo "ERROR: shellcheck is required for linting in CI."
    exit 1
  fi
  echo "WARN: shellcheck is not installed; skipping lint."
  echo "Install with: brew install shellcheck"
  exit 0
fi

shellcheck \
  --severity=error \
  paranoid_env_loader.sh \
  paranoid_scanner.sh \
  paranoid_macos_tools.sh \
  paranoid_threat_intel.sh \
  paranoid_plugin_system.sh \
  cmdbot_env_loader.sh \
  cmdbot_paranoid_scanner.sh \
  cmdbot_macos_tools.sh \
  cmdbot_threat_intel.sh \
  setup.sh \
  openai_api_quickstart.sh
