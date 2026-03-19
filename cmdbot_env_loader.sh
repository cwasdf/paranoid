#!/usr/bin/env bash
# Legacy compatibility wrapper. Prefer: paranoid_env_loader.sh
# shellcheck disable=SC1090
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/paranoid_env_loader.sh"
