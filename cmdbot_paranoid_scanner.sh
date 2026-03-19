#!/usr/bin/env bash
# Legacy compatibility wrapper. Prefer: paranoid_scanner.sh
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/paranoid_scanner.sh" "$@"
