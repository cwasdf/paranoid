# Changelog

## [3.0.1] - 2026-02-25

- Rebranded project from CMDBOT to Paranoid.
- Renamed primary scripts to `paranoid_*` with legacy `cmdbot_*` compatibility wrappers.
- Switched default findings and intel paths to `paranoid_findings/` and `~/.paranoid/`.
- Added `PARANOID_*` model/findings/API-timeout environment variable support.

## [3.0.0] - 2025-02-12

- Migrated scanner orchestration to OpenAI Responses API native tool calling.
- Added command catalog workflow for lower-token investigations.
- Expanded macOS and threat-intel tool coverage.
