# Security Policy

## Supported Versions

The latest commit on the default branch is considered supported.

## Reporting a Vulnerability

Please do not open public GitHub issues for suspected vulnerabilities.

Report details privately to the project maintainers with:

- A clear description of the issue
- Impact assessment
- Reproduction steps or proof-of-concept
- Any suggested remediation

You should receive an acknowledgment within 72 hours.

## Scope Notes

- This project is a defensive investigation tool and must be used only on systems you are authorized to assess.
- API keys should be stored in `.env` and never committed.
- Threat-intel lookups are hash-based where possible; avoid uploading sensitive binaries unless explicitly intended.
