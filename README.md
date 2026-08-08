<div align="center">
  <img src="./paranoid_logo.png" alt="Paranoid" width="96" />

  <h1>Paranoid</h1>
<p>
  LLM-driven macOS security investigation using the OpenAI Responses API with native tool calling.
</p>
</div>
<span><strong>⚠️ WARNING: This project is experimental and under active development. It has not been validated or hardened for production use and should NOT be deployed in production environments or relied upon as a primary security control.</strong></span>

## What It Does

- Runs structured security probes across persistence, network activity, binary integrity, privacy, and permissions.
- Uses native tool calling (`/v1/responses`) to restrict model execution to explicitly registered tools.
- Stores full supporting evidence locally in `paranoid_findings/` while returning compact summaries to the model.
- Supports optional threat-intelligence enrichment through YARA, VirusTotal hash lookups, abuse.ch, and CIRCL.
- Intended for research, testing, evaluation, and controlled experimental environments while the project remains in an experimental stage.

## Safety and Scope

- Target platform: macOS.
- Intended for defensive investigation on systems you own or are authorized to assess.
- Some probes use `sudo` where macOS data collection requires elevated read access.
- API keys are loaded from `.env`; do not commit `.env`.

## Architecture

```text
OpenAI Responses API (/v1/responses)
  ↕ function_call / function_call_output
Paranoid scanner (bash)
  ├─ core tools
  ├─ macOS probe tools
  └─ threat-intel tools
```

The scanner chains requests using `previous_response_id` and keeps execution auditable via deterministic tool dispatch.

## Quick Start

```bash
cp .env.example .env
chmod +x setup.sh
./setup.sh
```

Or run directly after setting `OPENAI_API_KEY`:

```bash
./paranoid_scanner.sh
```

Minimal API connectivity check:

```bash
./openai_api_quickstart.sh "Summarize what this scanner does in 2 lines."
```

## Key Environment Variables

Primary (preferred):

- `PARANOID_MODEL` (default `gpt-5-nano-2025-08-07`)
- `PARANOID_FINDINGS_DIR` (default `./paranoid_findings`)
- `PARANOID_MAX_SCAN_STEPS` (default `140`)
- `PARANOID_SOFT_TOKEN_LIMIT` (default `120000`, set `0` to disable)
- `PARANOID_API_CONNECT_TIMEOUT` (default `10`)
- `PARANOID_API_TIMEOUT_SECONDS` (default `90`)

Common scanner vars (legacy-compatible):

- `OPENAI_API_KEY` (required)
- `VIRUSTOTAL_API_KEY` (optional)

See `.env.example` for a fuller template.

## Scan Profiles

1. Full Paranoid
2. Persistence Only
3. Network and Process
4. Binary Integrity
5. Privacy and Permissions
6. Focused Discovery (up to 200 characters, optional directory scope)

## Project Files

- `paranoid_scanner.sh`: main scanner loop and tool dispatcher
- `paranoid_macos_tools.sh`: deterministic macOS probe tools
- `paranoid_threat_intel.sh`: optional intel and YARA tooling
- `paranoid_env_loader.sh`: safe dotenv parser (no shell code execution)
- `setup.sh`: dependency checks, key setup, scanner launch
- `openai_api_quickstart.sh`: direct Responses API smoke test

Legacy compatibility wrappers are still included (`cmdbot_*` scripts).

## Development

```bash
npm run lint
npm run test:syntax
npm test
```

CI runs on pull requests and pushes via GitHub Actions (`.github/workflows/ci.yml`).

## Security

Security policy and reporting guidance: [SECURITY.md](SECURITY.md)

## Contributing

Contribution workflow and standards: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT ([LICENSE](LICENSE))
