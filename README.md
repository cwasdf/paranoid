## Warning

**This is experimental and is under active development.** It has not been validated, hardened, or qualified for production environments. Do not deploy Paranoid in production or rely on it as a primary security control. The project is currently intended for security research, testing, evaluation, and controlled defensive investigation.

## What It Does

Paranoid performs structured macOS security investigation while using the OpenAI Responses API to coordinate deterministic, explicitly registered tools.

- Investigates persistence mechanisms, network activity, binary integrity, privacy controls, and permissions.
- Uses native Responses API tool calling through `/v1/responses`.
- Restricts model-initiated execution to tools explicitly registered by the scanner.
- Stores detailed evidence locally in `paranoid_findings/`.
- Returns compact findings to the model instead of unnecessarily passing full evidence into the model context.
- Supports optional threat-intelligence enrichment using YARA, VirusTotal, abuse.ch, and CIRCL.

## Safety and Scope

Paranoid is designed for defensive investigation of macOS systems.

- Target platform: macOS.
- Use only on systems you own or are explicitly authorized to assess.
- Some probes may require `sudo` where macOS restricts access to security-relevant data.
- API credentials are loaded from `.env`.
- Never commit `.env` or other credential-bearing files to source control.

## Architecture

```text
OpenAI Responses API
        │
        │  function_call
        │  function_call_output
        ▼
Paranoid Scanner
        │
        ├── Core Tools
        ├── macOS Probe Tools
        └── Threat Intelligence Tools
                │
                ▼
        paranoid_findings/
```

Paranoid uses deterministic tool dispatch and chains Responses API requests using `previous_response_id`.

Tool execution and evidence collection remain locally auditable.

## Quick Start

Clone or enter the project directory, then create your local environment configuration:

```bash
cp .env.example .env
```

Run the setup process:

```bash
chmod +x setup.sh
./setup.sh
```

Alternatively, after configuring `OPENAI_API_KEY`, run the scanner directly:

```bash
./paranoid_scanner.sh
```

Test basic Responses API connectivity with:

```bash
./openai_api_quickstart.sh "Summarize what this scanner does in 2 lines."
```

## Configuration

Primary Paranoid settings:

| Variable | Default | Purpose |
|---|---|---|
| `PARANOID_MODEL` | `gpt-5-nano-2025-08-07` | Model used by the scanner |
| `PARANOID_FINDINGS_DIR` | `./paranoid_findings` | Local evidence directory |
| `PARANOID_MAX_SCAN_STEPS` | `140` | Maximum scanner execution steps |
| `PARANOID_SOFT_TOKEN_LIMIT` | `120000` | Soft model token limit; `0` disables it |
| `PARANOID_API_CONNECT_TIMEOUT` | `10` | API connection timeout |
| `PARANOID_API_TIMEOUT_SECONDS` | `90` | API request timeout |

Additional environment variables:

| Variable | Requirement | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | Required | OpenAI API authentication |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal enrichment |

See `.env.example` for the complete configuration template.

## Scan Profiles

Paranoid provides several investigation profiles:

1. **Full Paranoid** — broad security investigation.
2. **Persistence Only** — focuses on persistence mechanisms.
3. **Network and Process** — examines network and process activity.
4. **Binary Integrity** — investigates executable and binary integrity.
5. **Privacy and Permissions** — examines macOS privacy and authorization controls.
6. **Focused Discovery** — accepts a focused investigation request of up to 200 characters with optional directory scope.

## Project Structure

| File | Purpose |
|---|---|
| `paranoid_scanner.sh` | Main scanner loop and deterministic tool dispatcher |
| `paranoid_macos_tools.sh` | macOS-specific security probes |
| `paranoid_threat_intel.sh` | Optional threat-intelligence and YARA tooling |
| `paranoid_env_loader.sh` | Dotenv parser that does not execute shell code |
| `setup.sh` | Dependency checks, configuration, and scanner launch |
| `openai_api_quickstart.sh` | Minimal Responses API connectivity test |

Legacy compatibility wrappers remain available through the `cmdbot_*` scripts.

## Development

Run linting:

```bash
npm run lint
```

Run shell syntax validation:

```bash
npm run test:syntax
```

Run the complete test suite:

```bash
npm test
```

GitHub Actions runs CI automatically for pull requests and pushes using:

```text
.github/workflows/ci.yml
```

## Security

Security reporting procedures and project security guidance are documented in:

`SECURITY.md`

## Contributing

Contribution requirements and development workflow are documented in:

`CONTRIBUTING.md`

### License

Licensed under the MIT License.

See `LICENSE` for the complete license text.
