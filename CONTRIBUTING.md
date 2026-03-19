# Contributing

## Development Setup

1. Install required tools: `bash`, `curl`, `jq`, `bc`.
2. Copy environment template: `cp .env.example .env`.
3. Set `OPENAI_API_KEY` in `.env`.
4. Run checks:
   - `npm run lint`
   - `npm run test:syntax`

## Pull Requests

1. Keep PRs focused and small when possible.
2. Include a concise description of behavior changes.
3. Add or update docs when user-facing behavior changes.
4. Ensure CI is green before requesting review.

## Bash Style

- Prefer safe defaults: `set -euo pipefail`.
- Quote variable expansions unless intentional globbing/splitting.
- Avoid `eval` for user-provided content.
- Keep tool behavior deterministic and auditable.

## Testing Expectations

- Syntax checks must pass for all shell scripts.
- ShellCheck warnings should be addressed or explicitly justified.
- For scanner behavior changes, include a short validation note in the PR.
