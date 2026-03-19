#!/usr/bin/env bash
# Minimal OpenAI Responses API caller for this project.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_LOADER_FILE="$SCRIPT_DIR/paranoid_env_loader.sh"
API_URL="${OPENAI_API_URL:-https://api.openai.com/v1/responses}"

if [ -f "$ENV_LOADER_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_LOADER_FILE"
fi

if [ -f "$ENV_FILE" ]; then
  if type load_env_file_safe >/dev/null 2>&1; then
    load_env_file_safe "$ENV_FILE"
  fi
fi

API_KEY="${OPENAI_API_KEY:-}"
MODEL="${PARANOID_MODEL:-${CMDBOT_MODEL:-gpt-5-nano-2025-08-07}}"
API_CONNECT_TIMEOUT="${PARANOID_API_CONNECT_TIMEOUT:-${CMDBOT_API_CONNECT_TIMEOUT:-10}}"
API_TIMEOUT_SECONDS="${PARANOID_API_TIMEOUT_SECONDS:-${CMDBOT_API_TIMEOUT_SECONDS:-60}}"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Usage: ./openai_api_quickstart.sh [prompt text]"
  echo "Example: ./openai_api_quickstart.sh \"Summarize active scanner phases.\""
  exit 0
fi

if [ -z "$API_KEY" ]; then
  echo "ERROR: OPENAI_API_KEY is not set."
  echo "Set it in .env or export it in your shell."
  exit 1
fi

if ! [[ "$API_CONNECT_TIMEOUT" =~ ^[0-9]+$ ]]; then
  API_CONNECT_TIMEOUT=10
fi
if ! [[ "$API_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]; then
  API_TIMEOUT_SECONDS=60
fi

PROMPT="${*:-Say hello from Paranoid and confirm the API call worked.}"

PAYLOAD="$(jq -n \
  --arg model "$MODEL" \
  --arg prompt "$PROMPT" \
  '{
    model: $model,
    input: [{role: "user", content: $prompt}]
  }')"

RESPONSE="$(curl -sS "$API_URL" \
  --connect-timeout "$API_CONNECT_TIMEOUT" \
  --max-time "$API_TIMEOUT_SECONDS" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")"

if echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
  echo "OpenAI API error:"
  echo "$RESPONSE" | jq -r '.error.message // .error'
  exit 1
fi

OUTPUT_TEXT="$(echo "$RESPONSE" | jq -r '.output_text // empty')"
if [ -z "$OUTPUT_TEXT" ]; then
  OUTPUT_TEXT="$(echo "$RESPONSE" | jq -r '[.output[]? | select(.type=="message") | .content[]? | select(.type=="output_text") | .text] | join("\n")')"
fi

if [ -n "$OUTPUT_TEXT" ]; then
  printf '%s\n' "$OUTPUT_TEXT"
else
  # Fallback: print raw JSON if text extraction is empty
  echo "$RESPONSE" | jq '.'
fi
