#!/usr/bin/env python3
"""
Paranoid Scanner — Write Plugin Local Shell Executor

Uses the OpenAI Responses API (raw HTTP, no SDK dependency) with codex-mini-latest
and the local_shell tool to investigate findings via shell commands.

Protocol (stdin/stdout JSON, stderr diagnostics):
  stdin  — {"api_key": "...", "list_file": "/path/to/running_list.txt",
            "scope_dir": "...", "timeout": 120}
  stdout — {"status": "ok"|"error", "commands_run": [...], "final_output": "..."}
  stderr — progress/diagnostics

Responses API protocol (matches reference mock server events):
  Request  → POST /v1/responses  {model, tools, input, previous_response_id?, store}
  Response → {id, output: [{type: "local_shell_call", call_id, action: {command, ...}},
                           {type: "message", content: [{type: "output_text", text}]}],
              usage: {input_tokens, output_tokens, total_tokens}}
  Followup → same endpoint, input: [{type: "local_shell_call_output", call_id, output}],
             previous_response_id: <prev.id>
"""

import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
import urllib.error

# ── Configuration ─────────────────────────────────────────────────────────────

API_BASE_URL = "https://api.openai.com/v1/responses"
MODEL = "codex-mini-latest"
MAX_SHELL_ROUNDS = 25
DEFAULT_CMD_TIMEOUT = 30
MAX_OUTPUT_BYTES = 8000

BLOCKED_PATTERNS = [
    "rm -rf /", "rm -rf ~", "mkfs", "dd if=", "> /dev/sd",
    ":(){ :|:& };:", "chmod -R 777 /",
    "curl|sh", "curl|bash", "wget|sh", "wget|bash",
    "launchctl bootout", "defaults delete", "csrutil disable",
    "shutdown", "reboot", "halt", "poweroff",
    "osascript", "sfltool",
    "launchctl reboot", "logout",
    "pfctl -f", "pfctl -e", "pfctl -d", "pfctl -k", "pfctl -K",
    "dscacheutil -flush", "killall -HUP mDNSResponder",
    "networksetup -set", "route flush", "route add", "route delete",
    "ifconfig down", "ifconfig destroy",
]


# ── Utilities ─────────────────────────────────────────────────────────────────

def err(msg):
    print(msg, file=sys.stderr, flush=True)


def is_command_blocked(cmd):
    """Check if a command matches known dangerous patterns."""
    cmd_lower = cmd.lower().strip()
    for pattern in BLOCKED_PATTERNS:
        if pattern in cmd_lower:
            return True
    return False


def execute_shell_command(command, working_directory=None, env_vars=None, timeout_ms=None):
    """Execute a shell command locally with safety checks and output truncation."""
    if isinstance(command, list):
        cmd_str = " ".join(command)
        cmd_argv = command
    else:
        cmd_str = command
        try:
            cmd_argv = shlex.split(command)
        except ValueError:
            cmd_argv = ["/bin/sh", "-c", command]

    if is_command_blocked(cmd_str):
        return {
            "output": f"BLOCKED: Command matched safety filter: {cmd_str}",
            "exit_code": 1,
        }

    timeout_sec = (timeout_ms / 1000) if timeout_ms else DEFAULT_CMD_TIMEOUT
    cwd = working_directory or os.getcwd()
    run_env = {**os.environ, **(env_vars or {})}

    try:
        completed = subprocess.run(
            cmd_argv,
            cwd=cwd,
            env=run_env,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        stdout = completed.stdout
        stderr = completed.stderr

        # Truncate large output
        if len(stdout) > MAX_OUTPUT_BYTES:
            stdout = stdout[:MAX_OUTPUT_BYTES] + f"\n... (truncated, {len(completed.stdout)} total bytes)"
        if len(stderr) > 2000:
            stderr = stderr[:2000] + "\n... (truncated)"

        output = stdout
        if stderr:
            output = f"{output}\n{stderr}" if output else stderr

        return {"output": output, "exit_code": completed.returncode}

    except subprocess.TimeoutExpired:
        return {"output": f"TIMEOUT: Command exceeded {timeout_sec}s limit", "exit_code": 124}
    except FileNotFoundError:
        return {"output": f"NOT_FOUND: Command not found: {cmd_argv[0]}", "exit_code": 127}
    except Exception as e:
        return {"output": f"ERROR: {e}", "exit_code": 1}


# ── Raw HTTP Responses API Client ─────────────────────────────────────────────

def api_request(api_key, payload):
    """
    POST to the Responses API endpoint.

    Returns the parsed JSON response dict, matching the protocol:
      {id, output: [...], usage: {...}}

    The output array contains items like:
      {type: "local_shell_call", call_id: "...", action: {command: [...], ...}}
      {type: "message", role: "assistant", content: [{type: "output_text", text: "..."}]}
    """
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    req = urllib.request.Request(
        API_BASE_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise RuntimeError(f"API HTTP {e.code}: {error_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"API connection failed: {e.reason}") from e


def extract_shell_calls(response):
    """
    Extract local_shell_call items from a Responses API response.

    Each item has:
      type: "local_shell_call"
      call_id: string
      action: {command: string|list, timeout_ms?: int, working_directory?: str, env?: dict}
    """
    calls = []
    for item in response.get("output", []):
        if item.get("type") == "local_shell_call":
            calls.append(item)
    return calls


def extract_text_output(response):
    """
    Extract assistant text from a Responses API response.

    Matches the reference protocol:
      {type: "message", role: "assistant", content: [{type: "output_text", text: "..."}]}
    Also handles direct {type: "text", text: "..."} items.
    """
    parts = []
    for item in response.get("output", []):
        item_type = item.get("type")
        if item_type == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    parts.append(content.get("text", ""))
        elif item_type == "text":
            parts.append(item.get("text", ""))
    return "".join(parts)


# ── Main Loop ─────────────────────────────────────────────────────────────────

def run_local_shell_loop(api_key, list_content, scope_dir=None, overall_timeout=120):
    """
    Run the local_shell agent loop with codex-mini-latest.

    Flow (per the Responses API local_shell docs):
      1. Send initial request with local_shell tool enabled
      2. Response contains local_shell_call items → execute commands
      3. Return local_shell_call_output items via previous_response_id
      4. Repeat until model returns text (no more shell calls) or limits hit
    """
    scope_instruction = ""
    if scope_dir:
        scope_instruction = (
            f"\n\nDIRECTORY SCOPE: You are CONFINED to {scope_dir}\n"
            "Only run commands that target files and directories within this path.\n"
            "Do NOT access files outside this directory."
        )

    system_prompt = (
        "You are a macOS security remediator. You have been given a distilled list of "
        "the 10 most critical findings from a paranoid security scan, each with a root cause "
        "file and a proposed fix action.\n\n"
        "Your job is to VERIFY and VALIDATE each finding's root cause, then confirm the fix:\n"
        "1. For each finding, verify the origin_file exists and contains what the finding claims\n"
        "2. Confirm the process/service is actually running or the config is actually active\n"
        "3. Validate the proposed fix_action is correct and safe\n"
        "4. Report: CONFIRMED (fix is valid), MODIFIED (fix needs adjustment, state corrected fix), "
        "or INVALID (root cause was wrong, state why)\n\n"
        "Work through findings in order of severity (CRITICAL first).\n"
        "For each finding, run 1-3 targeted verification commands, then report status.\n"
        "Do NOT run broad discovery commands. Do NOT gather general evidence.\n"
        "Each command must directly verify a specific origin_file or fix_action.\n\n"
        "Rules:\n"
        "- Run READ-ONLY commands. Do NOT modify, delete, or write any files.\n"
        "- NEVER run shutdown, reboot, restart, halt, poweroff, or logout commands.\n"
        "- NEVER run commands that would terminate the user session or power off the machine.\n"
        "- NEVER run osascript or sfltool.\n"
        "- Use sudo when needed for system inspection.\n"
        "- Be surgical — verify the specific file/service named in each finding.\n"
        "- After verifying all findings, provide a final summary with fix readiness status."
        f"{scope_instruction}"
    )

    commands_run = []
    final_output = ""
    start_time = time.time()

    # ── Initial request ───────────────────────────────────────────────────────
    payload = {
        "model": MODEL,
        "tools": [{"type": "local_shell"}],
        "store": True,
        "input": [
            {"role": "developer", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "Here are the 10 most critical findings from the security scan. "
                            "Investigate each one with targeted shell commands.\n\n"
                            + list_content
                        ),
                    },
                ],
            },
        ],
    }

    err("Sending initial request to API...")
    try:
        response = api_request(api_key, payload)
    except RuntimeError as e:
        return {"status": "error", "error": str(e), "commands_run": [], "final_output": ""}

    response_id = response.get("id", "")
    err(f"Response ID: {response_id}")

    # Log token usage from initial call
    usage = response.get("usage", {})
    if usage:
        err(f"Tokens: in={usage.get('input_tokens', 0)} out={usage.get('output_tokens', 0)} total={usage.get('total_tokens', 0)}")

    # ── Agent loop ────────────────────────────────────────────────────────────
    for round_num in range(MAX_SHELL_ROUNDS):
        elapsed = time.time() - start_time
        if elapsed > overall_timeout:
            err(f"Overall timeout ({overall_timeout}s) reached after {round_num} rounds ({elapsed:.0f}s)")
            break

        # Check for local_shell_call items in the response
        shell_calls = extract_shell_calls(response)

        if not shell_calls:
            # No more commands — model is done. Extract final text.
            final_output = extract_text_output(response)
            err(f"Model finished (no shell calls). Text output: {len(final_output)} chars")
            break

        err(f"Round {round_num + 1}: {len(shell_calls)} shell call(s)")

        # Execute each command and build the output items
        call_outputs = []
        for call in shell_calls:
            call_id = call.get("call_id", "")
            action = call.get("action", {})
            command = action.get("command", "")

            if not command:
                call_outputs.append({
                    "type": "local_shell_call_output",
                    "call_id": call_id,
                    "output": "ERROR: no command provided",
                })
                continue

            # Display for logging
            if isinstance(command, list):
                cmd_display = " ".join(command)
            else:
                cmd_display = command

            err(f"  [{round_num + 1}.{len(call_outputs) + 1}] {cmd_display[:120]}")

            result = execute_shell_command(
                command,
                working_directory=action.get("working_directory"),
                env_vars=action.get("env"),
                timeout_ms=action.get("timeout_ms"),
            )

            commands_run.append({
                "command": cmd_display,
                "exit_code": result["exit_code"],
                "output_len": len(result["output"]),
            })

            call_outputs.append({
                "type": "local_shell_call_output",
                "call_id": call_id,
                "output": result["output"] or "(no output)",
            })

        if not call_outputs:
            break

        # ── Send outputs back via previous_response_id ────────────────────────
        followup_payload = {
            "model": MODEL,
            "tools": [{"type": "local_shell"}],
            "previous_response_id": response_id,
            "store": True,
            "input": call_outputs,
        }

        try:
            response = api_request(api_key, followup_payload)
        except RuntimeError as e:
            err(f"API error on round {round_num + 1}: {e}")
            break

        response_id = response.get("id", "")

        # Log token usage
        usage = response.get("usage", {})
        if usage:
            err(f"  Tokens: in={usage.get('input_tokens', 0)} out={usage.get('output_tokens', 0)}")

    # Final text extraction if we exited the loop without capturing it
    if not final_output:
        final_output = extract_text_output(response)

    return {
        "status": "ok",
        "commands_run": commands_run,
        "final_output": final_output,
    }


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({"status": "error", "error": "no input"}, sys.stdout)
        return

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as e:
        json.dump({"status": "error", "error": f"invalid JSON: {e}"}, sys.stdout)
        return

    api_key = request.get("api_key", "")
    list_file = request.get("list_file", "")
    scope_dir = request.get("scope_dir", "")
    timeout = request.get("timeout", 120)

    if not api_key:
        json.dump({"status": "error", "error": "missing api_key"}, sys.stdout)
        return

    if not list_file or not os.path.isfile(list_file):
        json.dump({"status": "error", "error": f"list_file not found: {list_file}"}, sys.stdout)
        return

    with open(list_file, "r") as f:
        list_content = f.read()

    if not list_content.strip():
        json.dump({"status": "error", "error": "list_file is empty"}, sys.stdout)
        return

    err(f"Starting local shell investigation ({len(list_content)} bytes of findings)")
    result = run_local_shell_loop(api_key, list_content, scope_dir, timeout)
    err(f"Complete: {len(result.get('commands_run', []))} commands, "
        f"{len(result.get('final_output', ''))} chars output")

    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
