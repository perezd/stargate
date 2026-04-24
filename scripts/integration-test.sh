#!/usr/bin/env bash
# Integration test: simulates Claude Code hook protocol against a real stargate server.
# Usage: ./scripts/integration-test.sh
set -euo pipefail

STARGATE="./dist/stargate"
CONFIG="./stargate.toml"
LISTEN="127.0.0.1:19099"  # non-default port to avoid conflicts
PID_FILE="/tmp/stargate-integration-test.pid"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}PASS${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}FAIL${NC} $1: $2"; ((FAIL++)); }

# --- Setup ---
echo "=== Stargate Integration Test ==="
echo ""

# Build if needed
if [ ! -f "$STARGATE" ]; then
    echo "Building stargate..."
    just build
fi

# Start server
echo "Starting stargate serve on $LISTEN..."
$STARGATE -c "$CONFIG" serve -l "$LISTEN" &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
sleep 1

# Verify server is up
if ! curl -s "http://$LISTEN/health" > /dev/null 2>&1; then
    echo "ERROR: Server failed to start"
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
fi
echo "Server running (PID $SERVER_PID)"
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "Stopping server..."
    kill "$SERVER_PID" 2>/dev/null || true
    rm -f "$PID_FILE"
}
trap cleanup EXIT

# --- Helper: send PreToolUse hook ---
pre_tool_use() {
    local command="$1"
    local tool_use_id="${2:-toolu_test_$(date +%s%N)}"

    echo "{
        \"tool_name\": \"Bash\",
        \"tool_input\": {\"command\": \"$command\"},
        \"tool_use_id\": \"$tool_use_id\",
        \"session_id\": \"sess_integration_test\",
        \"cwd\": \"$(pwd)\"
    }" | $STARGATE hook --agent claude-code --event pre-tool-use --url "http://$LISTEN" 2>/dev/null
}

# --- Helper: send PostToolUse hook ---
post_tool_use() {
    local tool_use_id="$1"

    echo "{
        \"tool_name\": \"Bash\",
        \"tool_use_id\": \"$tool_use_id\",
        \"session_id\": \"sess_integration_test\"
    }" | $STARGATE hook --agent claude-code --event post-tool-use --url "http://$LISTEN" 2>/dev/null
}

# --- Helper: extract permissionDecision from hook output ---
get_decision() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hookSpecificOutput',{}).get('permissionDecision',''))" 2>/dev/null
}

# --- Helper: extract reason ---
get_reason() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('hookSpecificOutput',{}).get('permissionDecisionReason',''))" 2>/dev/null
}

# ==============================================================================
# TEST 1: Health endpoint
# ==============================================================================
echo "--- Test: Health endpoint ---"
HEALTH=$(curl -s "http://$LISTEN/health")
if echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'" 2>/dev/null; then
    pass "Health returns status=ok"
else
    fail "Health endpoint" "unexpected response: $HEALTH"
fi

# ==============================================================================
# TEST 2: GREEN commands → allow
# ==============================================================================
echo ""
echo "--- Test: GREEN commands → allow ---"

for cmd in "git status" "ls -la" "echo hello" "cat README.md" "pwd"; do
    OUTPUT=$(pre_tool_use "$cmd")
    DECISION=$(get_decision "$OUTPUT")
    if [ "$DECISION" = "allow" ]; then
        pass "GREEN: '$cmd' → allow"
    else
        fail "GREEN: '$cmd'" "expected allow, got '$DECISION' (output: $OUTPUT)"
    fi
done

# ==============================================================================
# TEST 3: RED commands → deny
# ==============================================================================
echo ""
echo "--- Test: RED commands → deny ---"

for cmd in "rm -rf /" "eval 'dangerous'" "shutdown now"; do
    OUTPUT=$(pre_tool_use "$cmd")
    DECISION=$(get_decision "$OUTPUT")
    if [ "$DECISION" = "deny" ]; then
        pass "RED: '$cmd' → deny"
    else
        fail "RED: '$cmd'" "expected deny, got '$DECISION' (output: $OUTPUT)"
    fi
done

# ==============================================================================
# TEST 4: YELLOW commands → ask
# ==============================================================================
echo ""
echo "--- Test: YELLOW commands → ask ---"

for cmd in "pip install requests" "ssh user@host" "kill 1234"; do
    OUTPUT=$(pre_tool_use "$cmd")
    DECISION=$(get_decision "$OUTPUT")
    if [ "$DECISION" = "ask" ]; then
        pass "YELLOW: '$cmd' → ask"
    else
        fail "YELLOW: '$cmd'" "expected ask, got '$DECISION' (output: $OUTPUT)"
    fi
done

# ==============================================================================
# TEST 5: Non-Bash tool → allow (passthrough)
# ==============================================================================
echo ""
echo "--- Test: Non-Bash tool → allow ---"

NON_BASH_OUTPUT=$(echo '{
    "tool_name": "Read",
    "tool_input": {"path": "/etc/passwd"},
    "tool_use_id": "toolu_nonbash",
    "session_id": "sess_test",
    "cwd": "."
}' | $STARGATE hook --agent claude-code --event pre-tool-use --url "http://$LISTEN" 2>/dev/null)
DECISION=$(get_decision "$NON_BASH_OUTPUT")
if [ "$DECISION" = "allow" ]; then
    pass "Non-Bash tool → allow passthrough"
else
    fail "Non-Bash tool" "expected allow, got '$DECISION'"
fi

# ==============================================================================
# TEST 6: POST /classify directly
# ==============================================================================
echo ""
echo "--- Test: POST /classify ---"

CLASSIFY_OUTPUT=$(curl -s -X POST "http://$LISTEN/classify" \
    -H "Content-Type: application/json" \
    -d '{"command": "git status"}')
CLASSIFY_DECISION=$(echo "$CLASSIFY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision',''))" 2>/dev/null)
if [ "$CLASSIFY_DECISION" = "green" ]; then
    pass "POST /classify: git status → green"
else
    fail "POST /classify" "expected green, got '$CLASSIFY_DECISION'"
fi

# Check trace_id is present
TRACE_ID=$(echo "$CLASSIFY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stargate_trace_id',''))" 2>/dev/null)
if [ -n "$TRACE_ID" ]; then
    pass "POST /classify returns stargate_trace_id"
else
    fail "POST /classify" "missing stargate_trace_id"
fi

# ==============================================================================
# TEST 7: POST /test (dry-run)
# ==============================================================================
echo ""
echo "--- Test: POST /test (dry-run) ---"

TEST_OUTPUT=$(curl -s -X POST "http://$LISTEN/test" \
    -H "Content-Type: application/json" \
    -d '{"command": "git status"}')
TEST_DECISION=$(echo "$TEST_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision',''))" 2>/dev/null)
if [ "$TEST_DECISION" = "green" ]; then
    pass "POST /test: git status → green"
else
    fail "POST /test" "expected green, got '$TEST_DECISION'"
fi

# Verify no feedback token on /test
FEEDBACK_TOKEN=$(echo "$TEST_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('feedback_token',''))" 2>/dev/null)
if [ -z "$FEEDBACK_TOKEN" ] || [ "$FEEDBACK_TOKEN" = "None" ]; then
    pass "POST /test: no feedback_token"
else
    fail "POST /test" "unexpected feedback_token: $FEEDBACK_TOKEN"
fi

# ==============================================================================
# TEST 8: stargate test CLI
# ==============================================================================
echo ""
echo "--- Test: stargate test CLI ---"

CLI_OUTPUT=$($STARGATE -c "$CONFIG" test --url "http://$LISTEN" "git status" 2>/dev/null)
if echo "$CLI_OUTPUT" | grep -qi "GREEN"; then
    pass "CLI: stargate test 'git status' → GREEN"
else
    fail "CLI test" "expected GREEN in output: '$CLI_OUTPUT'"
fi

CLI_JSON=$($STARGATE -c "$CONFIG" test --url "http://$LISTEN" --json "rm -rf /" 2>/dev/null)
CLI_JSON_DECISION=$(echo "$CLI_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision',''))" 2>/dev/null)
if [ "$CLI_JSON_DECISION" = "red" ]; then
    pass "CLI: stargate test --json 'rm -rf /' → red"
else
    fail "CLI test --json" "expected red, got '$CLI_JSON_DECISION'"
fi

# ==============================================================================
# TEST 9: Pre + Post tool use full cycle
# ==============================================================================
echo ""
echo "--- Test: Full hook cycle (pre + post) ---"

CYCLE_ID="toolu_cycle_$(date +%s)"
PRE_OUTPUT=$(pre_tool_use "git log --oneline -5" "$CYCLE_ID")
PRE_DECISION=$(get_decision "$PRE_OUTPUT")
if [ "$PRE_DECISION" = "allow" ]; then
    pass "Full cycle: pre-tool-use → allow"
else
    fail "Full cycle pre" "expected allow, got '$PRE_DECISION'"
fi

# Post tool use (fire-and-forget, always exits 0)
POST_EXIT=0
post_tool_use "$CYCLE_ID" || POST_EXIT=$?
if [ "$POST_EXIT" = "0" ]; then
    pass "Full cycle: post-tool-use → exit 0"
else
    fail "Full cycle post" "expected exit 0, got $POST_EXIT"
fi

# ==============================================================================
# TEST 10: Evasion vectors
# ==============================================================================
echo ""
echo "--- Test: Evasion vectors ---"

# Backslash evasion — walker should strip backslash, resolve to rm
EVASION_OUTPUT=$(pre_tool_use '\\rm -rf /')
EVASION_DECISION=$(get_decision "$EVASION_OUTPUT")
if [ "$EVASION_DECISION" = "deny" ]; then
    pass "Evasion: \\\\rm -rf / → deny (backslash stripped)"
else
    fail "Evasion: \\\\rm" "expected deny, got '$EVASION_DECISION'"
fi

# ==============================================================================
# TEST 11: Exit code 2 on server unreachable
# ==============================================================================
echo ""
echo "--- Test: Server unreachable → exit 2 ---"

UNREACHABLE_EXIT=0
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"toolu_unreachable","session_id":"s","cwd":"."}' | \
    $STARGATE hook --agent claude-code --event pre-tool-use --url "http://127.0.0.1:1" --timeout 500ms 2>/dev/null || UNREACHABLE_EXIT=$?
if [ "$UNREACHABLE_EXIT" = "2" ]; then
    pass "Server unreachable → exit 2 (fail-closed)"
else
    fail "Server unreachable" "expected exit 2, got $UNREACHABLE_EXIT"
fi

# ==============================================================================
# TEST 12: Config subcommands
# ==============================================================================
echo ""
echo "--- Test: Config subcommands ---"

VALIDATE_EXIT=0
$STARGATE -c "$CONFIG" config validate 2>/dev/null || VALIDATE_EXIT=$?
if [ "$VALIDATE_EXIT" = "0" ]; then
    pass "config validate → exit 0"
else
    fail "config validate" "expected exit 0, got $VALIDATE_EXIT"
fi

DUMP_OUTPUT=$($STARGATE -c "$CONFIG" config dump 2>/dev/null)
if echo "$DUMP_OUTPUT" | grep -q "stargate config dump"; then
    pass "config dump → has header"
else
    fail "config dump" "missing header"
fi

RULES_OUTPUT=$($STARGATE -c "$CONFIG" config rules 2>/dev/null)
if echo "$RULES_OUTPUT" | grep -q "LEVEL"; then
    pass "config rules → has header"
else
    fail "config rules" "missing header"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results ==="
TOTAL=$((PASS + FAIL))
echo -e "Total: $TOTAL  ${GREEN}Pass: $PASS${NC}  ${RED}Fail: $FAIL${NC}"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
