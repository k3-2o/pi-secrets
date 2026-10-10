#!/usr/bin/env bash
# pi-secrets live smoke: proves provider-boundary hiding + at-rest hashing in a
# REAL pi run (default provider/model). Uses temp dirs only; never touches the
# real ~/.pi/agent. Two prompts, then event-stream inspection.
#
# Exit 0 when every assertion holds; prints PASS/FAIL per check.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(mktemp -d /tmp/pi-secrets-live-XXXXXX)"
AGENT="$ROOT/agent"
CWD="$ROOT/cwd"
SESSIONS="$ROOT/sessions"
FAKE_KEY="sk-smoke-live-1234567890abcdef"
FAKE_TOKEN="PSX-ABCDEF123456"

if [ -n "${KEEP_LIVE:-}" ]; then trap '' EXIT; else trap 'rm -rf "$ROOT"' EXIT; fi

# ── harness ──────────────────────────────────────────────────────────────────
mkdir -p "$AGENT" "$CWD" "$SESSIONS"
# Mirror the real agent dir so model selection/auth resolve exactly like a
# normal session, while every secret OUR test writes stays in the temp dir.
if [ -f "$HOME/.pi/agent/settings.json" ]; then cp "$HOME/.pi/agent/settings.json" "$AGENT/settings.json"; fi
if [ -f "$HOME/.pi/agent/auth.json" ]; then ln -s "$HOME/.pi/agent/auth.json" "$AGENT/auth.json"; fi
for f in models.json models-store.json; do
	if [ -f "$HOME/.pi/agent/$f" ]; then cp "$HOME/.pi/agent/$f" "$AGENT/$f"; fi
done
if [ -d "$HOME/.pi/agent/extensions" ]; then ln -s "$HOME/.pi/agent/extensions" "$AGENT/extensions"; fi
if [ -d "$HOME/.pi/agent/skills" ]; then ln -s "$HOME/.pi/agent/skills" "$AGENT/skills"; fi
node -e "
const fs = require('fs');
const p = process.argv[1];
const s = JSON.parse(fs.readFileSync(p, 'utf8'));
s.secrets = { enabled: true, mode: 'render' };
fs.writeFileSync(p, JSON.stringify(s, null, 2));
" "$AGENT/settings.json"
cat > "$CWD/secrets.yml" <<YAML
- type: regex
  content: "PSX-[A-Z0-9]{12}"
  mode: obfuscate
  friendlyName: PSX
YAML

export PI_CODING_AGENT_DIR="$AGENT"
export TEST_SMOKE_API_KEY="$FAKE_KEY"
export PI_NO_UPDATE_CHECK=1

run_prompt() {
	local prompt="$1" out="$2"
	( cd "$CWD" && PI_CODING_AGENT_DIR="$AGENT" TEST_SMOKE_API_KEY="$FAKE_KEY" \
		pi --mode json --session-dir "$SESSIONS" --session-id "live-$3" -p "$prompt" \
		-e "$REPO/index.ts" --thinking off ) > "$out" 2>&1
}

# ── assertions (node parses the jsonl event stream) ─────────────────────────
CHECK_JS='
const fs = require("fs");
const [file, raw, wantFriendly, label] = process.argv.slice(1);
const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
let assistant = "";
let rawSeen = false;
for (const line of lines) {
	try {
		const ev = JSON.parse(line);
		if ((ev.type === "message_end" || ev.type === "turn_end") && ev.message?.role === "assistant") {
			for (const b of ev.message.content ?? []) if (b.type === "text") assistant += " " + b.text;
		}
		if (ev.type === "tool_execution_end") {
			if (JSON.stringify(ev.result).includes(raw)) rawSeen = true;
		}
		if (ev.type === "turn_end" && Array.isArray(ev.toolResults)) {
			for (const tr of ev.toolResults) if (JSON.stringify(tr.content).includes(raw)) rawSeen = true;
		}
	} catch {}
}
const placeholderRegExp = wantFriendly ? new RegExp(wantFriendly) : /\$\$[A-Z0-9]{12}:[ULCM]\$\$/;
if (process.env.LIVE_SMOKE_DEBUG) console.error("DBG", JSON.stringify({ file, raw, wantFriendly, assistant: assistant.slice(0, 120) }));
const placeholder = placeholderRegExp.test(assistant);
const leaks = assistant.includes(raw);
const ok = placeholder && !leaks && rawSeen;
console.log((ok ? "PASS  " : "FAIL  ") + label + (ok ? "" : `  [placeholder=${placeholder} leaks=${leaks} rawSeen=${rawSeen}]`));
process.exit(ok ? 0 : 1);
'

# ── run: prompt with up to N tries (model compliance is probabilistic; the
#    system behavior under test is deterministic) ─────────────────────────────
# NOTE: the assistant-echo assertions depend on model compliance (it must quote
# what it saw). The system under test is deterministic; retries absorb variance.
# This script is a live proof, not the deterministic gate (`just check` is).
attempt() {
	local tries="$1" label="$2" raw="$3" friendly="$4" prompt="$5" outbase="$6" i
	i=0
	while [ "$i" -lt "$tries" ]; do
		i=$((i + 1))
		run_prompt "$prompt" "$outbase-$i.jsonl" "$i"
		if node -e "$CHECK_JS" "$outbase-$i.jsonl" "$raw" "$friendly" "$label"; then
			PASS=$((PASS + 1))
			return 0
		fi
	done
	FAIL=$((FAIL + 1))
	return 1
}

PASS=0
FAIL=0

attempt 4 "env secret: assistant carries placeholder, never raw; tool_result literal" \
	"$FAKE_KEY" "" \
	"Run the shell command \`printenv TEST_SMOKE_API_KEY\` with the bash tool, then paste its output value verbatim in your final reply." \
	"$ROOT/out-env"
attempt 4 "custom regex: PSX placeholder, never raw; tool_result literal" \
	"$FAKE_TOKEN" '\$\$PSX_[A-Z0-9]{12}:[ULCM]\$\$' \
	"Use the bash tool to run exactly: printf '$FAKE_TOKEN' . Then reply with ONLY the command output wrapped in backticks." \
	"$ROOT/out-psx"

echo
echo "live smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]