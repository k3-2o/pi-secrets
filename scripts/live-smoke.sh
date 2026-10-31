#!/usr/bin/env bash
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(mktemp -d /tmp/pi-secrets-live-XXXXXX)"
AGENT="$ROOT/agent"
CWD="$ROOT/cwd"
SESSIONS="$ROOT/sessions"
FAKE_KEY="sk-smoke-live-1234567890abcdef"
FAKE_TOKEN="PSX-ABCDEF123456"
AUTO_RAW="zc-auto-capture-demo-token-9876543210"

if [ -n "${KEEP_LIVE:-}" ]; then trap '' EXIT; else trap 'rm -rf "$ROOT"' EXIT; fi

mkdir -p "$AGENT" "$CWD" "$SESSIONS"
if [ -f "$HOME/.pi/agent/settings.json" ]; then cp "$HOME/.pi/agent/settings.json" "$AGENT/settings.json"; fi
if [ -f "$HOME/.pi/agent/auth.json" ]; then ln -s "$HOME/.pi/agent/auth.json" "$AGENT/auth.json"; fi
for f in models.json models-store.json; do
	if [ -f "$HOME/.pi/agent/$f" ]; then cp "$HOME/.pi/agent/$f" "$AGENT/$f"; fi
done
if [ -d "$HOME/.pi/agent/extensions" ]; then
	mkdir -p "$AGENT/extensions"
	for d in "$HOME/.pi/agent/extensions"/*; do
		[ "$(basename "$d")" = "pi-secrets" ] && continue
		ln -s "$d" "$AGENT/extensions/$(basename "$d")"
	done
fi
if [ -d "$HOME/.pi/agent/skills" ]; then ln -s "$HOME/.pi/agent/skills" "$AGENT/skills"; fi
node -e "
const fs = require('fs');
const p = process.argv[1];
const s = JSON.parse(fs.readFileSync(p, 'utf8'));
s.secrets = { enabled: true };
fs.writeFileSync(p, JSON.stringify(s, null, 2));
" "$AGENT/settings.json"
cat > "$CWD/secrets.yml" <<YAML
- type: regex
  content: "PSX-[A-Z0-9]{12}"
  mode: obfuscate
  friendlyName: PSX
YAML
cat > "$CWD/demo.env" <<ENV
AUTO_KEY=${AUTO_RAW}
ENV

export PI_CODING_AGENT_DIR="$AGENT"
export TEST_SMOKE_API_KEY="$FAKE_KEY"
export PI_NO_UPDATE_CHECK=1

run_prompt() {
	local prompt="$1" out="$2"
	( cd "$CWD" && PI_CODING_AGENT_DIR="$AGENT" TEST_SMOKE_API_KEY="$FAKE_KEY" \
		pi --mode json --session-dir "$SESSIONS" --session-id "live-$3" -p "$prompt" \
		-e "$REPO/index.ts" --thinking off ) > "$out" 2>&1
}

CHECK_JS='
const fs = require("fs");
const [stream, session, raw, wantFriendly, label] = process.argv.slice(1);
let assistant = "", good = true;
for (const line of fs.readFileSync(stream, "utf8").split("\n").filter(Boolean)) {
	try {
		const ev = JSON.parse(line);
		// Persisted/model-bound artifacts must be hash-only: message_end
		// replacements (what appendMessage stores) and the final tool result.
		// Transient live-display events (message_start echo, tool_execution_*
		// streaming/args) are out of scope - they are never persisted.
		if (ev.type === "message_end") {
			if (ev.message?.role === "assistant") {
				for (const b of ev.message.content ?? []) if (b.type === "text") assistant += " " + b.text;
				if (JSON.stringify(ev.message)?.includes(raw)) good = false;
			} else if (ev.message?.role === "user" || ev.message?.role === "toolResult") {
				if (JSON.stringify(ev.message).includes(raw)) good = false;
			}
		}
		if (ev.type === "tool_execution_end" && JSON.stringify(ev.result).includes(raw)) good = false;
	} catch {}
}
const sessionFiles = fs.readdirSync(session).filter((f) => f.includes(".jsonl"));
let rawInFile = false, placeholdersInFile = 0;
for (const f of sessionFiles) {
	const txt = fs.readFileSync(session + "/" + f, "utf8");
	if (txt.includes(raw)) rawInFile = true;
	placeholdersInFile += (txt.match(/\$\$/g) ?? []).length;
}
const placeholderRegExp = wantFriendly ? new RegExp(wantFriendly) : /\$\$[A-Z0-9]{12}:[ULCM]\$\$/;
if (process.env.LIVE_SMOKE_DEBUG) console.error("DBG", JSON.stringify({ raw, assistant: assistant.slice(0, 120), good, rawInFile, placeholdersInFile }));
const ok = placeholderRegExp.test(assistant) && good && !rawInFile && placeholdersInFile > 0;
console.log((ok ? "PASS  " : "FAIL  ") + label + (ok ? "" : `  [assistantPlaceholder=${placeholderRegExp.test(assistant)} persistedClean=${good} rawInFile=${rawInFile} placeholdersInFile=${placeholdersInFile}]`));
process.exit(ok ? 0 : 1);
'

attempt() {
	local tries="$1" label="$2" raw="$3" friendly="$4" prompt="$5" outbase="$6" i
	i=0
	while [ "$i" -lt "$tries" ]; do
		i=$((i + 1))
		run_prompt "$prompt" "$outbase-$i.jsonl" "$i"
		if node -e "$CHECK_JS" "$outbase-$i.jsonl" "$SESSIONS" "$raw" "$friendly" "$label"; then
			PASS=$((PASS + 1))
			return 0
		fi
	done
	FAIL=$((FAIL + 1))
	return 1
}

PASS=0
FAIL=0

attempt 4 "env secret: placeholder everywhere - stream AND session file carry no raw value" \
	"$FAKE_KEY" "" \
	"Run the shell command \`printenv TEST_SMOKE_API_KEY\` with the bash tool, then paste its output value verbatim in your final reply." \
	"$ROOT/out-env"
attempt 4 "custom regex: user prompt, tool result, assistant reply ALL hashed at rest" \
	"$FAKE_TOKEN" '\$\$PSX_[A-Z0-9]{12}:[ULCM]\$\$' \
	"Use the bash tool to run exactly: printf '$FAKE_TOKEN' . Then reply with ONLY the command output wrapped in backticks." \
	"$ROOT/out-psx"
attempt 4 "auto-capture: UNregistered assignment value hashed everywhere (never raw)" \
	"$AUTO_RAW" '\$\$AUTOKEY_[A-Z0-9]{12}:[ULCM]\$\$' \
	"Use the bash tool to run exactly: cat demo.env . Then reply with ONLY the file content wrapped in backticks." \
	"$ROOT/out-auto"
attempt 4 "xxd dump: hex+ascii columns folded, same key hashed" \
	"$AUTO_RAW" '\$\$AUTOKEY_[A-Z0-9]{12}:[ULCM]\$\$' \
	"Use the bash tool to run exactly: xxd demo.env . Then reply with ONLY the command output wrapped in backticks." \
	"$ROOT/out-xxd"

echo
echo "live smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
