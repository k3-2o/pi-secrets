# pi-secrets security model

## Threat model

An LLM that can see a credential in its context can leak it: quote it into a file,
echo it into a tool call, or relay it, under prompt injection, somewhere it should
not go. Every such event is a real exposure because the text leaves the machine for
the provider's request logs, and then the operator has to rotate every affected key.

A second, quieter leak path is the transcript: session files, HTML exports, JSONL
exports.

pi-secrets stops both at the source:
- **real credentials never enter the model's context at all**, and
- **real credentials never enter the session file or any export**, for every
  message class the extension can reach.

What the model receives, and what the file stores, is a keyed placeholder
(`$$NAME_HASH:HINT$$`). Credential-shaped spans the capture floor does not take, such as
short password-named values and URL passwords, become reversible, span-local hashes
instead of a one-way fallback.
This is a reduction of exposure, not a sandbox. The model still executes tools with
user permissions. If it deliberately writes a credential to disk or to a
network endpoint, it can only do so with the placeholder it saw, not the real value.
## What is protected

| Surface | What happens | Guarantee |
|---|---|---|
| Provider requests | `context` handler obfuscates every conversation message before every LLM call: user text, tool results, and prior assistant replay (text, thinking, tool-call arguments) | The provider never receives a real secret from pi's own messages |
| Session file (`.jsonl`) | `message_end` hashes user + assistant text at rest; `tool_result` scrubs tool output (content + `structuredContent`); `user_bash` scrubs `!`-command output | Registered secrets never land in the file |
| HTML / JSONL exports | Exports render the file (`/export [.jsonl]`), which is already hashed; the interactive-only reveal never runs in exports | Exports contain no registered key material |
| Tool execution | `tool_call` handler deobfuscates arguments in place, immediately before the tool runs | `edit(old="…")` matches real bytes on disk; commands run with real env values |
| Human display | The markdown transformer reveals user + assistant text at paint time in the interactive transcript | You see the real key when you or the model reference a placeholder |
| Secret-shaped but unregistered text | `NAME=value` assignments with credential names and `scheme://user:password@host` URL passwords: assignment values are auto-captured on first sight only when key-shaped (vendor prefixes, password-like strings, 24+ hex, mixed-case alnum, credential symbols) and hashed session-scoped, reversible; prose-like, dated, path-, wordlist-, and digit-shaped values are left raw. URL passwords are always replaced at the URL span, and register session-wide only when mixed-case or credential-symbol (8+ chars) | Values nobody registered cannot ride tool output into the file or the model; a manual `secrets.yml` entry is only needed for values that never appear in assignment/URL form or do not look like keys |
| Dump formats | `od -c`, `hexdump`/`xxd`, and `base64` output that fragments a value into spaced chars, hex pairs, or base64 is folded back before detection | Default dump tools cannot hide a secret; the folded value is hashed like any other |
| Placeholder forgery | The deobfuscation map only accepts placeholders minted by this obfuscator under the per-install key | A model inventing `$$FAKE$$` text gets nothing back |
| Transcript attacks | Placeholder digests are HMAC-SHA256 under a 32-byte per-install key (`secret-placeholder.key`, mode `0600`) | A transcript reader cannot dictionary-hash a placeholder back to a secret |
| The key file itself | The key file content is registered as a `replace`-mode secret | A model reading the key file via a tool ships a marker, not the key |

The built-in patterns and `secrets.yml` entries run through the same engine as the
reversible obfuscation, so exact-match edits keep working: the model plans against a
placeholder, and the tool receives the real value.

## What is not protected

- **Deliberate exfiltration.** A tool that explicitly writes or sends data is not
  blocked. This reduces accidental and injection-driven leakage, not a model that is
  trying to steal: the covered dump formats (`od -c`, `hexdump`/`xxd`, `base64`) are
  folded, but arbitrary byte transforms (rot13, xor, python one-liners, gzip) are out
  of scope.
- **Tool-output blocks show hashes.** pi draws tool blocks through
  renderers shared with HTML exports, so tool blocks are hashed everywhere.
  User and assistant text still reveal.
- **Operator-authored command lines.** `!echo $MYKEY` or `!curl -H "x: <key>" …`
  record the command exactly as typed (the `user_bash` seam cannot rewrite it). The
  output of such commands is scrubbed; the literal command line you typed is your own
  text, like the launch system message.
- **The launch system message.** Your initial prompt (e.g. `pi "…"` or the startup
  prompt) is recorded in the first system message; it is never rewritten, because
  rewriting it would corrupt prompt replay.
- **One native-provider replay edge.** OpenAI Responses native history and Anthropic
  compaction `filesText` payloads mostly inherit hashes from already-obfuscated
  messages, but a deep provider-payload walker is not reachable from an extension.
  This is a documented edge case, not an observed leak.
- **Compacted summaries.** The LLM-written summary of compacted history is stored in a
  `compaction` entry; a secret that survived compaction would appear there. Known
  values are caught by the `context` re-obfuscation when the summary is composed, and
  the summary is written from the same hashed context.
- **Abandoned placeholder stability.** The per-install key is stable across sessions
  on purpose: persisted transcripts deobfuscate consistently for the interactive
  terminal. If you suspect compromise, see Rotation.

## Mechanism in one pass

1. `session_start` builds the obfuscator from your environment, `secrets.yml`, and the
   built-in patterns. The per-install key file is created lazily on the first
   placeholder mint, and a session that never matches a secret never creates a key.
   During the session, credential-named assignment values and URL passwords that no
   source registered are auto-captured on first sight, added to the registry as plain
   two-way secrets, and hashed in the same pass (session-scoped, learned by
   observation, never hardcoded).
2. Before every LLM call, the `context` handler hides every secret-shaped value. Text
   that is already placeholdered passes through untouched (the engine is a fixed
   point), so history and prompt caches stay stable.
3. When the model calls a tool with a placeholder in the arguments, the `tool_call`
   handler restores the real bytes in place.
4. When a tool finishes, the `tool_result` handler scrubs its output (content +
   `structuredContent`, plus `details`/nested-call records at `message_end`).
   Unregistered key-shaped assignment/URL values are auto-captured first, then known
   values become `$$HASH$$`; values under the 8-char floor and non-key-shaped values
   stay raw.
5. When a message ends, the `message_end` handler hashes user + assistant text for
   storage. System messages are never touched.
6. `!`-commands run through a scrubbing wrapper of pi's own shell operations; the
   recorded output is hashed.
7. At paint time, the markdown transformer reveals user + assistant text in the
   interactive transcript only. Tool blocks render the stored hashes.

## Rotation

If you suspect a placeholder or key was compromised:

1. Delete the per-install key: `rm ~/.pi/agent/secret-placeholder.key`
2. Rotate the real credentials that may have been exposed (at the provider).
3. Restart pi.

After the key changes, previously persisted placeholders no longer deobfuscate, and
old transcripts render as hashes. That is expected. A new key means the old mapping is
gone for everyone, including an attacker who stole the old key.

- **Auto-capture is per-session.** The registry is seeded at session start and grows
  by observation; each new session re-learns values on first sight. Nothing learned
  is persisted, no growing on-disk registry, and deterministic keyed hashing keeps
  the same secret hashing to the same token in every session.
- **Bare shapeless prose values stay raw.** Auto-capture requires a credential *name*
  and a key-shaped value; URL passwords are the exception, replaced by their branch
  alone. A value in no assignment, no URL, and matching no built-in shape (e.g. a bare
  vendor token in plain prose) passes through as-is unless the vendor net matches its
  prefix. All-caps or dotted runs that do not look like keys also stay raw; register
  them in `secrets.yml` if they matter.

## Enabling safety in practice

The feature is off by default (`secrets.enabled: false`). Turn it on, run the quick
start from the README with a fake key, and observe the transcript before trusting it
with real keys. The test suite (`just check`) asserts the security properties:
fixed-point, determinism, forgery resistance, one-way replace mode, span-local hashing,
and the at-rest map (every message class stores hashes;
the transformer reveals user + assistant only) and runs in hermetic temp directories; it never touches real
credentials or the real key file.

---

Inspired by OMP's secret obfuscation design.
