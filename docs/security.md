# pi-secrets security model

This document explains what pi-secrets protects, how it protects it, and where it
does not protect you. It is a port of the OMP secrets feature onto pi's extension
events; the mechanical details live in `Architecture.md`.

## Threat model

An LLM that can see a credential in its context can leak it: quote it into a file,
echo it into a tool call, or — under prompt injection — relay it somewhere it should
not go. Every such event is a real exposure because the text leaves the machine for
the provider's request logs, and then the operator has to rotate every affected key.

pi-secrets stops that at the source: **real credentials never enter the model's
context at all.** What the model receives is a keyed placeholder (`$$NAME_HASH:HINT$$`).

This is a reduction of exposure, not a sandbox. The model still executes tools with
your account's permissions. If it deliberately writes a credential to disk or to a
network endpoint, no prompt rewriting prevents that — but it can only do so with the
placeholder it saw, not the real value, unless a tool output puts the real value in
its hands and it acts within the same tool result.

## What is protected

| Surface | What happens | Guarantee |
|---|---|---|
| Provider requests | `context` handler obfuscates every conversation message before every LLM call: user text, tool results, and prior assistant replay (text, thinking, tool-call arguments) | The provider never receives a real secret from pi's own messages |
| Tool execution | `tool_call` handler deobfuscates arguments in place, immediately before the tool runs | `edit(old="…")` matches real bytes on disk; commands run with real env values |
| Human display | `message_end` (persist mode) or the render transformer (render mode) reveals assistant-authored content | You see the real key when the model references a placeholder |
| Placeholder forgery | The deobfuscation map only accepts placeholders minted by this obfuscator under the per-install key | A model inventing `$$FAKE$$` text gets nothing back |
| Transcript attacks | Placeholder digests are HMAC-SHA256 under a 32-byte per-install key (`secret-placeholder.key`, mode `0600`) | A transcript reader cannot dictionary-hash a placeholder back to a secret |
| The key file itself | The key file content is registered as a `replace`-mode secret | A model reading the key file via a tool ships a marker, not the key |

The built-in patterns and `secrets.yml` entries run through the same engine as the
reversible obfuscation, so exact-match edits keep working: the model plans against a
placeholder, and the tool receives the real value.

## What is not protected

- **Deliberate exfiltration.** A tool that explicitly writes or sends data is not
  blocked. The model may briefly hold a real value it just read from a tool output;
  that output is obfuscated before the next LLM call, but the model can act on it in
  the same turn. Secrets are about reducing accidental and injection-driven leakage,
  not about outsmarting a model that is trying to leak.
- **At rest, in persist mode.** With the default `mode: "persist"`, the session file
  (`session.jsonl`) stores the real values the human saw. Anyone who can read the
  session file can read the secrets. Set `"mode": "render"` to keep hashes at rest
  (see Configuration in the README).
- **Outputs that do not go through pi's renderer.** In render mode, exports and RPC
  consumers render hashes, not real values. Getting both (hashes at rest and real
  values everywhere a human looks) requires a small pi core patch; the extension can
  do one or the other.
- **One native-provider replay edge.** OpenAI Responses native history and Anthropic
  compaction `filesText` payloads mostly inherit hashes from already-obfuscated
  messages, but a deep provider-payload walker is not reachable from an extension.
  This is a documented edge case, not an observed leak.
- **Abandoned placeholder stability.** The per-install key is stable across sessions
  on purpose: persisted transcripts deobfuscate consistently. If you suspect
  compromise, see Rotation.

## Mechanism in one pass

1. `session_start` builds the obfuscator from your environment, `secrets.yml`, and the
   built-in patterns. The per-install key file is created lazily on the first
   placeholder mint — a session that never matches a secret never creates a key.
2. Before every LLM call, the `context` handler hides every secret-shaped value. Text
   that is already placeholdered passes through untouched (the engine is a fixed
   point), so history and prompt caches stay stable.
3. When the model calls a tool with a placeholder in the arguments, the `tool_call`
   handler restores the real bytes in place.
4. When an assistant message ends, the handler reveals assistant-authored content for
   your display. Only assistant content is ever revealed; user and tool-result text is
   persisted and displayed literally, so anything you type as `$$…$$` survives.

## Rotation

If you suspect a placeholder or key was compromised:

1. Delete the per-install key: `rm ~/.pi/agent/secret-placeholder.key`
2. Rotate the real credentials that may have been exposed (at the provider).
3. Restart pi.

After the key changes, previously persisted placeholders no longer deobfuscate —
old transcripts render as hashes. That is expected: a new key means the old mapping is
gone for everyone, including an attacker who stole the old key.

## Enabling safety in practice

The feature is off by default (`secrets.enabled: false`). Turn it on, run the quick
start from the README with a fake key, and observe the transcript before trusting it
with real keys. The test suite (`just check`) asserts the security properties —
fixed-point, determinism, forgery resistance, one-way replace mode — and runs in
hermetic temp directories; it never touches real credentials or the real key file.