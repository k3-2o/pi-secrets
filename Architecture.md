# pi-secrets — Architecture, Spec & Plan

> One file, three jobs: **architecture** (Part A, why/how it works), **reference** (Part B,
> exactly what is where), and **plan** (Part D, the checklisted work). Also serves as the
> project spec — design decisions here are binding unless a checkbox line says otherwise.

| | |
|---|---|
| Status | **MVP complete (Phases 0–6); interactive user validation + Phase 7 optional** |
| Target | vanilla pi ≥ 1.1.0 (`@earendil-works/pi-coding-agent`), extension only, **no core patch** (MVP) |
| Origin | OMP (Oh My Pi, a pi fork) `packages/coding-agent/src/secrets/` — v18.6.0 |
| Design decision | **Option B**: provider never sees real values; session file stores real values; human terminal shows real values |
| Repo | `~/.workspaces/projects/pi/pi-secrets` (this directory) |
| OMP source | `~/.workspaces/tracked/omp/packages/coding-agent/src/secrets/` |

---

## Part A — Architecture (why and how)

### A1. Purpose

`pi-secrets` is a pi extension that stops credentials (API keys, tokens, passwords) from
reaching the LLM provider. It finds secrets at session start, replaces them with reversible
keyed placeholders (`$$HASH$$`) in everything the model sees, and reveals the real values
where humans legitimately look: the interactive transcript, and tool execution (so edits
still match real bytes on disk).

It is a port of OMP's secrets feature onto **vanilla pi's extension events** — no pi source
changes. OMP is itself a pi fork, so the feature's core modules port almost verbatim; only
the harness integration is re-wired, from OMP core calls to pi extension handlers.

### A2. Problem and threat model

**Why this exists:** an LLM that can see an API key in its context can (accidentally or under
prompt injection) quote it, write it to a file, or echo it into tool input. Every such event
is a leak: the key appears in provider request logs, transcript artifacts, and anything the
agent writes. The operator then has to rotate every leaked credential. If the provider offers
no guaranteed zero-data-retention, the exposure is worse: the key persists on the vendor side.

**What we protect (in one line):** the model never *receives* a real secret from pi's own
messages — outbound context is obfuscated at every LLM call.

**What we do not promise:** not a sandbox. The model temporarily executes tools with the
operator's permissions; if a tool deliberately prints a secret to disk or to a network
endpoint, no prompt rewriting stops that. This is "reduce exposure", not "make exfiltration
impossible".

### A3. Design decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Reversible by default** (`obfuscate` mode) | The agent must be able to edit files containing real bytes; the human must read real values. Reversibility (a keyed placeholder) preserves both without exposing the secret to the model. |
| D2 | **Keyed HMAC placeholders** (`HMAC-SHA256(per-install key, secret)`, base-36, 12 chars) | Deterministic (same secret → same placeholder, prompt-cache stable) but not reversible without the 32-byte per-install key. A transcript reader cannot dictionary-hash a placeholder back to a secret. |
| D3 | **Fixed-point engine** | Re-obfuscating already-obfuscated text is a no-op. History re-enters every provider call, so without fixed-point, placeholders would drift and double-hide. |
| D4 | **Per-install key file** (`secret-placeholder.key`, `0600`, lazy creation) | A model-invented `$$…$$` placeholder cannot be forged: the deobfuscate map only accepts placeholders minted under this key + value. |
| D5 | **Option B wiring** (reveal at `message_end`) | `context` guarantees provider parity with OMP. Vanilla pi's `message_end` replacement persists, so the session file stores real content. See B2.3 for the comparison and D8 for the alternative. |
| D6 | **Tool-arg reveal immediately before execution** (`tool_call`, mutate `event.input` in place) | `edit(old="$$HASH$$", …)` would fail against real bytes on disk. The model plans with placeholders; the tool runs with reality. |
| D7 | **Only assistant-authored content is ever revealed** | User/developer/tool-result text is persisted and displayed literally. Operator-typed `$$…$$`-shaped text must survive untouched. |
| D8 | **Hashed-at-rest is deferred (not MVP)** | The combination "hashed at rest + real everywhere" needs a ~20-line core patch (displayEvent split in `agent-session.ts`, mirroring OMP). Extension-only gets one of Option B (real at rest) or Option A (render-only reveal, hashes in exports). See C2 and Phase 7. |
| D9 | **No core changes, MVP extension-only** | Ships on any vanilla pi ≥ 1.1.0. The fork/PR question is a later, separate decision (Phase 7). |
| D10 | **Enabled by config, off by default** | `secrets.enabled` (mirroring OMP's `secrets.enabled` setting). Zero behavior change unless opted in. |

### A4. Terms (jargon -> plain)

| Term | Meaning |
|---|---|
| Transcript / session file | The persisted `.jsonl` conversation log (pi `session.jsonl`). |
| Provider boundary | The point where prompt text leaves the machine for the LLM API. After it: out of our control. |
| Obfuscate (reversible) | Replace with a placeholder; keep a way to turn it back (the key). |
| Replace (one-way) | Replace permanently with a fixed marker; no way back. |
| HMAC (keyed hash) | Checksum of a value using a secret key. Deterministic, one-way, unforgeable without the key. |
| Fixed-point | Applying the transform to already-transformed text changes nothing. |
| In-place mutation | Changing an existing object directly instead of returning a copy. |
| Context | The message list (`AgentMessage[]`) pi composes for the provider call; excludes system prompt. |
| At rest | Stored on disk (vs. in motion over the network). |
| Replay | Re-sending prior conversation turns to the provider on later calls. |
| Compaction | Summarizing a long conversation to reclaim context window. |
| Prompt cache | Provider-side caching of the prompt prefix; broken if a prefix byte changes between calls. |
| Mutate in place | Documented pi contract: `tool_call` handlers patch `event.input` directly. |
| RPC / exporters | Other consumers of the transcript (HTML export, remote API). |

### A5. System overview

```
                        ┌────────────────────────  pi process  ────────────────────────┐
                        │                                                              │
  human terminal        │   ┌───────────────┐    context   ┌────────────┐  payload      │
  (TUI: shows REAL) ◄───┼───│ session.jsonl  │◄────────────│  pi core   │──────────► provider
                        │   │ (Option B:    │              │ agent-     │    (never     │
                        │   │  real content) │              │ session    │   a secret)  │
                        │   └───────▲───────┘              └─────▲──────┘              │
                        │           │ message_end (reveal)      │ messages             │
                        │   ┌───────┴────────────────────────────┴─────────┐            │
                        │   │              pi-secrets extension            │            │
                        │   │  session_start: build obfuscator (+key)      │            │
                        │   │  context:       obfuscate all outbound       │            │
                        │   │  tool_call:     deobfuscate input in place   │            │
                        │   │  message_end:   deobfuscate assistant only   │            │
                        │   └──────────┬───────────────────────────────────┘            │
                        │              │ reads                                        │
                        │   ┌──────────▼────────────┐   ┌─────────────────────────┐    │
                        │   │ env vars              │   │ secret-placeholder.key  │    │
                        │   │ secrets.yml (global+  │   │ (32 random bytes, 0600, │    │
                        │   │ project)              │   │  loaded lazily)         │    │
                        │   │ built-in patterns     │   └─────────────────────────┘    │
                        │   └───────────────────────┘                                  │
                        └──────────────────────────────────────────────────────────────┘
```

### A6. Runtime lifecycle (what happens on every turn)

1. **Session start** (`session_start`): if `secrets.enabled`, load secret entries from env,
   `secrets.yml` (global + project), and built-in patterns; build the `SecretObfuscator`.
   The per-install key file is created **lazily** on first placeholder mint — a built-in
   pattern that never matches creates no key.
2. **Every LLM call** (`context`): deep-walk `event.messages` (all roles: user, prior
   assistant replay incl. thinking and tool-call args, tool results, developer) and obfuscate
   any secret-shaped content. Tool results that printed a real secret get obfuscated here,
   before the model ever reads them. Already-present placeholders are left untouched
   (fixed-point). Return `{ messages }` only when something changed; otherwise return
   `undefined` so pi reuses its objects.
3. The model reasons with `$$NAME_HASH:L$$` placeholders only. It can plan an edit against
   a placeholder, but the file on disk contains real bytes.
4. **Tool execution** (`tool_call`): deobfuscate `event.input` **in place** so
   `edit(old="sk-smoke-…", …)` receives the real string. Tool runs against reality.
5. **Message end** (`message_end`): deobfuscate assistant content only, return the
   replacement. The human sees the real key when the model references a placeholder; under
   Option B this same content persists to `session.jsonl`.
6. Next turn repeats 2–5. On resume, `session.jsonl` (real values under Option B) is
   obfuscated again by step 2 before any provider call.

### A7. Secret sourcing

Three sources, merged at session start:

1. **Environment variables** — name matches
   `/(KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(_|$)/` **and** value
   ≥ 8 chars. Also parses `scheme://user:password@host` style env values and extracts the
   password (raw and percent-decoded).
2. **`secrets.yml`** — global `~/.pi/agent/secrets.yml`, project `<cwd>/secrets.yml`
   (project overrides global on equal `content`). Schema:
   `{type: "plain"|"regex", content, mode: "obfuscate"|"replace", replacement?, flags?, friendlyName?}`.
3. **Built-in patterns** — vendored credential shapes: GitHub (`ghp_`, `gho_`, `ghu_`,
   `github_pat_`), GitLab `glpat-`, OpenAI (`sk-`, `sk-proj-`, `sk-ant-`), AWS `AKIA`/`ASIA`,
   Google `AIza`, Slack `xox*`, npm, Stripe (`sk_`, `rk_live|test_`, `whsec_`), HuggingFace
   `hf_`, SendGrid `SG.`, JWTs `eyJ…`, `Bearer …`, PEM private-key blocks. Plus
   partial/typed-token rules (`sk-ant-`, `-----BEGIN`, …).

### A8. The obfuscation engine

**Placeholder grammar** (informative; the authoritative grammar lives in `placeholder.ts`):

```
$$H$$                  bare — 12-char base-36 keyed HMAC
$$H:L$$                with case hint (U/L/C/M) so a recased placeholder still deobfuscates
$$NAME_H:L$$           with sanitized friendlyName prefix for human recognition
```

**Key**: `secret-placeholder.key` under the pi agent dir (`getAgentDir()`, i.e.
`~/.pi/agent/`), 32 random bytes, `0600`, created lazily on first mint with a `wx` create
to survive concurrent process races (an empty winner file is re-read, never cached). The
key path itself is defensive: the key file content is registered as a **replace-mode**
secret, so a model reading the key file via a tool ships a marker, not the key.

**Two modes**:
- `obfuscate` (default): reversible via the deobfuscate map (key + value → placeholder).
- `replace`: one-way — configured `replacement`, or a deterministic same-length marker.

**Adversarial guards** (from `obfuscator.ts`): fixed-point re-entry, placeholders straddling
regex matches, friendly-name collisions with real secrets, and prefix forgery attempts —
only placeholders minted under this key+value deobfuscate; model-invented `$$FAKE$$` stays
literal everywhere.

---

## Part B — Reference (exactly what is where)

### B1. Module map & port status

Source of truth for ported files: `~/.workspaces/tracked/omp/packages/coding-agent/src/secrets/`.
`V` = copy verbatim, `A` = adapted (delta noted), `D` = deferred.

| OMP source (size) | Dest | Status | Delta to expected |
|---|---|---|---|
| `regex.ts` (0.8 KB) — `compileSecretRegex(pattern, flags)` | `src/secrets/regex.ts` | `[x]` | V + local `SENSITIVE_TOKEN_RE` copy and `escapeRegExp` helper added (see deltas) |
| `placeholder.ts` (19.8 KB) — placeholder format, friendly-name sanitizing, key-need helpers | `src/secrets/placeholder.ts` | `[x]` | A — imports only; key path logic moves to `index.ts` |
| `replacement.ts` (12 KB) — deterministic replacement generators, regex-rematch guards | `src/secrets/replacement.ts` | `[x]` | V + `seedFromString` (see deltas) |
| `placeholder-scan.ts` (20.2 KB) — placeholder-range scanner/transformer, `deepWalkStrings`, `mapJsonStrings`, `collectJsonRegexSecretValues` | `src/secrets/placeholder-scan.ts` | `[x]` | V |
| `registry-revision.ts` (2.4 KB) — `RegistryRevision`, `TrackedMap`, `TrackedSet` | `src/secrets/registry-revision.ts` | `[x]` | V |
| `patterns.ts` (4.1 KB) — `CREDENTIAL_PATTERNS` + partial-token rules | `src/secrets/patterns.ts` | `[x]` | A — `SENSITIVE_TOKEN_RE` imported from local `regex.ts` (one line) |
| `obfuscator.ts` (80 KB) — `SecretObfuscator`, `SecretEntry`, fixed-point engine | `src/secrets/obfuscator.ts` | `[x]` | V + `escapeRegExp` in `buildLiteralDetector` |
| `message-transform.ts` (28.4 KB) — `obfuscateProviderContext`, `obfuscateMessages`, `deobfuscateAgentMessages`, `deobfuscateAssistantContent`, `deobfuscateToolArguments`, `obfuscateToolArguments` | `src/secrets/message-transform.ts` | `[x]` | A — retyped for vanilla pi `AgentMessage` (pi-agent-core); fork-only branches dropped; native replay deferred (see deltas) |
| `index.ts` (16.8 KB) — `getSecretPlaceholderKey`, `getExistingSecretPlaceholderKey`, `loadSecrets`, `collectEnvSecrets`, `builtinCredentialSecretEntries`, `buildSecretObfuscator` | `src/secrets/index.ts` | `[x]` | A — landing: `@oh-my-pi/pi-utils` → local `isEnoent`/`logger`/`sleep`; `bun` YAML → `yaml` package; `Bun.file`→`readFile`, `Bun.sleep`→`setTimeout`; key path via pi `getAgentDir()`; project `secrets.yml` path is `<cwd>/secrets.yml` (pi convention) |
| `settings.ts` (1.3 KB) — `cfgSecretsEnabled` (OMP config registry) | `src/settings.ts` | `[x]` | **R**ewritten — `readSecretsSettings(pi, agentDir)`: `pi.getSettings().secrets` → `<agentDir>/settings.json` fallback → defaults; `--secrets` flag override lands in Phase 3 |
| (new) | `index.ts` (extension entry) | `[ ]` | Wire Phase 3 handlers |

OMP-ism replacements (all files, **actuated in Phase 1**):

| OMP-ism | Replacement (as landed) |
|---|---|
| `@oh-my-pi/pi-utils` (`getSecretPlaceholderKeyPath`, `isEnoent`, `logger`) | local helpers in `src/secrets/index.ts` (Phase 2) — `console` for logger, 2-line `isEnoent` |
| `bun` built-in YAML | `yaml` npm package (`parse()` only) — Phase 2 |
| `Bun.CryptoHasher` (placeholder.ts `buildHashBase`, `buildKeyedReplacementRun`) | `node:crypto` `createHmac("sha256", …)` — landed, with `// PORTED:` comments |
| `Bun.hash` (replacement.ts `generateDeterministicReplacement`) | `seedFromString` — SHA-256-derived 64-bit seed (`node:crypto`), deterministic across restarts; outputs are only consumed by our own obfuscator, so the algorithm swap is safe |
| `RegExp.escape` (obfuscator.ts `buildLiteralDetector`) | `escapeRegExp` helper in `regex.ts` (portable to Node SEA builds; TS 5.6 libs lack the ES2025 API) |
| pi-ai provider-`SENSITIVE_TOKEN_RE` import | local copy of the regex in `src/secrets/regex.ts` (verbatim source from the fork) |

**Message-shape deltas** (fork vs vanilla pi 1.1.0, all dropped branches are OMP fork additions):
- `ToolCall.intent` / `ToolCall.rawBlock` — absent; tool deals walk `arguments` only.
- "developer" role / `attribution === "user"` — absent from pi's `Message` union; user-facing walk covers `user`/`toolResult` only.
- compaction summary `shortSummary`/`blocks` — absent; summary text only.
- `deobfuscateSessionContext` — no vanilla-pi `SessionContext`; the `AgentMessage[]` walk `deobfuscateAgentMessages` stands alone.
- Native replay walkers (`obfuscateNativeReplay`, `collectNativeReplayRegexSecretValues`, `mapNative*`) deferred with a file-header `PORTED-DEFERRED` block (C2.2).

Type bindings: `AgentMessage` from `@earendil-works/pi-agent-core` (not re-exported by pi-coding-agent), `JsonObject` from `@earendil-works/pi-ai` — both pinned 1.1.0 devDeps. Tooling: `noAssignInExpressions` disabled in biome.json (ported OMP idiom `??=` in arrow bodies). Cosmetic biome style diffs (arrow parens/reflow) are mechanical and not logic deltas.

### B2. Harness wiring (verified against pi 1.1.0)

Verified signatures: `dist/core/extensions/types.d.ts` in the installed
`@earendil-works/pi-coding-agent` 1.1.0. `ExtensionAPI` type is exported from the package
root. State model: a module-level per-session `obfuscator: SecretObfuscator | undefined`
(`undefined` = disabled; all handlers short-circuit to no-op).

| Event | Exact contract | Handler behavior |
|---|---|---|
| `session_start` | `{type, reason, previousSessionFile?}` | If `secrets.enabled`: `obfuscator = await buildSecretObfuscator(await loadSecrets(cwd, getAgentDir()))`. Key created lazily, never here |
| `context` | `{messages: AgentMessage[]}` → `ContextEventResult {messages?}` | `obfuscateProviderContext(obfuscator, event.messages)`; return `{messages}` only when changed, else `undefined` (pi reuses objects — perf) |
| `tool_call` | union (`EditToolCallEvent …`); **"Mutate `event.input` in place to patch tool arguments before execution"** | `deobfuscateToolArguments(obfuscator, event.input)`; no return |
| `message_end` | `{message: AgentMessage}` → `MessageEndEventResult {message?}` — "replacement must keep the original message role" | `deobfuscateAssistantContent(obfuscator, event.message)`; return `{message}` only when changed |
| `before_provider_request` | `{payload: unknown}` → `unknown` | **Deferred (MVP)** — `payload` is provider-specific post-conversion; can't deep-walk generically. Optional last-chance net in Phase 7 |
| `registerMarkdownTransformer` | `(markdown, {messageType, isStreaming, availableWidth}) => string` | **Not used in Option B.** Option A's display reveal; kept as a config-switchable path (`secrets.mode = "render"`) |
| `getAgentDir()` | exported from package root | Key + global `secrets.yml` live under it |

**B2.3 Option A vs Option B** (D8):

| | Option B (chosen) | Option A |
|---|---|---|
| Display | real (via `message_end`) | real (via `markdownTransformer` per render) |
| At rest (`session.jsonl`) | real | hashed |
| Exports / RPC | real | hashed |
| Core changes | none | none |
| Provider parity with OMP | identical | identical |
| Both "hashed at rest + real in exports" | ✗ (needs core patch, Phase 7) | ✗ (needs core patch, Phase 7) |

### B3. Configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `secrets.enabled` | boolean | false | Master switch (off = zero behavior change) |
| `secrets.mode` | `"persist" \| "render"` | `"persist"` | Option B vs Option A reveal path (both extension-only) |
| CLI | `--secrets` flag | — | Fallback toggle if settings read is unavailable (registered via `pi.registerFlag`) |

Paths: global config `~/.pi/agent/secrets.yml`; project config `<cwd>/secrets.yml`
(project overrides global per equal `content`); key `~/.pi/agent/secret-placeholder.key`
(`0600`, lazily created).

### B4. Data formats

`secrets.yml` example:

```yaml
# ~/.pi/agent/secrets.yml (global); same schema per project: <cwd>/secrets.yml
- type: regex
  content: "(?<=--token=)[A-Za-z0-9_-]{20,64}"
  mode: obfuscate
  flags: "i"
  friendlyName: CLI_TOKEN
- type: plain
  content: "my-super-secret-label"
  mode: replace
  replacement: "[LABEL]"
  friendlyName: COOL_LABEL
```

Fields: `type` (`plain` exact-string match, `regex` match with optional `flags`),
`content`, `mode` (`obfuscate`|`replace`), `replacement` (required for replace),
`friendlyName` (sanitized into the placeholder prefix).

---

## Part C — Security model & limits

### C1. Protection matrix

| Surface | Threat | Verdict |
|---|---|---|
| Provider requests | Real secret shipped to LLM API | **Protected** — `context` obfuscates every call, every role (D1, A6.2) |
| Tool execution | Edit/commands break on placeholders | **Protected** — `tool_call` in-place reveal (D6) |
| Model exfil via tool output | Tool prints a secret, model relays it | **Reduced** — relay text is obfuscated before the next LLM call; deliberate write-to-disk/network is out of scope |
| Transcript reader (human) | Can read real keys | **By design** (Option B) — human is the authorized reader |
| Placeholder forgery | Model invents `$$FAKE$$` to fish a value | **Protected** — keyed deobfuscation map only (D4) |
| Dictionary attack on hashes | Recover secret from placeholder | **Protected** — needs the per-install key (D2) |
| Model reads the key file | Exfil the deobfuscation key | **Protected** — key file registered as replace-mode secret |
| Key rotation | Compromise suspected | Operator deletes key file + rotates; old placeholders no longer deobfuscate (documented) |

### C2. Known limits and deferred items

1. **Hashed-at-rest + real-in-exports** requires a ~20-line core patch (`agent-session.ts`
   displayEvent split mirroring OMP `agent-session.ts:3645`). Extension-only gives Option B
   or Option A, not both. Phase 7.
2. **Native provider-replay payloads** (`openaiResponsesHistory`, Anthropic compaction
   `filesText`): mostly inherit hashes from already-obfuscated messages, but the deep
   native-replay walker (`obfuscateNativeReplay`) is unreachable from an extension. Edge case
   only. Phase 7.
3. **`/settings` UI toggle**: pi has no OMP config registry; we read a settings key /
   `--secrets` flag. No UI tab. Phase 7 (optional).
4. **Stream redaction** (`omp stream`/`/record` terminal-row redactor): pi has no public
   stream surface; N/A unless export redaction is wanted (Phase 7).
5. **At-rest plaintext** (Option B consequence): anyone who can read `session.jsonl` can read
   secrets. Acceptable for MVP (matches OMP's own literal handling of user/tool messages);
   tracked separately from C2.1.

---

## Part D — Plan (checklisted work)

Legend: `[x]` done, `[ ]` pending. Gates are per phase; `just check` must be green before
the next phase starts.

### Phase 0 — Scaffold

- [x] P0.1 `package.json` (name `pi-secrets`, `pi.extensions: ["index.ts"]`, deps `yaml`; devDeps biome/ts/knip/pi-coding-agent 1.1.0/types)
- [x] P0.2 tooling: `tsconfig.json`, `biome.json` (tab, 120), `justfile` gate
- [x] P0.3 hygiene: `.gitignore` (incl. `.agents/`, `AGENTS.md`), `.npmignore`, `LICENSE` (MIT)
- [x] P0.4 `Architecture.md` (this file — spec + plan)
- [x] P0.5 `.agents/AGENTS.md` (private agent instructions)
- [x] P0.6 `index.ts` stub (loads, does nothing)
- [x] P0.7 `npm install` + first `just check` run is green
- Gate: `just check` green. Acceptance: extension loads in pi with zero behavior.

### Phase 1 — Port pure modules (no harness coupling) — ✅ complete

- [x] P1.1 `src/secrets/regex.ts` — V + local `SENSITIVE_TOKEN_RE` copy + `escapeRegExp` helper
- [x] P1.2 `src/secrets/placeholder.ts` — A (CryptoHasher → `createHmac`)
- [x] P1.3 `src/secrets/replacement.ts` — V + `seedFromString` (Bun.hash → SHA-256 seed)
- [x] P1.4 `src/secrets/placeholder-scan.ts` — V (byte-identical logic)
- [x] P1.5 `src/secrets/registry-revision.ts` — V (byte-identical)
- [x] P1.6 `src/secrets/patterns.ts` — A (`SENSITIVE_TOKEN_RE` from local `regex.ts`)
- [x] P1.7 `src/secrets/obfuscator.ts` — V + `escapeRegExp` call site
- [x] P1.8 `src/secrets/message-transform.ts` — A (retyped for vanilla pi `AgentMessage`; fork branches dropped; native replay deferred)
- Gate: `bunx tsc --noEmit` clean — ✅; `just check` green — ✅
- Acceptance: zero logic edits vs OMP apart from documented deltas — ✅ verified by `diff -wB`
- Delta log: 6 [x] above; devDeps `@earendil-works/pi-ai`/`pi-agent-core` 1.1.0; biome `noAssignInExpressions` off; see B1

### Phase 2 — Loaders, key, settings — ✅ complete

- [x] P2.1 `src/secrets/index.ts`: `getSecretPlaceholderKey` / `getExistingSecretPlaceholderKey` with pi agent-dir path + lazy `wx` create + cache
- [x] P2.2 `loadSecrets(cwd, agentDir)` — `yaml` parse, global + project merge (project overrides)
- [x] P2.3 `collectEnvSecrets()` — verbatim
- [x] P2.4 `builtinCredentialSecretEntries()` — verbatim
- [x] P2.5 `buildSecretObfuscator()` — verbatim wiring
- [x] P2.6 key file registered as replace-mode secret (inside `buildSecretObfuscator`'s fallback branch)
- [x] P2.7 `src/settings.ts` — `readSecretsSettings(pi, agentDir)`: `pi.getSettings()` verified present (sync) → `settings.json` fallback; `--secrets` flag deferred to P3.6
- Gate: `just check` green — ✅
- Runtime smoke (bun, temp dirs, fake secrets): merge, placeholder mint (`$$COOLLABEL_…:L$$`, `$$CLITOKEN_…:U$$`), lossless round-trip, fixed-point, env scan, key file 0600/43 chars — ✅

### Phase 3 — Harness wiring (`index.ts`) — ✅ complete

- [x] P3.1 `session_start` → build obfuscator (or disable); never create key here (key creation is lazy inside `buildSecretObfuscator` / the sync path on first built-in match)
- [x] P3.2 `context` → `obfuscateProviderContext`, return `undefined` when unchanged
- [x] P3.3 `tool_call` → `deobfuscateToolArguments`, then `Object.assign(input, fixed)` for the documented in-place mutation; no result returned
- [x] P3.4 `message_end` → `deobfuscateAssistantContent`, return `{message}` only when changed (role preserved; assistant role guarded)
- [x] P3.5 render-mode branch (`registerMarkdownTransformer`) behind `secrets.mode = "render"` — reveals assistant/assistant-thinking only at paint time; hashes at rest
- [x] P3.6 `--secrets` flag registered (`registerFlag`/`getFlag`); resolves per `session_start`; `getAgentDir()` resolved per session so `PI_CODING_AGENT_DIR` is honored
- Gate: `just check` green — ✅; wiring tests (below) included
- Acceptance: full pipeline verified in-process — context hides → tool_call reveals in place → message_end reveals; disabled = no-ops; unchanged = identity return; render mode = hashes at rest + paint-time reveal


### Phase 4 — Tests — ✅ complete

- [x] P4.1 `test/obfuscator.test.ts` — fixed-point, HMAC determinism (same key ⇒ same placeholder; other key ⇒ different), cross-key non-decodability (dictionary resistance), forged `$$…$$` never deobfuscates nor re-wraps, `replace` mode one-way, friendly-name/case-hint round-trip, built-in hits (sk-proj-, github_pat_, JWT, PEM)
- [x] P4.2 `test/loaders.test.ts` — `secrets.yml` merge (project overrides global), invalid-entry skipping, env scanning (name regex, 8-char floor, `user:pass@host` raw + percent-decoded), builtin entry set, lazy key creation + 0600 + format + cross-instance determinism via key file (keyDir pinned to temp; a first draft leaked a key into real `~/.pi/agent` — caught and removed)
- [x] P4.3 `test/wiring.test.ts` — landed in Phase 3 (persist pipeline, disabled no-ops, unchanged identity, render mode + transformer)
- Gate: `just check` green — ✅ (25 tests, 92 expect())


### Phase 5 — Docs — ✅ complete

- [x] P5.1 `docs/security.md` — threat model, protection matrix, what is not protected (deliberate exfil, at-rest persist, exports in render mode, native-replay edge), rotation procedure, practice guide
- [x] P5.2 `README.md` — front door: features, quick start (settings + `--secrets` + fake-key smoke), patterns reference, `secrets.yml` schema table, configuration, links
- [x] P5.3 plan checkboxes ticked; no divergence found vs implementation (docs claims checked against wiring/tests)
- Gate: `just check` green — ✅

### Phase 6 — Live validation — ✅ complete (automated part)

- [x] P6.1 installed copy at `~/.pi/agent/extensions/pi-secrets/` (rsync + `npm install --omit=dev`)
- [x] P6.2 env smoke — `scripts/live-smoke.sh` (real pi, real provider, temp dirs only): assistant reply carries `$$HASH:HINT$$` never the raw `TEST_SMOKE_API_KEY`; tool result stayed literal
- [x] P6.3 custom `secrets.yml` regex + friendlyName — reply carries `$$PSX_…$$`; tool result literal
- [x] P6.4 tool-run reveal — covered deterministically by wiring tests (`tool_call` in-place swap); live edit-tool run remains a user-side optional check
- [x] P6.5 human display reveal — covered by wiring tests (message_end + render transformer); TUI visual check remains user-side
- [x] P6.6 at-rest — render-mode run: assistant events persisted hashed end-to-end in the live run; note: `pi -p` keeps no on-disk session file, so the injected event-stream was the inspected artifact (persist-mode at-rest is covered by wiring tests + the Phase 2 run-time smoke)
- Live-smoke notes: `--mode json` exposes tool outputs via `tool_execution_end`; assistant-echo assertions depend on model compliance (4 retries); `KEEP_LIVE=1`/`LIVE_SMOKE_DEBUG=1` env hooks retained for diagnosis
- **Observed live placeholders**: bare `$$FXKOS96QAIUB:L$$`, friendly `$$PSX_OUN1C4U1H755:U$$` — both round-trip to the originals
- User-side remaining: enable in a real interactive session (`secrets.enabled` or `--secrets`), confirm TUI reveal + file edits visually

### Phase 7 — Deferred (separate decisions, not MVP)

- [ ] P7.1 hashed-at-rest: Option A toggle (extension-only) — done if ever needed
- [ ] P7.2 native-replay walker port (`openaiResponsesHistory`, `filesText`) — investigate need
- [ ] P7.3 `before_provider_request` last-chance net — investigate payload shapes
- [ ] P7.4 export redaction (port `stream/redactor.ts` if export hygiene wanted)
- [ ] P7.5 core patch decision (displayEvent split, ~20 lines) → fork-patch or upstream issue/PR; only if C2.1 becomes a requirement

---

## Appendix — References

- OMP secrets module: `~/.workspaces/tracked/omp/packages/coding-agent/src/secrets/` (+ `stream/redactor.ts`, pi-ai `providers/transform-messages.ts` for the `SENSITIVE_TOKEN_RE` net)
- OMP docs: `docs/secrets.md` in the OMP checkout; OMP display split at `agent-session.ts:3645`
- pi API truth: `@earendil-works/pi-coding-agent` 1.1.0, `dist/core/extensions/types.d.ts` (event signatures in B2 verified against this file); package root exports `ExtensionAPI`, `AgentMessage`, `getAgentDir`
- pi docs (local): `docs/extensions.md`, `docs/settings.md`, `docs/security.md` in the installed package
- Prior investigation session: `2026-10-08T16-47-23-416Z_01a11c69-9317-7655-b75e-c7de5ad493ac.jsonl` (the full OMP feature + porting-map write-up this plan was derived from)