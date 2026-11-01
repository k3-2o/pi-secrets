# pi-secrets

> A pi extension that keeps real credentials out of the model's context **and out of
> your session files and exports**. API keys and tokens are replaced with reversible
> `$$PLACEHOLDER$$` hashes before every provider call; user and assistant text is stored
> hashed at rest (a paint-time reveal shows you the real values); tool output is scrubbed
> before it is persisted; and HTML/JSONL exports contain only hashes. "Store safe, show real".

## Features

- **The model never receives a real secret.** `context` obfuscates every message before
  every LLM call: user text, tool results, and prior assistant replay (text, thinking,
  tool-call arguments).
- **Files and exports are clean.** `message_end` hashes user and assistant text at rest;
  `tool_result` scrubs tool output (content **and** `structuredContent`); `user_bash`
  scrubs `!`-command output. HTML and JSONL exports derive from the file, so they are
  clean by construction.
- **You still read real values.** Your own messages render with real values at paint time.
  Tool-output blocks show `$$…$$`: pi draws them with the same renderer used for HTML
  exports, so a reveal there would leak into the exported file. 
- **Tools still work on real bytes.** Edits and commands run with real values; the model
  plans against placeholders (`edit old="$$HASH$$"` matches the file).
- **Learn-on-first-sight.** A `KEY=value` line or URL password that is not registered yet
  is captured the first time it appears and hashed like any registered secret, unless the
  value is deterministically a non-secret (dates, paths, wordlists, digits), which is left
  as-is. No `secrets.yml` entry needed.
- **Key-shaped gate, vendor fallback.** A credential-named assignment is redacted only
  when its value looks like a key: vendor prefixes (`sk-…`, `ghp_…`, `AKIA…`), password-like
  strings, UUIDs (unless the name ends in `_ID`), 24+ hex runs, mixed-case alphanumeric
  values, or values with credential characters (`& ! ? ~ % ^ * + # = @`). Templates,
  display strings, filenames, versions,
  dates, and serials stay raw. Vendor shapes are the fallback and hash anywhere, with or
  without a `NAME=`.
- **Span hashes for shape hits.** Password-named values under 8 chars and short URL
  passwords become reversible, span-local `$$HASH$$` placeholders, minted only at the
  detected span and never entered in the global registry.
- **Hash morphing done right.** `$$NAME_HASH:HINT$$` placeholders are HMAC-keyed per
  install: deterministic (provider prompt-cache stable), unforgeable, and undictionaryable
  without your key file.
- **Custom redaction.** Add `secrets.yml` entries for anything the built-ins miss:
  exact strings or regexes, reversible hashes or one-way replacements (table below).
- **Off by default.** No behavior change until `secrets.enabled` (or the `--secrets` flag).

## Quick start

1. Install the extension as a pi package:

   ```bash
   pi install npm:@k3_2o/pi-secrets                # published on npm
   pi install git:github.com/k3-2o/pi-secrets   # straight from the repo
   pi install ./pi-secrets                  # local checkout
   ```

   Try it without installing: `pi -e ./pi-secrets`. Manage installs with
   `pi list`, `pi remove <source>`, and `pi update --extensions`.

2. Enable it in `~/.pi/agent/settings.json`:

   ```json
   { "secrets": { "enabled": true } }
   ```

   or per session with the flag: `pi --secrets`.

3. Smoke test with a fake key:
   ```bash
   TEST_SMOKE_API_KEY=sk-smoke-1234567890abcdef pi
   ```

   Ask the agent to `read` the value of `TEST_SMOKE_API_KEY`. It sees
   `$$SMOKEKEY_…$$`, never the real string. Quote the placeholder back and your
   terminal shows the real key; the session file stores the placeholder.

## What is stored where

| Message class | Session file (`.jsonl`) | Your terminal | HTML / JSONL exports |
|---|---|---|---|
| User text (typed/pasted) | `$$HASH$$` | real (paint reveal) | `$$HASH$$` |
| Assistant text | `$$HASH$$` | real (paint reveal) | `$$HASH$$` |
| Tool call arguments | `$$HASH$$` (the model's own args) | (none) | `$$HASH$$` |
| Tool output | `$$HASH$$` (scrubbed) | `$$HASH$$` | `$$HASH$$` |
| `!`-command output | `$$HASH$$` (scrubbed) | real until recorded, then hashed | `$$HASH$$` |

**Tool-output blocks show `$$…$$` even on your screen:** pi draws them with the same
renderer used for HTML exports, so a reveal there would leak into the exported file.
Everything else you type and read renders with real values.

## Editing files that contain secrets

Two kinds of protection, two edit realities:

**Registered values (`$$HASH$$`) are editable, safely.** The model only ever sees the
placeholder, but pi-secrets restores the real value into tool-call arguments at
execution time. So edit calls that reference a line containing a registered value
keep working (exact old-string matching succeeds after restoration) while the
provider and every persisted artifact only ever saw the hash. This is why built-in
credential *shapes* are hash-routed: edits around known secrets stay lossless.

**Unregistered values** are captured or raw, never silently reusable. When tool output
contains a credential-*named* assignment (`API_KEY=…`) or a connection-URL password,
pi-secrets redacts the value on first sight only when it looks like a key: vendor
prefixes, password-like strings, 24+ hex runs, mixed-case alphanumeric values, or values
with credential characters. Anything else under a secret name stays raw: prose, display
strings, filenames, templates, versions, dates, digit runs, and wordlist values. Key-shaped
values register session-scoped and hash, so they become editable exactly like a registered
value (two-way round-trip). A bare value in prose that matches no name gate and no
vendor shape stays raw. That is the honest boundary; all-caps or dotted runs that look
like neither a key nor a name are best registered in `secrets.yml` or exported as an env
var. Values under the 8-char floor stay raw except where the span net catches a
redaction shape: password-named values and short URL passwords become reversible,
span-local `$$HASH$$`, minted only at the detected span and never registered. The model
edits around those placeholders like registered values, because the tool-call reveal
restores them.

Ways the agent can still touch such a file, honestly:

- **Register the value** with a `secrets.yml` entry, or export it as a
  credential-named env var: normal edits round-trip against the `$$HASH$$`.
- **Whole-line rewrites from the shell**, which never need the old value:
  `sed -i 's/^API_KEY=.*/API_KEY=newvalue/' file`.
- **Side note:** a hashline-based edit tool (replaces by line number from a recent read)
  can rewrite a line without knowing its old content.

## Usage

### Built-in patterns

Credential shapes are matched automatically, in four groups:

- **Git & CI:** GitHub (`ghp_`, `gho_`, `github_pat_`), GitLab (`glpat-`), npm
- **Cloud & AI:** AWS (`AKIA`/`ASIA`), Google (`AIza`), OpenAI (`sk-`, `sk-proj-`, `sk-ant-`), HuggingFace (`hf_`)
- **Payments & comms:** Stripe (`sk_`/`rk_live`/`rk_test`, `whsec_`), SendGrid (`SG.`), Twilio (`SK`+32 hex)
- **More:** Slack (`xox*`), JWTs (`eyJ…`), `Bearer …` tokens, PEM private-key blocks, Shopify (`shpat_`/`shpca_`/`shppa_`), Postman (`PMAK-`), Pulumi (`pul-`), DigitalOcean (`dop_v1_`), Grafana Cloud (`glc_`), Alibaba (`LTAI`)

Environment variables whose names match `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AUTH`,
`CREDENTIAL`, `PRIVATE`, or `OAUTH` are also added at startup (values of 8+ characters,
plus passwords embedded in `scheme://user:password@host` URLs).

### Where secrets are found

At session start, pi-secrets registers values from three sources and obfuscates any
occurrence of them that would otherwise reach the model **or the disk**:

1. Environment variables with credential-shaped names (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AUTH`, …)
2. `secrets.yml` (global + project)
3. Built-in vendor shapes (GitHub, OpenAI, AWS, Google, Slack, Stripe, JWT, PEM, …)

**The boundary:** only *recognized* values are hidden. A bare value in prose that
matches no source and no shape passes through as-is. But a credential-*named*
assignment (`API_KEY=…`) or connection-URL password is **auto-captured on first
sight** and hashed (`$$HASH$$`, reversible) with no `secrets.yml` line needed. To cover
anything else, add a `secrets.yml` entry or export it as a credential-named
environment variable.

### The three nets

| Net | Hardcoded trigger | What it catches |
|---|---|---|
| Auto-capture (learn-on-first-sight) | Credential-*named* assignments (name contains `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `PASS`, `AUTH`, `CREDENTIAL`, `PRIVATE`, or `OAUTH`) and `scheme://user:password@host` URLs | Key-shaped assignment values (vendor prefixes, password-like strings, 24+ hex, mixed-case alnum, credential symbols) are hashed on first sight, session-scoped, reversible; prose-like values, dates, paths, wordlists, digits, and below-floor values stay raw |
| Built-in shapes | Vendor prefixes (`sk-`, `ghp_`, `glpat-`, `AKIA`, `eyJ`, …) | Bare prefixed tokens, anywhere, no assignment needed |
| `secrets.yml` | Your entries | Everything the two automatic nets miss |

**What stays raw:** anything that looks like neither a `KEY=value` line nor a recognized
shape. A bare vendor token in prose, a key under a non-keyword name (`NXOP=…`), or a
JSON field whose name carries no keyword is only hidden if you register it in
`secrets.yml`. URL passwords are the one exception: their shape alone triggers capture.

**Dump formats are read through** (`od -c`, hexdump/xxd, base64); the full boundary is in `docs/explain.md`.

### Custom patterns: `secrets.yml`

Global: `~/.pi/agent/secrets.yml`. Project: `<cwd>/secrets.yml` (project entries
override globals with the same `content`).

See [examples/secrets.yml](examples/secrets.yml) for a full, annotated
example covering every field and mode.

| Field | Values | Meaning |
|---|---|---|
| `type` | `plain` \| `regex` | Exact string vs. pattern match |
| `content` | string | The literal or pattern to hide |
| `mode` | `obfuscate` (default) \| `replace` | Reversible placeholder vs. one-way replacement |
| `replacement` | string | Replace-mode output. Omit to get a deterministic same-length replacement (stable across sessions) |
| `flags` | regex flags, e.g. `"i"` | Only for `regex` entries |
| `friendlyName` | string | Human-readable placeholder prefix, e.g. `$$CLI_TOKEN_…$$` |

### Configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `secrets.enabled` | boolean | `false` | Master switch |
| `--secrets` flag | boolean | unset | Force the feature on/off for a session |

During a session, `/secrets` lists what was auto-captured: labels and count, never values.

The per-install key lives at `~/.pi/agent/secret-placeholder.key` (mode `0600`,
created lazily on the first placeholder mint). Delete it to invalidate old
placeholders. See Rotation in `docs/explain.md`.

## Documentation

- **[docs/explain.md](docs/explain.md): important read**. The threat model, protection matrix, what is not protected, and rotation.

## Contributing

Run `just check` (format, lint, types, tests) and keep it green.

## License

MIT. See [LICENSE](LICENSE).

Inspired by OMP's secret obfuscation design.
