# pi-secrets

> A pi extension that keeps real credentials out of the model's context. API keys and tokens are replaced with reversible `$$PLACEHOLDER$$` hashes before every provider call — you still see the real values, tools still work on real bytes, and the model never sees a key. Ported from OMP's secrets feature onto pi's extension events; no pi core changes.

## Features

- **Hides secrets outbound** — env vars, `secrets.yml` patterns, and built-in credential shapes (GitHub, OpenAI, AWS, Google, Slack, Stripe, JWT, PEM blocks, and more) are replaced with keyed placeholders before every LLM call.
- **Reveals to tools** — edits and commands run against the real bytes; the model plans against a placeholder (`edit old="$$HASH$$"` matches the file).
- **Reveals to you** — the real key is rendered in the terminal whenever the model references a placeholder. User-typed text is never rewritten.
- **Hash morphing done right** — `$$WIRING_0UX60MSBVKK4:L$$`-style placeholders are HMAC-keyed per install: deterministic (prompt-cache stable), unforgeable, and undictionaryable without your key file.
- **Custom redaction** — a `secrets.yml` with regex or plain patterns for anything the built-ins miss, including a one-way `replace` mode.
- **Off by default** — no behavior change until `secrets.enabled` (or the `--secrets` flag).

## Quick start

1. Install the extension into pi (as a standalone package or by copying this repo to
   `~/.pi/agent/extensions/pi-secrets/`).
2. Enable it — in `~/.pi/agent/settings.json`:

   ```json
   { "secrets": { "enabled": true } }
   ```

   or per session with the flag: `pi --secrets`.

3. Smoke test with a fake key:

   ```bash
   TEST_SMOKE_API_KEY=sk-smoke-1234567890abcdef pi
   ```

   Ask the agent to `read` the value of `TEST_SMOKE_API_KEY` — it sees
   `$$SMOKEKEY_…$$`, never the real string. Quote the placeholder back and your
   terminal shows the real key.

## Usage

### Built-in patterns

Credential shapes are matched automatically: GitHub (`ghp_`, `gho_`, `github_pat_`),
GitLab (`glpat-`), OpenAI (`sk-`, `sk-proj-`, `sk-ant-`), AWS (`AKIA`/`ASIA`), Google
(`AIza`), Slack (`xox*`), npm, Stripe (`sk_`/`rk_live`/`rk_test`, `whsec_`), HuggingFace
(`hf_`), SendGrid (`SG.`), JWTs (`eyJ…`), `Bearer …` tokens, and PEM private-key blocks.
Environment variables whose names match `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AUTH`,
`CREDENTIAL`, `PRIVATE`, or `OAUTH` are added at startup (values of 8+ characters, plus
passwords embedded in `scheme://user:password@host` URLs).

### Custom patterns — `secrets.yml`

Global: `~/.pi/agent/secrets.yml`. Project: `<cwd>/secrets.yml` (project entries
override globals with the same `content`).

```yaml
# ~/.pi/agent/secrets.yml
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

| Field | Values | Meaning |
|---|---|---|
| `type` | `plain` \| `regex` | Exact string vs. pattern match |
| `content` | string | The literal or pattern to hide |
| `mode` | `obfuscate` (default) \| `replace` | Reversible placeholder vs. one-way replacement |
| `replacement` | string | Required for `replace` mode when you want a fixed marker |
| `flags` | regex flags, e.g. `"i"` | Only for `regex` entries |
| `friendlyName` | string | Human-readable placeholder prefix, e.g. `$$CLI_TOKEN_…$$` |

### Configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `secrets.enabled` | boolean | `false` | Master switch |
| `secrets.mode` | `"persist"` \| `"render"` | `"persist"` | Real values in the session file (`persist`) vs. hashes at rest with paint-time reveal (`render`) |
| `--secrets` flag | boolean | unset | Force the feature on/off for a session |

The per-install key lives at `~/.pi/agent/secret-placeholder.key` (mode `0600`,
created lazily on the first placeholder mint). Delete it to invalidate old
placeholders — see Rotation in `docs/security.md`.

## Documentation

- [docs/security.md](docs/security.md) — threat model, protection matrix, what is not protected, rotation.
- [Architecture.md](Architecture.md) — the full spec: design decisions, module map, port deltas, checklisted plan.

## Contributing

The gate is `just check` (format, lint, types, tests) and must stay green. Tests live
in `test/` and assert real behavior — no test theater. Architecture.md is the
binding spec; ported modules came from OMP (`~/.workspaces/tracked/omp/.../secrets/`)
and keep the smallest possible delta.

## License

MIT — see [LICENSE](LICENSE).