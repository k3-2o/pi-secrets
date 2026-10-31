# Changelog

## 0.4.1 — 2026-11-01

- Quoted credential values containing spaces, like `KEY="a b c"`, are captured and masked instead of passing through raw.
- `od -c` control tokens (`\n`, `\t`, `\r`) fold to the real control characters, so a secret split across a control token no longer escapes detection.
- Secrets longer than 1 KiB in streaming shell output (JWTs, URLs, user-regex matches) are held to the line end and scrubbed whole instead of leaking in fragments.
- `xxd` dump folding no longer re-decodes the ASCII column as hex, applies overlapping dump regions shift-correctly, and no longer glues following lines onto the placeholder.
- URL passwords containing `@` are masked whole instead of truncated at the first `@`.
- A timed-out `user_bash` exec still delivers its buffered output tail instead of dropping the last bytes.

## 0.4.0 — 2026-10-25

- Auto-capture no longer registers source-code values as secrets.
- Wrong captures are unlearned when re-encountered as code.
- Add /secrets command: shows what the session learned.

## 0.3.1 — 2026-10-24

- Security fix: bare hex values (24+ hex chars) under credential-named assignments are hashed and captured again, closing a leak where an unregistered key pasted as `SERPER_API_KEY=<hex>` stayed raw in tool output. The hex veto now applies only to hyphenated UUIDs.

## 0.3.0 — 2026-10-22

- Value gate: credential-named assignments with non-secret-shaped values (dates, times, versions, UUIDs, hex, paths, wordlists, digits, auth schemes) are left raw and never auto-captured.
- `PASSWORD`/`PASSWD`/`PASS` fields ignore the 8-char floor for ambiguous short values, so `PASSWORD=hunter2` is hashed.
- Dump views (`xxd`/`od`/base64) still capture hex-shaped values; only plain text keeps the veto.

## 0.2.1 — 2026-10-11

- Fold dump-view leaks: space-folded (`od -c`), hex-pair (`xxd`/`hexdump`), base64-folded, char-per-line hex, and address-suppressed hexdumps are folded back to contiguous text before detection.
- Fixed xxd 4-char hex groups leaking (groups were wider than the fold window).
- Bash streaming scrub is buffer-safe: secrets spanning chunk boundaries are held and scrubbed whole; PEM blocks held until `-----END`.
- Secret-name gate is word-boundary matched: `monkey=`, `bypass=`, `whiskey=` no longer trigger; `API_KEY=`, `apiKey=`, `SECRET_KEY=` still do.
- One-way bullets share the 8-char capture floor: `key=lambda` and other short values stay raw instead of being bullet-redacted.
- Invalid secrets config fails closed with a startup error instead of running unprotected.
- When obfuscation is active, the system prompt notes that `$$…$$`/`••••••` placeholders are the scrubber, so the agent doesn't misread them as corruption.
