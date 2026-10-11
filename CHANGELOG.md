# Changelog

## 0.2.1 — 2026-10-11

- Fold dump-view leaks: space-folded (`od -c`), hex-pair (`xxd`/`hexdump`), base64-folded, char-per-line hex, and address-suppressed hexdumps are folded back to contiguous text before detection.
- Fixed xxd 4-char hex groups leaking (groups were wider than the fold window).
- Bash streaming scrub is buffer-safe: secrets spanning chunk boundaries are held and scrubbed whole; PEM blocks held until `-----END`.
- Secret-name gate is word-boundary matched: `monkey=`, `bypass=`, `whiskey=` no longer trigger; `API_KEY=`, `apiKey=`, `SECRET_KEY=` still do.
- One-way bullets share the 8-char capture floor: `key=lambda` and other short values stay raw instead of being bullet-redacted.
- Invalid secrets config fails closed with a startup error instead of running unprotected.
- When obfuscation is active, the system prompt notes that `$$…$$`/`••••••` placeholders are the scrubber, so the agent doesn't misread them as corruption.
