# pi-secrets — reversible credential obfuscation for pi, ported from OMP.
# Gate: `just check` = fmt -> lint -> types -> test.

BIOME := "bunx biome"
KNIP := "bunx knip"

# ── format ────────────────────────────────────────────────────────────────
fmt:
	{{BIOME}} format --write .

# ── lint (biome) + dead-code (knip) ───────────────────────────────────────
lint:
	{{BIOME}} check .
	{{KNIP}}

# ── typecheck ─────────────────────────────────────────────────────────────
types:
	bunx tsc --noEmit

test:
	bun test

check: fmt lint types test