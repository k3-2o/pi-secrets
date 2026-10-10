
BIOME := "bunx biome"
KNIP := "bunx knip"

fmt:
	{{BIOME}} format --write .

lint:
	{{BIOME}} check .
	{{KNIP}}

types:
	bunx tsc --noEmit

test:
	bun test

check: fmt lint types test
