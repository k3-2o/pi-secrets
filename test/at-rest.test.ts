import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { buildSecretObfuscator } from "../src/secrets";
import { redactShapes, scrubJsonValue, scrubString, scrubToolResult } from "../src/secrets/at-rest";
import { SecretObfuscator } from "../src/secrets/obfuscator";
import { readSecretsSettings } from "../src/settings";

const SECRET = "at-rest-secret-1234567890123";

let tmpRoot: string;
let agentDir: string;
let cwd: string;
let obfuscator: SecretObfuscator;

beforeEach(async () => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pi-secrets-at-rest-"));
	agentDir = path.join(tmpRoot, "agent");
	cwd = path.join(tmpRoot, "cwd");
	fs.mkdirSync(agentDir, { recursive: true });
	fs.mkdirSync(cwd, { recursive: true });
	fs.writeFileSync(
		path.join(cwd, "secrets.yml"),
		`- type: plain\n  content: "${SECRET}"\n  mode: obfuscate\n  friendlyName: ATREST\n`,
	);
	process.env.PI_CODING_AGENT_DIR = agentDir;
	obfuscator = await buildSecretObfuscator(cwd, agentDir);
});

afterEach(() => {
	fs.rmSync(tmpRoot, { recursive: true, force: true });
	delete process.env.PI_CODING_AGENT_DIR;
});

describe("at-rest - shape redaction (unknown-shaped spans → bullets)", () => {
	test("assignment with a credential name is bulleted", () => {
		expect(redactShapes('API_KEY="plain-visible-secret-1234"')).toBe('API_KEY="••••••"');
		expect(redactShapes("TOKEN=plain-visible-secret-1234")).toBe("TOKEN=••••••");
		expect(redactShapes("export PASSWORD='hunter2hunter'")).toBe("export PASSWORD='••••••'");
	});

	test("connection-URL password is bulleted", () => {
		expect(redactShapes("curl https://user:supersekret@example.com/x")).toBe("curl https://user:••••••@example.com/x");
	});

	test("non-secret assignments and already-hashed spans survive untouched", () => {
		expect(redactShapes("NAME=folder MAKEFILE=yes CWD=/tmp")).toBe("NAME=folder MAKEFILE=yes CWD=/tmp");
		expect(redactShapes('KEY="$$WIRING_0UX60MSBVKK4:L$$"')).toBe('KEY="$$WIRING_0UX60MSBVKK4:L$$"');
		expect(redactShapes("no secrets at all")).toBe("no secrets at all");
	});

	test("keyword ending a word does not gate: monkey, bypass, whiskey stay raw", () => {
		expect(redactShapes("monkey=e347a175cc0a6526c29654610a3a2add56e1aec4")).toBe(
			"monkey=e347a175cc0a6526c29654610a3a2add56e1aec4",
		);
		expect(redactShapes("bypass=on")).toBe("bypass=on");
		expect(redactShapes("whiskey=bottle")).toBe("whiskey=bottle");
		expect(redactShapes("TURKEY_KEY=slim")).toBe("TURKEY_KEY=slim");
	});

	test("camelCase and underscore-prefixed secret names still gate", () => {
		const value = "q7mZ2xK9pL4vN8cB1T6wY3sH5jF0dG";
		expect(redactShapes(`apiKey=${value}`)).not.toBe(`apiKey=${value}`);
		expect(redactShapes(`userKey=${value}`)).not.toBe(`userKey=${value}`);
		expect(redactShapes(`_pass=${value}`)).not.toBe(`_pass=${value}`);
		expect(redactShapes(`SERPER_API_KEY=${value}`)).not.toBe(`SERPER_API_KEY=${value}`);
	});

	test("below-floor values stay raw even behind a gated name (key=lambda kwargs)", () => {
		expect(redactShapes("results.sort(key=lambda r: r.size)")).toBe("results.sort(key=lambda r: r.size)");
		expect(redactShapes("token_count = 42")).toBe("token_count = 42");
		expect(redactShapes("AUTH_TYPE=none")).toBe("AUTH_TYPE=none");
	});
});

describe("at-rest - scrubString ordering (registered values stay reversible)", () => {
	test("a registered value inside an assignment survives as $$HASH$$, not bullets", () => {
		const out = scrubString(obfuscator, `API_KEY="${SECRET}"`);
		expect(out).not.toContain(SECRET);
		expect(out).toContain("$$");
		expect(out).not.toContain("••••••");
	});

	test("already-hashed text is a byte no-op (fixed point)", () => {
		const once = scrubString(obfuscator, `key=${SECRET}`);
		const twice = scrubString(obfuscator, once);
		expect(twice).toBe(once);
	});
});

describe("at-rest - scrubToolResult composite", () => {
	test("scrubs content + structuredContent + details and returns everything together", () => {
		const out = scrubToolResult(obfuscator, {
			content: [{ type: "text", text: `token ${SECRET}` }],
			structuredContent: { rows: [{ value: SECRET }] },
			details: { token: SECRET },
			nestedCalls: { calls: [{ id: "n1", name: "bash", arguments: { cmd: `echo ${SECRET}` } }], complete: true },
		});
		expect(out).toBeDefined();
		const serialized = JSON.stringify(out);
		expect(serialized).not.toContain(SECRET);
		expect(serialized).toContain("$$");
		expect(JSON.stringify(out?.structuredContent)).toContain("$$");
	});

	test("returns undefined when nothing changed", () => {
		const out = scrubToolResult(obfuscator, {
			content: [{ type: "text", text: "plain output, everything fine" }],
		});
		expect(out).toBeUndefined();
	});

	test("captures unregistered secret-shaped spans the registry never saw (Phase 9)", () => {
		const out = scrubToolResult(obfuscator, {
			content: [{ type: "text", text: 'unregistered leak: API_TOKEN="zz-unregistered-token-999"' }],
		});
		expect(JSON.stringify(out)).not.toContain("zz-unregistered-token-999");
		expect(JSON.stringify(out)).toContain("$$");
		expect(JSON.stringify(out)).not.toContain("••••••");
	});

	test("below-floor assignment values stay raw (same floor as capture)", () => {
		const out = scrubToolResult(obfuscator, {
			content: [{ type: "text", text: "API_TOKEN=short" }],
		});
		expect(out).toBeUndefined();
	});
});

describe("at-rest - JSON walker", () => {
	test("scrubJsonValue walks strings at any depth", () => {
		const out = scrubJsonValue(obfuscator, { a: { b: [`x ${SECRET} y`] }, c: SECRET });
		expect(JSON.stringify(out)).not.toContain(SECRET);
		expect(JSON.stringify(out)).toContain("$$");
	});

	test("scrubJsonValue(undefined) is undefined", () => {
		expect(scrubJsonValue(obfuscator, undefined)).toBeUndefined();
	});
});

describe("config - legacy mode key is ignored (P8.6)", () => {
	test("readSecretsSettings tolerates a leftover secrets.mode and returns enabled only", () => {
		fs.writeFileSync(
			path.join(agentDir, "settings.json"),
			JSON.stringify({ secrets: { enabled: true, mode: "persist" } }),
		);
		const fakePi = {} as never;
		const settings = readSecretsSettings(fakePi, agentDir);
		expect(settings).toEqual({ enabled: true });
		expect("mode" in settings).toBe(false);
	});

	test("legacy 'render' value is tolerated too", () => {
		fs.writeFileSync(
			path.join(agentDir, "settings.json"),
			JSON.stringify({ secrets: { enabled: false, mode: "render" } }),
		);
		const settings = readSecretsSettings({} as never, agentDir);
		expect(settings).toEqual({ enabled: false });
	});
});

describe("phase 11 - code-noise guard", () => {
	test("S1: unquoted values with code punctuation are neither captured nor masked", () => {
		const o = new SecretObfuscator([], "unit-test-key-0123456789abcdef");
		const lines = ["    state.noteRowKey = rowKey(row);", "    const token = createProbeToken();"];
		for (const line of lines) {
			expect(scrubString(o, line)).toBe(line);
			expect(o.isKnown("rowKey(row)")).toBe(false);
			expect(o.isKnown("createProbeToken()")).toBe(false);
		}
	});
});

describe("phase 11 - code-noise guard (cont.)", () => {
	test("S2: unquoted colon values in code-shaped text are not captured", () => {
		const o = new SecretObfuscator([], "unit-test-key-0123456789abcdef");
		const text = [
			'import { createProbeToken } from "./token.ts";',
			"",
			"export class SilentProbe {",
			"  readonly token: ProbeToken;",
			"  private attempt = { started: true, token: createProbeToken(), completion };",
			"};",
			"",
		].join("\n");
		expect(scrubString(o, text)).toBe(text);
		expect(o.isKnown("ProbeToken")).toBe(false);
	});

	test("S2: unquoted colon values in config-shaped text are still captured", () => {
		const o = new SecretObfuscator([], "unit-test-key-0123456789abcdef");
		const out = scrubString(o, "api_token: Zz9plain-YAML-style-value42");
		expect(o.isKnown("Zz9plain-YAML-style-value42")).toBe(true);
		expect(out).not.toContain("Zz9plain-YAML-style-value42");
	});
});

describe("phase 11 - code-noise guard (quoted values)", () => {
	test("S3: quoted identifier-shaped and short values in code are left raw, real keys still captured", () => {
		const o = new SecretObfuscator([], "unit-test-key-0123456789abcdef");
		const text = [
			"export const THEME = {",
			'  "system-prompt": { key: "systemPromptColor", color: "mdHeading" },',
			'  "skills": { key: "skillsColor", color: "customMessageLabel" },',
			"};",
			"",
			'const noteRowKey = "option:0";',
			"",
			'export const API_TOKEN = "Ax9Q2mN4vB8cL1zK7pR3"; // hardcoded, must be caught',
			"",
		].join("\n");
		const out = scrubString(o, text);
		expect(out).not.toContain("Ax9Q2mN4vB8cL1zK7pR3");
		expect(o.isKnown("Ax9Q2mN4vB8cL1zK7pR3")).toBe(true);
		expect(o.isKnown("systemPromptColor")).toBe(false);
		expect(o.isKnown("skillsColor")).toBe(false);
		expect(o.isKnown("option:0")).toBe(false);
		expect(out).toContain("systemPromptColor");
		expect(out).toContain(`"option:0"`);
	});
});

describe("phase 11 - registry eviction", () => {
	test("S4: a previously captured code value is evicted on contrary evidence and heals the line", () => {
		const o = new SecretObfuscator([], "unit-test-key-0123456789abcdef");
		// Simulate the pre-fix poisoning: the raw statement fragment was learned as a "secret".
		expect(o.addPlainSecret("undefined;", "noteRowKey")).toBe(true);
		expect(o.addPlainSecret("adjustment.oauth", "oauth")).toBe(true);
		const line = "    state.noteRowKey = undefined;\n";
		expect(scrubString(o, line)).toBe(line);
		expect(o.isKnown("undefined;")).toBe(false);
		expect(scrubString(o, "    oauth: adjustment.oauth,\n")).toBe("    oauth: adjustment.oauth,\n");
		expect(o.isKnown("adjustment.oauth")).toBe(false);
	});

	test("S4: eviction only touches auto-captured values - configured secrets survive", () => {
		const o = new SecretObfuscator(
			[{ type: "plain", content: "undefined;", mode: "obfuscate" }],
			"unit-test-key-0123456789abcdef",
		);
		// noteRowKey IS a gated name and `undefined;` is the shape-refused raw slice: the eviction scan
		// runs against this exact line - only the auto-capture check may save a configured entry.
		const out = scrubString(o, "    state.noteRowKey = undefined;\n");
		expect(out).toContain("$$");
	});
});
