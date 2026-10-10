import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { buildSecretObfuscator } from "../src/secrets";
import { redactShapes, scrubJsonValue, scrubString, scrubToolResult } from "../src/secrets/at-rest";
import type { SecretObfuscator } from "../src/secrets/obfuscator";
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
		// structuredContent key survives (contract), hashed inside.
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
		expect(JSON.stringify(out)).toContain("$$"); // captured → reversible hash, not bullets
		expect(JSON.stringify(out)).not.toContain("••••••");
	});

	test("below-floor assignment values still bullet (nothing to capture)", () => {
		const out = scrubToolResult(obfuscator, {
			content: [{ type: "text", text: "API_TOKEN=short" }],
		});
		expect(JSON.stringify(out)).toContain("••••••");
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
