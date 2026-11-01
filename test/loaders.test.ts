import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	buildSecretObfuscator,
	builtinCredentialSecretEntries,
	collectEnvSecrets,
	getExistingSecretPlaceholderKey,
	getSecretPlaceholderKey,
	loadSecrets,
} from "../src/secrets/loaders";

const SECRET_NAME_RE = /(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(?:_|$)/i;

function scrubSecretEnv(): Array<[string, string | undefined]> {
	const saved: Array<[string, string | undefined]> = [];
	for (const name of Object.keys(process.env)) {
		if (SECRET_NAME_RE.test(name)) {
			saved.push([name, process.env[name]]);
			delete process.env[name];
		}
	}
	return saved;
}

function restoreEnv(saved: Array<[string, string | undefined]>): void {
	for (const [name, value] of saved) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
}

let tmpRoot: string;
let agentDir: string;
let cwd: string;

beforeEach(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pi-secrets-loaders-"));
	agentDir = path.join(tmpRoot, "agent");
	cwd = path.join(tmpRoot, "cwd");
	fs.mkdirSync(agentDir, { recursive: true });
	fs.mkdirSync(cwd, { recursive: true });
});

afterEach(() => {
	fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe("loadSecrets - secrets.yml merge", () => {
	test("global + project merge; project overrides global on equal content", async () => {
		fs.writeFileSync(
			path.join(agentDir, "secrets.yml"),
			[
				{ type: "plain", content: "shared-secret-abc", mode: "obfuscate", friendlyName: "GLOBAL_ONLY" },
				{ type: "plain", content: "override-me-123", mode: "obfuscate", friendlyName: "GLOBAL" },
			]
				.map(
					(e) => `- type: ${e.type}\n  content: "${e.content}"\n  mode: ${e.mode}\n  friendlyName: ${e.friendlyName}`,
				)
				.join("\n"),
		);
		fs.writeFileSync(
			path.join(cwd, "secrets.yml"),
			`- type: plain\n  content: "override-me-123"\n  mode: replace\n  replacement: "[GONE]"\n  friendlyName: PROJECT\n`,
		);

		const entries = await loadSecrets(cwd, agentDir);
		expect(entries).toHaveLength(2);
		const overridden = entries.find((e) => e.content === "override-me-123");
		expect(overridden?.mode).toBe("replace");
		expect(overridden?.replacement).toBe("[GONE]");
		expect(entries.some((e) => e.content === "shared-secret-abc")).toBe(true);
	});

	test("no files → empty list", async () => {
		expect(await loadSecrets(cwd, agentDir)).toEqual([]);
	});

	test("unparseable YAML fails closed (throws, never silent [])", async () => {
		fs.writeFileSync(path.join(agentDir, "secrets.yml"), "::: not yaml [[[");
		await expect(loadSecrets(cwd, agentDir)).rejects.toThrow();
	});

	test("scalar root (not an array) fails closed", async () => {
		fs.writeFileSync(path.join(agentDir, "secrets.yml"), "just-a-string");
		await expect(loadSecrets(cwd, agentDir)).rejects.toThrow();
	});

	test("invalid entries are skipped with warnings, valid ones load", async () => {
		fs.writeFileSync(
			path.join(agentDir, "secrets.yml"),
			[
				"- type: nope\n  content: x",
				'- type: plain\n  content: ""',
				"- type: regex\n  content: '[unclosed'",
				'- type: plain\n  content: "valid-secret-456"\n  friendlyName: OKAY',
			].join("\n"),
		);
		const entries = await loadSecrets(cwd, agentDir);
		expect(entries).toHaveLength(1);
		expect(entries[0].content).toBe("valid-secret-456");
		expect(entries[0].friendlyName).toBe("OKAY");
		expect(entries[0].mode).toBe("obfuscate");
	});
});

describe("collectEnvSecrets", () => {
	test("name pattern + 8-char floor", () => {
		try {
			process.env.PSTEST_API_KEY = "abcdefghijklmnop123";
			process.env.PSTEST_TOKEN_VAL = "shrt";
			process.env.PSTEST_BLAND_PATH = "x".repeat(200);
			const entries = collectEnvSecrets();
			expect(entries.some((e) => e.content === "abcdefghijklmnop123")).toBe(true);
			expect(entries.some((e) => e.content === "shrt")).toBe(false);
			expect(entries.some((e) => e.content === "x".repeat(200))).toBe(false);
		} finally {
			delete process.env.PSTEST_API_KEY;
			delete process.env.PSTEST_TOKEN_VAL;
			delete process.env.PSTEST_BLAND_PATH;
		}
	});

	test("connection-URL passwords extracted (raw + percent-decoded), name-independent", () => {
		try {
			process.env.PSTEST_DATABASE_URL = "postgres://user:supersecretPass123@host:5432/db";
			process.env.PSTEST_WEIRD_URL = "redis://u:p%40ss%20word789@host:6379";
			const entries = collectEnvSecrets();
			expect(entries.some((e) => e.content === "supersecretPass123")).toBe(true);
			expect(entries.some((e) => e.content === "p@ss word789")).toBe(true);
		} finally {
			delete process.env.PSTEST_DATABASE_URL;
			delete process.env.PSTEST_WEIRD_URL;
		}
	});
});

describe("env declaration trust", () => {
	const withEnv = <T>(vars: Array<[string, string]>, run: () => T): T => {
		const saved = new Map<string, string | undefined>();
		try {
			for (const [k, v] of vars) {
				saved.set(k, process.env[k]);
				process.env[k] = v;
			}
			return run();
		} finally {
			for (const [k, v] of saved) {
				if (v === undefined) delete process.env[k];
				else process.env[k] = v;
			}
		}
	};
	test("credential-named values register regardless of shape", () => {
		const vars: Array<[string, string]> = [
			["PSTEST_TOKEN_COUNT", "12345678"],
			["PSTEST_PASSWORD", "password"],
			["PSTEST_SECRET", "changeme"],
			["PSTEST_API_KEY", `sk-proj-${"A".repeat(40)}`],
			["PSTEST_UUID_KEY", "123e4567-e89b-12d3-a456-426614174000"],
		];
		withEnv(vars, () => {
			const contents = collectEnvSecrets().map((e) => e.content);
			for (const [, v] of vars) expect(contents).toContain(v);
		});
	});
	test("URL passwords in env values register regardless of shape", () => {
		withEnv([["PSTEST_DB_URL", "postgres://app:password123@host/db"]], () => {
			expect(collectEnvSecrets().map((e) => e.content)).toContain("password123");
		});
	});
});

describe("builtinCredentialSecretEntries", () => {
	test("covers the vendored pattern set as regex obfuscate entries", () => {
		const entries = builtinCredentialSecretEntries();
		expect(entries.length).toBeGreaterThan(10);
		const names = entries.map((e) => e.friendlyName);
		for (const expected of ["Credential", "AWSAccessKey", "GoogleAPIKey", "StripeKey", "JWT", "PrivateKey"]) {
			expect(names).toContain(expected);
		}
		for (const entry of entries) {
			expect(entry.type).toBe("regex");
			expect(entry.mode).toBe("obfuscate");
		}
	});
});

describe("placeholder key lifecycle", () => {
	test("key created lazily for builtin-only sessions; valid format, 0600, cached", async () => {
		const saved = scrubSecretEnv();
		try {
			const keyPath = path.join(agentDir, "secret-placeholder.key");

			const o = await buildSecretObfuscator(cwd, agentDir, agentDir);
			expect(fs.existsSync(keyPath)).toBe(false);

			const hidden = o?.obfuscate(`lazy ghp_${"c".repeat(40)} mint`);
			expect(hidden).toContain("$$");
			expect(fs.existsSync(keyPath)).toBe(true);
			expect(fs.statSync(keyPath).mode & 0o777).toBe(0o600);

			const key = await getSecretPlaceholderKey(agentDir);
			expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);

			const o2 = await buildSecretObfuscator(cwd, agentDir, agentDir);
			const hidden2 = o2?.obfuscate(`lazy ghp_${"c".repeat(40)} mint`);
			expect(hidden2).toBe(hidden);
		} finally {
			restoreEnv(saved);
		}
	});

	test("corrupt key file is reported as corrupt, not collapsed to missing (E2)", async () => {
		const saved2 = scrubSecretEnv();
		try {
			const keyPath = path.join(agentDir, "secret-placeholder.key");
			fs.writeFileSync(keyPath, "not-a-valid-key!!!");
			const result = await getExistingSecretPlaceholderKey(agentDir);
			expect(result.key).toBeUndefined();
			expect(result.corrupt).toBeInstanceOf(Error);
			await expect(buildSecretObfuscator(cwd, agentDir, agentDir)).rejects.toThrow(/corrupt/);
		} finally {
			restoreEnv(saved2);
		}
	});
});
