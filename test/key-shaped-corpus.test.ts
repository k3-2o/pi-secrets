import { describe, expect, test } from "bun:test";
import { scrubString } from "../src/secrets/at-rest";
import { builtinCredentialSecretEntries } from "../src/secrets/loaders";
import { SecretObfuscator } from "../src/secrets/obfuscator";

const KEY = "unit-test-key-0123456789abcdef";
const SK = `sk-proj-${"A".repeat(40)}`;
const GHP = `github_pat_11${"A".repeat(36)}`;
const JWT = `eyJ${"A".repeat(30)}.eyJ${"B".repeat(30)}.eyJ${"C".repeat(30)}`;

function obf(seeds: Array<{ content: string; mode?: "obfuscate" | "replace" }> = []): SecretObfuscator {
	return new SecretObfuscator(
		[...builtinCredentialSecretEntries(), ...seeds.map((e) => ({ ...e, mode: e.mode ?? "obfuscate" }) as never)],
		KEY,
	);
}

describe("key-shaped gate corpus - true secrets must redact", () => {
	const rows: string[] = [
		`export API_KEY="${SK}"`,
		`found ${SK} in logs`,
		`AUTH ${SK}`,
		`the token ${GHP} lives here`,
		`TOKEN=${JWT}`,
		"DEPLOY_API_TOKEN=Zz9real-Captured-Secret42",
		"API_KEY=q7mZ2xK9pL4vN8cB1T6wY3sH5jF0dG",
		'API_KEY="123e4567-e89b-12d3-a456-426614174000"',
		"TOKEN=550e8400-e29b-41d4-a716-446655440000",
		"PASSWORD=Tr0ub4dor&3",
		"PASSWORD=hunter2",
		"postgres://app:u8r9PgQwXzA4vB2cD6fH1jK3lM5nO7pQ@db.internal:5432/main",
	];
	for (const line of rows) {
		test(`redacts: ${line.slice(0, 48)}`, () => {
			expect(scrubString(obf(), line)).not.toBe(line);
		});
	}
});

describe("key-shaped gate corpus - non-secrets must stay raw", () => {
	const rows: string[] = [
		"KEY_ID=550e8400-e29b-41d4-a716-446655440000",
		"AUTH_REQUEST_ID=550e8400-e29b-41d4-a716-446655440000",
		'TOKEN="<your-token>"',
		'TOKEN="{apiKey}"',
		'{"key": "Hello World"}',
		'{"token": "GitHub Actions"}',
		'{"key": "README.md"}',
		"TOKEN=v1.2.3-betax",
		"TOKEN=v2026.5.0",
		"TOKEN=2026-4-1",
		"TOKEN=ABCD-EFGH-IJKL-MNOP",
		"TOKEN=2026-04-10T14:22:31Z",
		"TOKEN=1776332221",
		"TOKEN_COUNT=12345678",
		"KEY=abcdefgh",
		"apiKey=x",
		"monkey=e347a175cc0a6526c29654610a3a2add56e1aec4",
		"password_resets_total=1234",
		"PASSWORD=abcd",
		"TOKEN=/home/pi/projects/x",
		"TOKEN=foo/bar/baz",
		"TOKEN=abracadabra-hokus-pocus",
	];
	for (const line of rows) {
		test(`raw: ${line.slice(0, 48)}`, () => {
			expect(scrubString(obf(), line)).toBe(line);
		});
	}
});

describe("key-shaped gate corpus - symbol exception", () => {
	test("symbol-bearing values redact, prose-like punctuation stays raw", () => {
		const o = obf();
		expect(scrubString(o, "TOKEN=p@ssw0rd")).not.toBe("TOKEN=p@ssw0rd");
		expect(scrubString(o, "API_KEY=3x&9#d2q7z1v4")).not.toBe("API_KEY=3x&9#d2q7z1v4");
		expect(scrubString(o, "TOKEN=value.with.dots.1234")).toBe("TOKEN=value.with.dots.1234");
		expect(scrubString(o, "TOKEN=<angle/bracket>")).toBe("TOKEN=<angle/bracket>");
		expect(scrubString(o, '{"key": "README.md"}')).toBe('{"key": "README.md"}');
	});
});

describe("key-shaped gate corpus - documented residuals still redact", () => {
	test("key-shaped display string under a metric-ish name stays redacted", () => {
		expect(scrubString(obf(), "Token_Cache_Hits=CacheValue123")).not.toBe("Token_Cache_Hits=CacheValue123");
	});
	test("URL-branch rows stay redacted (parked asymmetry)", () => {
		expect(scrubString(obf(), "curl https://user:example@example.com/x")).not.toBe(
			"curl https://user:example@example.com/x",
		);
		expect(scrubString(obf(), "mysql://root:root@localhost/db")).not.toBe("mysql://root:root@localhost/db");
		expect(scrubString(obf(), "postgres://app:2026-04-10T14:22:31Z@host.example/db")).not.toBe(
			"postgres://app:2026-04-10T14:22:31Z@host.example/db",
		);
	});
});

describe("key-shaped gate corpus - vendor fallback (tier 2, no name gate)", () => {
	test("vendor shape redacts under a non-secret name", () => {
		expect(scrubString(obf(), `count=${SK}`)).not.toContain("sk-proj-");
	});
	test("vendor shape redacts under a metric name", () => {
		expect(scrubString(obf(), `Token_Cache_Hits=${SK}`)).not.toContain("sk-proj-");
	});
	test("vendor shape redacts inside an attribute-heavy line", () => {
		const line = `api_calls_total{env="prod"}=${SK}`;
		expect(scrubString(obf(), line)).not.toContain("sk-proj-");
	});
	test("vendor shape redacts in bare prose", () => {
		expect(scrubString(obf(), `prose mentions ${SK} and nothing else`)).not.toContain("sk-proj-");
	});
	test("gate tightening cannot weaken the fallback: non-key-shaped prose values stay raw alongside vendor hits", () => {
		const o = obf();
		expect(scrubString(o, `count=hello-world-description ${SK}`)).not.toContain("sk-proj-");
		expect(scrubString(o, "TOKEN=v1.2.3-betax")).toBe("TOKEN=v1.2.3-betax");
	});
});

describe("key-shaped gate corpus - documented coverage gap", () => {
	test("all-caps alnum runs and dotted values stay raw...", () => {
		const allCaps = "TOKEN=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		expect(scrubString(obf(), allCaps)).toBe(allCaps);
		expect(scrubString(obf(), "TOKEN=q1.w2.e3.r4.t5.y6")).toBe("TOKEN=q1.w2.e3.r4.t5.y6");
	});
	test("...and a registered value of the same shape hashes everywhere", () => {
		const o = obf([{ content: "TOPNOTCHCAPSA", mode: "obfuscate" }]);
		expect(scrubString(o, "TOKEN=TOPNOTCHCAPSA")).not.toBe("TOKEN=TOPNOTCHCAPSA");
	});
});
