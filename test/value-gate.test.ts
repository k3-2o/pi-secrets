import { describe, expect, test } from "bun:test";
import { redactShapes, scrubString } from "../src/secrets/at-rest";
import { SecretObfuscator } from "../src/secrets/obfuscator";
import { classifyValueShape, type ValueShape, valueRedactionVerdict } from "../src/secrets/value-gate";

describe("classifyValueShape", () => {
	const cases: Array<[string, ValueShape]> = [
		["2026-04-10T14:22:31Z", "iso-datetime"],
		["2026-04-10", "iso-datetime"],
		["20260410T142231Z", "iso-datetime"],
		["1776332221", "unix-seconds"],
		["1776332221000", "unix-ms"],
		["1.2.3", "version"],
		["2026.5.0-rc1", "version"],
		["550e8400e29b41d4a716446655440000", "uuid"],
		["550e8400-e29b-41d4-a716-446655440000", "uuid"],
		["deadbeefdeadbeefdeadbeefdeadbeef", "uuid"],
		["abababababababababababababababababababab", "hex-digest"],
		["/home/pi/projects/x", "path"],
		["~/config/app.yml", "path"],
		["./secrets.yml", "path"],
		["foo/bar/baz", "path"],
		["abracadabra-hokus-pocus", "wordlist"],
		["config_default", "wordlist"],
		["abcdefgh", "lowercase-word"],
		["ABCDEFGH", "uppercase-word"],
		["12345678", "digits"],
		["Tr0ub4dor&3", "passwordish"],
		["aZ9xQ2mN4vB8cL1", "mixed-alnum"],
		["ghp_abcDEFghiJKLmnoPQRstuVWXyz0123456789", "vendor-key"],
		["sk-test-abcdefghijk222233334444", "vendor-key"],
		["AKIAIOSFODNN7EXAMPLE", "vendor-key"],
		["oauth2-bearer", "scheme"],
		["bearer", "scheme"],
		["hunter2", "other"],
		["abc123", "other"],
		["", "empty"],
	];
	for (const [value, shape] of cases) {
		test(`${JSON.stringify(value)} -> ${shape}`, () => {
			expect(classifyValueShape(value)).toBe(shape);
		});
	}
});

describe("valueRedactionVerdict", () => {
	test("non-secret shapes beat strong names", () => {
		expect(valueRedactionVerdict("TOKEN", "2026-04-10T14:22:31Z")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "1776332221")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "1.2.3")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "550e8400e29b41d4a716446655440000")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "deadbeefdeadbeefdeadbeefdeadbeef")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "/home/pi/projects/x")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "abracadabra-hokus-pocus")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN_COUNT", "12345678")).toBe("keep");
		expect(valueRedactionVerdict("secret", "config_default")).toBe("keep");
		expect(valueRedactionVerdict("KEY", "abcdefgh")).toBe("keep");
		expect(valueRedactionVerdict("AUTH_TYPE", "oauth2-bearer")).toBe("keep");
	});

	test("credential shapes mask under secret names", () => {
		expect(valueRedactionVerdict("TOKEN", "ghp_abcDEFghiJKLmnoPQRstuVWXyz0123456789")).toBe("mask");
		expect(valueRedactionVerdict("TOKEN", "sk-test-abcdefghijk222233334444")).toBe("mask");
		expect(valueRedactionVerdict("TOKEN", "aZ9xQ2mN4vB8cL1")).toBe("mask");
		expect(valueRedactionVerdict("PASSWORD", "Tr0ub4dor&3")).toBe("mask");
	});

	test("password-named fields override the floor for ambiguous shapes", () => {
		expect(valueRedactionVerdict("PASSWORD", "hunter2")).toBe("mask");
		expect(valueRedactionVerdict("PASSWORD", "abc123")).toBe("mask");
		expect(valueRedactionVerdict("DB_PASSWORD", "hunter2")).toBe("mask");
		expect(valueRedactionVerdict("PASSWD", "hunter2")).toBe("mask");
	});

	test("floor applies to neutral shapes under non-password names", () => {
		expect(valueRedactionVerdict("TOKEN", "abc123")).toBe("keep");
		expect(valueRedactionVerdict("TOKEN", "aBcDeFgH")).toBe("mask");
		expect(valueRedactionVerdict("TOKEN", "sk-1", 8)).toBe("keep");
	});
});

describe("integration with the at-rest pipeline", () => {
	test("time-, path- and word-shaped values under secret names stay raw", () => {
		expect(redactShapes("TOKEN=2026-04-10T14:22:31Z")).toBe("TOKEN=2026-04-10T14:22:31Z");
		expect(redactShapes("TOKEN=1776332221")).toBe("TOKEN=1776332221");
		expect(redactShapes("KEY=abcdefgh")).toBe("KEY=abcdefgh");
		expect(redactShapes("TOKEN_COUNT=12345678")).toBe("TOKEN_COUNT=12345678");
		expect(redactShapes("TOKEN=/home/pi/projects/x")).toBe("TOKEN=/home/pi/projects/x");
		expect(redactShapes("TOKEN=abracadabra-hokus-pocus")).toBe("TOKEN=abracadabra-hokus-pocus");
	});

	test("vendor keys and password-like values still bullet", () => {
		expect(redactShapes("TOKEN=ghp_abcDEFghiJKLmnoPQRstuVWXyz0123456789")).toBe("TOKEN=••••••");
		expect(redactShapes("PASSWORD=hunter2")).toBe("PASSWORD=••••••");
		expect(redactShapes("PASSWORD=Tr0ub4dor&3")).toBe("PASSWORD=••••••");
		expect(redactShapes("TOKEN=aZ9xQ2mN4vB8cL1")).toBe("TOKEN=••••••");
	});

	test("vetoed values are never captured, so later forms stay raw", () => {
		const o = new SecretObfuscator([], "value-gate-test-key-0123456789");
		const input = "TOKEN=2026-04-10T14:22:31Z and again TOKEN=2026-04-10T14:22:31Z";
		expect(scrubString(o, input)).toBe(input);
		expect(o.isKnown("2026-04-10T14:22:31Z")).toBe(false);
		expect(o.hasSecrets()).toBe(false);
	});

	test("neutral shapes are still captured on first contact", () => {
		const o = new SecretObfuscator([], "value-gate-test-key-0123456789");
		const out = scrubString(o, "API_KEY=q7mZ2xK9pL4vN8cB1T6wY3sH5jF0dG");
		expect(out).not.toContain("q7mZ2xK9pL4vN8cB1T6wY3sH5jF0dG");
		expect(o.isKnown("q7mZ2xK9pL4vN8cB1T6wY3sH5jF0dG")).toBe(true);
	});

	test("hex values stay raw: 32-char (uuid path) and 40-char (hex branch)", () => {
		const o = new SecretObfuscator([], "value-gate-test-key-0123456789");
		const short = "deadbeefdeadbeefdeadbeefdeadbeef";
		const long = "abababababababababababababababababababab";
		expect(scrubString(o, `SERPER_API_KEY=${short}`)).toBe(`SERPER_API_KEY=${short}`);
		expect(scrubString(o, `SERPER_API_KEY=${long}`)).toBe(`SERPER_API_KEY=${long}`);
		expect(o.isKnown(short)).toBe(false);
		expect(o.isKnown(long)).toBe(false);
	});
});
