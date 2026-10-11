import { describe, expect, test } from "bun:test";
import { scrubString } from "../src/secrets/at-rest";
import { SecretObfuscator } from "../src/secrets/obfuscator";

const KEY = "probe-key-0123456789abcdef";

function obf(entries: { content: string; mode?: "obfuscate" | "replace" }[] = []): SecretObfuscator {
	return new SecretObfuscator(
		entries.map((e) => ({ ...e, mode: e.mode ?? "obfuscate" }) as never),
		KEY,
	);
}

describe("phase 10 - dump-format decode views", () => {
	test("od -c of a credential line is captured and hashed", () => {
		const o = obf();
		const dump =
			"0000000   A   P   I   _   K   E   Y   =   h   y   i   -   t   e   s   t\n" +
			"0000020   -   1   2   3   4   5   6   7   8   9   0  \\n\n0000033";
		const out = scrubString(o, dump);
		expect(out).not.toContain("hyi-test-1234567890");
		expect(out).toContain("$$");
	});

	test("od -c value is captured into the registry, so plain later appearance hashes", () => {
		const o = obf();
		const dump =
			"0000000   R   E   G   _   K   E   Y   =   s   e   c   r   e   t   -   1\n0000020   2   3   4   5   6   7   8   9   0   1   2   3   4   5   6\n0000037";
		scrubString(o, dump);
		expect(o.isKnown("secret-1234567890123456")).toBe(true);
		expect(scrubString(o, "REG_KEY=secret-1234567890123456")).toContain("$$");
	});

	test("hexdump (xxd-style) of a known secret is caught", () => {
		const o = obf([{ content: "my-hex-secret-abcdef123456" }]);
		// my-hex-secret-abcdef123456 as hex pairs
		const hex = Array.from("my-hex-secret-abcdef123456")
			.map((c) => c.charCodeAt(0).toString(16))
			.join(" ");
		const out = scrubString(o, `prefix ${hex} suffix`);
		expect(out).not.toContain("my-hex-secret-abcdef123456");
		expect(out).toContain("$$");
	});

	test("base64 of a known secret is caught (exact match only)", () => {
		const o = obf([{ content: "b64sec-this-is-a-real-1" }]);
		const b64 = Buffer.from("b64sec-this-is-a-real-1").toString("base64");
		const out = scrubString(o, `token=${b64}`);
		expect(out).not.toContain("b64sec-this-is-a-real-1");
		expect(out).toContain("$$");
	});

	test("base64 of a NON-known blob is left alone", () => {
		const o = obf();
		const b64 = Buffer.from("not-a-secret-just-random".repeat(2)).toString("base64");
		const out = scrubString(o, b64);
		expect(out).toContain(b64); // untouched
	});

	test("hex MAC address does not false positive", () => {
		const o = obf([{ content: "00:11:22:33:44:55" }]);
		const macHex = "00 11 22 33 44 55";
		const out = scrubString(o, `mac=${macHex}`);
		expect(out).toContain(macHex);
	});

	test("prose with spaced words is not mangled", () => {
		const o = obf();
		const prose = "o n e  t w o  t h r e e"; // od-like but not a dump (no addresses)
		expect(scrubString(o, prose)).toBe(prose);
	});

	test("fixed point: re-scrubbing a dump already hashed is stable", () => {
		const o = obf();
		const dump =
			"0000000   A   P   I   _   K   E   Y   =   a   b   c   d   e   f   g   h\n0000020   i   j   k   l   m   n   o   p   q   r   s   t   u   v   w\n0000037";
		const once = scrubString(o, dump);
		const twice = scrubString(o, once);
		expect(twice).toBe(once);
	});
});
