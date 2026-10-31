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
	test("xxd ascii column of an unknown credential-named assignment folds (capture path)", () => {
		const o = obf();
		const xxd =
			"00000000: 6578 706f 7274 2053 4552 5045 525f 4150  export SERPER_AP\n" +
			'00000010: 495f 4b45 593d 2265 3334 3761 3137 3563  I_KEY="e347a175c\n' +
			"00000020: 6330 6136 3532 3663 3239 3635 3436 3130  c0a6526c29654610\n" +
			'00000030: 6133 6132 6164 6435 3665 3161 6563 3422  a3a2add56e1aec4"\n' +
			"00000040: 0a                                            .\n";
		const out = scrubString(o, xxd);
		expect(out).not.toContain("e347a175cc0a6526c29654610a3a2add56e1aec4");
		expect(out).toContain("$$");
	});

	test("plain hex assignments hash and folded dumps still capture", () => {
		const o = obf();
		const secret = "a3f9c4d8b2e6a1f7c9d4e8b2a6f1c3d9e7b4a8f2";
		expect(scrubString(o, `SERPER_API_KEY=${secret}`)).not.toBe(`SERPER_API_KEY=${secret}`);
		expect(o.isKnown(secret)).toBe(true);
		const line = `TOKEN=${secret}`;
		const hex = [...line].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
		const out = scrubString(o, hex);
		expect(out).not.toContain(secret);
		expect([...out].filter((c) => c === "$").length).toBeGreaterThanOrEqual(2);
	});

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
		expect(out).toContain(b64);
	});

	test("hex MAC address does not false positive", () => {
		const o = obf([{ content: "00:11:22:33:44:55" }]);
		const macHex = "00 11 22 33 44 55";
		const out = scrubString(o, `mac=${macHex}`);
		expect(out).toContain(macHex);
	});

	test("prose with spaced words is not mangled", () => {
		const o = obf();
		const prose = "o n e  t w o  t h r e e";
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
describe("phase 10 - od -c control tokens fold to real control chars", () => {
	// Build an od -c shaped dump: 7-digit octal address + 3 spaces, tokens 3-space
	// separated, control characters rendered as their two-char backslash tokens.
	function odC(data: string): string {
		const tok = [...data].map((c) =>
			c === "\n" ? "\\n" : c === "\t" ? "\\t" : c === "\r" ? "\\r" : c === " " ? "sp" : c,
		);
		const rows: string[] = [];
		for (let i = 0; i < tok.length; i += 16) {
			rows.push(`${i.toString(8).padStart(7, "0")}   ${tok.slice(i, i + 16).join("   ")}`);
		}
		if (tok.length > 0) rows.push(tok.length.toString(8).padStart(7, "0"));
		return rows.join("\n");
	}

	test("a newline-bearing secret folds to its real bytes and hashes when dumped", () => {
		const secret = "ab\ncd ef"; // 8 chars, over the floor
		expect(secret.length).toBe(8);
		const o = obf([{ content: secret }]);
		const dump = odC(secret);
		const out = scrubString(o, dump);
		// Letter-injection would fold to "abncd ef", which never matches, and the
		// dump would pass raw. Real control folding reconstructs the exact value.
		expect(out).not.toContain(secret);
		expect(out).toContain("$$");
	});

	test("a tab-bearing secret folds and captures as a plain registered value", () => {
		const secret = "ab\tcd ef";
		const o = obf([{ content: secret }]);
		const dump = odC(secret);
		const out = scrubString(o, dump);
		expect(out).not.toContain(secret);
		expect(out).toContain("$$");
	});

	test("control tokens in a secret-free dump leave the output byte-identical", () => {
		const o = obf();
		const dump = odC("a\nb\nc\n");
		const before = scrubString(o, "plain prose"); // warm nothing
		void before;
		expect(scrubString(o, dump)).toBe(dump);
	});
});

describe("session-proven dump shapes", () => {
	const VAL = "x1234567890x1234567890x1234567890";
	test("char-per-line [x] NN loop (turn-25 shape) folds to a hash", () => {
		const o = obf();
		const body = `SERPER_API_KEY="${VAL}"`;
		const dump = [...body].map((c) => `  [${c}] ${c.charCodeAt(0).toString(16).toUpperCase()}`).join("\n");
		const out = scrubString(o, dump);
		expect(out.includes(VAL)).toBe(false);
		expect([...out].filter((c) => c === "$").length).toBeGreaterThanOrEqual(2);
	});
	test("address-suppressed od hexdump (turn-27 shape) folds to a hash", () => {
		const o = obf();
		const src = `export TEST_KEY="${VAL}"`;
		const hex = [...src].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"));
		let od = "";
		for (let i = 0; i < hex.length; i += 8) {
			const row = hex.slice(i, i + 8);
			od += `${row.join(" ")}   ${row.map((h) => String.fromCharCode(parseInt(h, 16))).join("")}\n`;
		}
		const out = scrubString(o, od);
		expect(out.includes(VAL)).toBe(false);
		expect([...out].filter((c) => c === "$").length).toBeGreaterThanOrEqual(2);
	});
	test("prose with inline [a] 61 stays untouched", () => {
		const o = obf();
		const prose = "some [a] 61 and [b] 62 words here";
		expect(scrubString(o, prose)).toBe(prose);
	});
});
