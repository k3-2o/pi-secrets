import { describe, expect, test } from "bun:test";
import { hashShapes, scrubString, scrubToolResult } from "../src/secrets/at-rest";
import { deobfuscateToolArguments } from "../src/secrets/message-transform";
import { SecretObfuscator } from "../src/secrets/obfuscator";
import { createStreamScrubber } from "../src/secrets/stream-scrub";

const KEY = "unit-test-key-0123456789abcdef";
const FLOOR_HASH = /PASSWORD=\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$/;

function obf(): SecretObfuscator {
	return new SecretObfuscator([], KEY);
}

describe("hash-only at-rest - assignment spans", () => {
	test("password-named values under the capture floor become placeholders", () => {
		for (const value of ["abc", "abc123", "hunter2"]) {
			const out = hashShapes(obf(), `PASSWORD=${value}`);
			expect(out).toMatch(FLOOR_HASH);
			expect(out).not.toContain(value);
			expect(out).not.toContain("••••••");
		}
	});

	test("single-character password value becomes a placeholder", () => {
		const out = hashShapes(obf(), "PASSWORD=x");
		expect(out).toMatch(FLOOR_HASH);
		expect(out).not.toContain("••••••");
	});

	test("quoted password values keep their quotes", () => {
		expect(hashShapes(obf(), "export PASSWORD='hunter2'")).toMatch(
			/export PASSWORD='\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$'/,
		);
		expect(hashShapes(obf(), 'PASSWORD="hunter2"')).toMatch(/PASSWORD="\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$"/);
		expect(hashShapes(obf(), '{"PASSWORD":"hunter2"}')).toMatch(
			/\{"PASSWORD":"\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$"\}/,
		);
	});

	test("a value containing $$ stays raw", () => {
		const out = hashShapes(obf(), "PASSWORD=pa$$word");
		expect(out).toBe("PASSWORD=pa$$word");
		expect(out).not.toContain("••••••");
	});

	test("a raw $$ value does not block a later span", () => {
		const out = hashShapes(obf(), "PASSWORD=pa$$word and PASSWORD=hunter2");
		expect(out).toContain("PASSWORD=pa$$word");
		expect(out).toMatch(/ and PASSWORD=\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$$/);
	});

	test("legacy bullet value is left untouched", () => {
		const o = obf();
		const out = scrubString(o, "PASSWORD=••••••");
		expect(out).toBe("PASSWORD=••••••");
		expect(out).not.toContain("$$");
		expect(o.hasSecrets()).toBe(false);
	});

	test("a legacy bullet does not block a later span", () => {
		const out = hashShapes(obf(), "PASSWORD=•••••• and PASSWORD=hunter2");
		expect(out).toMatch(/^PASSWORD=•••••• and PASSWORD=\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$$/);
	});

	test("an eight-dot legacy value is never captured", () => {
		const o = obf();
		expect(scrubString(o, "PASSWORD=••••••••")).toBe("PASSWORD=••••••••");
		expect(o.isKnown("••••••••")).toBe(false);
		expect(o.hasSecrets()).toBe(false);
		expect(scrubString(o, "the marker •••••••• ends here")).toBe("the marker •••••••• ends here");
		expect(o.hasSecrets()).toBe(false);
	});

	test("friendly names are sanitized identically for span hashes", () => {
		const match = /\$\$DBPASSWORD_[A-Z0-9]{12}:[ULCM]\$\$/;
		expect(hashShapes(obf(), "dbPassword=x")).toMatch(/^dbPassword=/);
		expect(hashShapes(obf(), "dbPassword=x")).toMatch(match);
		expect(hashShapes(obf(), "DB_PASSWORD=x")).toMatch(/^DB_PASSWORD=/);
		expect(hashShapes(obf(), "DB_PASSWORD=x")).toMatch(match);
	});

	test("a friendly name that collides with the value drops its prefix", () => {
		const out = hashShapes(obf(), "PASSWORD=ASS");
		expect(out).toMatch(/PASSWORD=\$\$[A-Z0-9]{12}:[ULCM]\$\$/);
		expect(out).not.toContain("PASSWORD_");
	});

	test("non-password secret names keep the capture floor", () => {
		const out = hashShapes(obf(), "apiKey=x");
		expect(out).toBe("apiKey=x");
	});

	test("a forged placeholder under a credential name is untouched", () => {
		const o = obf();
		const input = "TOKEN=$$FAKE_ABCDEFGHIJKL:U$$";
		expect(scrubString(o, input)).toBe(input);
		expect(o.deobfuscate(input)).toBe(input);
	});

	test("values already over the floor keep hashing globally", () => {
		const o = obf();
		const out = scrubString(o, "PASSWORD=Tr0ub4dor&3");
		expect(out).toMatch(/PASSWORD=\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$/);
		expect(out).not.toContain("Tr0ub4dor&3");
		expect(out).not.toContain("••••••");
		expect(o.isKnown("Tr0ub4dor&3")).toBe(true);
	});

	test("existing placeholders are untouched", () => {
		expect(scrubString(obf(), 'KEY="$$WIRING_0UX60MSBVKK4:L$$"')).toBe('KEY="$$WIRING_0UX60MSBVKK4:L$$"');
	});
});

describe("hash-only at-rest - URL password spans", () => {
	const URL_LOCAL = (host = "host\\.example", port = "") =>
		new RegExp(`postgres://app:\\$\\$[A-Z0-9]{12}:[ULCM]\\$\\$@${host}${port}/db`);

	test("short URL password becomes a placeholder", () => {
		const out = scrubString(obf(), "postgres://app:hunter2@host.example:5432/db");
		expect(out).toMatch(URL_LOCAL("host\\.example", ":5432"));
		expect(out).not.toContain("hunter2");
		expect(out).not.toContain("••••••");
	});

	test("URL password is replaced even when the assignment name is not secret", () => {
		const out = scrubString(obf(), "URL=postgres://app:pass@host.example/db");
		expect(out).toMatch(/^URL=postgres:\/\/app:\$\$[A-Z0-9]{12}:[ULCM]\$\$@host\.example\/db$/);
		expect(out).not.toContain(":pass@");
	});

	test("wordlike URL password becomes a placeholder", () => {
		const out = scrubString(obf(), "postgres://app:pass@host.example/db");
		expect(out).toMatch(/^postgres:\/\/app:\$\$[A-Z0-9]{12}:[ULCM]\$\$@host\.example\/db$/);
		expect(out).not.toContain(":pass@");
	});

	test("vetoed-shape URL password becomes a placeholder", () => {
		const out = scrubString(obf(), "postgres://app:2026-04-10T14:22:31Z@host.example/db");
		expect(out).toMatch(/^postgres:\/\/app:\$\$[A-Z0-9]{12}:[ULCM]\$\$@host\.example\/db$/);
		expect(out).not.toContain("2026-04-10T14:22:31Z");
	});

	test("URL password containing @ is replaced whole", () => {
		const input = "postgres://app:pa" + "ssw0rd!2024x@host.example:5432/db";
		const out = scrubString(obf(), input);
		expect(out).toMatch(/^postgres:\/\/app:\$\$[A-Z0-9]{12}:[ULCM]\$\$@host\.example:5432\/db$/);
		expect(out).not.toContain("ssw0rd!2024x");
	});

	test("legacy bullet URL password is left untouched", () => {
		const o = obf();
		const input = "postgres://app:••••••@host.example/db";
		expect(scrubString(o, input)).toBe(input);
		expect(o.hasSecrets()).toBe(false);
	});

	test("eight-dot legacy URL password is never captured", () => {
		const o = obf();
		const input = "postgres://app:••••••••@host.example/db";
		expect(scrubString(o, input)).toBe(input);
		expect(o.isKnown("••••••••")).toBe(false);
		expect(o.hasSecrets()).toBe(false);
	});

	test("password containing $$ is treated as already placeholded", () => {
		const out = scrubString(obf(), "postgres://app:pa$$word@host.example/db");
		expect(out).toBe("postgres://app:pa$$word@host.example/db");
	});

	test("already-placeholder URL password is untouched", () => {
		expect(scrubString(obf(), "curl https://user:$$WIRING_0UX60MSBVKK4:L$$@example.com/x")).toBe(
			"curl https://user:$$WIRING_0UX60MSBVKK4:L$$@example.com/x",
		);
	});

	test("a forged placeholder URL password is untouched", () => {
		const o = obf();
		const input = "curl https://user:$$FAKE_ABCDEFGHIJKL:U$$@example.com/x";
		expect(scrubString(o, input)).toBe(input);
		expect(o.deobfuscate(input)).toBe(input);
	});
});

describe("hash-only at-rest - span locality", () => {
	const SPAN = /\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$/;

	test("short value is replaced only at the detected span", () => {
		const out = hashShapes(obf(), "PASSWORD=x and x marks the spot");
		expect(out).toMatch(new RegExp(`^PASSWORD=${SPAN.source} and x marks the spot$`));
	});

	test("under-floor value is replaced only at the detected span", () => {
		const out = hashShapes(obf(), "PASSWORD=hunter2 and hunter2");
		expect(out).toMatch(new RegExp(`^PASSWORD=${SPAN.source} and hunter2$`));
	});

	test("URL password is replaced only inside the URL", () => {
		const out = hashShapes(obf(), "postgres://app:pass@host.example/db and pass the salt");
		expect(out).toMatch(/^postgres:\/\/app:\$\$[A-Z0-9]{12}:[ULCM]\$\$@host\.example\/db and pass the salt$/);
	});

	test("a span-minted value is not globally replaced in a later call", () => {
		const o = obf();
		expect(hashShapes(o, "PASSWORD=x")).toMatch(SPAN);
		expect(o.isKnown("x")).toBe(false);
		expect(hashShapes(o, "x marks the spot")).toBe("x marks the spot");
	});

	test("repeated spans for the same value each become an identical placeholder", () => {
		const out = hashShapes(obf(), "PASSWORD=x and PASSWORD=x");
		expect(out).toMatch(new RegExp(`^PASSWORD=${SPAN.source} and PASSWORD=${SPAN.source}$`));
		const [a, b] = out.match(/\$\$[A-Z0-9]+_[A-Z0-9]{12}:[ULCM]\$\$/g)!;
		expect(a).toBe(b);
	});

	test("different short values in one line are replaced back-to-front", () => {
		const out = hashShapes(obf(), "PASSWORD=x and PASSWORD=hunter2");
		expect(out).toMatch(new RegExp(`^PASSWORD=${SPAN.source} and PASSWORD=${SPAN.source}$`));
	});

	test("an assignment containing a URL is replaced once as the assignment value", () => {
		const input = "DB_PASSWORD=postgres://app:pass@host.example/db";
		const o = obf();
		const out = hashShapes(o, input);
		expect(out).toMatch(/^DB_PASSWORD=\$\$DBPASSWORD_[A-Z0-9]{12}:[ULCM]\$\$$/);
		expect(out).not.toContain("postgres://");
		expect(out).not.toContain("••••••");
		const pipelined = scrubString(obf(), input);
		expect(pipelined).toBe(out);
		expect(pipelined.match(/\$\$/g)?.length).toBe(2);
	});
});

describe("hash-only at-rest - round-trip and fixed point", () => {
	const SPAN = /\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$/;

	test("span-minted placeholder deobfuscates in a tool call", () => {
		const o = obf();
		const scrubbed = scrubString(o, "PASSWORD=hunter2");
		const placeholder = scrubbed.match(SPAN)![0];
		const args = deobfuscateToolArguments(o, { command: `echo ${placeholder}` });
		expect(args.command).toBe("echo hunter2");
	});

	test("span minting works through scrubToolResult", () => {
		const o = new SecretObfuscator(
			[{ type: "plain", content: "registered-1234567890", mode: "obfuscate", friendlyName: "UNRELATED" }],
			KEY,
		);
		const out = scrubToolResult(o, { content: [{ type: "text", text: "PASSWORD=hunter2" }] });
		expect(out).toBeDefined();
		const text = (out!.content[0] as { text: string }).text;
		expect(text).toContain("$$");
		expect(text).not.toContain("hunter2");
		const args = deobfuscateToolArguments(o, { input: text });
		expect(args.input).toContain("hunter2");
	});

	test("span minting activates the obfuscator", () => {
		const o = obf();
		expect(o.hasSecrets()).toBe(false);
		const out = scrubString(o, "PASSWORD=hunter2");
		expect(o.hasSecrets()).toBe(true);
		expect(out).toContain("$$");
	});

	test("a zero-secret session never scrubs through scrubToolResult", () => {
		const o = obf();
		const input = { content: [{ type: "text", text: "PASSWORD=hunter2" }] };
		expect(scrubToolResult(o, input)).toBeUndefined();
		expect(o.hasSecrets()).toBe(false);
	});

	test("streaming output scrubs a chunk-split span to a placeholder", () => {
		const o = obf();
		const emitted: string[] = [];
		const stream = createStreamScrubber({
			onData: (chunk) => emitted.push(chunk.toString("utf8")),
			scrub: (text) => scrubString(o, text),
		});
		stream.write(Buffer.from("PASSWORD=hu"));
		stream.write(Buffer.from("nter2\n"));
		stream.flush();
		expect(emitted.join("")).toMatch(/^PASSWORD=\$\$PASSWORD_[A-Z0-9]{12}:[ULCM]\$\$\n$/);
		expect(emitted.join("")).not.toContain("hunter2");
		expect(emitted.join("")).not.toContain("••••••");
	});

	test("scrubbing twice is a fixed point", () => {
		const o = obf();
		const once = scrubString(o, "PASSWORD=hunter2");
		const twice = scrubString(o, once);
		expect(twice).toBe(once);
		expect(twice.match(/\$\$/g)?.length).toBe(2);
		expect(twice).not.toContain("••••••");
	});

	test("placeholder minting is deterministic for the same key", () => {
		const a = obf();
		const b = obf();
		expect(scrubString(a, "PASSWORD=hunter2")).toBe(scrubString(b, "PASSWORD=hunter2"));
	});

	test("configured secrets still hash every occurrence", () => {
		const o = new SecretObfuscator(
			[{ type: "plain", content: "registered-secret-123456", mode: "obfuscate", friendlyName: "CONF" }],
			KEY,
		);
		const out = scrubString(o, "echo registered-secret-123456 and registered-secret-123456");
		expect(out.match(/\$\$/g)?.length).toBe(4);
		expect(out).not.toContain("registered-secret-123456");
	});
});
