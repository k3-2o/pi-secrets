import { describe, expect, test } from "bun:test";
import { scrubString as scrubText } from "../src/secrets/at-rest";
import { builtinCredentialSecretEntries } from "../src/secrets/loaders";
import { SecretObfuscator } from "../src/secrets/obfuscator";
import { createStreamScrubber } from "../src/secrets/stream-scrub";

const KEY = "stream-key-0123456789";
const JWT_MARKER =
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIy";

function obf(): SecretObfuscator {
	return new SecretObfuscator(builtinCredentialSecretEntries(), KEY);
}

function stream(scrub: (t: string) => string, input: Buffer, chunk = 700): Buffer {
	const chunks: Buffer[] = [];
	const s = createStreamScrubber({
		onData: (c) => chunks.push(c),
		scrub,
	});
	for (let i = 0; i < input.length; i += chunk) s.write(input.subarray(i, i + chunk));
	s.flush();
	return Buffer.concat(chunks);
}

describe("stream scrub - user_bash at-rest", () => {
	test("a long JWT arriving in small chunks is scrubbed whole, not fragment by fragment", () => {
		const jwt = JWT_MARKER.repeat(220);
		const input = Buffer.from(`token: ${jwt}\n`);
		const out = stream((t) => scrubText(obf(), t), input).toString("utf8");
		expect(out).not.toContain(JWT_MARKER);
		expect(out).toContain("$$");
		expect(out.length).toBeLessThan(input.length);
	});

	test("the same JWT in one write scrubs identically (whole-text control)", () => {
		const jwt = JWT_MARKER.repeat(220);
		const input = Buffer.from(`token: ${jwt}\n`);
		const out = stream((t) => scrubText(obf(), t), input, input.length).toString("utf8");
		expect(out).toContain("$$");
		expect(out).not.toContain(JWT_MARKER);
	});

	test("secret on line 2: neighbors stay byte-identical, the token hashes once", () => {
		const secret = "val12345678";
		const input = `line one\nTOKEN=${secret}\nline three\n`;
		const out = stream((t) => scrubText(obf(), t), Buffer.from(input), 7).toString("utf8");
		expect(out).toContain("line one\n");
		expect(out).toContain("\nline three\n");
		expect(out).not.toContain(secret);
		expect(out).toContain("$$");
	});

	test("a token split exactly at a chunk boundary inside its own line is still caught", () => {
		const secret = "val12345678";
		const input = `x\nTOKEN=${secret}\n`;
		const chunks: Buffer[] = [];
		const s = createStreamScrubber({ onData: (c) => chunks.push(c), scrub: (t) => scrubText(obf(), t) });
		const cut = input.indexOf(secret) + 3;
		s.write(Buffer.from(input.slice(0, cut)));
		s.write(Buffer.from(input.slice(cut)));
		s.flush();
		const out = Buffer.concat(chunks).toString("utf8");
		expect(out).not.toContain(secret);
		expect(out).toContain("$$");
	});

	test("PEM spanning chunk boundaries is held until END and scrubbed whole", () => {
		const open = "-----" + "BEGIN PRIVATE KEY-----";
		const close = "-----" + "END PRIVATE KEY-----";
		const body = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCel8TxocCLYJ";
		const pem = `${open}\n${body}\n${close}\n`;
		const out = stream((t) => scrubText(obf(), t), Buffer.from(pem), 32).toString("utf8");
		expect(out).not.toContain(body);
		expect(out).not.toContain("BEGIN PRIVATE");
		expect(out).toContain("$");
		expect(out.length).toBeLessThan(pem.length);
	});

	test("binary output with no line breaks is byte-exact (no secret-shaped text)", () => {
		const raw = Buffer.from(Array.from({ length: 4096 }, (_, i) => ((i * 131) % 250) + 3));
		const out = stream((t) => scrubText(obf(), t), raw, 333);
		expect(Buffer.compare(out, raw)).toBe(0);
	});

	test("binary output with newline bytes splits at boundaries and is byte-exact", () => {
		const raw = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 97 + (i % 2 === 0 ? 0 : 10)) % 251));
		const out = stream((t) => scrubText(obf(), t), raw, 509);
		expect(Buffer.compare(out, raw)).toBe(0);
	});

	test("\\r progress updates flush per update and round-trip byte-exact", () => {
		const raw = Buffer.from("12% done\r37% done\r100% done\r");
		const out = stream((t) => scrubText(obf(), t), raw, 6);
		expect(out.toString("utf8")).toBe(raw.toString("utf8"));
	});

	test("a newline-free blob past the line cap degrades: emitted in fragments, byte-exact when secret-free", () => {
		const raw = Buffer.from("A".repeat(70 * 1024));
		const out = stream((t) => scrubText(obf(), t), raw, 4096);
		expect(Buffer.compare(out, raw)).toBe(0);
	});

	test("flush on empty buffer is a no-op", () => {
		const s = createStreamScrubber({ onData: () => undefined, scrub: (t) => t });
		expect(() => s.flush()).not.toThrow();
	});
});
