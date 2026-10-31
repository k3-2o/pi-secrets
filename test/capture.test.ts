import { describe, expect, test } from "bun:test";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import { captureUnregistered, scrubString } from "../src/secrets/at-rest";
import { builtinCredentialSecretEntries } from "../src/secrets/loaders";
import { obfuscateMessages } from "../src/secrets/message-transform";
import { type SecretEntry, SecretObfuscator } from "../src/secrets/obfuscator";

/** Fixed test key: identical value across instances ⇒ deterministic cross-instance behavior. */
const KEY = "unit-test-key-0123456789abcdef";

/** Unregistered, shapeless value (would trip no built-in shape, no secrets.yml). */
const RAW = "hyi-XuavR6H7ntIAVPcucu7973HpCC2Ik4z_x2Iq2ZPpZzM";
const URL_PASSWORD = "u8r9PgQwXzA4vB2cD6fH1jK3lM5nO7pQ";

function obf(entries: SecretEntry[] = [], key: string = KEY): SecretObfuscator {
	return new SecretObfuscator(entries, key);
}

describe("phase 9 - auto-capture (learn on first sight)", () => {
	test("assignment value: first scrub hashes the never-registered value", () => {
		const o = obf();
		const input = `export API_KEY=${RAW}`;
		const out = scrubString(o, input);
		expect(out).not.toContain(RAW);
		expect(out).toContain("$$");
		expect(o.isKnown(RAW)).toBe(true); // captured + registered by first contact
	});

	test("captured value reveals (two-way, not bullets)", () => {
		const o = obf();
		const out = scrubString(o, `API_KEY=${RAW}`);
		expect(out).not.toContain("••");
		expect(o.deobfuscate(out)).toContain(RAW); // the screen-reveal path
	});

	test("tool-arg round-trip restores the exact bytes", () => {
		const o = obf();
		const hashed = scrubString(o, `TOKEN=${RAW}`);
		expect(o.deobfuscate(hashed)).toBe(`TOKEN=${RAW}`);
	});

	test("connection-URL password is captured", () => {
		const o = obf();
		const input = `postgres://app:${URL_PASSWORD}@db.internal:5432/main`;
		const out = scrubString(o, input);
		expect(out).not.toContain(URL_PASSWORD);
		expect(o.isKnown(URL_PASSWORD)).toBe(true);
	});

	test("non-secret names are skipped - no capture, no redaction", () => {
		const o = obf();
		const input = "count=12345678 and leak=abracadabra-1234567890";
		expect(scrubString(o, input)).toBe(input);
		expect(o.hasSecrets()).toBe(false);
	});

	test("short values under the floor are never captured and stay raw (same floor as bullets)", () => {
		const o = obf();
		const out = scrubString(o, "API_KEY=short");
		expect(o.isKnown("short")).toBe(false);
		expect(o.hasSecrets()).toBe(false);
		expect(out).toBe("API_KEY=short"); // below-floor: bullets net leaves it raw too
	});

	test("capture itself is idempotent; known values never re-register", () => {
		const o = obf([{ type: "plain", content: RAW, mode: "obfuscate" }]);
		expect(o.isKnown(RAW)).toBe(true);
		expect(o.addPlainSecret(RAW)).toBe(false);
		expect(captureUnregistered(o, `API_KEY=${RAW}`)).toBe(`API_KEY=${RAW}`); // no throw, no re-add
	});

	test("built-ins keep precedence; capture fills the unregistered remainder", () => {
		const o = obf(builtinCredentialSecretEntries());
		const input = `AUTH sk-proj-${"A".repeat(40)} then API_KEY=${RAW}`;
		const out = scrubString(o, input);
		expect(out).not.toContain("sk-proj-");
		expect(out).not.toContain(RAW);
		expect(out.match(/\$\$/g)?.length).toBeGreaterThanOrEqual(2);
	});

	test("fixed point: re-scrubbing hashed output is a byte no-op", () => {
		const o = obf();
		const once = scrubString(o, `API_KEY=${RAW}`);
		const twice = scrubString(o, once);
		expect(twice).toBe(once);
	});

	test("cross-instance determinism: same key ⇒ identical placeholder token", () => {
		const a = obf();
		const b = obf();
		expect(scrubString(a, `API_KEY=${RAW}`)).toBe(scrubString(b, `API_KEY=${RAW}`));
	});

	test("capture registers the VALUE, not the line: every later form is hashed too", () => {
		const o = obf();
		// first contact: keyword-named assignment captures the value
		expect(scrubString(o, `export API_KEY=${RAW}`)).toContain("$$");
		// same value, but now in forms the name gate would NOT catch:
		for (const form of [RAW, `X=${RAW}`, `{"ref": "${RAW}"}`, `bear ${RAW} end`]) {
			expect(scrubString(o, form)).not.toContain(RAW);
		}
		// and it still round-trips (two-way), untouched by where it was first seen
		expect(o.deobfuscate(scrubString(o, `X=${RAW}`))).toBe(`X=${RAW}`);
	});
	test("context path: user text is hashed at first look", () => {
		const o = obf();
		const messages = [{ role: "user", content: `Please apply API_KEY=${RAW} now` }] as unknown as AgentMessage[];
		const out = obfuscateMessages(o, messages);
		const content = (out[0].content ?? "") as string;
		expect(content).not.toContain(RAW);
		expect(content).toContain("$$");
		expect(o.isKnown(RAW)).toBe(true);
	});
});

describe("phase 11 - capture diagnostics", () => {
	test("S5: report lists friendly labels and count, never values; eviction shrinks it", () => {
		const o = obf();
		scrubString(o, "DEPLOY_API_TOKEN=Zz9real-Captured-Secret42\nnoteRowKey = undefined;\n");
		// The second is refused by the shape gate, so only the first is captured at all.
		const report = o.autoCaptureReport();
		expect(report.count).toBe(1);
		expect(report.labels).toContain("DEPLOY_API_TOKEN");
		expect(JSON.stringify(report)).not.toContain("Zz9real-Captured-Secret42");
		o.removeAutoCaptured("Zz9real-Captured-Secret42");
		expect(o.autoCaptureReport().count).toBe(0);
	});
});
