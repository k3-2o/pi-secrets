import { describe, expect, test } from "bun:test";
import { builtinCredentialSecretEntries } from "../src/secrets/loaders";
import { type SecretEntry, SecretObfuscator } from "../src/secrets/obfuscator";

/** Fixed test key: same value across instances ⇒ deterministic cross-instance behavior. */
const KEY = "K3Y-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
const OTHER_KEY = "OTHR-KEY-00000000000000000000000000000000000000";

const PLAIN_ENTRY: SecretEntry = {
	type: "plain",
	content: "plain-secret-value-123",
	mode: "obfuscate",
	friendlyName: "PSV",
};
const REGEX_ENTRY: SecretEntry = {
	type: "regex",
	content: "TOK[_-][A-Z0-9]{16}",
	mode: "obfuscate",
	friendlyName: "CLI",
};

function obf(entries: SecretEntry[], key: string = KEY): SecretObfuscator {
	return new SecretObfuscator(entries, key);
}

describe("obfuscator - fixed point", () => {
	test("re-obfuscating hidden text is a no-op", () => {
		const o = obf([PLAIN_ENTRY]);
		const once = o.obfuscate("secret plain-secret-value-123 here");
		expect(o.obfuscate(once)).toBe(once);
		expect(o.deobfuscate(once)).toBe("secret plain-secret-value-123 here");
	});
});

describe("obfuscator - keyed determinism", () => {
	test("same key ⇒ same placeholder across instances", () => {
		const a = obf([PLAIN_ENTRY], KEY).obfuscate("plain-secret-value-123");
		const b = obf([PLAIN_ENTRY], KEY).obfuscate("plain-secret-value-123");
		expect(a).toBe(b);
	});

	test("different key ⇒ different placeholder", () => {
		const a = obf([PLAIN_ENTRY], KEY).obfuscate("plain-secret-value-123");
		const b = obf([PLAIN_ENTRY], OTHER_KEY).obfuscate("plain-secret-value-123");
		expect(a).not.toBe(b);
	});

	test("placeholder minted under one key never deobfuscates under another (dictionary resistance)", () => {
		const hidden = obf([PLAIN_ENTRY], KEY).obfuscate("plain-secret-value-123");
		const other = obf([PLAIN_ENTRY], OTHER_KEY);
		const back = other.deobfuscate(hidden);
		expect(back).not.toContain("plain-secret-value-123");
	});
});

describe("obfuscator - regex entries round trip", () => {
	test("regex match hidden and restored", () => {
		const input = "use TOK_ABCDEF1234567890 plz";
		const o = obf([REGEX_ENTRY]);
		const hidden = o.obfuscate(input);
		expect(hidden).not.toContain("TOK_ABCDEF1234567890");
		expect(o.deobfuscate(hidden)).toBe(input);
	});
});

describe("obfuscator - forgery resistance", () => {
	test("model-invented $$…$$ text stays literal (never becomes a secret)", () => {
		const o = obf([PLAIN_ENTRY]);
		const forged = "$$FORGED_ABC123DEF456:L$$";
		expect(o.deobfuscate(forged)).toBe(forged);
		// even when passed through obfuscate, it must survive untouched
		expect(o.obfuscate(`prefix ${forged} suffix`)).toContain(forged);
	});
});

describe("obfuscator - replace mode (one-way)", () => {
	test("custom replacement is emitted and never restored", () => {
		const o = obf([{ type: "plain", content: "do-not-recover", mode: "replace", replacement: "[REDACTED]" }]);
		const hidden = o.obfuscate("the do-not-recover stays");
		expect(hidden).toBe("the [REDACTED] stays");
		expect(o.deobfuscate(hidden)).toBe(hidden); // one-way: nothing to restore
	});
});

describe("obfuscator - friendly names and case hints", () => {
	test("placeholder carries sanitized friendly prefix and case hint, round-trips", () => {
		const o = obf([{ type: "plain", content: "MySecretValueX", mode: "obfuscate", friendlyName: "GH_TOKEN" }]);
		const hidden = o.obfuscate("MySecretValueX");
		expect(hidden).toMatch(/^\$\$GHTOKEN_[A-Z0-9]{12}:[ULCM]\$\$$/);
		expect(o.deobfuscate(hidden)).toBe("MySecretValueX");
	});
});

describe("obfuscator - built-in credential patterns", () => {
	const builtins = new SecretObfuscator(builtinCredentialSecretEntries(), KEY);
	const roundTrip = (input: string): void => {
		const hidden = builtins.obfuscate(input);
		expect(hidden).not.toContain(input.slice(4)); // the token body never survives
		expect(builtins.deobfuscate(hidden)).toBe(input);
	};

	test("OpenAI sk-proj- token", () => {
		roundTrip(`use sk-proj-${"A".repeat(40)} here`);
	});
	test("GitHub github_pat_ token", () => {
		roundTrip(`auth github_pat_${"b".repeat(40)} now`);
	});
	test("JWT", () => {
		const jwt = `eyJ${"a".repeat(30)}.eyJ${"b".repeat(30)}.${"c".repeat(30)}`;
		roundTrip(`token ${jwt}`);
	});
	test("PEM private-key block", () => {
		const pem =
			"-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASC\nAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n-----END PRIVATE KEY-----";
		const hidden = builtins.obfuscate(pem);
		expect(hidden).not.toContain("BEGIN PRIVATE KEY");
		expect(builtins.deobfuscate(hidden)).toBe(pem);
	});

	test("0.1.0 curated batch round-trips (Shopify, Postman, Pulumi, DigitalOcean, Grafana, Twilio, Alibaba)", () => {
		roundTrip(`key shpat_${"a".repeat(32)} x`);
		roundTrip(`key shpca_${"b".repeat(32)} x`);
		roundTrip(`key shppa_${"c".repeat(32)} x`);
		roundTrip(`key PMAK-${"d".repeat(24)}-${"e".repeat(34)} x`);
		roundTrip(`key pul-${"f".repeat(40)} x`);
		roundTrip(`key dop_v1_${"g".repeat(64)} x`);
		roundTrip(`key glc_${"h".repeat(40)} x`);
		roundTrip(`key SK${"0".repeat(32)} x`);
		roundTrip(`key LTAI${"i".repeat(20)} x`);
	});
});
