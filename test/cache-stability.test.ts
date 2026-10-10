import { describe, expect, test } from "bun:test";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import {
	deobfuscateAssistantContent,
	deobfuscateToolArguments,
	obfuscateProviderContext,
} from "../src/secrets/message-transform";
import type { SecretObfuscator } from "../src/secrets/obfuscator";
import { SecretObfuscator as Obf } from "../src/secrets/obfuscator";

/**
 * Cache-stability guarantees. Providers bill cache misses per rewritten prefix
 * byte; these tests pin the properties that keep the provider cache intact:
 *   1. hashing happens before first transmission (no raw-then-hashed churn),
 *   2. placeholders are deterministic (same key+value ⇒ same bytes),
 *   3. re-obfuscation of already-sent text is a byte no-op (fixed point),
 *   4. the persist-mode reveal → re-hash round trip reproduces prior bytes.
 */
const KEY = "K3Y-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
const SECRET = "pink-floyd-12345678";
const SECRET_VALUE = "some tool output with pink-floyd-12345678 inside";

function obf(): SecretObfuscator {
	return new Obf([{ type: "plain", content: SECRET, mode: "obfuscate", friendlyName: "PF" }], KEY);
}

function bytes(messages: readonly unknown[]): string {
	return JSON.stringify(
		messages.map((m) => ({ role: (m as { role: string }).role, content: (m as { content: unknown }).content })),
	);
}

describe("cache stability", () => {
	test("a secret-bearing message never changes bytes between consecutive requests", () => {
		const o = obf();
		const user = { role: "user", content: `the key is ${SECRET} ok`, timestamp: 0 } as unknown as AgentMessage;

		const req1 = obfuscateProviderContext(o, { messages: [user] });
		const req2 = obfuscateProviderContext(o, { messages: [user] });
		expect(bytes(req1.messages)).toBe(bytes(req2.messages)); // deterministic, not just equal shadows
	});

	test("already-hashed text is a byte no-op across ten passes (fixed point)", () => {
		const o = obf();
		const user = { role: "user", content: `key: ${SECRET}`, timestamp: 0 } as unknown as AgentMessage;
		const once = obfuscateProviderContext(o, { messages: [user] });
		let current = once;
		for (let i = 0; i < 10; i++) {
			current = obfuscateProviderContext(o, { messages: current.messages });
			expect(bytes(current.messages)).toBe(bytes(once.messages));
		}
	});

	test("persist-mode round trip: revealed assistant re-hashes to the exact prior request bytes", () => {
		const o = obf();
		const user = { role: "user", content: `key: ${SECRET}`, timestamp: 0 } as unknown as AgentMessage;

		// turn 1 request — the only bytes the provider ever saw
		const req1 = obfuscateProviderContext(o, { messages: [user] });
		const hashedUser = req1.messages[0];
		const placeholder = ((hashedUser as { content: string }).content.match(/\$\$[A-Z]+_[A-Z0-9]{12}:[ULCM]\$\$/) ??
			[])[0];
		expect(placeholder).toBeDefined();

		// the model replies quoting what it saw, then message_end reveals (persist mode)
		const assistant = {
			role: "assistant",
			content: [{ type: "text", text: `use the token ${placeholder}` }],
		} as unknown as AgentMessage;
		const revealed = deobfuscateAssistantContent(o, assistant.content);
		expect((revealed[0] as { text: string }).text).toContain(SECRET); // human-visible state

		// turn 2 request carries the REVEALED assistant message; context must re-hash it
		const turn2 = [
			{ role: "user", content: "continue", timestamp: 1 } as unknown as AgentMessage,
			{ ...assistant, content: revealed } as unknown as AgentMessage,
		];
		const req2 = obfuscateProviderContext(o, { messages: turn2 });
		const seenAssistant = req2.messages[1];
		expect(bytes([seenAssistant])).toBe(bytes([assistant])); // byte-identical to what turn 1's request carried in history terms
	});

	test("tool-call reveal (deobfuscate) restores the same value the obfuscator knows, without rewriting other fields", () => {
		const o = obf();
		const toolInput = { path: "/f", old: SECRET, new: "replacement" };
		const fixed = deobfuscateToolArguments(o, { ...toolInput });
		expect(fixed.old).toBe(SECRET); // already-real input passes through unchanged (deobfuscate is an identity on plain values)
		const hashed = o.obfuscate(SECRET_VALUE);
		expect(hashed).not.toContain(SECRET);
		expect(o.deobfuscate(hashed)).toBe(SECRET_VALUE);
	});
});
