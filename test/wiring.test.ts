import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import extensionFactory from "../index.ts";

const SECRET = "wiring-secret-12345678901";
const PLAIN_INPUT = `here is my ${SECRET} token`;
const PLACEHOLDER_RE = /\$\$[A-Z]+_[A-Z0-9]{12}:[ULCM]\$\$/;

interface FakePi {
	pi: ExtensionAPI;
	handlers: Map<string, (event: unknown, ctx?: unknown) => unknown>;
	transformers: Array<(markdown: string, context: unknown) => string>;
	run: (event: string, eventData: unknown, ctx?: unknown) => Promise<unknown>;
}

function makeFakePi(flag: boolean | string | undefined, getSettings?: () => Record<string, unknown>): FakePi {
	const handlers = new Map<string, (event: unknown, ctx?: unknown) => unknown>();
	const transformers: Array<(markdown: string, context: unknown) => string> = [];
	const pi = {
		registerFlag: () => {},
		getFlag: () => flag,
		on: (event: string, handler: (event: unknown, ctx?: unknown) => unknown) => {
			handlers.set(event, handler);
			return () => {};
		},
		registerMarkdownTransformer: (fn: (markdown: string, context: unknown) => string) => {
			transformers.push(fn);
		},
		getSettings,
	} as unknown as ExtensionAPI;
	return {
		pi,
		handlers,
		transformers,
		run: async (event: string, eventData: unknown, ctx?: unknown) => {
			const handler = handlers.get(event);
			if (!handler) throw new Error(`no handler for ${event}`);
			return handler(eventData, ctx);
		},
	};
}

let tmpRoot: string;
let agentDir: string;
let cwd: string;

beforeEach(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pi-secrets-wiring-"));
	agentDir = path.join(tmpRoot, "agent");
	cwd = path.join(tmpRoot, "cwd");
	fs.mkdirSync(agentDir, { recursive: true });
	fs.mkdirSync(cwd, { recursive: true });
	fs.writeFileSync(
		path.join(cwd, "secrets.yml"),
		`- type: plain\n  content: "${SECRET}"\n  mode: obfuscate\n  friendlyName: WIRING\n`,
	);
	process.env.PI_CODING_AGENT_DIR = agentDir; // getAgentDir() resolves here
});

afterEach(() => {
	fs.rmSync(tmpRoot, { recursive: true, force: true });
	delete process.env.PI_CODING_AGENT_DIR;
});

describe("pi-secrets wiring — persist mode (Option B)", () => {
	test("full pipeline: session → context hides → tool_call reveals → message_end reveals", async () => {
		const fake = makeFakePi(true); // --secrets flag forces on
		extensionFactory(fake.pi);

		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		// context: the model must never see the real secret.
		const context = (await fake.run("context", {
			type: "context",
			messages: [{ role: "user", content: PLAIN_INPUT, timestamp: 0 }],
		})) as { messages: Array<{ content: string }> };
		expect(context.messages[0].content).not.toContain(SECRET);
		const placeholder = PLACEHOLDER_RE.exec(context.messages[0].content)?.[0];
		expect(placeholder).toBeDefined();

		// tool_call: edit input arrives with the placeholder (what the model saw),
		// the handler must swap real bytes back in place.
		const editEvent = {
			type: "tool_call",
			toolName: "edit",
			toolCallId: "call-1",
			input: { path: "/tmp/f", old: placeholder, new: "replacement" },
		};
		await fake.run("tool_call", editEvent);
		expect((editEvent.input as { old: string }).old).toBe(SECRET);
		expect((editEvent.input as { new: string }).new).toBe("replacement");

		// message_end: assistant content quoting the placeholder must reveal to the human.
		const endEvent = {
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: `the token is ${placeholder}` }] },
		};
		const ended = (await fake.run("message_end", endEvent)) as {
			message: { role: string; content: Array<{ type: string; text: string }> };
		};
		expect(ended.message.role).toBe("assistant");
		expect(ended.message.content[0].text).toBe(`the token is ${SECRET}`);
	});

	test("disabled session: every handler is a no-op", async () => {
		const fake = makeFakePi(false);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const context = await fake.run("context", {
			type: "context",
			messages: [{ role: "user", content: PLAIN_INPUT, timestamp: 0 }],
		});
		expect(context).toBeUndefined();

		const editEvent = {
			type: "tool_call",
			toolName: "edit",
			toolCallId: "call-1",
			input: { old: SECRET, new: "x" },
		};
		await fake.run("tool_call", editEvent);
		expect((editEvent.input as { old: string }).old).toBe(SECRET);

		const ended = await fake.run("message_end", {
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: SECRET }] },
		});
		expect(ended).toBeUndefined();
	});

	test("context returns undefined when nothing changed (pi reuses its objects)", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const plain = [{ role: "user", content: "no secrets in this message at all", timestamp: 0 }];
		const result = await fake.run("context", { type: "context", messages: plain });
		expect(result).toBeUndefined();
	});
});

describe("pi-secrets wiring — render mode (Option A)", () => {
	test("message_end stays untouched (hashes at rest); transformer reveals at paint time", async () => {
		// Enabled via settings file; no CLI flag.
		fs.writeFileSync(
			path.join(agentDir, "settings.json"),
			JSON.stringify({ secrets: { enabled: true, mode: "render" } }),
		);
		const fake = makeFakePi(undefined);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const context = (await fake.run("context", {
			type: "context",
			messages: [{ role: "user", content: PLAIN_INPUT, timestamp: 0 }],
		})) as { messages: Array<{ content: string }> };
		const placeholder = PLACEHOLDER_RE.exec(context.messages[0].content)?.[0];
		expect(placeholder).toBeDefined();

		// No message_end reveal: the replacement must be absent, hashes persist.
		const ended = await fake.run("message_end", {
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: `the token is ${placeholder}` }] },
		});
		expect(ended).toBeUndefined();

		// The registered transformer reveals on assistant render only.
		expect(fake.transformers).toHaveLength(1);
		const transform = fake.transformers[0];
		const revealed = transform(`the token is ${placeholder}`, {
			messageType: "assistant",
			isStreaming: false,
			availableWidth: 80,
		});
		expect(revealed).toBe(`the token is ${SECRET}`);
		const userText = transform(`the token is ${placeholder}`, {
			messageType: "user",
			isStreaming: false,
			availableWidth: 80,
		});
		expect(userText).toBe(`the token is ${placeholder}`);
	});
});
