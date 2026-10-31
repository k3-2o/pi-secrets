import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { BashOperations, ExtensionAPI } from "@earendil-works/pi-coding-agent";
import extensionFactory from "../index.ts";

const SECRET = "wiring-secret-12345678901";
const PLAIN_INPUT = `here is my ${SECRET} token`;
const PLACEHOLDER_RE = /\$\$[A-Z]+_[A-Z0-9]{12}:[ULCM]\$\$/;

interface FakePi {
	pi: ExtensionAPI;
	handlers: Map<string, (event: unknown, ctx?: unknown) => unknown>;
	transformers: Array<(markdown: string, context: unknown) => string>;
	commands: Map<string, { description?: string; handler: (args: string, ctx: unknown) => Promise<void> }>;
	run: (event: string, eventData: unknown, ctx?: unknown) => Promise<unknown>;
}

function makeFakePi(flag: boolean | string | undefined, getSettings?: () => Record<string, unknown>): FakePi {
	const handlers = new Map<string, (event: unknown, ctx?: unknown) => unknown>();
	const transformers: Array<(markdown: string, context: unknown) => string> = [];
	const commands = new Map<string, { description?: string; handler: (args: string, ctx: unknown) => Promise<void> }>();
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
		registerCommand: (
			name: string,
			options: { description?: string; handler: (args: string, ctx: unknown) => Promise<void> },
		) => {
			commands.set(name, options);
		},
		getSettings,
	} as unknown as ExtensionAPI;
	return {
		pi,
		handlers,
		transformers,
		commands,
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
	process.env.PI_CODING_AGENT_DIR = agentDir;
});

afterEach(() => {
	fs.rmSync(tmpRoot, { recursive: true, force: true });
	delete process.env.PI_CODING_AGENT_DIR;
});

describe("pi-secrets wiring - single mode (Phase 8)", () => {
	test("full pipeline: session → context hides → tool_call reveals → user/assistant message_end stores hashes", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);

		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const context = (await fake.run("context", {
			type: "context",
			messages: [{ role: "user", content: PLAIN_INPUT, timestamp: 0 }],
		})) as { messages: Array<{ content: string }> };
		expect(context.messages[0].content).not.toContain(SECRET);
		const placeholder = PLACEHOLDER_RE.exec(context.messages[0].content)?.[0];
		expect(placeholder).toBeDefined();

		const editEvent = {
			type: "tool_call",
			toolName: "edit",
			toolCallId: "call-1",
			input: { path: "/tmp/f", old: placeholder, new: "replacement" },
		};
		await fake.run("tool_call", editEvent);
		expect((editEvent.input as { old: string }).old).toBe(SECRET);
		expect((editEvent.input as { new: string }).new).toBe("replacement");

		const userEnd = (await fake.run("message_end", {
			type: "message_end",
			message: { role: "user", content: PLAIN_INPUT, timestamp: 0 },
		})) as { message: { role: string; content: string } };
		expect(userEnd.message.role).toBe("user");
		expect(userEnd.message.content).not.toContain(SECRET);
		expect(userEnd.message.content).toContain(placeholder);

		const safeEnd = await fake.run("message_end", {
			type: "message_end",
			message: {
				role: "assistant",
				content: [{ type: "text", text: `the token is ${placeholder}` }],
			},
		});
		expect(safeEnd).toBeUndefined();

		const assembledEnd = (await fake.run("message_end", {
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: `rebuild: ${SECRET}` }] },
		})) as { message: { content: Array<{ text: string }> } };
		expect(assembledEnd.message.content[0].text).not.toContain(SECRET);
		expect(assembledEnd.message.content[0].text).toContain("$$");
	});

	test("transformer reveals user, assistant, and assistant-thinking at paint time; ignores other types", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const context = (await fake.run("context", {
			type: "context",
			messages: [{ role: "user", content: PLAIN_INPUT, timestamp: 0 }],
		})) as { messages: Array<{ content: string }> };
		const placeholder = PLACEHOLDER_RE.exec(context.messages[0].content)?.[0];
		expect(placeholder).toBeDefined();

		expect(fake.transformers).toHaveLength(1);
		const transform = fake.transformers[0];
		for (const messageType of ["user", "assistant", "assistant-thinking"] as const) {
			expect(transform(`the token is ${placeholder}`, { messageType, isStreaming: false, availableWidth: 80 })).toBe(
				`the token is ${SECRET}`,
			);
		}

		expect(
			transform(`the token is ${placeholder}`, {
				messageType: "toolResult" as never,
				isStreaming: false,
				availableWidth: 80,
			}),
		).toBe(`the token is ${placeholder}`);
	});

	test("tool_result scrubs content AND structuredContent, returned together", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const result = (await fake.run("tool_result", {
			type: "tool_result",
			toolName: "bash",
			toolCallId: "call-2",
			input: {},
			content: [{ type: "text", text: `cat .env: ${SECRET}` }],
			structuredContent: { rows: [{ key: "TOP_FREEINFERENCE_API_KEY", value: SECRET }] },
			isError: false,
			details: undefined,
		})) as { content: Array<{ text: string }>; structuredContent?: { rows: Array<{ value: string }> } };

		expect(result.content[0].text).not.toContain(SECRET);
		expect(result.content[0].text).toContain("$$");

		expect(result.structuredContent).toBeDefined();
		expect(JSON.stringify(result.structuredContent)).not.toContain(SECRET);
		expect(JSON.stringify(result.structuredContent)).toContain("$$");
	});

	test("message_end (toolResult) scrubs content, details, and nested-call args at rest", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const ended = (await fake.run("message_end", {
			type: "message_end",
			message: {
				role: "toolResult",
				toolCallId: "call-3",
				toolName: "custom",
				content: [{ type: "text", text: `output says ${SECRET}` }],
				details: { token: SECRET },
				nestedCalls: {
					calls: [{ id: "n1", name: "bash", arguments: { command: `echo ${SECRET}` }, status: "ok" }],
					complete: true,
				},
				isError: false,
				timestamp: 0,
			},
		})) as {
			message: {
				role: string;
				content: Array<{ text: string }>;
				details?: unknown;
				nestedCalls?: { calls: Array<{ arguments?: unknown }> };
			};
		};

		expect(ended.message.role).toBe("toolResult");
		expect(ended.message.content[0].text).not.toContain(SECRET);
		expect(JSON.stringify(ended.message.details)).not.toContain(SECRET);
		expect(JSON.stringify(ended.message.nestedCalls)).not.toContain(SECRET);
		expect(JSON.stringify(ended.message)).not.toContain(SECRET);
	});

	test("user_bash returns scrubbing operations when enabled, undefined when disabled", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const enabled = (await fake.run("user_bash", {
			type: "user_bash",
			command: `echo ${SECRET}`,
			excludeFromContext: false,
			cwd,
		})) as { operations: BashOperations };
		expect(enabled.operations).toBeDefined();

		const chunks: string[] = [];
		const exit = await enabled.operations.exec(`printf %s '${SECRET}'`, cwd, {
			onData: (data) => chunks.push(data.toString("utf8")),
		});
		expect(exit.exitCode).toBe(0);
		const output = chunks.join("");
		expect(output).not.toContain(SECRET);
		expect(output).toContain("$$");

		const off = makeFakePi(false);
		extensionFactory(off.pi);
		await off.run("session_start", { type: "session_start", reason: "startup" }, { cwd });
		const disabled = await off.run("user_bash", {
			type: "user_bash",
			command: "echo hi",
			excludeFromContext: false,
			cwd,
		});
		expect(disabled).toBeUndefined();
	});

	test("a timed-out exec still delivers the held tail before rejecting", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });

		const { operations } = (await fake.run("user_bash", {
			type: "user_bash",
			command: "printf %s 'heldfrag-no-newline'; sleep 0.3",
			excludeFromContext: false,
			cwd,
		})) as { operations: BashOperations };

		const chunks: Buffer[] = [];
		const outcome = await operations
			.exec(`printf %s 'heldfrag-no-newline'; sleep 0.3`, cwd, {
				onData: (d) => chunks.push(d),
				signal: AbortSignal.timeout(50),
			})
			.catch((err: unknown) => ({ rejected: String(err) }));

		expect(outcome).toHaveProperty("rejected");
		expect(chunks.join("")).toContain("heldfrag-no-newline");
	});

	test("disabled session: every handler is a no-op and the transformer is a pass-through", async () => {
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
			message: { role: "user", content: PLAIN_INPUT, timestamp: 0 },
		});
		expect(ended).toBeUndefined();

		const userBash = await fake.run("user_bash", {
			type: "user_bash",
			command: "echo hi",
			excludeFromContext: false,
			cwd,
		});
		expect(userBash).toBeUndefined();

		const transform = fake.transformers[0];
		expect(transform(`token ${SECRET}`, { messageType: "assistant", isStreaming: false, availableWidth: 80 })).toBe(
			`token ${SECRET}`,
		);
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

describe("phase 11 - /secrets diagnostics command", () => {
	test("command reports auto-captured labels and count, never values; silent when nothing learned", async () => {
		const fake = makeFakePi(true);
		extensionFactory(fake.pi);
		await fake.run("session_start", { type: "session_start", reason: "startup" }, { cwd });
		expect(fake.commands.has("secrets")).toBe(true);

		const notices: string[] = [];
		const ctx = { ui: { notify: (m: string) => notices.push(m) } };
		await fake.commands.get("secrets")!.handler("", ctx);
		expect(notices.length).toBe(1);
		expect(notices[0]).not.toContain(SECRET);

		await fake.run("tool_result", {
			type: "tool_result",
			callId: "c1",
			toolName: "bash",
			isError: false,
			content: [{ type: "text", text: "DEPLOY_API_TOKEN=Zz9real-Unregistered-Secret42\n" }],
			structuredContent: undefined,
		});
		notices.length = 0;
		await fake.commands.get("secrets")!.handler("", ctx);
		expect(notices[0]).toContain("DEPLOY_API_TOKEN");
		expect(notices[0]).toContain("1");
		expect(notices[0]).not.toContain("Zz9real-Unregistered-Secret42");
	});
});
