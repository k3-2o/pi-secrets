/** pi-secrets - reversible credential obfuscation for pi; off by default (`secrets.enabled`). */

import type { AgentMessage } from "@earendil-works/pi-agent-core";
import type {
	BashOperations,
	ExtensionAPI,
	MessageEndEvent,
	MessageEndEventResult,
	ToolResultEvent,
	ToolResultEventResult,
	UserBashEventResult,
} from "@earendil-works/pi-coding-agent";
import { createLocalBashOperations, getAgentDir } from "@earendil-works/pi-coding-agent";
import { buildSecretObfuscator } from "./src/secrets";
import { scrubString as scrubText, scrubToolResult } from "./src/secrets/at-rest";
import { deobfuscateToolArguments, obfuscateMessages } from "./src/secrets/message-transform";
import type { JsonValue, SecretObfuscator } from "./src/secrets/obfuscator";
import { readSecretsSettings } from "./src/settings";

/** Content block type stored on a toolResult message (pi-ai `TextContent | ImageContent`). */
type ContentBlock = Extract<AgentMessage, { role: "toolResult" }>["content"][number];

const FLAG = "secrets";

/** How many characters of bash output are held back before emitting, so a secret spanning a chunk boundary is still scrubbed in one piece. */
const BASH_HOLD = 1024;

// PEM opener in buffer: hold output until END arrives so a straddling key is scrubbed whole.
const BASH_PEM_OPEN = "-----BEGIN ";
const BASH_PEM_CLOSE = "-----END ";
const BASH_PEM_MAX = 32 * 1024;

interface SessionState {
	obfuscator: SecretObfuscator | undefined;
}

let state: SessionState = { obfuscator: undefined };

/** Wrap pi's local shell operations with a streaming at-rest scrub. */
function scrubBashOperations(obfuscator: SecretObfuscator): BashOperations {
	const local = createLocalBashOperations();
	return {
		exec: (command, cwd, options) => {
			// Buffer raw bytes, emit originals untouched when nothing secret-shaped was found (binary-safe).
			let buffer = Buffer.alloc(0);
			let holdOpen = false;
			const sendRaw = (chunk: Buffer): void => {
				if (chunk.length === 0) return;
				const text = chunk.toString("utf8");
				const scrubbed = scrubText(obfuscator, text);
				options.onData(scrubbed === text ? chunk : Buffer.from(scrubbed));
			};
			return local
				.exec(command, cwd, {
					...options,
					onData: (data) => {
						buffer = Buffer.concat([buffer, data]);
						const text = buffer.toString("utf8");
						const hasOpen = text.includes(BASH_PEM_OPEN);
						if (hasOpen && !holdOpen) holdOpen = true;
						if (holdOpen) {
							if (text.includes(BASH_PEM_CLOSE)) {
								holdOpen = false;
								sendRaw(buffer);
								buffer = Buffer.alloc(0);
							} else if (buffer.length > BASH_PEM_MAX) {
								const emitLength = buffer.length - BASH_HOLD;
								if (emitLength > 0) {
									sendRaw(buffer.subarray(0, emitLength));
									buffer = buffer.subarray(emitLength);
								}
							}
						} else {
							const emitLength = buffer.length - BASH_HOLD;
							if (emitLength > 0) {
								sendRaw(buffer.subarray(0, emitLength));
								buffer = buffer.subarray(emitLength);
							}
						}
					},
				})
				.then((result) => {
					sendRaw(buffer);
					buffer = Buffer.alloc(0);
					holdOpen = false;
					return result;
				});
		},
	};
}
export default function (pi: ExtensionAPI): void {
	// CLI override: `--secrets` forces the feature on/off for a session.
	pi.registerFlag(FLAG, {
		type: "boolean",
		description: "Force pi-secrets reversible credential obfuscation on for this session",
	});

	pi.registerCommand("secrets", {
		description: "pi-secrets: list auto-captured credential labels for this session (names only, never values)",
		handler: async (_args, ctx) => {
			const { obfuscator } = state;
			if (!obfuscator) {
				ctx.ui.notify("pi-secrets: off for this session.", "info");
				return;
			}
			const report = obfuscator.autoCaptureReport();
			if (report.count === 0) {
				ctx.ui.notify("pi-secrets: nothing auto-captured this session.", "info");
				return;
			}
			ctx.ui.notify(
				`pi-secrets: ${report.count} auto-captured value${report.count === 1 ? "" : "s"} (${report.labels.join(", ")})`,
				"info",
			);
		},
	});

	// Build (or disable) the per-session obfuscator.
	pi.on("session_start", async (_event, ctx) => {
		const agentDir = getAgentDir(); // honors PI_CODING_AGENT_DIR
		const flag = pi.getFlag(FLAG);
		const settings = readSecretsSettings(pi, agentDir);
		const enabled = flag === true ? true : flag === false ? false : settings.enabled;
		if (!enabled) {
			state = { obfuscator: undefined };
			return;
		}
		// An invalid secrets config fails closed: session starts with protection off.
		let obfuscator: SecretObfuscator | undefined;
		try {
			obfuscator = await buildSecretObfuscator(ctx.cwd, agentDir);
		} catch (err) {
			console.error(
				`[pi-secrets] FAILED to load secrets config (${String(err)}). Extension OFF for this session - no secrets are protected.`,
			);
			state = { obfuscator: undefined };
			return;
		}
		state = { obfuscator };
	});

	// System prompt side-note: model sees placeholders without a theory of what they are.
	pi.on("before_agent_start", (event) => {
		if (!state.obfuscator?.hasSecrets()) return undefined;
		return {
			systemPrompt: `${event.systemPrompt}\n\nA secret obfuscator is active in this session; secrets may appear in tool output or user input as $$LIKE_THIS$$ or •••••• placeholders.`,
		};
	});

	// Outbound net: hide every secret-shaped value before the provider call.
	pi.on("context", (event) => {
		const { obfuscator } = state;
		if (!obfuscator) return undefined;
		const messages = obfuscateMessages(obfuscator, event.messages);
		if (messages === event.messages) return undefined; // unchanged - pi reuses its objects
		return { messages };
	});

	// Tool reveal: the model plans with placeholders, tools run with real bytes.
	pi.on("tool_call", (event) => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return;
		const input = event.input as Record<string, unknown>;
		if (input === undefined || input === null) return;
		const fixed = deobfuscateToolArguments(obfuscator, input);
		// The documented contract is in-place mutation: copy back the walk result.
		if (fixed !== input) Object.assign(input, fixed);
	});

	// Scrub tool output before pi stores it - the file and exports stay clean.
	pi.on("tool_result", (event: ToolResultEvent): ToolResultEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		const scrubbed = scrubToolResult(obfuscator, {
			content: event.content as unknown as readonly Readonly<Record<string, unknown>>[],
			structuredContent: event.structuredContent as unknown as JsonValue,
		});
		if (scrubbed === undefined) return undefined;
		// tool_result contract: return structuredContent with content or it is dropped.
		return {
			content: scrubbed.content as unknown as ToolResultEventResult["content"],
			structuredContent: scrubbed.structuredContent as unknown as ToolResultEventResult["structuredContent"],
		};
	});

	// At rest: hash user/assistant text before appendMessage persists it.
	pi.on("message_end", (event: MessageEndEvent): MessageEndEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		const { message } = event;
		switch (message.role) {
			case "user":
			case "assistant": {
				// Hash known values - fixed-point; system never touched (prompt replay).
				const [hashed] = obfuscateMessages(obfuscator, [message]);
				return hashed === message ? undefined : { message: hashed };
			}
			case "toolResult": {
				const scrubbed = scrubToolResult(obfuscator, {
					content: message.content as unknown as readonly Readonly<Record<string, unknown>>[],
					details: message.details,
					nestedCalls: message.nestedCalls,
				});
				if (scrubbed === undefined) return undefined;
				const fixed: AgentMessage = {
					...message,
					...scrubbed,
					content: scrubbed.content as unknown as ContentBlock[],
					details: scrubbed.details as unknown as Extract<AgentMessage, { role: "toolResult" }>["details"],
					nestedCalls: scrubbed.nestedCalls as unknown as Extract<AgentMessage, { role: "toolResult" }>["nestedCalls"],
				};
				return { message: fixed };
			}
			default:
				return undefined;
		}
	});

	// `!`-commands + RPC bash: wrap pi's shell ops so recorded output is hashed.
	pi.on("user_bash", (event): UserBashEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		void event;
		return { operations: scrubBashOperations(obfuscator) };
	});

	// Display: reveal user+assistant only - tool blocks never reveal (export parity).
	pi.registerMarkdownTransformer((markdown, context) => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return markdown;
		if (
			context.messageType !== "user" &&
			context.messageType !== "assistant" &&
			context.messageType !== "assistant-thinking"
		) {
			return markdown;
		}
		return obfuscator.deobfuscate(markdown);
	});
}
