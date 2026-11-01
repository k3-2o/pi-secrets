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
import { scrubString as scrubText, scrubToolResult } from "./src/secrets/at-rest";
import { buildSecretObfuscator } from "./src/secrets/loaders";
import { deobfuscateToolArguments, obfuscateMessages } from "./src/secrets/message-transform";
import type { JsonValue, SecretObfuscator } from "./src/secrets/obfuscator";
import { createStreamScrubber } from "./src/secrets/stream-scrub";
import { readSecretsSettings } from "./src/settings";

type ContentBlock = Extract<AgentMessage, { role: "toolResult" }>["content"][number];

const FLAG = "secrets";

interface SessionState {
	obfuscator: SecretObfuscator | undefined;
}

let state: SessionState = { obfuscator: undefined };

function scrubBashOperations(obfuscator: SecretObfuscator): BashOperations {
	const local = createLocalBashOperations();
	return {
		exec: (command, cwd, options) => {
			const stream = createStreamScrubber({
				onData: (chunk) => options.onData(chunk),
				scrub: (text) => scrubText(obfuscator, text),
			});
			return local
				.exec(command, cwd, {
					...options,
					onData: (data) => stream.write(data),
				})
				.then((result) => {
					stream.flush();
					return result;
				})
				.catch((err) => {
					stream.flush();
					throw err;
				});
		},
	};
}
export default function (pi: ExtensionAPI): void {
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

	pi.on("session_start", async (_event, ctx) => {
		const agentDir = getAgentDir();
		const flag = pi.getFlag(FLAG);
		const settings = readSecretsSettings(pi, agentDir);
		const enabled = flag === true ? true : flag === false ? false : settings.enabled;
		if (!enabled) {
			state = { obfuscator: undefined };
			return;
		}

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

	pi.on("before_agent_start", (event) => {
		if (!state.obfuscator?.hasSecrets()) return undefined;
		return {
			systemPrompt: `${event.systemPrompt}\n\nObfuscation is active, secrets appear as $$HASH$$ references, resolved at use.`,
		};
	});

	pi.on("context", (event) => {
		const { obfuscator } = state;
		if (!obfuscator) return undefined;
		const messages = obfuscateMessages(obfuscator, event.messages);
		if (messages === event.messages) return undefined;
		return { messages };
	});

	pi.on("tool_call", (event) => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return;
		const input = event.input as Record<string, unknown>;
		if (input === undefined || input === null) return;
		const fixed = deobfuscateToolArguments(obfuscator, input);

		if (fixed !== input) Object.assign(input, fixed);
	});

	pi.on("tool_result", (event: ToolResultEvent): ToolResultEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		const scrubbed = scrubToolResult(obfuscator, {
			content: event.content as unknown as readonly Readonly<Record<string, unknown>>[],
			structuredContent: event.structuredContent as unknown as JsonValue,
		});
		if (scrubbed === undefined) return undefined;

		return {
			content: scrubbed.content as unknown as ToolResultEventResult["content"],
			structuredContent: scrubbed.structuredContent as unknown as ToolResultEventResult["structuredContent"],
		};
	});

	pi.on("message_end", (event: MessageEndEvent): MessageEndEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		const { message } = event;
		switch (message.role) {
			case "user":
			case "assistant": {
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

	pi.on("user_bash", (event): UserBashEventResult | undefined => {
		const { obfuscator } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		void event;
		return { operations: scrubBashOperations(obfuscator) };
	});

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
