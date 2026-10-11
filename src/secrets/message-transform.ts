import type { AgentMessage } from "@earendil-works/pi-agent-core";
import type { JsonObject } from "@earendil-works/pi-ai";
import { captureUnregistered } from "./at-rest";
import type { JsonValue, SecretObfuscator } from "./obfuscator";
import { SecretValueSet } from "./placeholder";
import { collectJsonRegexSecretValues, mapJsonStrings } from "./placeholder-scan";

type AssistantContent = Extract<AgentMessage, { role: "assistant" }>["content"];
/** Tool-result content is always a block array; user content may be a string. */
type ContentBlocks = Extract<AgentMessage, { role: "toolResult" }>["content"];
type UserFacingMessage = Extract<AgentMessage, { role: "user" | "toolResult" }>;

/** Reveal in assistant-authored content only; user/tool-result roles are never walked so operator-shaped text survives. */
export function deobfuscateAgentMessages(obfuscator: SecretObfuscator, messages: AgentMessage[]): AgentMessage[] {
	const deob = (text: string): string => obfuscator.deobfuscate(text);
	let changed = false;
	const result = messages.map((message): AgentMessage => {
		switch (message.role) {
			case "assistant": {
				const content = deobfuscateAssistantContent(obfuscator, message.content);
				if (content === message.content) return message;
				changed = true;
				return { ...message, content };
			}
			case "branchSummary": {
				const summary = deob(message.summary);
				if (summary === message.summary) return message;
				changed = true;
				return { ...message, summary };
			}
			case "compactionSummary": {
				const summary = deob(message.summary);
				if (summary === message.summary) return message;
				changed = true;
				return { ...message, summary };
			}
			default:
				return message;
		}
	});
	return changed ? result : messages;
}

/** Restore placeholders in assistant text and tool-call arguments (thinking passes through byte-identical). */
export function deobfuscateAssistantContent(obfuscator: SecretObfuscator, content: AssistantContent): AssistantContent {
	if (!obfuscator.hasSecrets()) return content;
	const deob = (text: string): string => obfuscator.deobfuscate(text);
	let changed = false;
	const result = content.map((block): AssistantContent[number] => {
		if (block.type === "text") {
			const text = deob(block.text);
			if (text === block.text) return block;
			changed = true;
			return { ...block, text };
		}

		if (block.type === "toolCall") {
			const args = deobfuscateToolArguments(obfuscator, block.arguments);
			if (args === block.arguments) return block;
			changed = true;
			return { ...block, arguments: args as unknown as JsonObject };
		}
		return block;
	});
	return changed ? result : content;
}

/** Restore placeholders in model-authored argument values. Argument keys name tool parameters and must remain unchanged. */
export function deobfuscateToolArguments(
	obfuscator: SecretObfuscator,
	args: Record<string, unknown>,
): Record<string, unknown> {
	if (!obfuscator.hasSecrets()) return args;
	return mapJsonStrings(args as JsonValue, (s) => obfuscator.deobfuscate(s)) as Record<string, unknown>;
}

/** Redact secrets inside a tool call's arguments (same JSON-walk exception as {@link deobfuscateToolArguments}). */
export function obfuscateToolArguments(
	obfuscator: SecretObfuscator,
	args: Record<string, unknown>,
	sharedRegexSecretValues?: ReadonlySet<string>,
): Record<string, unknown> {
	if (!obfuscator.hasSecrets()) return args;
	// `batch()` joins an outer batch when one is already open.
	return obfuscator.batch(() => {
		const regexSecretValues = sharedRegexSecretValues ?? collectJsonRegexSecretValues(obfuscator, args as JsonValue);
		return mapJsonStrings(args as JsonValue, (s) => obfuscator.obfuscate(s, regexSecretValues)) as Record<
			string,
			unknown
		>;
	});
}

/** Obfuscate `text` blocks of a content array; image and other blocks pass through. */
function obfuscateTextBlocks(
	obfuscator: SecretObfuscator,
	content: ContentBlocks,
	sharedRegexSecretValues?: ReadonlySet<string>,
): ContentBlocks {
	let changed = false;
	const result = content.map((block): ContentBlocks[number] => {
		if (block.type !== "text") return block;
		const text = obfuscator.obfuscate(block.text, sharedRegexSecretValues);
		if (text === block.text) return block;
		changed = true;
		return { ...block, text };
	});
	return changed ? result : content;
}

/** Restore placeholders in `text` blocks of a content array; image and other blocks pass through. */
export function deobfuscateTextBlocks(obfuscator: SecretObfuscator, content: ContentBlocks): ContentBlocks {
	if (!obfuscator.hasSecrets()) return content;
	let changed = false;
	const result = content.map((block): ContentBlocks[number] => {
		if (block.type !== "text") return block;
		const text = obfuscator.deobfuscate(block.text);
		if (text === block.text) return block;
		changed = true;
		return { ...block, text };
	});
	return changed ? result : content;
}

/** Re-obfuscate assistant content after restoration, dropping friendly prefixes made unsafe by this batch. */
function obfuscateAssistantContentForReplay(
	obfuscator: SecretObfuscator,
	content: AssistantContent,
	sharedRegexSecretValues: ReadonlySet<string>,
): AssistantContent {
	const obfuscate = (text: string): string =>
		obfuscator.stripUnsafeFriendlyPlaceholderPrefixes(
			obfuscator.obfuscate(text, sharedRegexSecretValues),
			sharedRegexSecretValues,
		);
	let changed = false;
	const result = content.map((block): AssistantContent[number] => {
		if (block.type === "text") {
			const text = obfuscate(block.text);
			if (text === block.text) return block;
			changed = true;
			return { ...block, text };
		}
		if (block.type === "thinking") {
			const thinking = obfuscate(block.thinking);
			if (thinking === block.thinking) return block;
			changed = true;
			return { ...block, thinking, thinkingSignature: undefined };
		}
		if (block.type === "toolCall") {
			const args = mapJsonStrings(block.arguments as JsonValue, obfuscate) as Record<string, unknown>;
			if (args === block.arguments) return block;
			changed = true;
			return { ...block, arguments: args as unknown as JsonObject };
		}
		return block;
	});
	return changed ? result : content;
}

/** One shared collision set per batch - a value obfuscated elsewhere must not re-obfuscate its own placeholder. */
function collectMessageRegexSecretValues(obfuscator: SecretObfuscator, messages: AgentMessage[]): SecretValueSet {
	const values = new SecretValueSet();
	const addText = (text: string | undefined): void => {
		if (text === undefined) return;
		for (const value of obfuscator.collectRegexSecretValuesForObfuscation(text)) {
			values.add(value);
		}
	};
	for (const message of messages) {
		if (message.role === "assistant") {
			for (const block of message.content) {
				if (block.type === "text") addText(block.text);
				else if (block.type === "thinking") addText(block.thinking);
				else if (block.type === "toolCall") {
					for (const value of collectJsonRegexSecretValues(obfuscator, block.arguments as JsonValue)) {
						values.add(value);
					}
				}
			}
			continue;
		}
		if (message.role !== "user" && message.role !== "toolResult") continue;
		const target = message as UserFacingMessage;
		if (typeof target.content === "string") {
			addText(target.content);
			continue;
		}
		for (const block of target.content) {
			if (block.type === "text") addText(block.text);
		}
	}
	return values;
}

/** Obfuscate user/toolResult; re-obfuscate assistant replay (restoration expands placeholders); inline images never walked. */
export function obfuscateMessages(obfuscator: SecretObfuscator, messages: AgentMessage[]): AgentMessage[] {
	// Capture assignment/URL values first - capture seeds the registry even when empty.
	for (const message of messages) {
		if ("content" in message) captureContentText(obfuscator, message.content);
	}
	if (!obfuscator.obfuscates()) return messages;
	return obfuscator.batch(() => obfuscateMessageBatch(obfuscator, messages));
}

/** Capture unregistered assignment/URL-password values in message text (content blocks). */
function captureContentText(obfuscator: SecretObfuscator, content: unknown): void {
	if (typeof content === "string") {
		captureUnregistered(obfuscator, content);
		return;
	}
	if (!Array.isArray(content)) return;
	for (const block of content) {
		if (
			block !== null &&
			typeof block === "object" &&
			"type" in block &&
			(block as { type?: unknown }).type === "text" &&
			typeof (block as { text?: unknown }).text === "string"
		) {
			captureUnregistered(obfuscator, (block as { text: string }).text);
		}
	}
}

function obfuscateMessageBatch(obfuscator: SecretObfuscator, messages: AgentMessage[]): AgentMessage[] {
	const sharedRegexSecretValues = collectMessageRegexSecretValues(obfuscator, messages);
	let changed = false;
	const result = messages.map((message): AgentMessage => {
		if (message.role === "assistant") {
			const content = obfuscateAssistantContentForReplay(obfuscator, message.content, sharedRegexSecretValues);
			if (content === message.content) return message;
			changed = true;
			return { ...message, content };
		}
		if (message.role !== "user" && message.role !== "toolResult") return message;
		const target = message as UserFacingMessage;
		if (typeof target.content === "string") {
			const content = obfuscator.obfuscate(target.content, sharedRegexSecretValues);
			if (content === target.content) return message;
			changed = true;
			return { ...target, content } as AgentMessage;
		}
		const content = obfuscateTextBlocks(obfuscator, target.content, sharedRegexSecretValues);
		if (content === target.content) return message;
		changed = true;
		return { ...target, content } as AgentMessage;
	});
	return changed ? result : messages;
}

/** Outbound provider context: just the conversation messages (the static system prompt stays untouched). */
export interface ProviderContext {
	messages: AgentMessage[];
}

/** Redact outbound provider context; returns the same context object when nothing changed. */
export function obfuscateProviderContext(
	obfuscator: SecretObfuscator | undefined,
	context: ProviderContext,
): ProviderContext {
	if (!obfuscator?.obfuscates()) return context;
	const messages = obfuscateMessages(obfuscator, context.messages);
	return messages === context.messages ? context : { ...context, messages };
}
