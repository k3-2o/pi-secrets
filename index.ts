/**
 * pi-secrets — reversible credential obfuscation for pi.
 *
 * Port of OMP's secrets feature onto vanilla pi extension events (Phase 3).
 * The obfuscator hides secrets outbound (`context`), reveals them to tools
 * (`tool_call`) and to the human (`message_end`, or the render transformer in
 * "render" mode). Off by default; see Architecture.md for the full spec.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { buildSecretObfuscator } from "./src/secrets";
import {
	deobfuscateAssistantContent,
	deobfuscateToolArguments,
	obfuscateProviderContext,
} from "./src/secrets/message-transform";
import type { SecretObfuscator } from "./src/secrets/obfuscator";
import { readSecretsSettings } from "./src/settings";

const FLAG = "secrets";

interface SessionState {
	obfuscator: SecretObfuscator | undefined;
	mode: "persist" | "render";
}

let state: SessionState = { obfuscator: undefined, mode: "persist" };

export default function (pi: ExtensionAPI): void {
	// CLI override: `--secrets` forces the feature on/off for a session,
	// bypassing `secrets.enabled` in the settings.
	pi.registerFlag(FLAG, {
		type: "boolean",
		description: "Force pi-secrets reversible credential obfuscation on for this session",
	});

	// Build (or disable) the per-session obfuscator.
	pi.on("session_start", async (_event, ctx) => {
		const agentDir = getAgentDir(); // resolved per session: honors PI_CODING_AGENT_DIR
		const flag = pi.getFlag(FLAG);
		const settings = readSecretsSettings(pi, agentDir);
		const enabled = flag === true ? true : flag === false ? false : settings.enabled;
		if (!enabled) {
			state = { obfuscator: undefined, mode: settings.mode };
			return;
		}
		const obfuscator = await buildSecretObfuscator(ctx.cwd, agentDir);
		state = { obfuscator, mode: settings.mode };
	});

	// Outbound net: hide every secret-shaped value before the provider call.
	pi.on("context", (event) => {
		const { obfuscator } = state;
		if (!obfuscator) return undefined;
		const context = obfuscateProviderContext(obfuscator, { messages: event.messages });
		if (context.messages === event.messages) return undefined; // unchanged — pi reuses its objects
		return { messages: context.messages };
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

	// Display: reveal assistant-authored content for the human.
	pi.on("message_end", (event) => {
		const { obfuscator, mode } = state;
		if (!obfuscator?.hasSecrets()) return undefined;
		if (mode === "render") return undefined; // render mode reveals via the transformer below
		const { message } = event;
		if (message.role !== "assistant") return undefined;
		const content = deobfuscateAssistantContent(obfuscator, message.content);
		if (content === message.content) return undefined;
		return { message: { ...message, content } };
	});

	// Option A ("render" mode): display-only reveal at paint time; the session
	// file keeps hashes because `message_end` is left untouched above.
	pi.registerMarkdownTransformer((markdown, context) => {
		const { obfuscator, mode } = state;
		if (!obfuscator?.hasSecrets() || mode !== "render") return markdown;
		if (context.messageType !== "assistant" && context.messageType !== "assistant-thinking") return markdown;
		return obfuscator.deobfuscate(markdown);
	});
}
