import type { JsonValue, SecretObfuscator } from "./obfuscator";
import { mapJsonStrings } from "./placeholder-scan";

/** At-rest redaction in order: known → `$$HASH$$` (fixed point), then secret-shaped assignment/URL spans → bullets; shapes skip `$$` spans; tool-authored output only. */

const BULLET = "••••••";

const SECRET_NAME_RE = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(_|$)/i;
// Name + delimiter only: a rejected name must never swallow a real assignment value.
const ASSIGNMENT_NAME_RE = /["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?:=|:)/g;
const VALUE_RE = /^\s*(?:"([^"\s]{4,})"|'([^'\s]{4,})'|([^\s"']{4,}))/;
const CONNECTION_URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#@\s]+)@/gi;

/** Replace the matched secret-shaped spans in `text` with bullets. */
export function redactShapes(text: string): string {
	if (text.length === 0) return text;
	const spans: Array<[number, number]> = [];

	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!SECRET_NAME_RE.test(match[1])) continue;
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const value = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		if (value.includes("$$")) continue; // already-hashed registered value - leave it
		const valueStart = ASSIGNMENT_NAME_RE.lastIndex + valueMatch.index + valueMatch[0].lastIndexOf(value);
		spans.push([valueStart, valueStart + value.length]);
	}

	CONNECTION_URL_RE.lastIndex = 0;
	while ((match = CONNECTION_URL_RE.exec(text)) !== null) {
		const password = match[1];
		if (password.includes("$$")) continue;
		const start = match.index + match[0].lastIndexOf(password);
		spans.push([start, start + password.length]);
	}

	if (spans.length === 0) return text;
	return replaceSpans(text, spans);
}

/** Sort + merge overlapping spans, then rebuild the string with bullets. */
function replaceSpans(text: string, spans: Array<[number, number]>): string {
	const sorted = spans.sort((a, b) => a[0] - b[0]);
	const merged: Array<[number, number]> = [];
	for (const [start, end] of sorted) {
		const last = merged[merged.length - 1];
		if (last !== undefined && start <= last[1]) {
			last[1] = Math.max(last[1], end);
		} else {
			merged.push([start, end]);
		}
	}
	let out = "";
	let cursor = 0;
	for (const [start, end] of merged) {
		out += text.slice(cursor, start);
		out += BULLET;
		cursor = end;
	}
	return out + text.slice(cursor);
}

/** Auto-capture: register unregistered assignment/URL values as plain obfuscate secrets before hashing - same gates as `redactShapes`; input returned unchanged. */
export function captureUnregistered(obfuscator: SecretObfuscator, text: string): string {
	if (text.length === 0) return text;
	const seen = new Set<string>();
	const tryCapture = (value: string, friendlyName?: string): void => {
		if (value.includes("$$")) return; // already-hashed span - leave it
		if (obfuscator.isKnown(value)) return;
		if (seen.has(value)) return;
		seen.add(value);
		obfuscator.addPlainSecret(value, friendlyName); // length floor enforced inside
	};

	// Credential-*named* assignments: `API_KEY=…`, `"apiKey": "…"`, `key: '…'`.
	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!SECRET_NAME_RE.test(match[1])) continue;
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const value = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		tryCapture(value, match[1]);
	}

	// Connection-URL passwords: `scheme://user:password@host`.
	CONNECTION_URL_RE.lastIndex = 0;
	while ((match = CONNECTION_URL_RE.exec(text)) !== null) {
		tryCapture(match[1]);
	}
	return text;
}

/** Known values → `$$HASH$$`, then secret-shaped spans → bullets. */
export function scrubString(obfuscator: SecretObfuscator, text: string): string {
	if (text.length === 0) return text;
	captureUnregistered(obfuscator, text); // registers unknowns before hashing (learn on first sight)
	const hashed = obfuscator.obfuscate(text);
	return redactShapes(hashed);
}

/** A text-bearing block (the subset of content blocks we rewrite). */
type ScrubBlock = { type: "text"; text: string };

/** Scrub `text` blocks of a content array; other blocks (images) pass through. */
export function scrubTextBlocks(
	obfuscator: SecretObfuscator,
	content: readonly Readonly<Record<string, unknown>>[],
): readonly Readonly<Record<string, unknown>>[] {
	let changed = false;
	const result = content.map((block): Readonly<Record<string, unknown>> => {
		if (block === null || typeof block !== "object") return block;
		const candidate = block as Readonly<ScrubBlock>;
		if (candidate.type !== "text" || typeof candidate.text !== "string") return block;
		const text = scrubString(obfuscator, candidate.text);
		if (text === candidate.text) return block;
		changed = true;
		return { ...candidate, text };
	});
	return changed ? result : content;
}

/** Scrub every string inside a JSON value (structuredContent, details, …). */
export function scrubJsonValue(obfuscator: SecretObfuscator, value: JsonValue | undefined): JsonValue | undefined {
	if (value === undefined) return undefined;
	return mapJsonStrings(value, (s) => scrubString(obfuscator, s));
}

/** One tool-result unit: what `tool_result` and the persisted toolResult message carry. */
export interface ToolResultScrubInput {
	content: readonly Readonly<Record<string, unknown>>[];
	structuredContent?: JsonValue;
	details?: unknown;
	nestedCalls?: { calls: Array<{ arguments?: unknown }>; complete: boolean };
}

export interface ToolResultScrubOutput {
	content: readonly Readonly<Record<string, unknown>>[];
	structuredContent?: JsonValue;
	details?: unknown;
	nestedCalls?: { calls: Array<{ arguments?: unknown }>; complete: boolean };
}

/** Scrub a tool result for persistence; `undefined` when unchanged (tool_result drops structuredContent if content is replaced without it). */
export function scrubToolResult(
	obfuscator: SecretObfuscator,
	input: ToolResultScrubInput,
): ToolResultScrubOutput | undefined {
	if (!obfuscator.hasSecrets()) return undefined;
	return obfuscator.batch(() => {
		const content = scrubTextBlocks(obfuscator, input.content);
		const structuredContent =
			input.structuredContent === undefined ? undefined : scrubJsonValue(obfuscator, input.structuredContent);
		const details = input.details === undefined ? undefined : scrubJsonValue(obfuscator, input.details as JsonValue);
		let nestedCalls = input.nestedCalls;
		let nestedChanged = false;
		if (nestedCalls?.calls && nestedCalls.calls.length > 0) {
			const calls = nestedCalls.calls.map((call) => {
				if (call.arguments === undefined) return call;
				const args = scrubJsonValue(obfuscator, call.arguments as JsonValue);
				if (args === call.arguments) return call;
				nestedChanged = true;
				return { ...call, arguments: args };
			});
			if (nestedChanged) nestedCalls = { ...nestedCalls, calls };
		}
		if (
			content === input.content &&
			structuredContent === input.structuredContent &&
			details === input.details &&
			!nestedChanged
		) {
			return undefined;
		}
		return { content, structuredContent, details, nestedCalls };
	});
}
