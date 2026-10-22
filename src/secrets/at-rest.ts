import { foldDumpViews } from "./dump-views";
import type { JsonValue, SecretObfuscator } from "./obfuscator";
import { mapJsonStrings } from "./placeholder-scan";
import { valueRedactionVerdict, valueVetoesRedaction } from "./value-gate";

const BULLET = "••••••";

const SECRET_NAME_RE = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(_|$)/i;

function isSecretName(name: string): boolean {
	const m = SECRET_NAME_RE.exec(name);
	if (m === null) return false;
	const i = m.index;
	if (i === 0) return true;
	const before = name[i - 1];
	if (before === "_") return true;
	return /[a-z]/.test(before) && /[A-Z]/.test(m[1][0]);
}

const ASSIGNMENT_NAME_RE = /["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?:=|:)/g;
const VALUE_RE = /^\s*(?:"([^"\s]{1,})"|'([^'\s]{1,})'|([^\s"']{1,}))/;
const CONNECTION_URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#@\s]+)@/gi;

export function redactShapes(text: string): string {
	if (text.length === 0) return text;
	const spans: Array<[number, number]> = [];

	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!isSecretName(match[1])) continue;
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const value = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		if (value.includes("$$")) continue;
		if (valueRedactionVerdict(match[1], value) === "keep") continue;
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

export function captureUnregistered(
	obfuscator: SecretObfuscator,
	text: string,
	options: { skipValueVeto?: boolean } = {},
): string {
	if (text.length === 0) return text;
	const seen = new Set<string>();
	const tryCapture = (value: string, friendlyName?: string): void => {
		if (value.includes("$$")) return;
		if (!options.skipValueVeto && valueVetoesRedaction(value)) return;
		if (obfuscator.isKnown(value)) return;
		if (seen.has(value)) return;
		seen.add(value);
		obfuscator.addPlainSecret(value, friendlyName);
	};

	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!isSecretName(match[1])) continue;
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const value = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		tryCapture(value, match[1]);
	}

	CONNECTION_URL_RE.lastIndex = 0;
	while ((match = CONNECTION_URL_RE.exec(text)) !== null) {
		tryCapture(match[1]);
	}
	return text;
}

export function scrubString(obfuscator: SecretObfuscator, text: string): string {
	if (text.length === 0) return text;
	const out = foldDumpViews(obfuscator, text);
	captureUnregistered(obfuscator, out);
	const hashed = obfuscator.obfuscate(out);
	return redactShapes(hashed);
}

type ScrubBlock = { type: "text"; text: string };

function scrubTextBlocks(
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

export function scrubJsonValue(obfuscator: SecretObfuscator, value: JsonValue | undefined): JsonValue | undefined {
	if (value === undefined) return undefined;
	return mapJsonStrings(value, (s) => scrubString(obfuscator, s));
}

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
