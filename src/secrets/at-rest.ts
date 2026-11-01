import { foldDumpViews } from "./dump-views";
import type { JsonValue, SecretObfuscator } from "./obfuscator";
import { mapJsonStrings } from "./placeholder-scan";
import { valueRedactionVerdict, valueVetoesRedaction } from "./value-gate";

const BULLET_CHAR = "•";

function isLegacyRedacted(value: string): boolean {
	return value.includes(BULLET_CHAR);
}

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

const ASSIGNMENT_NAME_RE = /["']?([A-Za-z_][A-Za-z0-9_]{0,63})["']?\s*(=|:)/g;

const VALUE_RE = /^\s*(?:"([^"]+)"|'([^']+)'|([^\s"']{1,}))/;

const CONNECTION_URL_RE = /[a-z][a-z0-9+.-]{0,30}:\/\/[^/:@?#\s]*:([^/?#\s]+)@/gi;

const TRAILING_PUNCT_RE = /[;,)\]}]+$/;

const CODE_VALUE_RE = /[()[\]{}<>|`]/;

const DOTTED_REFERENCE_RE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;
const JS_LITERAL_VALUES = new Set(["undefined", "null", "true", "false", "NaN", "Infinity"]);

function refusableValueShape(value: string): boolean {
	return CODE_VALUE_RE.test(value) || DOTTED_REFERENCE_RE.test(value) || JS_LITERAL_VALUES.has(value);
}

interface AssignmentCandidate {
	name: string;
	value: string;
	valueStart: number;
	valueEnd: number;
	quoted: boolean;
}

const CODE_LINE_RE =
	/=>|\b(?:const|let|var|function|class|interface|type|enum|import|export|return|async|public|private|readonly)\b|\?\.|[;{}]\s*$/;
const CODE_MIN_LINES = 3;
const CODE_MIN_RATIO = 0.15;

function looksLikeCode(text: string): boolean {
	let nonEmpty = 0;
	let code = 0;
	for (const line of text.split("\n")) {
		if (line.length === 0) continue;
		nonEmpty++;
		if (CODE_LINE_RE.test(line)) code++;
	}
	return code >= CODE_MIN_LINES && code / nonEmpty >= CODE_MIN_RATIO;
}

function acceptedUnquotedValue(raw: string): string | undefined {
	const value = raw.replace(TRAILING_PUNCT_RE, "");
	if (value.length === 0 || refusableValueShape(value)) return undefined;
	return value;
}

function evictContradicted(obfuscator: SecretObfuscator, text: string): void {
	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!isSecretName(match[1])) continue;
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const raw = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		const trimmed = raw.replace(TRAILING_PUNCT_RE, "");
		if (!refusableValueShape(trimmed)) continue;
		if (obfuscator.isAutoCaptured(raw)) obfuscator.removeAutoCaptured(raw);
		if (obfuscator.isAutoCaptured(trimmed)) obfuscator.removeAutoCaptured(trimmed);
	}
}

function assignmentCandidates(text: string): AssignmentCandidate[] {
	const out: AssignmentCandidate[] = [];
	const codeShaped = looksLikeCode(text);
	ASSIGNMENT_NAME_RE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_NAME_RE.exec(text)) !== null) {
		if (!isSecretName(match[1])) continue;
		const operator = match[2];
		const valueMatch = VALUE_RE.exec(text.slice(ASSIGNMENT_NAME_RE.lastIndex));
		if (valueMatch === null) continue;
		const raw = valueMatch[1] ?? valueMatch[2] ?? valueMatch[3];
		const quoted = valueMatch[1] !== undefined || valueMatch[2] !== undefined;

		if (codeShaped && operator === ":" && !quoted) continue;

		if (codeShaped && quoted && (raw.length < 12 || /^[A-Za-z]+$/.test(raw))) continue;
		let value = raw;
		if (!quoted) {
			const accepted = acceptedUnquotedValue(raw);
			if (accepted === undefined) continue;
			value = accepted;
		}
		if (value.includes("$$") || isLegacyRedacted(value)) continue;

		const valueStart = ASSIGNMENT_NAME_RE.lastIndex + valueMatch.index + valueMatch[0].lastIndexOf(raw);
		out.push({ name: match[1], value, valueStart, valueEnd: valueStart + value.length, quoted });
	}
	return out;
}

interface ShapeSpan {
	start: number;
	end: number;
	value: string;
	name: string | undefined;
}

export function hashShapes(obfuscator: SecretObfuscator, text: string): string {
	if (text.length === 0) return text;
	const spans: ShapeSpan[] = [];

	for (const c of assignmentCandidates(text)) {
		if (valueRedactionVerdict(c.name, c.value) === "keep") continue;
		spans.push({ start: c.valueStart, end: c.valueEnd, value: c.value, name: c.name });
	}

	CONNECTION_URL_RE.lastIndex = 0;
	let urlMatch: RegExpExecArray | null;
	while ((urlMatch = CONNECTION_URL_RE.exec(text)) !== null) {
		const password = urlMatch[1];
		if (password.includes("$$") || isLegacyRedacted(password)) continue;
		const start = urlMatch.index + urlMatch[0].lastIndexOf(password);
		spans.push({ start, end: start + password.length, value: password, name: undefined });
	}

	if (spans.length === 0) return text;

	const sorted = spans.sort((a, b) => a.start - b.start);
	const merged: ShapeSpan[] = [];
	for (const span of sorted) {
		const last = merged[merged.length - 1];
		if (last !== undefined && span.start <= last.end) {
			last.end = Math.max(last.end, span.end);
		} else {
			merged.push(span);
		}
	}

	for (let i = merged.length - 1; i >= 0; i--) {
		const span = merged[i]!;
		const placeholder = obfuscator.placeholderForSpan(span.value, span.name);
		text = text.slice(0, span.start) + placeholder + text.slice(span.end);
	}
	return text;
}

export function captureUnregistered(
	obfuscator: SecretObfuscator,
	text: string,
	options: { skipValueVeto?: boolean } = {},
): string {
	if (text.length === 0) return text;
	evictContradicted(obfuscator, text);
	const seen = new Set<string>();
	const tryCapture = (value: string, friendlyName?: string): void => {
		if (value.includes("$$")) return;
		if (isLegacyRedacted(value)) return;
		if (!options.skipValueVeto && valueVetoesRedaction(value)) return;
		if (obfuscator.isKnown(value)) return;
		if (seen.has(value)) return;
		seen.add(value);
		obfuscator.addPlainSecret(value, friendlyName);
	};

	for (const c of assignmentCandidates(text)) {
		if (valueRedactionVerdict(c.name, c.value) === "keep") continue;
		tryCapture(c.value, c.name);
	}

	CONNECTION_URL_RE.lastIndex = 0;
	let urlMatch: RegExpExecArray | null;
	while ((urlMatch = CONNECTION_URL_RE.exec(text)) !== null) {
		tryCapture(urlMatch[1]);
	}
	return text;
}

export function scrubString(obfuscator: SecretObfuscator, text: string): string {
	if (text.length === 0) return text;
	const out = foldDumpViews(obfuscator, text);
	captureUnregistered(obfuscator, out);
	const hashed = obfuscator.obfuscate(out);
	return hashShapes(obfuscator, hashed);
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
