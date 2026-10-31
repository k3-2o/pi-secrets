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

// Group 2 captures the operator: `:` is YAML/config shape in plain text but a type/object member in source code.
// Name bounded to 64 chars: unbounded `*` backtracks quadratically when a long non-assignment
// run (e.g. a hex blob) fails to find `=`/`:`, and the streaming scrub now feeds whole lines.
const ASSIGNMENT_NAME_RE = /["']?([A-Za-z_][A-Za-z0-9_]{0,63})["']?\s*(=|:)/g;
// Quoted alternatives span whitespace: `KEY="a b"` is a single value. The unquoted
// alternative stays whitespace-delimited; a value may still not START with a quote
// unless the line was quoted (an unclosed quote falls through and stays raw).
const VALUE_RE = /^\s*(?:"([^"]+)"|'([^']+)'|([^\s"']{1,}))/;
// Scheme bounded to 31 chars: with the i flag `[a-z]` matches any letter and the unbounded
// `*` backtracks quadratically on a long run that never reaches `://` (a hex/blob dump).
const CONNECTION_URL_RE = /[a-z][a-z0-9+.-]{0,30}:\/\/[^/:@?#\s]*:([^/?#@\s]+)@/gi;

const TRAILING_PUNCT_RE = /[;,)\]}]+$/;
// Values that carry bracket/call syntax are expressions, not credential tokens. Operators that live
// passwords legitimately use (`& ! ? ~ % ^ * + # - =`) must NOT be listed: `PASSWORD=Tr0ub4dor&3` is a secret.
const CODE_VALUE_RE = /[()[\]{}<>|`]/;
// `a.b.c` as a whole value is a member reference, never a credential (dots inside longer mixed values stay allowed).
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

// Credential-dump text (`.env`, transcripts, folded dumps) never stacks up code markers; source reads always do.
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

// Only runtime-learned (auto-captured) values are eligible; configured secrets.yml/env entries are never touched.
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
		// In code-shaped text an unquoted `name: value` is a type/object member, not a credential line.
		if (codeShaped && operator === ":" && !quoted) continue;
		// In code-shaped text a quoted value must not read as code vocabulary: short values (`"option:0"`,
		// `"Map:"`) and letter-only identifiers (`"systemPromptColor"`) are labels, not credentials.
		if (codeShaped && quoted && (raw.length < 12 || /^[A-Za-z]+$/.test(raw))) continue;
		let value = raw;
		if (!quoted) {
			const accepted = acceptedUnquotedValue(raw);
			if (accepted === undefined) continue;
			value = accepted;
		}
		if (value.includes("$$")) continue;
		// Trimming only ever removes trailing characters, so the start offset is unchanged.
		const valueStart = ASSIGNMENT_NAME_RE.lastIndex + valueMatch.index + valueMatch[0].lastIndexOf(raw);
		out.push({ name: match[1], value, valueStart, valueEnd: valueStart + value.length, quoted });
	}
	return out;
}

export function redactShapes(text: string): string {
	if (text.length === 0) return text;
	const spans: Array<[number, number]> = [];

	for (const c of assignmentCandidates(text)) {
		if (valueRedactionVerdict(c.name, c.value) === "keep") continue;
		spans.push([c.valueStart, c.valueEnd]);
	}

	CONNECTION_URL_RE.lastIndex = 0;
	let urlMatch: RegExpExecArray | null;
	while ((urlMatch = CONNECTION_URL_RE.exec(text)) !== null) {
		const password = urlMatch[1];
		if (password.includes("$$")) continue;
		const start = urlMatch.index + urlMatch[0].lastIndexOf(password);
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
	evictContradicted(obfuscator, text);
	const seen = new Set<string>();
	const tryCapture = (value: string, friendlyName?: string): void => {
		if (value.includes("$$")) return;
		if (!options.skipValueVeto && valueVetoesRedaction(value)) return;
		if (obfuscator.isKnown(value)) return;
		if (seen.has(value)) return;
		seen.add(value);
		obfuscator.addPlainSecret(value, friendlyName);
	};

	for (const c of assignmentCandidates(text)) {
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
