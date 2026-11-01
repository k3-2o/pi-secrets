import type { JsonRecord, JsonValue, SecretObfuscator } from "./obfuscator";
import {
	lookupFriendlyPlaceholderAlias,
	PLACEHOLDER_RE,
	type RegexScanSegment,
	type ReplaceRegexScan,
	resumePlaceholderScanAfterRejectedCandidate,
	SecretValueSet,
} from "./placeholder";

export function transformOutsidePlaceholdersTracked(
	text: string,
	origin: string,
	shouldSkipPlaceholder: (placeholder: string) => boolean,
	transform: (chunk: string) => string,
	preservePlaceholder?: (placeholder: string) => string,
): { text: string; origin: string } {
	PLACEHOLDER_RE.lastIndex = 0;
	let result = "";
	let resultOrigin = "";
	let pendingIndex = 0;
	for (;;) {
		const match = PLACEHOLDER_RE.exec(text);
		if (match === null) break;
		if (!shouldSkipPlaceholder(match[0])) {
			resumePlaceholderScanAfterRejectedCandidate(match);
			continue;
		}
		const transformed = transform(text.slice(pendingIndex, match.index));
		result += transformed;
		resultOrigin += "I".repeat(transformed.length);
		const preserved = preservePlaceholder ? preservePlaceholder(match[0]) : match[0];
		result += preserved;
		resultOrigin += origin.slice(match.index, match.index + match[0].length);
		pendingIndex = match.index + match[0].length;
	}
	const trailing = transform(text.slice(pendingIndex));
	result += trailing;
	resultOrigin += "I".repeat(trailing.length);
	return { text: result, origin: resultOrigin };
}

export function trailingOutsidePreservedPlaceholderChunk(
	text: string,
	shouldPreservePlaceholder: (placeholder: string) => boolean,
): string {
	PLACEHOLDER_RE.lastIndex = 0;
	let pendingIndex = 0;
	let sawPlaceholder = false;
	for (;;) {
		const match = PLACEHOLDER_RE.exec(text);
		if (match === null) break;
		if (!shouldPreservePlaceholder(match[0])) {
			resumePlaceholderScanAfterRejectedCandidate(match);
			continue;
		}
		sawPlaceholder = true;
		pendingIndex = match.index + match[0].length;
	}
	return sawPlaceholder ? text.slice(pendingIndex) : "";
}

export function buildReplaceRegexScan(
	text: string,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
): ReplaceRegexScan {
	let scanText = "";
	let cursor = 0;
	const segments: RegexScanSegment[] = [];
	const appendSegment = (
		value: string,
		textStart: number,
		textEnd: number,
		generatedPlaceholder: boolean,
		recursive: boolean,
	) => {
		if (value.length === 0) return;
		const scanStart = scanText.length;
		scanText += value;
		segments.push({
			scanStart,
			scanEnd: scanStart + value.length,
			textStart,
			textEnd,
			generatedPlaceholder,
			recursive,
		});
	};

	for (const range of ranges) {
		appendSegment(text.slice(cursor, range.start), cursor, range.start, false, false);
		const placeholder = text.slice(range.start, range.end);
		const mapping = lookupFriendlyPlaceholderAlias(deobfuscateMap, placeholder);
		appendSegment(mapping?.secret ?? placeholder, range.start, range.end, true, mapping?.recursive ?? false);
		cursor = range.end;
	}
	appendSegment(text.slice(cursor), cursor, text.length, false, false);

	return { text: scanText, segments };
}

export function mapReplaceRegexMatch(
	segments: ReadonlyArray<RegexScanSegment>,
	scanStart: number,
	scanEnd: number,
): {
	start: number;
	end: number;
	recursive: boolean;
	preserveGeneratedPlaceholders: boolean;
	partialPlaceholderCut: boolean;
	cutResumeIndex: number;
	firstPlaceholderScanStart: number;
} {
	const startSegment = findScanSegment(segments, scanStart);
	const endSegment = findScanSegment(segments, scanEnd - 1);
	const start = startSegment.generatedPlaceholder
		? startSegment.textStart
		: startSegment.textStart + (scanStart - startSegment.scanStart);
	const end = endSegment.generatedPlaceholder
		? endSegment.textEnd
		: endSegment.textStart + (scanEnd - endSegment.scanStart);

	const partialPlaceholderCut =
		(startSegment.generatedPlaceholder && scanStart > startSegment.scanStart) ||
		(endSegment.generatedPlaceholder && scanEnd < endSegment.scanEnd);
	let recursive = false;
	let preserveGeneratedPlaceholders = false;

	let cutResumeIndex = scanStart;
	let firstPlaceholderScanStart = -1;
	for (const segment of segments) {
		if (segment.scanStart >= scanEnd || segment.scanEnd <= scanStart) continue;
		recursive ||= segment.recursive;
		preserveGeneratedPlaceholders ||= segment.generatedPlaceholder;
		if (segment.generatedPlaceholder) {
			if (firstPlaceholderScanStart === -1) firstPlaceholderScanStart = segment.scanStart;
			if (segment.scanEnd > cutResumeIndex) cutResumeIndex = segment.scanEnd;
		}
	}
	return {
		start,
		end,
		recursive,
		preserveGeneratedPlaceholders,
		partialPlaceholderCut,
		cutResumeIndex,
		firstPlaceholderScanStart,
	};
}

function findScanSegment(segments: ReadonlyArray<RegexScanSegment>, scanIndex: number): RegexScanSegment {
	for (const segment of segments) {
		if (scanIndex >= segment.scanStart && scanIndex < segment.scanEnd) return segment;
	}
	throw new Error("regex match did not map to source text");
}

export function extendPastAdjacentPlaceholders(segments: ReadonlyArray<RegexScanSegment>, index: number): number {
	let cursor = index;
	for (;;) {
		const segment = segments.find((candidate) => candidate.scanStart === cursor && candidate.generatedPlaceholder);
		if (!segment) return cursor;
		cursor = segment.scanEnd;
	}
}

export function redactWithFixedReplacementOutsidePlaceholders(
	text: string,
	origin: string,
	replacement: string,
	shouldPreservePlaceholder: (placeholder: string) => boolean,
): { text: string; origin: string } {
	let emitted = false;
	return transformOutsidePlaceholdersTracked(
		text,
		origin,
		shouldPreservePlaceholder,
		(chunk) => {
			if (chunk.length === 0) return "";
			if (!emitted) {
				emitted = true;
				return replacement;
			}
			return replacement.startsWith(chunk) ? replacement : "";
		},
		(placeholder) => placeholder,
	);
}

export function deobfuscateGeneratedPlaceholderRanges(
	text: string,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
): { text: string; recursive: boolean } {
	let result = "";
	let cursor = start;
	let recursive = false;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		result += text.slice(cursor, overlapStart);
		const placeholder = text.slice(overlapStart, overlapEnd);
		const mapping = lookupFriendlyPlaceholderAlias(deobfuscateMap, placeholder);
		result += mapping?.secret ?? placeholder;
		recursive ||= mapping?.recursive ?? false;
		cursor = overlapEnd;
	}
	result += text.slice(cursor, end);
	return { text: result, recursive };
}

export function placeholderInnerText(
	text: string,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
): string {
	let result = "";
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		const placeholder = text.slice(overlapStart, overlapEnd);
		const mapping = lookupFriendlyPlaceholderAlias(deobfuscateMap, placeholder);
		result += mapping?.secret ?? placeholder;
	}
	return result;
}

export function textOutsidePlaceholderRanges(
	text: string,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): string {
	let result = "";
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		result += text.slice(cursor, overlapStart);
		cursor = overlapEnd;
	}
	result += text.slice(cursor, end);
	return result;
}

export function outsidePlaceholderRangesAnyIndependentlyMatch(
	text: string,
	scanText: string,
	segments: ReadonlyArray<RegexScanSegment>,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	regex: RegExp,
): boolean {
	const toScanSpace = (chunkStart: number, chunkEnd: number): [number, number] | undefined => {
		for (const segment of segments) {
			if (segment.generatedPlaceholder || segment.textStart > chunkStart || segment.textEnd < chunkEnd) continue;
			const offset = segment.scanStart - segment.textStart;
			return [chunkStart + offset, chunkEnd + offset];
		}
		return undefined;
	};
	const chunkIndependentlyMatches = (chunkStart: number, chunkEnd: number): boolean => {
		if (chunkMatchesInSourceContext(text, chunkStart, chunkEnd, regex)) return true;
		const scanSpan = toScanSpace(chunkStart, chunkEnd);
		return scanSpan !== undefined && chunkMatchesInSourceContext(scanText, scanSpan[0], scanSpan[1], regex);
	};
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		if (cursor < overlapStart && chunkIndependentlyMatches(cursor, overlapStart)) return true;
		cursor = overlapEnd;
	}
	return cursor < end && chunkIndependentlyMatches(cursor, end);
}

function chunkMatchesInSourceContext(text: string, chunkStart: number, chunkEnd: number, regex: RegExp): boolean {
	regex.lastIndex = chunkStart;
	for (;;) {
		const found = regex.exec(text);
		if (found === null || found.index >= chunkEnd) return false;
		const matchEnd = found.index + found[0].length;
		if (matchEnd <= chunkEnd) return true;
		regex.lastIndex = found[0].length === 0 ? found.index + 1 : matchEnd;
	}
}

export function firstOutsidePlaceholderRange(
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): { start: number; end: number } | undefined {
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		if (cursor < overlapStart) return { start: cursor, end: overlapStart };
		cursor = overlapEnd;
	}
	return cursor < end ? { start: cursor, end } : undefined;
}

export function countOutsidePlaceholderRanges(
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): number {
	let count = 0;
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		if (cursor < overlapStart) count++;
		cursor = overlapEnd;
	}
	if (cursor < end) count++;
	return count;
}

export function replaceRange(text: string, start: number, end: number, replacement: string): string {
	return text.slice(0, start) + replacement + text.slice(end);
}

export function collectJsonRegexSecretValues(obfuscator: SecretObfuscator, value: JsonValue): SecretValueSet {
	const values = new SecretValueSet();
	const collect = (item: JsonValue): void => {
		if (typeof item === "string") {
			for (const secretValue of obfuscator.collectRegexSecretValuesForObfuscation(item)) {
				values.add(secretValue);
			}
			return;
		}
		if (Array.isArray(item)) {
			for (const child of item) collect(child);
			return;
		}
		if (item !== null && typeof item === "object") {
			for (const child of Object.values(item)) {
				if (child !== undefined) collect(child);
			}
		}
	};
	collect(value);
	return values;
}

export function mapJsonStrings(value: JsonValue, fn: (s: string) => string): JsonValue {
	if (typeof value === "string") return fn(value);
	if (Array.isArray(value)) {
		let out: JsonValue[] | undefined;
		for (let index = 0; index < value.length; index++) {
			const item = value[index]!;
			const next = mapJsonStrings(item, fn);
			if (next === item) continue;
			out ??= value.slice();
			out[index] = next;
		}
		return out ?? value;
	}
	if (value !== null && typeof value === "object") {
		let out: JsonRecord | undefined;
		for (const key in value) {
			if (!Object.hasOwn(value, key)) continue;
			const item = value[key];
			if (item === undefined) continue;
			const next = mapJsonStrings(item, fn);
			if (next === item) continue;
			out ??= { ...value };
			out[key] = next;
		}
		return out ?? value;
	}
	return value;
}
