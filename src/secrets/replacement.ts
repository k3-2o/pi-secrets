import { createHash } from "node:crypto";

export const REPLACEMENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const NONMATCHING_REPLACEMENT_CHARS = `${REPLACEMENT_CHARS}!#$%&()*+,-./:;<=>?@[]^_{|}~`;

const WHITESPACE_REPLACEMENT_CHARS = " \t";

function seedFromString(value: string): bigint {
	const hex = createHash("sha256").update(value).digest("hex").slice(0, 16);
	return BigInt(`0x${hex}`);
}

export function generateDeterministicReplacement(secret: string): string {
	if (secret.length === 0) return "";

	const hash = seedFromString(secret);
	const chars = secret.length === 1 ? ["Z"] : ["Z", "Z"];
	let h = hash;
	for (let i = chars.length; i < secret.length; i++) {
		h = h ^ (BigInt(i + 1) * 0x9e3779b97f4a7c15n);
		const idx = Number((h < 0n ? -h : h) % BigInt(REPLACEMENT_CHARS.length));
		chars.push(REPLACEMENT_CHARS[idx]);
	}
	return chars.join("");
}

export function ensureDistinctReplacement(replacement: string, secret: string): string {
	if (replacement.length === 0 || replacement !== secret) return replacement;
	const alt = replacement[0] === REPLACEMENT_CHARS[0] ? REPLACEMENT_CHARS[1] : REPLACEMENT_CHARS[0];
	return alt + replacement.slice(1);
}

const REGEX_REMATCH_BACKSCAN = 512;

export interface RegexMatchContext {
	text: string;

	start: number;
	end: number;
}

export function regexRematchesInContext(candidate: string, regex: RegExp, ctx: RegexMatchContext): boolean {
	const probe = ctx.text.slice(0, ctx.start) + candidate + ctx.text.slice(ctx.end);
	const spanStart = ctx.start;
	const spanEnd = spanStart + candidate.length;
	regex.lastIndex = Math.max(0, spanStart - REGEX_REMATCH_BACKSCAN);
	for (let m = regex.exec(probe); m !== null; m = regex.exec(probe)) {
		const matchStart = m.index;
		const matchEnd = m.index + m[0].length;

		if (matchStart >= spanEnd) break;

		if (matchEnd > spanStart) return true;

		if (m[0].length === 0) regex.lastIndex++;
	}
	return false;
}

export function findNonMatchingReplacement(
	value: string,
	regex: RegExp,
	context: RegexMatchContext,
): string | undefined {
	const len = value.length;
	if (len === 0) return undefined;

	const baseline = NONMATCHING_REPLACEMENT_CHARS[0].repeat(len);
	for (let position = 0; position < len; position++) {
		for (const ch of NONMATCHING_REPLACEMENT_CHARS) {
			const candidate = `${baseline.slice(0, position)}${ch}${baseline.slice(position + 1)}`;
			if (candidate === value) continue;
			if (!regexRematchesInContext(candidate, regex, context)) return candidate;
		}
	}

	for (const ch of NONMATCHING_REPLACEMENT_CHARS) {
		const candidate = ch.repeat(len);
		if (candidate === value) continue;
		if (!regexRematchesInContext(candidate, regex, context)) return candidate;
	}
	return findWhitespaceFallbackReplacement(value, regex, context);
}

function findWhitespaceFallbackReplacement(
	value: string,
	regex: RegExp,
	context: RegexMatchContext,
): string | undefined {
	const len = value.length;
	const filler = NONMATCHING_REPLACEMENT_CHARS[0];
	for (const ws of WHITESPACE_REPLACEMENT_CHARS) {
		const full = ws.repeat(len);
		if (full !== value) {
			if (!regexRematchesInContext(full, regex, context)) return full;
		}
		for (let pos = 0; pos < len; pos++) {
			const candidate = `${filler.repeat(pos)}${ws}${filler.repeat(len - pos - 1)}`;
			if (candidate === value) continue;
			if (!regexRematchesInContext(candidate, regex, context)) return candidate;
		}
	}
	return undefined;
}

export function regexHasUnresolvableShortMatchFallback(regex: RegExp): boolean {
	return ([1, 2] as const).some((length) => {
		const probe = "\u0000".repeat(length);
		const savedLastIndex = regex.lastIndex;
		try {
			return findNonMatchingReplacement(probe, regex, { text: probe, start: 0, end: length }) === undefined;
		} finally {
			regex.lastIndex = savedLastIndex;
		}
	});
}
