// Deterministic replacement generation

import { createHash } from "node:crypto";

export const REPLACEMENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const NONMATCHING_REPLACEMENT_CHARS = `${REPLACEMENT_CHARS}!#$%&()*+,-./:;<=>?@[]^_{|}~`;
// Space/tab only (never line terminators) so `\S`-style regexes still exhaust to the sentinel.
const WHITESPACE_REPLACEMENT_CHARS = " \t";

// Stable SHA-256-derived seed (Bun.hash unavailable on Node SEA builds); determinism is the only contract.
function seedFromString(value: string): bigint {
	const hex = createHash("sha256").update(value).digest("hex").slice(0, 16);
	return BigInt(`0x${hex}`);
}

/** Generate a deterministic same-length replacement string from a secret value. */
export function generateDeterministicReplacement(secret: string): string {
	if (secret.length === 0) return "";
	// `ZZ` sentinel keeps 1–2 char replacement remainders a fixed point across restarts.
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

// Perturb the first char so a configured `Z`/`ZZ` value can never emit itself unchanged.
export function ensureDistinctReplacement(replacement: string, secret: string): string {
	if (replacement.length === 0 || replacement !== secret) return replacement;
	const alt = replacement[0] === REPLACEMENT_CHARS[0] ? REPLACEMENT_CHARS[1] : REPLACEMENT_CHARS[0];
	return alt + replacement.slice(1);
}

// Bounds the match-start lookback only; the probe always evaluates full lookbehind/lookahead context.
const REGEX_REMATCH_BACKSCAN = 512;

export interface RegexMatchContext {
	/** Full text the match was found in (positions are offsets into it). */
	text: string;
	/** Start/end of the matched span being replaced. */
	start: number;
	end: number;
}

// Substitute into the FULL text - a context-dependent regex can otherwise oscillate between match and miss (leaky).
export function regexRematchesInContext(candidate: string, regex: RegExp, ctx: RegexMatchContext): boolean {
	const probe = ctx.text.slice(0, ctx.start) + candidate + ctx.text.slice(ctx.end);
	const spanStart = ctx.start;
	const spanEnd = spanStart + candidate.length;
	regex.lastIndex = Math.max(0, spanStart - REGEX_REMATCH_BACKSCAN);
	for (let m = regex.exec(probe); m !== null; m = regex.exec(probe)) {
		const matchStart = m.index;
		const matchEnd = m.index + m[0].length;
		// A match starting past the span's end cannot cover the candidate.
		if (matchStart >= spanEnd) break;
		// Overlap = re-redaction on a later pass - not a fixed point.
		if (matchEnd > spanStart) return true;
		// Step past zero-width matches.
		if (m[0].length === 0) regex.lastIndex++;
	}
	return false;
}

// Bounded sweep for a nonmatching fixed-point candidate; single-position probes first, then full-width fallbacks, then whitespace.
export function findNonMatchingReplacement(
	value: string,
	regex: RegExp,
	context: RegexMatchContext,
): string | undefined {
	const len = value.length;
	if (len === 0) return undefined;
	// Single-position probes cover most cases cheaply.
	const baseline = NONMATCHING_REPLACEMENT_CHARS[0].repeat(len);
	for (let position = 0; position < len; position++) {
		for (const ch of NONMATCHING_REPLACEMENT_CHARS) {
			const candidate = `${baseline.slice(0, position)}${ch}${baseline.slice(position + 1)}`;
			if (candidate === value) continue;
			if (!regexRematchesInContext(candidate, regex, context)) return candidate;
		}
	}
	// Fall back to full-width same-byte candidates when one perturbed byte is re-matched in context.
	for (const ch of NONMATCHING_REPLACEMENT_CHARS) {
		const candidate = ch.repeat(len);
		if (candidate === value) continue;
		if (!regexRematchesInContext(candidate, regex, context)) return candidate;
	}
	return findWhitespaceFallbackReplacement(value, regex, context);
}

// Whitespace markers that match-everything regexes cannot match; genuinely match-everything still exhausts to the sentinel.
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

// Search alphabet already exhausts every marker byte - if none escapes the regex, no key-derived marker can either.
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
