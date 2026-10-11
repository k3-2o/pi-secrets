import * as crypto from "node:crypto";
import type { SecretEntry } from "./obfuscator";
import type { RegistryRevision } from "./registry-revision";
import { ensureDistinctReplacement, generateDeterministicReplacement, REPLACEMENT_CHARS } from "./replacement";

// Placeholder format

const HASH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// ~62 bits of keyed digest as 12 base36 chars - unrelated secrets must not collide on a shared base.
const HASH_LEN = 12;
const MAX_FRIENDLY_NAME_LEN = 32;
// Under-floor matches are never placeheld, to avoid redacting small words/fragments.
export const MIN_OBFUSCATE_SECRET_LEN = 8;

// Fallback key is random per process (no cross-session stability) - never shipped in source.
let ephemeralPlaceholderKey: string | undefined;
export function defaultPlaceholderKey(): string {
	ephemeralPlaceholderKey ??= crypto.randomBytes(32).toString("base64url");
	return ephemeralPlaceholderKey;
}

type PlaceholderCaseHint = "U" | "L" | "C" | "M";

/** Normalize a friendly name into the model-visible placeholder prefix. */
export function sanitizeSecretFriendlyName(name: string): string | undefined {
	const sanitized = name
		.replace(/[^A-Za-z0-9]/g, "")
		.toUpperCase()
		.slice(0, MAX_FRIENDLY_NAME_LEN);
	return sanitized.length > 0 ? sanitized : undefined;
}

// Same sanitized shape as labels - a raw lowercase/punctuated value compares against visible text.
export function sanitizeForCollisionCheck(value: string): string {
	return value.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}

// A label leaks if it contains the whole secret or, past the display cap, is its visible prefix.
export function sanitizedLabelCollidesWithSecret(sanitizedLabel: string, sanitizedSecret: string): boolean {
	if (sanitizedSecret.length === 0) return false;
	if (sanitizedLabel.includes(sanitizedSecret)) return true;
	return sanitizedLabel.length >= MAX_FRIENDLY_NAME_LEN && sanitizedSecret.startsWith(sanitizedLabel);
}

// Index of collision-normalized forms so label-collision tests skip per-member rescans.
export class SecretValueSet extends Set<string> {
	// Normalized value → member count.
	#normalized = new Map<string, number>();
	// Normalized length → distinct-value count.
	#lengths = new Map<number, number>();
	// Display-cap prefix → overlapping values (prefix leaks).
	#heads = new Map<string, Set<string>>();
	// Version bump for obfuscator registry cache invalidation.
	readonly #revision: RegistryRevision | undefined;

	constructor(values?: Iterable<string>, revision?: RegistryRevision) {
		// `Set`'s constructor calls add before subclass fields exist - populate after super().
		super();
		this.#revision = revision;
		if (values) for (const value of values) this.add(value);
	}

	override add(value: string): this {
		if (super.has(value)) return this;
		super.add(value);
		this.#revision?.bump();
		const normalized = sanitizeForCollisionCheck(value);
		if (normalized.length === 0) return this;
		const count = this.#normalized.get(normalized) ?? 0;
		this.#normalized.set(normalized, count + 1);
		if (count > 0) return this;
		this.#lengths.set(normalized.length, (this.#lengths.get(normalized.length) ?? 0) + 1);
		if (normalized.length >= MAX_FRIENDLY_NAME_LEN) {
			const head = normalized.slice(0, MAX_FRIENDLY_NAME_LEN);
			let bucket = this.#heads.get(head);
			if (bucket === undefined) {
				bucket = new Set();
				this.#heads.set(head, bucket);
			}
			bucket.add(normalized);
		}
		return this;
	}

	override delete(value: string): boolean {
		if (!super.delete(value)) return false;
		this.#revision?.bump();
		const normalized = sanitizeForCollisionCheck(value);
		if (normalized.length === 0) return true;
		const count = this.#normalized.get(normalized)!;
		if (count > 1) {
			this.#normalized.set(normalized, count - 1);
			return true;
		}
		this.#normalized.delete(normalized);
		const lengthCount = this.#lengths.get(normalized.length)!;
		if (lengthCount > 1) this.#lengths.set(normalized.length, lengthCount - 1);
		else this.#lengths.delete(normalized.length);
		if (normalized.length >= MAX_FRIENDLY_NAME_LEN) {
			const head = normalized.slice(0, MAX_FRIENDLY_NAME_LEN);
			const bucket = this.#heads.get(head)!;
			bucket.delete(normalized);
			if (bucket.size === 0) this.#heads.delete(head);
		}
		return true;
	}

	override clear(): void {
		if (this.size === 0) return;
		super.clear();
		this.#revision?.bump();
		this.#normalized.clear();
		this.#lengths.clear();
		this.#heads.clear();
	}

	/** Same answer as `sanitizedLabelCollidesWithSecret(label, sanitizeForCollisionCheck(v))` for any member `v`. */
	collidesWithLabel(sanitizedLabel: string): boolean {
		if (this.#normalized.size === 0) return false;
		const labelLength = sanitizedLabel.length;
		for (const length of this.#lengths.keys()) {
			for (let start = 0; start + length <= labelLength; start++) {
				if (this.#normalized.has(sanitizedLabel.slice(start, start + length))) return true;
			}
		}
		if (labelLength < MAX_FRIENDLY_NAME_LEN) return false;
		const bucket = this.#heads.get(sanitizedLabel.slice(0, MAX_FRIENDLY_NAME_LEN));
		if (bucket === undefined) return false;
		for (const normalized of bucket) {
			if (normalized.startsWith(sanitizedLabel)) return true;
		}
		return false;
	}
}

/** Whether any value in `values` normalizes to a secret `sanitizedLabel` would expose. */
export function labelCollidesWithAnySecret(sanitizedLabel: string, values: ReadonlySet<string>): boolean {
	if (values instanceof SecretValueSet) return values.collidesWithLabel(sanitizedLabel);
	for (const value of values) {
		if (sanitizedLabelCollidesWithSecret(sanitizedLabel, sanitizeForCollisionCheck(value))) return true;
	}
	return false;
}

// Key needed iff a reversible placeholder can still reach the obfuscate pass after the replace phase; avoid writing the key file for replace-only configs.
export function secretEntryNeedsPlaceholderKey(entry: SecretEntry): boolean {
	if ((entry.mode ?? "obfuscate") === "obfuscate") {
		if (entry.type === "regex") return true;
		return entry.content.length >= MIN_OBFUSCATE_SECRET_LEN;
	}
	return entry.type === "regex" && entry.replacement === undefined;
}

// Does a replacement help retile `content` (empty/substring/superstring/border)? Drives key necessity.
function replacementCanFormContent(replacement: string, content: string): boolean {
	if (replacement.length === 0) return content.length > 0;
	if (content.includes(replacement) || replacement.includes(content)) return true;
	const maxOverlap = Math.min(replacement.length, content.length);
	for (let k = 1; k <= maxOverlap; k++) {
		// Border case: replacement suffix forms content prefix, or prefix forms content suffix.
		if (content.startsWith(replacement.slice(replacement.length - k)) || content.endsWith(replacement.slice(0, k))) {
			return true;
		}
	}
	return false;
}

// Simulates the replace phase (content-keyed, descending length) to decide if any obfuscate entry can still produce a keyed placeholder.
export function secretEntriesNeedPlaceholderKey(entries: SecretEntry[]): boolean {
	const replaceMap = new Map<string, string>();
	for (const entry of entries) {
		if (entry.type !== "plain" || (entry.mode ?? "obfuscate") !== "replace") continue;
		replaceMap.set(
			entry.content,
			entry.replacement ?? ensureDistinctReplacement(generateDeterministicReplacement(entry.content), entry.content),
		);
	}
	const replacePhase = [...replaceMap].sort((a, b) => b[0].length - a[0].length);
	// Simulate replace phase from `start`; later (shorter) replacements rewrite earlier outputs.
	const applyReplacePhaseFrom = (text: string, start: number): string => {
		let result = text;
		for (let i = start; i < replacePhase.length; i++) {
			result = result.split(replacePhase[i][0]).join(replacePhase[i][1]);
		}
		return result;
	};
	return entries.some((entry) => {
		if (!secretEntryNeedsPlaceholderKey(entry)) return false;
		// Regex obfuscate entries can always match - require the key.
		if (entry.type !== "plain") return true;
		const content = entry.content;
		if (applyReplacePhaseFrom(content, 0).includes(content)) return true;
		// Only fragments that survive later replacements can force the key.
		return replacePhase.some(
			([, replacement], i) =>
				applyReplacePhaseFrom(content, i + 1) === content &&
				replacementCanFormContent(applyReplacePhaseFrom(replacement, i + 1), content),
		);
	});
}

// HMAC-SHA256 under the per-install key - unkeyed hashes of low-entropy secrets would be dictionaried.
export function buildHashBase(key: string, value: string): string {
	// node:crypto createHmac (Bun.CryptoHasher unavailable on Node SEA builds).
	const digest = crypto.createHmac("sha256", key).update(value).digest();
	let v = 0n;
	for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[i]);
	const radix = BigInt(HASH_CHARS.length);
	let tag = "";
	for (let i = 0; i < HASH_LEN; i++) {
		tag += HASH_CHARS[Number(v % radix)];
		v /= radix;
	}
	return tag;
}

// Key-derived marker run: idempotent across restarts, unpredictable without the key.
export function buildKeyedReplacementRun(key: string, length: number): string {
	if (length <= 0) return "";
	const radix = REPLACEMENT_CHARS.length;
	let out = "";
	for (let block = 0; out.length < length; block++) {
		// node:crypto createHmac (Bun.CryptoHasher unavailable on Node SEA builds).
		const digest = crypto.createHmac("sha256", key).update(`replace-chunk\0${length}\0${block}`).digest();
		for (let i = 0; i < digest.length && out.length < length; i++) {
			out += REPLACEMENT_CHARS[digest[i] % radix];
		}
	}
	return out;
}

export function inferCaseHint(secret: string): PlaceholderCaseHint | undefined {
	let hasCased = false;
	let hasUpper = false;
	let hasLower = false;
	let capitalized = true;
	let seenFirstCased = false;

	for (let i = 0; i < secret.length; i++) {
		const code = secret.charCodeAt(i);
		const isUpper = code >= 65 && code <= 90;
		const isLower = code >= 97 && code <= 122;
		if (!isUpper && !isLower) continue;

		hasCased = true;
		if (isUpper) {
			hasUpper = true;
			if (seenFirstCased) capitalized = false;
		} else {
			hasLower = true;
			if (!seenFirstCased) capitalized = false;
		}
		seenFirstCased = true;
	}

	if (!hasCased) return undefined;
	if (hasUpper && !hasLower) return "U";
	if (hasLower && !hasUpper) return "L";
	if (capitalized) return "C";
	return "M";
}

export function buildPlaceholder(hint: PlaceholderCaseHint | undefined, base: string, friendlyName?: string): string {
	const prefix = friendlyName ? `${friendlyName}_` : "";
	return hint ? `$$${prefix}${base}:${hint}$$` : `$$${prefix}${base}$$`;
}

/** Regex matching `$$HASH$$`, `$$HASH:U$$`, and `$$FRIENDLY_HASH(:hint)$$` placeholders. */
export const PLACEHOLDER_RE = /\$\$(?:[A-Z0-9]+_)?[A-Z0-9]{4,}(?::[ULCM])?\$\$/g;

export function resumePlaceholderScanAfterRejectedCandidate(match: RegExpExecArray): void {
	// Restart at the rejected candidate's closing delimiter - it can open an adjacent placeholder.
	PLACEHOLDER_RE.lastIndex = match.index + match[0].length - 2;
}

export function placeholderWithoutFriendlyName(placeholder: string): string | undefined {
	const match = /^\$\$[A-Z0-9]+_([A-Z0-9]{4,}(?::[ULCM])?)\$\$$/.exec(placeholder);
	return match ? `$$${match[1]}$$` : undefined;
}

export function lookupFriendlyPlaceholderAlias(
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
	placeholder: string,
): { secret: string; recursive: boolean } | undefined {
	const direct = deobfuscateMap.get(placeholder);
	if (direct !== undefined) return direct;
	const unprefixed = placeholderWithoutFriendlyName(placeholder);
	return unprefixed !== undefined ? deobfuscateMap.get(unprefixed) : undefined;
}

const PENDING_PLACEHOLDER_SUFFIX_RE = /(?:\$\$(?:[A-Z0-9]+_)?[A-Z0-9]*(?::[ULCM]?)?|\$)$/;

// Buffer trailing delimiters so a partial placeholder token is never emitted before deobfuscation.
export function stripPendingSecretPlaceholderSuffix(text: string): string {
	const pendingPlaceholderStart = text.match(PENDING_PLACEHOLDER_SUFFIX_RE);
	if (pendingPlaceholderStart?.index === undefined) return text;
	return text.slice(0, pendingPlaceholderStart.index);
}

export interface RegexScanSegment {
	scanStart: number;
	scanEnd: number;
	textStart: number;
	textEnd: number;
	generatedPlaceholder: boolean;
	recursive: boolean;
}

export interface ReplaceRegexScan {
	text: string;
	segments: RegexScanSegment[];
}
