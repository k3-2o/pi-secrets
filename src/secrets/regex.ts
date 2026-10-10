/** Add global flag while preserving user-provided flags. */
function enforceGlobalFlag(flags: string): string {
	return flags.includes("g") ? flags : `${flags}g`;
}

/** Compile a secret regex entry with global scanning enabled by default. */
export function compileSecretRegex(pattern: string, flags?: string): RegExp {
	let resolvedPattern = pattern;
	let resolvedFlags = flags ?? "";

	// Detect regex literal syntax: /pattern/flags
	const literalMatch = /^\/((?:[^\\/]|\\.)*)\/([ gimsuy]*)$/.exec(pattern);
	if (literalMatch) {
		resolvedPattern = literalMatch[1];
		// Merge flags from literal with explicit flags param (deduplicate)
		const combined = new Set([...resolvedFlags, ...literalMatch[2]]);
		resolvedFlags = [...combined].join("");
	}

	return new RegExp(resolvedPattern, enforceGlobalFlag(resolvedFlags));
}

/**
 * Credential-shaped token patterns scrubbed from outbound provider traffic.
 *
 * Local copy of pi-ai's `SENSITIVE_TOKEN_RE` (OMP source:
 * `packages/ai/src/providers/transform-messages.ts:437`) so the obfuscator can
 * route the same shapes through reversible keyed placeholders. An irreversible
 * `[*_token_redacted]` rewrite echoed back into an edit-tool `old_string` could
 * never match the real bytes on disk, which is why the obfuscator owns these
 * shapes instead of only the provider-side net.
 */
/**
 * Escape a literal string for use inside a RegExp source.
 * PORTED: OMP used `RegExp.escape` (ES2025; unavailable on older Node SEA
 * builds and unknown to TS 5.6 libs). This is the equivalent portable form.
 */
export function escapeRegExp(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const SENSITIVE_TOKEN_RE =
	/(?<![a-zA-Z0-9_*-])(gh[opusr]_[a-zA-Z0-9_*]{36,}|github_pat_[a-zA-Z0-9_*]{36,}|glpat-[a-zA-Z0-9_*-]{20,}|sk-proj-[a-zA-Z0-9_*-]{36,}|sk-ant-[a-zA-Z0-9_*-]{36,}|sk-[a-zA-Z0-9_*-]{48,})(?![a-zA-Z0-9_*-])/gi;
