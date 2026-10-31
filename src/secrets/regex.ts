function enforceGlobalFlag(flags: string): string {
	return flags.includes("g") ? flags : `${flags}g`;
}

export function compileSecretRegex(pattern: string, flags?: string): RegExp {
	let resolvedPattern = pattern;
	let resolvedFlags = flags ?? "";

	const literalMatch = /^\/((?:[^\\/]|\\.)*)\/([ gimsuy]*)$/.exec(pattern);
	if (literalMatch) {
		resolvedPattern = literalMatch[1];

		const combined = new Set([...resolvedFlags, ...literalMatch[2]]);
		resolvedFlags = [...combined].join("");
	}

	return new RegExp(resolvedPattern, enforceGlobalFlag(resolvedFlags));
}

export function escapeRegExp(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const SENSITIVE_TOKEN_RE =
	/(?<![a-zA-Z0-9_*-])(gh[opusr]_[a-zA-Z0-9_*]{36,}|github_pat_[a-zA-Z0-9_*]{36,}|glpat-[a-zA-Z0-9_*-]{20,}|sk-proj-[a-zA-Z0-9_*-]{36,}|sk-ant-[a-zA-Z0-9_*-]{36,}|sk-[a-zA-Z0-9_*-]{48,})(?![a-zA-Z0-9_*-])/gi;
