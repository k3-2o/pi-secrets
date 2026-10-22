import { CREDENTIAL_PATTERNS } from "./patterns";
import { MIN_OBFUSCATE_SECRET_LEN } from "./placeholder";

export type ValueShape =
	| "vendor-key"
	| "scheme"
	| "iso-datetime"
	| "unix-seconds"
	| "unix-ms"
	| "version"
	| "uuid"
	| "hex-digest"
	| "path"
	| "wordlist"
	| "lowercase-word"
	| "uppercase-word"
	| "digits"
	| "passwordish"
	| "mixed-alnum"
	| "other"
	| "empty";

const VENDOR_PREFIXES: string[] = [
	...CREDENTIAL_PATTERNS.flatMap((pattern) => pattern.literalPrefixes ?? []),
]
	.filter((prefix) => prefix !== "SK")
	.map((prefix) => prefix.toLowerCase());

const SCHEME_NAMES = new Set([
	"oauth2-bearer",
	"oauth2",
	"oauth",
	"bearer",
	"basic",
	"digest",
	"jwt",
	"ntlm",
	"negotiate",
	"anonymous",
	"apikey",
	"api-key",
]);

const VETO_SHAPES: ReadonlySet<ValueShape> = new Set([
	"empty",
	"scheme",
	"iso-datetime",
	"unix-seconds",
	"unix-ms",
	"version",
	"uuid",
	"hex-digest",
	"path",
	"wordlist",
	"lowercase-word",
	"uppercase-word",
	"digits",
]);

const PASSWORD_NAME_RE = /(?:PASSWORD|PASSWD|PASS)(?:_|$)/i;

export function classifyValueShape(value: string): ValueShape {
	if (value.length === 0) return "empty";
	const lower = value.toLowerCase();
	if (VENDOR_PREFIXES.some((prefix) => lower.startsWith(prefix))) return "vendor-key";
	if (SCHEME_NAMES.has(lower)) return "scheme";
	if (isIsoDatetime(value)) return "iso-datetime";
	if (/^\d{10}$/.test(value)) {
		const n = Number(value);
		if (n > 1_000_000_000 && n < 2_000_000_000) return "unix-seconds";
	}
	if (/^\d{13}$/.test(value)) return "unix-ms";
	if (/^\d+(\.\d+){1,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(value)) return "version";
	if (/^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/.test(value)) return "uuid";
	if (/^[0-9a-fA-F]{24,}$/.test(value)) return "hex-digest";
	if (isPath(value)) return "path";
	if (/^[a-z]+(?:[-_. ][a-z]+){1,}$/.test(value)) return "wordlist";
	if (/^[a-z]{4,32}$/.test(value)) return "lowercase-word";
	if (/^[A-Z]{4,32}$/.test(value)) return "uppercase-word";
	if (/^\d{4,}$/.test(value)) return "digits";
	if (
		value.length >= 8 &&
		/[A-Z]/.test(value) &&
		/[a-z]/.test(value) &&
		/\d/.test(value) &&
		/[^A-Za-z0-9]/.test(value)
	) {
		return "passwordish";
	}
	if (/^[A-Za-z0-9_-]{8,}$/.test(value)) return "mixed-alnum";
	return "other";
}

export function valueVetoesRedaction(value: string): boolean {
	return VETO_SHAPES.has(classifyValueShape(value));
}

export function valueRedactionVerdict(
	name: string,
	value: string,
	floor: number = MIN_OBFUSCATE_SECRET_LEN,
): "keep" | "mask" {
	const shape = classifyValueShape(value);
	if (VETO_SHAPES.has(shape)) return "keep";
	if (shape === "vendor-key") {
		return value.length >= floor ? "mask" : "keep";
	}
	if (PASSWORD_NAME_RE.test(name) && (shape === "passwordish" || shape === "other")) return "mask";
	if (value.length < floor) return "keep";
	return "mask";
}

function isIsoDatetime(value: string): boolean {
	return (
		/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/.test(value) ||
		/^\d{4}\d{2}\d{2}T\d{6}Z?$/.test(value)
	);
}

function isPath(value: string): boolean {
	if (/^(?:\/|~\/|\.\/|\.\.\/)/.test(value)) return true;
	return (
		value.includes("/") &&
		value
			.split("/")
			.every((segment) => segment.length > 0 && /^[A-Za-z0-9._-]+$/.test(segment))
	);
}