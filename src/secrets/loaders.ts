import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { parse as parseYaml } from "yaml";
import { type SecretEntry, SecretObfuscator } from "./obfuscator";
import { CREDENTIAL_PATTERNS } from "./patterns";
import { sanitizeSecretFriendlyName, secretEntriesNeedPlaceholderKey } from "./placeholder";
import { compileSecretRegex } from "./regex";
import { regexHasUnresolvableShortMatchFallback } from "./replacement";

function isEnoent(err: unknown): boolean {
	return (err as NodeJS.ErrnoException | null)?.code === "ENOENT";
}

const logger = {
	warn(message: string, data?: { path?: string; error?: string; pattern?: unknown; [key: string]: unknown }): void {
		console.warn(`[pi-secrets] ${message}`, data ?? "");
	},
};

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultKeyPath(): string {
	return path.join(getAgentDir(), "secret-placeholder.key");
}

const PLACEHOLDER_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const cachedPlaceholderKeys = new Map<string, string>();

export async function getSecretPlaceholderKey(keyDir?: string): Promise<string> {
	const keyPath = keyDir ? path.join(keyDir, "secret-placeholder.key") : defaultKeyPath();
	const cached = cachedPlaceholderKeys.get(keyPath);
	if (cached !== undefined) return cached;

	const existing = await readPlaceholderKeyFile(keyPath, false);
	if (existing !== undefined) {
		cachedPlaceholderKeys.set(keyPath, existing);
		return existing;
	}

	const generated = crypto.randomBytes(32).toString("base64url");
	await fs.promises.mkdir(path.dirname(keyPath), { recursive: true });
	try {
		await fs.promises.writeFile(keyPath, generated, { flag: "wx", mode: 0o600 });
		cachedPlaceholderKeys.set(keyPath, generated);
		return generated;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;

		const winner = await readPlaceholderKeyFile(keyPath, true);
		if (winner === undefined) {
			throw new Error(`secret placeholder key at ${keyPath} exists but is empty or unreadable`);
		}
		cachedPlaceholderKeys.set(keyPath, winner);
		return winner;
	}
}

export async function getExistingSecretPlaceholderKey(keyDir?: string): Promise<{ key?: string; corrupt?: Error }> {
	const keyPath = keyDir ? path.join(keyDir, "secret-placeholder.key") : defaultKeyPath();
	const cached = cachedPlaceholderKeys.get(keyPath);
	if (cached !== undefined) return { key: cached };
	try {
		const key = await readPlaceholderKeyFile(keyPath, true);
		if (key !== undefined) cachedPlaceholderKeys.set(keyPath, key);
		return { key };
	} catch (err) {
		return { corrupt: err instanceof Error ? err : new Error(String(err)) };
	}
}

let ephemeralSyncPlaceholderKey: string | undefined;

export function getSecretPlaceholderKeySync(keyDir?: string): string {
	const keyPath = keyDir ? path.join(keyDir, "secret-placeholder.key") : defaultKeyPath();
	const cached = cachedPlaceholderKeys.get(keyPath);
	if (cached !== undefined) return cached;
	try {
		const existing = fs.readFileSync(keyPath, "utf8").trim();
		if (PLACEHOLDER_KEY_RE.test(existing)) {
			cachedPlaceholderKeys.set(keyPath, existing);
			return existing;
		}
	} catch {}
	const generated = crypto.randomBytes(32).toString("base64url");
	try {
		fs.mkdirSync(path.dirname(keyPath), { recursive: true });
		fs.writeFileSync(keyPath, generated, { flag: "wx", mode: 0o600 });
		cachedPlaceholderKeys.set(keyPath, generated);
		return generated;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "EEXIST") {
			try {
				const winner = fs.readFileSync(keyPath, "utf8").trim();
				if (PLACEHOLDER_KEY_RE.test(winner)) {
					cachedPlaceholderKeys.set(keyPath, winner);
					return winner;
				}
			} catch {}
		}
		logger.warn("Could not persist secret placeholder key, using a process-ephemeral key", {
			path: keyPath,
			error: String(err),
		});
		ephemeralSyncPlaceholderKey ??= crypto.randomBytes(32).toString("base64url");
		return ephemeralSyncPlaceholderKey;
	}
}

async function readPlaceholderKeyFile(keyPath: string, retry: boolean): Promise<string | undefined> {
	const attempts = retry ? 50 : 1;
	let invalidValue: string | undefined;
	for (let attempt = 0; attempt < attempts; attempt++) {
		if (attempt > 0) await sleep(10);
		try {
			const value = (await fs.promises.readFile(keyPath, "utf8")).trim();
			if (PLACEHOLDER_KEY_RE.test(value)) return value;
			if (value.length > 0) invalidValue = value;
		} catch (err) {
			if (isEnoent(err)) return undefined;
			throw err;
		}
	}
	if (invalidValue !== undefined) {
		throw new Error(`secret placeholder key at ${keyPath} is invalid`);
	}
	return undefined;
}

type RawSecretEntry = Omit<SecretEntry, "friendlyName"> & { friendlyName?: unknown };

export { deobfuscateToolArguments, obfuscateMessages, obfuscateProviderContext } from "./message-transform";
export { type SecretEntry, SecretObfuscator } from "./obfuscator";
export * from "./patterns";
export { secretEntriesNeedPlaceholderKey, secretEntryNeedsPlaceholderKey } from "./placeholder";

export async function loadSecrets(cwd: string, agentDir: string): Promise<SecretEntry[]> {
	const projectPath = path.join(cwd, "secrets.yml");
	const globalPath = path.join(agentDir, "secrets.yml");

	const globalEntries = await loadSecretsFile(globalPath);
	const projectEntries = await loadSecretsFile(projectPath);

	if (globalEntries.length === 0) return projectEntries;
	if (projectEntries.length === 0) return globalEntries;

	const projectContents = new Set(projectEntries.map((e) => e.content));
	const merged = [...globalEntries.filter((e) => !projectContents.has(e.content)), ...projectEntries];
	return merged;
}

const MIN_ENV_VALUE_LENGTH = 8;

const SECRET_ENV_PATTERNS = /(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(?:_|$)/i;

const CONNECTION_URL_PASSWORD_RE = /^[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#\s]+)@/i;

export function collectEnvSecrets(): SecretEntry[] {
	const entries: SecretEntry[] = [];
	const seen = new Set<string>();
	for (const [name, value] of Object.entries(process.env)) {
		if (!value || value.length < MIN_ENV_VALUE_LENGTH) continue;
		if (!SECRET_ENV_PATTERNS.test(name)) continue;
		if (seen.has(value)) continue;
		seen.add(value);
		entries.push({ type: "plain", content: value, mode: "obfuscate" });
	}

	for (const [, value] of Object.entries(process.env)) {
		const match = CONNECTION_URL_PASSWORD_RE.exec(value ?? "");
		if (!match) continue;
		const password = match[1];
		if (password.length >= MIN_ENV_VALUE_LENGTH && !seen.has(password)) {
			seen.add(password);
			entries.push({ type: "plain", content: password, mode: "obfuscate" });
		}
		try {
			const decoded = decodeURIComponent(password);
			if (decoded !== password && decoded.length >= MIN_ENV_VALUE_LENGTH && !seen.has(decoded)) {
				seen.add(decoded);
				entries.push({ type: "plain", content: decoded, mode: "obfuscate" });
			}
		} catch {}
	}
	return entries;
}

export function builtinCredentialSecretEntries(): SecretEntry[] {
	return CREDENTIAL_PATTERNS.map((pattern) => ({
		type: "regex",
		content: pattern.source,
		flags: pattern.flags,
		mode: "obfuscate",
		friendlyName: pattern.name,
		literalPrefixes: pattern.literalPrefixes,
	}));
}

export async function buildSecretObfuscator(
	cwd: string,
	agentDir: string,
	keyDir?: string,
): Promise<SecretObfuscator | undefined> {
	const fileEntries = await loadSecrets(cwd, agentDir);
	const envEntries = collectEnvSecrets();

	const allEntries = [...envEntries, ...fileEntries, ...builtinCredentialSecretEntries()];
	const needsPlaceholderKey = secretEntriesNeedPlaceholderKey([...envEntries, ...fileEntries]);

	const existing = await getExistingSecretPlaceholderKey(keyDir);
	if (existing.corrupt !== undefined) {
		throw new Error(`secret placeholder key exists but is corrupt: ${existing.corrupt.message}`);
	}
	const placeholderKey = needsPlaceholderKey ? await getSecretPlaceholderKey(keyDir) : existing.key;
	let obfuscator: SecretObfuscator | undefined;
	if (allEntries.length > 0) {
		obfuscator = new SecretObfuscator(allEntries, placeholderKey ?? (() => getSecretPlaceholderKeySync(keyDir)));
	}
	if (obfuscator?.hasSecrets() !== true && placeholderKey !== undefined) {
		obfuscator = new SecretObfuscator([{ type: "plain", mode: "replace", content: placeholderKey }], placeholderKey);
	}
	return obfuscator;
}

async function loadSecretsFile(filePath: string): Promise<SecretEntry[]> {
	try {
		const text = await fs.promises.readFile(filePath, "utf8");
		const raw = parseYaml(text);
		if (!Array.isArray(raw)) {
			throw new Error(`${filePath} must be a YAML array (got ${typeof raw})`);
		}
		const entries: SecretEntry[] = [];
		for (let i = 0; i < raw.length; i++) {
			const entry = raw[i];
			if (!validateEntry(entry, filePath, i)) continue;
			const friendlyName = loadFriendlyName(entry, filePath, i);
			entries.push({
				type: entry.type,
				content: entry.content,
				mode: entry.mode ?? "obfuscate",
				replacement: entry.replacement,
				flags: entry.flags,
				friendlyName,
			});
		}
		return entries;
	} catch (err) {
		if (isEnoent(err)) return [];

		throw new Error(`Failed to load ${filePath}: ${String(err)}`, { cause: err });
	}
}

function loadFriendlyName(entry: RawSecretEntry, filePath: string, index: number): string | undefined {
	if (entry.friendlyName === undefined) return undefined;
	if (typeof entry.friendlyName !== "string") {
		logger.warn(`secrets.yml[${index}]: friendlyName must be a string`, { path: filePath });
		return undefined;
	}
	if (sanitizeSecretFriendlyName(entry.friendlyName) === undefined) {
		logger.warn(`secrets.yml[${index}]: friendlyName must contain at least one letter or digit`, { path: filePath });
		return undefined;
	}
	return entry.friendlyName;
}

function validateEntry(entry: unknown, filePath: string, index: number): entry is RawSecretEntry {
	if (entry === null || typeof entry !== "object") {
		logger.warn(`secrets.yml[${index}]: entry must be an object`, { path: filePath });
		return false;
	}
	const e = entry as Record<string, unknown>;
	if (e.type !== "plain" && e.type !== "regex") {
		logger.warn(`secrets.yml[${index}]: type must be "plain" or "regex"`, { path: filePath });
		return false;
	}
	if (typeof e.content !== "string" || e.content.length === 0) {
		logger.warn(`secrets.yml[${index}]: content must be a non-empty string`, { path: filePath });
		return false;
	}
	if (e.mode !== undefined && e.mode !== "obfuscate" && e.mode !== "replace") {
		logger.warn(`secrets.yml[${index}]: mode must be "obfuscate" or "replace"`, { path: filePath });
		return false;
	}
	if (e.replacement !== undefined && typeof e.replacement !== "string") {
		logger.warn(`secrets.yml[${index}]: replacement must be a string`, { path: filePath });
		return false;
	}
	if (e.flags !== undefined && typeof e.flags !== "string") {
		logger.warn(`secrets.yml[${index}]: flags must be a string`, { path: filePath });
		return false;
	}
	if (e.type === "regex") {
		let regex: RegExp;
		try {
			regex = compileSecretRegex(e.content as string, e.flags as string | undefined);
		} catch (error) {
			logger.warn(`secrets.yml[${index}]: invalid regex pattern`, {
				path: filePath,
				pattern: e.content,
				error: String(error),
			});
			return false;
		}
		const mode = (e.mode as "obfuscate" | "replace" | undefined) ?? "obfuscate";
		if (mode === "replace" && e.replacement === undefined && regexHasUnresolvableShortMatchFallback(regex)) {
			logger.warn(
				`secrets.yml[${index}]: regex matches every 1-2 character candidate with no custom replacement, so a match can never be redacted distinctly from itself`,
				{ path: filePath, pattern: e.content },
			);
			return false;
		}
	}
	return true;
}
