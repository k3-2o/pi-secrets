import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/** Settings resolution: pi.getSettings().secrets → `<agentDir>/settings.json` → defaults(false); the legacy `secrets.mode` key is read and ignored. */

export interface SecretsSettings {
	/** Master switch; off = the extension is a complete no-op. */
	enabled: boolean;
}

const DEFAULTS: SecretsSettings = { enabled: false };

function normalize(raw: unknown): SecretsSettings | undefined {
	if (raw === null || typeof raw !== "object") return undefined;
	const record = raw as Record<string, unknown>;
	const result: SecretsSettings = { ...DEFAULTS };
	if (typeof record.enabled === "boolean") result.enabled = record.enabled;
	if (record.mode === "persist" || record.mode === "render") {
		console.warn(
			"pi-secrets: the legacy secrets.mode setting is ignored; there is one behavior now (at-rest hashing everywhere, reveal in the interactive terminal only).",
		);
	}
	return result;
}

function readFromApi(pi: ExtensionAPI): SecretsSettings | undefined {
	// `Settings` is a closed interface - read extension keys via the index signature.
	const api = pi as unknown as { getSettings?: () => Record<string, unknown> };
	const settings = api.getSettings?.();
	if (settings === undefined) return undefined;
	return normalize(settings.secrets);
}

function readFromFile(agentDir: string): SecretsSettings | undefined {
	const settingsPath = path.join(agentDir, "settings.json");
	try {
		const parsed: unknown = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
		if (parsed === null || typeof parsed !== "object") return undefined;
		return normalize((parsed as Record<string, unknown>).secrets);
	} catch {
		return undefined;
	}
}

/** Resolve the effective secrets settings for a session. */
export function readSecretsSettings(pi: ExtensionAPI, agentDir: string): SecretsSettings {
	return readFromApi(pi) ?? readFromFile(agentDir) ?? { ...DEFAULTS };
}
