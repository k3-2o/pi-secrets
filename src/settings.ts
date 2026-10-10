import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/**
 * pi-secrets configuration surface.
 *
 * PORTED: OMP read `secrets.enabled` from its own config registry
 * (`secrets/settings.ts`); vanilla pi has no equivalent registry, so we resolve
 * the setting in precedence order:
 *   1. `pi.getSettings().secrets` (effective settings, when the API provides it)
 *   2. `<agentDir>/settings.json` → `secrets` (direct file read fallback)
 *   3. defaults (disabled)
 * The `--secrets` CLI flag (registered in index.ts) overrides at the wiring
 * layer, see Phase 3.
 */

export interface SecretsSettings {
	/** Master switch; off = the extension is a complete no-op. */
	enabled: boolean;
	/**
	 * Reveal path. "persist" (Option B): deobfuscate at `message_end`, real
	 * values at rest. "render" (Option A): reveal only via
	 * `registerMarkdownTransformer`, hashes at rest. Both are extension-only.
	 */
	mode: "persist" | "render";
}

const DEFAULTS: SecretsSettings = { enabled: false, mode: "persist" };

function normalize(raw: unknown): SecretsSettings | undefined {
	if (raw === null || typeof raw !== "object") return undefined;
	const record = raw as Record<string, unknown>;
	const result: SecretsSettings = { ...DEFAULTS };
	if (typeof record.enabled === "boolean") result.enabled = record.enabled;
	if (record.mode === "persist" || record.mode === "render") result.mode = record.mode;
	return result;
}

function readFromApi(pi: ExtensionAPI): SecretsSettings | undefined {
	// `Settings` is a closed interface; extension-owned keys like `secrets` can
	// still be present at runtime, so read through an index signature.
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
