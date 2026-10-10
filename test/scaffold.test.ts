import { describe, expect, test } from "bun:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import extensionFactory from "../index.ts";

describe("pi-secrets extension contract", () => {
	test("default export is an extension factory", () => {
		expect(typeof extensionFactory).toBe("function");
	});

	test("factory registers the --secrets flag and a markdown transformer at load", () => {
		const flags: Array<{ name: string; options: unknown }> = [];
		const transformers: Array<unknown> = [];
		const stub = {
			registerFlag: (name: string, options: unknown) => void flags.push({ name, options }),
			registerMarkdownTransformer: (fn: unknown) => void transformers.push(fn),
			on: () => () => {},
			getFlag: () => undefined,
		} as unknown as ExtensionAPI;
		expect(() => extensionFactory(stub)).not.toThrow();
		expect(flags).toHaveLength(1);
		expect(flags[0].name).toBe("secrets");
		expect(transformers).toHaveLength(1);
	});
});
