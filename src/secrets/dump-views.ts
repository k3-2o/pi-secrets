import { captureUnregistered } from "./at-rest";
import type { SecretObfuscator } from "./obfuscator";

// Dump-format views: tool output can fragment a secret into spaced chars,
// hex pairs, or base64. Reconstruct each shape, run the detector on the fold,
// and replace the matched original region with its obfuscated form.

const OCTAL_ADDR_RE = /^[0-7]{7,8}(?: {3}|\s{2,})/;
const HEXPAIR_RUN_RE = /(?:[0-9a-fA-F]{2}[ \t]+)+[0-9a-fA-F]{2}/g;
const B64_RUN_RE = /[A-Za-z0-9+/]{16,}={0,2}\s*/g;
type Region = [number, number, string];

function hexPairsToBytes(run: string): string {
	const toks = run.trim().split(/[ \t]+/);
	let out = "";
	for (const t of toks) {
		const b = parseInt(t, 16);
		if (Number.isNaN(b)) return "";
		out += String.fromCharCode(b);
	}
	return out;
}

function odCFoldRegions(text: string): Region[] {
	const out: Region[] = [];
	const lines = text.split("\n");
	let offset = 0;
	for (let li = 0; li < lines.length; li++) {
		if (OCTAL_ADDR_RE.exec(lines[li]) === null) {
			offset += lines[li].length + 1;
			continue;
		}
		const regionStart = offset;
		let folded = "";
		let lastIdx = li;
		for (let k = li; k < lines.length; k++) {
			const a = OCTAL_ADDR_RE.exec(lines[k]);
			if (a === null) break;
			for (const t of lines[k]
				.slice(a[0].length)
				.split(/\s{2,}/)
				.filter(Boolean)) {
				if (t.length === 1 && t.charCodeAt(0) >= 32 && t.charCodeAt(0) < 127) folded += t;
				else if (t === "sp") folded += " ";
				else if (t === "\\n" || t === "\\t" || t === "\\r" || t === "\\\\") folded += t.slice(1);
			}
			lastIdx = k;
		}
		const seg = lines.slice(li, lastIdx + 1).join("\n") + "\n";
		let end = regionStart + seg.length;
		if (end > text.length) end = text.length;
		if (folded.length >= 4) out.push([regionStart, end, folded]);
		for (let k = li; k <= lastIdx; k++) offset += lines[k].length + 1;
		li = lastIdx;
	}
	return out;
}

function hexFoldRegions(text: string): Region[] {
	const out: Region[] = [];
	HEXPAIR_RUN_RE.lastIndex = 0;
	for (;;) {
		const m = HEXPAIR_RUN_RE.exec(text);
		if (m === null) break;
		const bytes = hexPairsToBytes(m[0]);
		if (bytes.length >= 4 && /[ -~]/.test(bytes)) out.push([m.index, m.index + m[0].length, bytes]);
	}
	return out;
}

function b64Regions(text: string): Region[] {
	const out: Region[] = [];
	B64_RUN_RE.lastIndex = 0;
	for (;;) {
		const m = B64_RUN_RE.exec(text);
		if (m === null) break;
		let decoded = "";
		try {
			decoded = Buffer.from(m[0].trim(), "base64").toString("utf8");
		} catch {
			continue;
		}
		if (decoded.length >= 8) out.push([m.index, m.index + m[0].length, decoded]);
	}
	return out;
}

// Capture + obfuscate each folded region, applying back-to-front so offsets hold.
export function redactFoldedRegions(obfuscator: SecretObfuscator, text: string, regions: Region[]): string {
	let out = text;
	for (let i = regions.length - 1; i >= 0; i--) {
		const [start, end, folded] = regions[i];
		captureUnregistered(obfuscator, folded);
		const hashed = obfuscator.obfuscate(folded);
		if (hashed !== folded) out = out.slice(0, start) + hashed + out.slice(end);
	}
	return out;
}

export function foldDumpViews(obfuscator: SecretObfuscator, text: string): string {
	let out = redactFoldedRegions(obfuscator, text, odCFoldRegions(text));
	out = redactFoldedRegions(obfuscator, out, hexFoldRegions(out));
	out = redactFoldedRegions(obfuscator, out, b64Regions(out));
	return out;
}
