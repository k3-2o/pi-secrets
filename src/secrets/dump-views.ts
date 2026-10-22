import { captureUnregistered } from "./at-rest";
import type { SecretObfuscator } from "./obfuscator";

const OCTAL_ADDR_RE = /^[0-7]{7,8}(?: {3}|\s{2,})/;
const HEXPAIR_RUN_RE = /(?:[0-9a-fA-F]{2}[ \t]+)+[0-9a-fA-F]{2}/g;
const B64_RUN_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;
type Region = [number, number, string];

function hexPairsToBytes(run: string): string {
	const toks = run.trim().split(/[ \t]+/);
	let out = "";
	for (const t of toks) {
		const n = t.length;
		if (n % 2 !== 0) return "";
		for (let i = 0; i < n; i += 2) {
			const b = parseInt(t.slice(i, i + 2), 16);
			if (Number.isNaN(b)) return "";
			out += String.fromCharCode(b);
		}
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
		const seg = `${lines.slice(li, lastIdx + 1).join("\n")}\n`;
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

	const LINE_RE = /^[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2,4}[ \t]+)+[0-9a-fA-F]{2,4})\s+(.+)$/;
	const lines = text.split("\n");
	for (let li = 0; li < lines.length; li++) {
		const m = LINE_RE.exec(lines[li]);
		if (m === null) continue;
		let bytes = "";
		let lastIdx = li;
		for (let k = li; k < lines.length; k++) {
			const mk = LINE_RE.exec(lines[k]);
			if (mk === null) break;
			const b = hexPairsToBytes(mk[1]);
			if (b.length < 4 || !/[ -~]/.test(b)) break;
			bytes += b;
			lastIdx = k;
		}
		if (bytes.length < 4) {
			li = lastIdx;
			continue;
		}
		let start = 0;
		for (let k = 0; k < li; k++) start += lines[k].length + 1;
		let end = start;
		for (let k = li; k <= lastIdx; k++) end += lines[k].length + 1;
		if (end > text.length) end = text.length;
		out.push([start, end, bytes]);
		li = lastIdx;
	}
	return out;
}

function noAddressHexFoldRegions(text: string): Region[] {
	const out: Region[] = [];
	const NO_ADDR_LINE = /^((?:[0-9a-fA-F]{2}[ \t]+)+[0-9a-fA-F]{2})\s{2}([ -~]{1,})$/;
	const lines = text.split("\n");
	let offset = 0;
	for (let li = 0; li < lines.length; li++) {
		const line = lines[li];
		const m = NO_ADDR_LINE.exec(line);
		if (m === null) {
			offset += line.length + 1;
			continue;
		}
		let bytes = hexPairsToBytes(m[1]);
		if (bytes.length < 4 || !/[ -~]/.test(bytes)) {
			offset += line.length + 1;
			continue;
		}
		let end = offset + line.length + 1;
		let k = li + 1;
		while (k < lines.length) {
			const nk = NO_ADDR_LINE.exec(lines[k]);
			if (nk === null) break;
			bytes += hexPairsToBytes(nk[1]);
			end += lines[k].length + 1;
			k += 1;
		}
		out.push([offset, Math.min(end, text.length), bytes]);
		offset = end;
		li = k - 1;
	}
	return out;
}

function charLineFoldRegions(text: string): Region[] {
	const out: Region[] = [];
	const CHAR_LINE =
		/^\s*(?:\[([^\]\s])\]|\(['"]([^'"])\)|ord\('[^']*'\)\s*=\s*)(?:0x([0-9A-Fa-f]{1,2}))?\s*([0-9A-Fa-f]{1,3})?\s*$/;
	const lines = text.split("\n");
	let offset = 0;
	for (let li = 0; li < lines.length; li++) {
		const line = lines[li];
		const m = CHAR_LINE.exec(line);
		if (m === null) {
			offset += line.length + 1;
			continue;
		}
		const lit = m[1] ?? m[2];
		const codeStr = m[3] ?? m[4];
		let ch: string;
		if (lit !== undefined && codeStr !== undefined) {
			ch = parseInt(codeStr, 16) === lit.charCodeAt(0) ? lit : String.fromCharCode(parseInt(codeStr, 16));
		} else if (lit !== undefined) {
			ch = lit;
		} else if (codeStr !== undefined) {
			ch = String.fromCharCode(parseInt(codeStr, 16));
		} else {
			offset += line.length + 1;
			continue;
		}
		let folded = ch;
		let k = li + 1;
		let end = offset + line.length + 1;
		while (k < lines.length) {
			const nk = CHAR_LINE.exec(lines[k]);
			if (nk === null) break;
			const l2 = nk[1] ?? nk[2];
			const c2 = nk[3] ?? nk[4];
			if (l2 !== undefined && c2 !== undefined)
				folded += parseInt(c2, 16) === l2.charCodeAt(0) ? l2 : String.fromCharCode(parseInt(c2, 16));
			else if (l2 !== undefined) folded += l2;
			else if (c2 !== undefined) folded += String.fromCharCode(parseInt(c2, 16));
			else break;
			end += lines[k].length + 1;
			k += 1;
		}
		if (folded.length >= 4) out.push([offset, Math.min(end, text.length), folded]);
		offset = end;
		li = k - 1;
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

function redactFoldedRegions(obfuscator: SecretObfuscator, text: string, regions: Region[]): string {
	if (regions.length === 0) return text;
	const sorted = regions.slice().sort((a, b) => b[0] - a[0]);
	let out = text;
	for (const [start, end, folded] of sorted) {
		if (start >= out.length || end > out.length) continue;
		captureUnregistered(obfuscator, folded, { skipValueVeto: true });
		const hashed = obfuscator.obfuscate(folded);
		if (hashed !== folded) out = out.slice(0, start) + hashed + out.slice(end);
	}
	return out;
}

export function foldDumpViews(obfuscator: SecretObfuscator, text: string): string {
	let out = redactFoldedRegions(obfuscator, text, odCFoldRegions(text));
	out = redactFoldedRegions(obfuscator, out, hexFoldRegions(out));
	out = redactFoldedRegions(obfuscator, out, noAddressHexFoldRegions(out));
	out = redactFoldedRegions(obfuscator, out, charLineFoldRegions(out));
	out = redactFoldedRegions(obfuscator, out, b64Regions(out));
	return out;
}
