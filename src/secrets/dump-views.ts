import { captureUnregistered } from "./at-rest";
import type { SecretObfuscator } from "./obfuscator";

const OCTAL_ADDR_RE = /^[0-7]{7,8}(?: {3}|\s{2,})/;
// \b-guarded like the xxd line fold: without boundaries the run decodes ASCII-column
// text as hex (tail rows leak \"4V\"-style garbage into the fold).
const HEXPAIR_RUN_RE = /(?:\b[0-9a-fA-F]{2}\b[ \t]+)+\b[0-9a-fA-F]{2}\b/g;
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
				// Control tokens fold to their real characters - mapping them to letters
				// (n/t/r) glues content AND injects bytes a registered secret can never
				// match, so a control-bearing dump would pass undetected.
				else if (t === "\\n") folded += "\n";
				else if (t === "\\t") folded += "\t";
				else if (t === "\\r") folded += "\r";
				else if (t === "\\\\") folded += "\\";
			}
			lastIdx = k;
		}
		const seg = `${lines.slice(li, lastIdx + 1).join("\n")}\n`;
		// Exclude the last row's trailing newline so the fold never glues the next content.
		let end = regionStart + seg.length - 1;
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

	// Row parser: the hex area and ASCII column mirror the SAME bytes, so a parse is
	// accepted only when decoded hex bytes equal ASCII render length. That rejects
	// ASCII-column text absorbed as hex (`3456` -> 4V) while accepting both 2- and
	// 4-char group widths (GNU vs toybox xxd).
	function parseXxdRow(line: string): { groups: string; bytes: string } | undefined {
		const head = /^([0-9a-fA-F]{7,8}): (.*)$/.exec(line);
		if (head === null) return undefined;
		const rest = head[2];
		const candidates: Array<{ groups: string; ascii: string }> = [];
		const grouped = /((?:\b[0-9a-fA-F]{2,4}\b[ \t]+)*\b[0-9a-fA-F]{2,4}\b)[ \t]+([ -~]{1,})$/.exec(rest);
		if (grouped !== null) candidates.push({ groups: grouped[1], ascii: grouped[2].trimEnd() });
		const gap = / {2,}/.exec(rest);
		if (gap !== null)
			candidates.push({ groups: rest.slice(0, gap.index).trim(), ascii: rest.slice(gap.index).trimStart().trimEnd() });
		for (const c of candidates) {
			const bytes = hexPairsToBytes(c.groups);
			if (bytes.length > 0 && bytes.length === c.ascii.length) return { groups: c.groups, bytes };
		}
		return undefined;
	}
	const lines = text.split("\n");
	for (let li = 0; li < lines.length; li++) {
		const first = parseXxdRow(lines[li]);
		if (first === undefined) continue;
		let bytes = "";
		let lastIdx = li;
		for (let k = li; k < lines.length; k++) {
			const mk = parseXxdRow(lines[k]);
			if (mk === undefined) break;
			const b = mk.bytes;
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
		end -= 1; // exclude the last row's trailing newline (no content gluing)
		if (end > text.length) end = text.length;
		out.push([start, end, bytes]);
		li = lastIdx;
	}
	return out;
}

function noAddressHexFoldRegions(text: string): Region[] {
	const out: Region[] = [];
	const NO_ADDR_LINE = /^((?:\b[0-9a-fA-F]{2}\b[ \t]+)*\b[0-9a-fA-F]{2}\b)\s{2}([ -~]{1,})$/;
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
		end -= 1; // exclude the last row's trailing newline
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
		end -= 1; // exclude the last row's trailing newline
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
	// Regions from one family are computed on the source text and can overlap each
	// other (bare hex runs sit inside row blocks). Applying overlapping or stale
	// offsets corrupts the transcript (glued lines, second dump leak). Walk ascending,
	// keep a disjoint set, and shift later positions by prior replacements.
	const sorted = regions.slice().sort((a, b) => a[0] - b[0]);
	let out = text;
	let shift = 0;
	let lastEnd = 0;
	for (const [start, end, folded] of sorted) {
		if (start < lastEnd) continue; // overlapping: the earlier-starting region covers the same content
		const s = start + shift;
		const e = end + shift;
		if (s < 0 || e > out.length) continue; // stale: drops out of the already-shortened text
		captureUnregistered(obfuscator, folded, { skipValueVeto: true });
		const hashed = obfuscator.obfuscate(folded);
		if (hashed !== folded) {
			out = out.slice(0, s) + hashed + out.slice(e);
			shift += hashed.length - (end - start);
		}
		lastEnd = end;
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
