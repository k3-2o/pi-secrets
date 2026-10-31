/**
 * Streaming at-rest scrubber for `user_bash` output (pi's local shell operations).
 *
 * The hard part is chunk boundaries: a secret arriving in pieces must be scrubbed
 * whole, not fragment by fragment (each fragment fails the full pattern and passes
 * through raw). Strategy:
 *
 * - Emit at **line boundaries** (`\n`/`\r`): the emitted unit is whole lines, so a
 *   token-like secret (JWT, key, URL, assignment) can never be split across units.
 *   `\r` counts so `curl`-style progress updates flush per update.
 * - **PEM hold**: from `-----BEGIN ` until `-----END ` multiple lines are one unit
 *   (keys span lines), capped at `pemMax`.
 * - **Cap degrade**: a newline-free blob past `lineCap` is emitted in fragments
 *   holding back `hold` bytes — a > lineCap token cannot be scrubbed streaming;
 *   the whole-text `tool_result` path still covers it.
 *
 * Units pass through byte-identical unless scrubbing changed them (binary-safe).
 */
const STREAM_PEM_OPEN = "-----BEGIN ";
const STREAM_PEM_CLOSE = "-----END ";
const STREAM_PEM_MAX = 32 * 1024;
const STREAM_LINE_CAP = 64 * 1024;
const STREAM_HOLD = 1024;

export interface StreamScrubber {
	write(data: Buffer): void;
	/** Emit whatever is still held (end of stream). */
	flush(): void;
}

export function createStreamScrubber(options: {
	onData: (chunk: Buffer) => void;
	scrub: (text: string) => string;
	pemMax?: number;
	lineCap?: number;
	hold?: number;
}): StreamScrubber {
	const pemMax = options.pemMax ?? STREAM_PEM_MAX;
	const lineCap = options.lineCap ?? STREAM_LINE_CAP;
	const hold = options.hold ?? STREAM_HOLD;
	let buffer = Buffer.alloc(0);
	let pemHolding = false;

	const emitUnit = (unit: Buffer): void => {
		if (unit.length === 0) return;
		const text = unit.toString("utf8");
		const scrubbed = options.scrub(text);
		options.onData(scrubbed === text ? unit : Buffer.from(scrubbed));
	};

	const emitCapFragment = (): void => {
		const emitLength = buffer.length - hold;
		if (emitLength <= 0) return;
		emitUnit(buffer.subarray(0, emitLength));
		buffer = buffer.subarray(emitLength);
	};

	return {
		write(data: Buffer): void {
			buffer = Buffer.concat([buffer, data]);
			const text = buffer.toString("utf8");
			const hasOpen = text.includes(STREAM_PEM_OPEN);
			if (hasOpen && !pemHolding) pemHolding = true;
			if (pemHolding) {
				if (text.includes(STREAM_PEM_CLOSE)) {
					pemHolding = false;
					emitUnit(buffer);
					buffer = Buffer.alloc(0);
				} else if (buffer.length > pemMax) {
					emitCapFragment();
				}
				return;
			}
			// Byte-level boundary scan (text indices would misalign on multi-byte UTF-8).
			const nl = buffer.lastIndexOf(0x0a);
			const cr = buffer.lastIndexOf(0x0d);
			const cut = Math.max(nl, cr) + 1;
			if (cut > 0) {
				emitUnit(buffer.subarray(0, cut));
				buffer = buffer.subarray(cut);
			} else if (buffer.length > lineCap) {
				emitCapFragment();
			}
		},
		flush(): void {
			emitUnit(buffer);
			buffer = Buffer.alloc(0);
			pemHolding = false;
		},
	};
}
