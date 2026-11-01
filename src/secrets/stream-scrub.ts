const STREAM_PEM_OPEN = "-----BEGIN ";
const STREAM_PEM_CLOSE = "-----END ";
const STREAM_PEM_MAX = 32 * 1024;
const STREAM_LINE_CAP = 64 * 1024;
const STREAM_HOLD = 1024;

interface StreamScrubber {
	write(data: Buffer): void;

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
