export class RegistryRevision {
	value = 0;

	bump(): void {
		this.value++;
	}
}

export class TrackedMap<K, V> implements ReadonlyMap<K, V> {
	readonly #map = new Map<K, V>();
	readonly #revision: RegistryRevision;
	#version = 0;

	constructor(revision: RegistryRevision) {
		this.#revision = revision;
	}

	get version(): number {
		return this.#version;
	}

	get size(): number {
		return this.#map.size;
	}

	get(key: K): V | undefined {
		return this.#map.get(key);
	}

	has(key: K): boolean {
		return this.#map.has(key);
	}

	set(key: K, value: V): this {
		if (this.#map.has(key) && this.#map.get(key) === value) return this;
		this.#map.set(key, value);
		this.#version++;
		this.#revision.bump();
		return this;
	}

	delete(key: K): boolean {
		if (!this.#map.delete(key)) return false;
		this.#version++;
		this.#revision.bump();
		return true;
	}

	keys(): MapIterator<K> {
		return this.#map.keys();
	}

	values(): MapIterator<V> {
		return this.#map.values();
	}

	entries(): MapIterator<[K, V]> {
		return this.#map.entries();
	}

	forEach(callback: (value: V, key: K, map: ReadonlyMap<K, V>) => void, thisArg?: unknown): void {
		for (const [key, value] of this.#map) callback.call(thisArg, value, key, this);
	}

	[Symbol.iterator](): MapIterator<[K, V]> {
		return this.#map[Symbol.iterator]();
	}
}

export class TrackedSet<T> {
	readonly #set = new Set<T>();
	readonly #revision: RegistryRevision;

	constructor(revision: RegistryRevision) {
		this.#revision = revision;
	}

	get size(): number {
		return this.#set.size;
	}

	has(value: T): boolean {
		return this.#set.has(value);
	}

	add(value: T): this {
		if (this.#set.has(value)) return this;
		this.#set.add(value);
		this.#revision.bump();
		return this;
	}

	delete(value: T): boolean {
		if (!this.#set.delete(value)) return false;
		this.#revision.bump();
		return true;
	}

	[Symbol.iterator](): SetIterator<T> {
		return this.#set[Symbol.iterator]();
	}
}
