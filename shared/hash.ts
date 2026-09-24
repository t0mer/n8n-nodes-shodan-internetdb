/** 32-bit FNV-1a hash of a string, as 8 hex characters. Not cryptographic. */
export function fnv1a(input: string): string {
	let hash = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return (hash >>> 0).toString(16).padStart(8, '0');
}

/** Hash of a normalized (sorted, canonical) target list. */
export function hashTargets(normalizedTargets: readonly string[]): string {
	return fnv1a(normalizedTargets.join('\n'));
}
