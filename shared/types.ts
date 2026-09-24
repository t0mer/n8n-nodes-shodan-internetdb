/** Host record returned by `GET https://internetdb.shodan.io/{ip}` (OpenAPI `Host` schema). */
export interface InternetDbHost {
	ip: string;
	ports: number[];
	/** CPE 2.2 URIs, e.g. "cpe:/a:openbsd:openssh:7.4". */
	cpes: string[];
	hostnames: string[];
	/** e.g. "vpn", "cdn", "cloud", "self-signed", "eol-product". */
	tags: string[];
	/** CVE IDs, e.g. "CVE-2017-15906". */
	vulns: string[];
}

/** Every key of `InternetDbHost`, used by the OpenAPI drift test. */
export const INTERNETDB_HOST_KEYS = [
	'ip',
	'ports',
	'cpes',
	'hostnames',
	'tags',
	'vulns',
] as const satisfies ReadonlyArray<keyof InternetDbHost>;

/** Compile-time guard: fails to type-check if `INTERNETDB_HOST_KEYS` misses a key. */
export const INTERNETDB_HOST_KEYS_EXHAUSTIVE: [
	Exclude<keyof InternetDbHost, (typeof INTERNETDB_HOST_KEYS)[number]>,
] extends [never]
	? true
	: false = true;

export type LookupResult =
	| { status: 'found'; host: InternetDbHost }
	| { status: 'not_found'; ip: string };

export type OutputMode = 'host' | 'ports' | 'vulns' | 'raw';
export type NoDataBehavior = 'returnEmpty' | 'skip' | 'error';
export type NonPublicBehavior = 'skip' | 'error';

/** Per-IP state stored by the trigger. Arrays are always sorted. */
export interface HostSnapshot {
	found: boolean;
	ports: number[];
	vulns: string[];
	tags: string[];
	hostnames: string[];
	cpes: string[];
	seenAt: string;
}

export interface TriggerState {
	version: 1;
	targetsHash: string;
	snapshots: Record<string, HostSnapshot>;
}
