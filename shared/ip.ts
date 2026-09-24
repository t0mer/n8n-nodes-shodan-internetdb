/**
 * IP parsing, CIDR expansion and non-public range checks.
 * Written in-house: the package must have zero runtime dependencies and may not import `node:net`.
 */

export const HOSTNAME_MESSAGE =
	'InternetDB only accepts IP addresses. Resolve the hostname first (for example with the DNS node) and pass the IP.';

/** A target that is invalid as typed. The nodes wrap it in a NodeOperationError. */
export class InvalidTargetError extends Error {}

export type ParsedTarget =
	| { kind: 'ipv4'; ip: string }
	| { kind: 'cidr'; network: number; prefix: number }
	| { kind: 'ipv6'; ip: string };

/** One address ready to look up. */
export interface ResolvedTarget {
	ip: string;
	/** Non-public addresses never have data and are never sent to the API. */
	nonPublic: boolean;
}

const OCTET = /^(0|[1-9]\d{0,2})$/;

/** Parses a dotted-quad IPv4 address into an unsigned 32-bit integer. Rejects leading zeros. */
export function parseIPv4(s: string): number | null {
	const parts = s.split('.');
	if (parts.length !== 4) return null;
	let value = 0;
	for (const part of parts) {
		if (!OCTET.test(part)) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		value = value * 256 + octet;
	}
	return value;
}

export function intToIPv4(n: number): string {
	return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function prefixMask(prefix: number): number {
	return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** Parses an IPv6 address into eight 16-bit groups. Zone IDs are rejected. */
function parseIPv6(s: string): number[] | null {
	if (!s.includes(':') || s.includes('%')) return null;

	let str = s;
	let tail: number[] = [];
	const lastColon = str.lastIndexOf(':');
	const last = str.slice(lastColon + 1);
	if (last.includes('.')) {
		const v4 = parseIPv4(last);
		if (v4 === null) return null;
		tail = [v4 >>> 16, v4 & 0xffff];
		str = str.slice(0, lastColon + 1);
		if (!str.endsWith('::')) str = str.slice(0, -1);
	}

	const halves = str.split('::');
	if (halves.length > 2) return null;
	const groups = (part: string) =>
		part === ''
			? []
			: part.split(':').map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN));
	const head = groups(halves[0]);
	const rest = halves.length === 2 ? groups(halves[1]) : [];
	if ([...head, ...rest].some((g) => Number.isNaN(g))) return null;

	const count = head.length + rest.length + tail.length;
	if (halves.length === 2) {
		if (count > 7) return null;
		return [...head, ...new Array<number>(8 - count).fill(0), ...rest, ...tail];
	}
	return count === 8 ? [...head, ...tail] : null;
}

/** Formats IPv6 groups in RFC 5952 canonical form. */
function formatIPv6(groups: number[]): string {
	let bestStart = -1;
	let bestLen = 1;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLen) {
			bestStart = i;
			bestLen = j - i;
		}
		i = j;
	}
	const hex = groups.map((g) => g.toString(16));
	if (bestStart === -1) return hex.join(':');
	return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

function invalidIPv4(value: string, raw: string): InvalidTargetError {
	if (value.split('.').some((part) => /^0\d+$/.test(part))) {
		return new InvalidTargetError(
			`"${raw}" has a leading zero in an octet, which is ambiguous (it can be read as octal). Remove the leading zeros.`,
		);
	}
	return new InvalidTargetError(`"${raw}" is not a valid IPv4 address.`);
}

const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.?$/i;

/**
 * True for a hostname, optionally followed by a port or path (`example.com`, `example.com:443`,
 * `www.example.com/path`). The host part must contain a letter and must not be a bare IPv6
 * hex group, so `fe80::1` and `2001:db8::/32` are not matched.
 */
function looksLikeHostname(s: string): boolean {
	const host = s.split(/[:/]/)[0];
	if (!HOSTNAME.test(host) || !/[a-z]/i.test(host)) return false;
	return host.includes('.') || /[g-z]/i.test(host) || host.length > 4 || !/[:/]/.test(s);
}

/** Parses one target: an IPv4 address, an IPv4 CIDR range, or a single IPv6 address. */
export function parseTarget(raw: string): ParsedTarget {
	const s = raw.trim();
	if (s === '') throw new InvalidTargetError('Empty target. Pass an IP address or CIDR range.');
	if (s.includes('://') || looksLikeHostname(s)) throw new InvalidTargetError(HOSTNAME_MESSAGE);

	const withPort = /^\[([^\]]+)\]:\d+$/.exec(s) ?? /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
	if (withPort) {
		throw new InvalidTargetError(
			`"${s}" includes a port. Pass the IP address only (${withPort[1]}).`,
		);
	}

	if (s.includes('/')) {
		const [addr, prefixText, ...extra] = s.split('/');
		if (addr.includes(':') && parseIPv6(addr)) {
			throw new InvalidTargetError(
				`"${s}": IPv6 ranges are not supported. InternetDB covers IPv4; pass single IPv6 addresses instead.`,
			);
		}
		if (extra.length > 0 || !/^\d{1,2}$/.test(prefixText) || Number(prefixText) > 32) {
			throw new InvalidTargetError(`"${s}" has an invalid prefix length. Use /0 to /32.`);
		}
		const value = parseIPv4(addr);
		if (value === null) throw invalidIPv4(addr, s);
		const prefix = Number(prefixText);
		return { kind: 'cidr', network: (value & prefixMask(prefix)) >>> 0, prefix };
	}

	if (s.includes(':')) {
		const groups = parseIPv6(s);
		if (!groups) throw new InvalidTargetError(`"${s}" is not a valid IP address.`);
		// IPv4-mapped (::ffff:a.b.c.d): InternetDB indexes the IPv4 form.
		if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
			return { kind: 'ipv4', ip: intToIPv4(((groups[6] << 16) | groups[7]) >>> 0) };
		}
		return { kind: 'ipv6', ip: formatIPv6(groups) };
	}

	if (/^[\d.]+$/.test(s)) {
		if (parseIPv4(s) === null) throw invalidIPv4(s, s);
		return { kind: 'ipv4', ip: s };
	}

	throw new InvalidTargetError(`"${s}" is not a valid IP address or CIDR range.`);
}

/** Number of addresses a CIDR prefix expands to (host range, except /31 and /32). */
export function hostCount(prefix: number): number {
	const size = 2 ** (32 - prefix);
	return prefix >= 31 ? size : size - 2;
}

/** Lazily yields the addresses of a CIDR range. Network and broadcast are skipped except for /31 and /32. */
export function* expandCidr(network: number, prefix: number): Generator<number> {
	const size = 2 ** (32 - prefix);
	const first = prefix >= 31 ? network : network + 1;
	const last = prefix >= 31 ? network + size - 1 : network + size - 2;
	for (let n = first; n <= last; n++) yield n;
}

/** IPv4 ranges that can never have InternetDB data. */
const NON_PUBLIC_IPV4: Array<[number, number]> = (
	[
		['0.0.0.0', 8], // "this network"
		['10.0.0.0', 8], // RFC 1918
		['100.64.0.0', 10], // CGNAT
		['127.0.0.0', 8], // loopback
		['169.254.0.0', 16], // link-local
		['172.16.0.0', 12], // RFC 1918
		['192.0.0.0', 24], // IETF protocol assignments
		['192.0.2.0', 24], // TEST-NET-1
		['192.88.99.0', 24], // 6to4 relay anycast (deprecated)
		['192.168.0.0', 16], // RFC 1918
		['198.18.0.0', 15], // benchmarking
		['198.51.100.0', 24], // TEST-NET-2
		['203.0.113.0', 24], // TEST-NET-3
		['224.0.0.0', 4], // multicast
		['240.0.0.0', 4], // reserved, includes 255.255.255.255 broadcast
	] as Array<[string, number]>
).map(([addr, prefix]) => [parseIPv4(addr) as number, prefix]);

export function isNonPublicIPv4(value: number): boolean {
	return NON_PUBLIC_IPV4.some(
		([network, prefix]) => (value & prefixMask(prefix)) >>> 0 === network,
	);
}

function isNonPublicIPv6(groups: number[]): boolean {
	const [g0, g1] = groups;
	const leadingZeros = groups.slice(0, 5).every((g) => g === 0);
	if (leadingZeros && groups[5] === 0 && groups[6] === 0 && groups[7] <= 1) return true; // :: and ::1
	return (
		(g0 & 0xfe00) === 0xfc00 || // unique local
		(g0 & 0xffc0) === 0xfe80 || // link-local
		(g0 & 0xff00) === 0xff00 || // multicast
		(g0 === 0x2001 && g1 === 0x0db8) // documentation
	);
}

function resolveSingle(target: { kind: 'ipv4' | 'ipv6'; ip: string }): ResolvedTarget {
	const nonPublic =
		target.kind === 'ipv4'
			? isNonPublicIPv4(parseIPv4(target.ip) as number)
			: isNonPublicIPv6(parseIPv6(target.ip) as number[]);
	return { ip: target.ip, nonPublic };
}

/** Parses the single-IP input of the Lookup operation. */
export function parseSingleIp(raw: string): ResolvedTarget {
	const target = parseTarget(raw);
	if (target.kind === 'cidr') {
		throw new InvalidTargetError(
			`"${raw.trim()}" is a range. Lookup takes a single IP address; use Lookup Many for CIDR ranges.`,
		);
	}
	return resolveSingle(target);
}

/** Splits a target list on commas, whitespace and newlines. */
export function splitTargets(raw: string): string[] {
	return raw.split(/[\s,]+/).filter((token) => token !== '');
}

function parseTargetList(raw: string): ParsedTarget[] {
	const tokens = splitTargets(raw);
	if (tokens.length === 0)
		throw new InvalidTargetError('No targets given. Pass IP addresses or CIDR ranges.');
	return tokens.map((token, index) => {
		let result: ParsedTarget | Error;
		try {
			result = parseTarget(token);
		} catch (error) {
			result = error as Error;
		}
		if (result instanceof Error) {
			throw new InvalidTargetError(`Target ${index + 1} ("${token}"): ${result.message}`);
		}
		return result;
	});
}

/**
 * Expands a target list into unique addresses, in input order.
 * Throws before any request if more than `maxAddresses` unique addresses result.
 */
export function expandTargets(raw: string, maxAddresses: number): ResolvedTarget[] {
	const parsed = parseTargetList(raw);
	const total = parsed.reduce((sum, t) => sum + (t.kind === 'cidr' ? hostCount(t.prefix) : 1), 0);

	const seen = new Set<string>();
	const out: ResolvedTarget[] = [];
	const add = (target: ResolvedTarget) => {
		if (seen.has(target.ip)) return;
		seen.add(target.ip);
		out.push(target);
		if (out.length > maxAddresses) {
			throw new InvalidTargetError(
				`The targets expand to ${total} addresses, more than the Max Addresses limit of ${maxAddresses}. Narrow the ranges or raise Max Addresses.`,
			);
		}
	};

	for (const target of parsed) {
		if (target.kind !== 'cidr') {
			add(resolveSingle(target));
			continue;
		}
		for (const n of expandCidr(target.network, target.prefix)) {
			add({ ip: intToIPv4(n), nonPublic: isNonPublicIPv4(n) });
		}
	}
	return out;
}

/** Canonical, sorted, de-duplicated target list. Used to detect edits to the trigger's targets. */
export function normalizeTargetList(raw: string): string[] {
	const canonical = parseTargetList(raw).map((t) =>
		t.kind === 'cidr' ? `${intToIPv4(t.network)}/${t.prefix}` : t.ip,
	);
	return [...new Set(canonical)].sort();
}
