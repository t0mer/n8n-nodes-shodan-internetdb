import { describe, expect, it } from 'vitest';
import {
	HOSTNAME_MESSAGE,
	expandCidr,
	expandTargets,
	hostCount,
	intToIPv4,
	isNonPublicIPv4,
	normalizeTargetList,
	parseIPv4,
	parseSingleIp,
	parseTarget,
	splitTargets,
} from '../shared/ip';

const ip = (s: string) => {
	const n = parseIPv4(s);
	if (n === null) throw new Error(`bad test ip ${s}`);
	return n;
};

describe('parseIPv4', () => {
	it.each(['0.0.0.0', '1.1.1.1', '255.255.255.255', '192.168.0.10'])('accepts %s', (s) => {
		expect(intToIPv4(ip(s))).toBe(s);
	});

	it.each([
		'1.2.3',
		'1.2.3.4.5',
		'256.1.1.1',
		'1.2.3.-1',
		'1..2.3',
		'a.b.c.d',
		'01.2.3.4',
		'1.2.3.004',
		'',
	])('rejects %s', (s) => {
		expect(parseIPv4(s)).toBeNull();
	});
});

describe('parseTarget', () => {
	it('parses IPv4 and trims whitespace', () => {
		expect(parseTarget('  8.8.8.8\n')).toEqual({ kind: 'ipv4', ip: '8.8.8.8' });
	});

	it('parses CIDR and normalizes to the network address', () => {
		expect(parseTarget('8.8.8.5/30')).toEqual({ kind: 'cidr', network: ip('8.8.8.4'), prefix: 30 });
	});

	it('parses IPv6 into canonical form', () => {
		expect(parseTarget('2001:0DB8:0000:0000:0000:0000:0000:0001')).toEqual({
			kind: 'ipv6',
			ip: '2001:db8::1',
		});
		expect(parseTarget('2606:4700:4700::1111')).toEqual({
			kind: 'ipv6',
			ip: '2606:4700:4700::1111',
		});
		expect(parseTarget('fe80::1')).toEqual({ kind: 'ipv6', ip: 'fe80::1' });
		expect(parseTarget('abcd::1')).toEqual({ kind: 'ipv6', ip: 'abcd::1' });
		expect(parseTarget('::ffff:1.2.3.4')).toEqual({ kind: 'ipv6', ip: '::ffff:102:304' });
	});

	it('rejects IPv6 CIDR', () => {
		expect(() => parseTarget('2001:db8::/32')).toThrow(/IPv6 ranges are not supported/);
	});

	it.each([
		'example.com',
		'www.shodan.io',
		'https://example.com/path',
		'localhost',
		'example.com:443',
		'localhost:8080',
		'www.example.com/path',
		'example.com/24',
		'router:80',
	])('rejects hostname/URL %s with the exact message', (s) => {
		expect(() => parseTarget(s)).toThrow(HOSTNAME_MESSAGE);
	});

	it('has the exact hostname message from the spec', () => {
		expect(HOSTNAME_MESSAGE).toBe(
			'InternetDB only accepts IP addresses. Resolve the hostname first (for example with the DNS node) and pass the IP.',
		);
	});

	it('rejects ip:port', () => {
		expect(() => parseTarget('1.2.3.4:443')).toThrow(
			'"1.2.3.4:443" includes a port. Pass the IP address only (1.2.3.4).',
		);
		expect(() => parseTarget('[2001:db8::1]:443')).toThrow(/includes a port/);
	});

	it('rejects leading zeros', () => {
		expect(() => parseTarget('01.2.3.4')).toThrow(/leading zero/);
	});

	it.each([
		'256.1.1.1',
		'1.2.3',
		'1.2.3.4/33',
		'1.2.3.4/',
		'1.2.3.4/0x',
		'!!',
		'fe80::1%eth0',
		'1:2:3',
	])('rejects invalid %s', (s) => {
		expect(() => parseTarget(s)).toThrow();
	});
});

describe('parseSingleIp', () => {
	it('rejects CIDR with a pointer to Lookup Many', () => {
		expect(() => parseSingleIp('1.1.1.0/24')).toThrow(/Lookup Many/);
	});

	it('flags non-public addresses', () => {
		expect(parseSingleIp('10.0.0.1')).toEqual({ ip: '10.0.0.1', nonPublic: true });
		expect(parseSingleIp('1.1.1.1')).toEqual({ ip: '1.1.1.1', nonPublic: false });
		expect(parseSingleIp('::1')).toEqual({ ip: '::1', nonPublic: true });
		expect(parseSingleIp('2606:4700:4700::1111')).toEqual({
			ip: '2606:4700:4700::1111',
			nonPublic: false,
		});
	});
});

describe('CIDR expansion', () => {
	it.each([
		[32, 1],
		[31, 2],
		[30, 2],
		[24, 254],
		[16, 65534],
		[0, 4294967294],
	])('/%i has %i host addresses', (prefix, count) => {
		expect(hostCount(prefix)).toBe(count);
	});

	it('/32 yields the address itself', () => {
		expect([...expandCidr(ip('1.2.3.4'), 32)].map(intToIPv4)).toEqual(['1.2.3.4']);
	});

	it('/31 includes both addresses', () => {
		expect([...expandCidr(ip('1.2.3.4'), 31)].map(intToIPv4)).toEqual(['1.2.3.4', '1.2.3.5']);
	});

	it('/30 excludes network and broadcast', () => {
		expect([...expandCidr(ip('1.2.3.4'), 30)].map(intToIPv4)).toEqual(['1.2.3.5', '1.2.3.6']);
	});

	it('/24 yields 254 hosts', () => {
		const all = [...expandCidr(ip('8.8.8.0'), 24)].map(intToIPv4);
		expect(all).toHaveLength(254);
		expect(all[0]).toBe('8.8.8.1');
		expect(all[253]).toBe('8.8.8.254');
	});

	it('/0 is lazy', () => {
		const gen = expandCidr(0, 0);
		expect(intToIPv4(gen.next().value as number)).toBe('0.0.0.1');
		expect(intToIPv4(gen.next().value as number)).toBe('0.0.0.2');
	});
});

describe('isNonPublicIPv4', () => {
	it.each([
		'0.1.2.3',
		'10.0.0.1',
		'100.64.0.1',
		'100.127.255.254',
		'127.0.0.1',
		'169.254.1.1',
		'172.16.0.1',
		'172.31.255.255',
		'192.0.0.8',
		'192.0.2.1',
		'192.88.99.1',
		'192.168.1.1',
		'198.18.0.1',
		'198.19.255.1',
		'198.51.100.7',
		'203.0.113.9',
		'224.0.0.1',
		'239.255.255.255',
		'240.0.0.1',
		'255.255.255.255',
	])('%s is non-public', (s) => {
		expect(isNonPublicIPv4(ip(s))).toBe(true);
	});

	it.each([
		'1.1.1.1',
		'8.8.8.8',
		'100.63.255.255',
		'100.128.0.0',
		'172.15.255.255',
		'172.32.0.0',
		'223.255.255.255',
	])('%s is public', (s) => {
		expect(isNonPublicIPv4(ip(s))).toBe(false);
	});
});

describe('splitTargets', () => {
	it('splits on commas, whitespace and newlines', () => {
		expect(splitTargets(' 1.1.1.1, 8.8.8.0/30\n9.9.9.9\t,,  ')).toEqual([
			'1.1.1.1',
			'8.8.8.0/30',
			'9.9.9.9',
		]);
	});
});

describe('expandTargets', () => {
	it('expands, de-duplicates and preserves input order', () => {
		const res = expandTargets('8.8.8.8, 1.1.1.0/30, 8.8.8.8, 1.1.1.1, 10.0.0.1', 256);
		expect(res.map((t) => t.ip)).toEqual(['8.8.8.8', '1.1.1.1', '1.1.1.2', '10.0.0.1']);
		expect(res.find((t) => t.ip === '10.0.0.1')?.nonPublic).toBe(true);
	});

	it('accepts IPv6 pass-through', () => {
		expect(expandTargets('2606:4700:4700::1111', 1)).toEqual([
			{ ip: '2606:4700:4700::1111', nonPublic: false },
		]);
	});

	it('allows a /24 within limits', () => {
		expect(expandTargets('8.8.8.0/24', 256)).toHaveLength(254);
	});

	it('refuses a /16 with the expanded count', () => {
		expect(() => expandTargets('8.8.0.0/16', 256)).toThrow(
			'The targets expand to 65534 addresses, more than the Max Addresses limit of 256. Narrow the ranges or raise Max Addresses.',
		);
	});

	it('refuses /0 without iterating it', () => {
		const start = Date.now();
		expect(() => expandTargets('0.0.0.0/0', 4096)).toThrow(/4294967294 addresses/);
		expect(Date.now() - start).toBeLessThan(1000);
	});

	it('does not count duplicates against the limit', () => {
		expect(expandTargets('1.1.1.1, 1.1.1.1, 1.1.1.1', 1)).toHaveLength(1);
	});

	it('names the offending value and position', () => {
		expect(() => expandTargets('1.1.1.1, example.com', 10)).toThrow(
			`Target 2 ("example.com"): ${HOSTNAME_MESSAGE}`,
		);
	});

	it('rejects an empty list', () => {
		expect(() => expandTargets(' , ', 10)).toThrow(/No targets/);
	});
});

describe('normalizeTargetList', () => {
	it('produces a sorted, de-duplicated canonical list', () => {
		expect(normalizeTargetList('8.8.8.9/30, 1.1.1.1 1.1.1.1 2001:DB8::1')).toEqual([
			'1.1.1.1',
			'2001:db8::1',
			'8.8.8.8/30',
		]);
	});
});
