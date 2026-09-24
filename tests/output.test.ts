import { describe, expect, it } from 'vitest';
import {
	compareCve,
	shapeOutcome,
	sortCves,
	sortPorts,
	toExecutionData,
	type IpOutcome,
	type OutputOptions,
} from '../shared/output';
import type { InternetDbHost } from '../shared/types';

const host: InternetDbHost = {
	ip: '51.83.59.99',
	ports: [500, 22, 443, 80],
	cpes: ['cpe:/a:openbsd:openssh:7.4', 'cpe:/a:igor_sysoev:nginx'],
	hostnames: ['www.sampleresponse.fr'],
	tags: ['vpn', 'eol-product'],
	vulns: ['CVE-2021-10000', 'CVE-2017-15906', 'CVE-2021-9999'],
};

const AT = '2026-09-24T00:00:00.000Z';
const found: IpOutcome = { kind: 'lookup', result: { status: 'found', host }, lookedUpAt: AT };
const notFound: IpOutcome = {
	kind: 'lookup',
	result: { status: 'not_found', ip: '9.9.9.9' },
	lookedUpAt: AT,
};
const nonPublic: IpOutcome = { kind: 'nonPublic', ip: '10.0.0.1' };

const opts = (overrides: Partial<OutputOptions> = {}): OutputOptions => ({
	outputMode: 'host',
	noDataBehavior: 'returnEmpty',
	includeSummary: true,
	includePortNames: false,
	...overrides,
});

describe('sorting', () => {
	it('sorts ports numerically', () => {
		expect(sortPorts([8080, 22, 443, 80])).toEqual([22, 80, 443, 8080]);
	});

	it('sorts CVEs by year then number', () => {
		expect(sortCves(['CVE-2021-10000', 'CVE-2020-99999', 'CVE-2021-9999'])).toEqual([
			'CVE-2020-99999',
			'CVE-2021-9999',
			'CVE-2021-10000',
		]);
	});

	it('puts unknown identifiers after CVEs', () => {
		expect(compareCve('GHSA-xxxx', 'CVE-2020-1')).toBeGreaterThan(0);
		expect(sortCves(['b', 'CVE-2020-1', 'a'])).toEqual(['CVE-2020-1', 'a', 'b']);
	});

	it('does not mutate its input', () => {
		const ports = [3, 1, 2];
		sortPorts(ports);
		expect(ports).toEqual([3, 1, 2]);
	});
});

describe('host mode', () => {
	it('emits the sorted host with summary fields', () => {
		expect(shapeOutcome(found, opts())).toEqual([
			{
				ip: '51.83.59.99',
				ports: [22, 80, 443, 500],
				cpes: host.cpes,
				hostnames: host.hostnames,
				tags: host.tags,
				vulns: ['CVE-2017-15906', 'CVE-2021-9999', 'CVE-2021-10000'],
				found: true,
				portCount: 4,
				vulnCount: 3,
				hasVulns: true,
				hasEolProduct: true,
				lookedUpAt: '2026-09-24T00:00:00.000Z',
				source: 'shodan-internetdb',
			},
		]);
	});

	it('omits summary fields when includeSummary is off', () => {
		const [item] = shapeOutcome(found, opts({ includeSummary: false }));
		expect(Object.keys(item)).toEqual([
			'ip',
			'ports',
			'cpes',
			'hostnames',
			'tags',
			'vulns',
			'found',
		]);
	});

	it('adds services when includePortNames is on', () => {
		const [item] = shapeOutcome(
			{
				kind: 'lookup',
				result: { status: 'found', host: { ...host, ports: [22, 60000] } },
				lookedUpAt: AT,
			},
			opts({ includePortNames: true }),
		);
		expect(item.services).toEqual([
			{ port: 22, name: 'ssh' },
			{ port: 60000, name: null },
		]);
	});

	it('emits an empty host for 404 with returnEmpty', () => {
		expect(shapeOutcome(notFound, opts())).toEqual([
			expect.objectContaining({
				ip: '9.9.9.9',
				ports: [],
				vulns: [],
				found: false,
				portCount: 0,
				hasVulns: false,
			}),
		]);
	});

	it('emits nothing for 404 with skip', () => {
		expect(shapeOutcome(notFound, opts({ noDataBehavior: 'skip' }))).toEqual([]);
	});

	it('marks non-public IPs as skipped', () => {
		expect(shapeOutcome(nonPublic, opts())).toEqual([
			{ ip: '10.0.0.1', found: false, skipped: 'non_public' },
		]);
	});
});

describe('ports mode', () => {
	it('emits one item per port', () => {
		expect(shapeOutcome(found, opts({ outputMode: 'ports' }))).toEqual([
			{ ip: '51.83.59.99', port: 22 },
			{ ip: '51.83.59.99', port: 80 },
			{ ip: '51.83.59.99', port: 443 },
			{ ip: '51.83.59.99', port: 500 },
		]);
	});

	it('adds serviceName when includePortNames is on', () => {
		expect(shapeOutcome(found, opts({ outputMode: 'ports', includePortNames: true }))[0]).toEqual({
			ip: '51.83.59.99',
			port: 22,
			serviceName: 'ssh',
		});
	});

	it.each(['returnEmpty', 'skip'] as const)('emits nothing for 404 with %s', (noDataBehavior) => {
		expect(shapeOutcome(notFound, opts({ outputMode: 'ports', noDataBehavior }))).toEqual([]);
	});

	it('emits nothing for non-public IPs', () => {
		expect(shapeOutcome(nonPublic, opts({ outputMode: 'ports' }))).toEqual([]);
	});
});

describe('vulns mode', () => {
	it('emits one item per CVE in sorted order', () => {
		expect(shapeOutcome(found, opts({ outputMode: 'vulns' }))).toEqual([
			{ ip: '51.83.59.99', cve: 'CVE-2017-15906' },
			{ ip: '51.83.59.99', cve: 'CVE-2021-9999' },
			{ ip: '51.83.59.99', cve: 'CVE-2021-10000' },
		]);
	});

	it('emits nothing for hosts without vulns', () => {
		const clean: IpOutcome = {
			kind: 'lookup',
			result: { status: 'found', host: { ...host, vulns: [] } },
			lookedUpAt: AT,
		};
		expect(shapeOutcome(clean, opts({ outputMode: 'vulns' }))).toEqual([]);
	});

	it.each(['returnEmpty', 'skip'] as const)('emits nothing for 404 with %s', (noDataBehavior) => {
		expect(shapeOutcome(notFound, opts({ outputMode: 'vulns', noDataBehavior }))).toEqual([]);
	});
});

describe('raw mode', () => {
	it('emits the API response unchanged, without derived fields', () => {
		expect(shapeOutcome(found, opts({ outputMode: 'raw', includePortNames: true }))).toEqual([
			host,
		]);
	});

	it('emits an empty host for 404 with returnEmpty', () => {
		expect(shapeOutcome(notFound, opts({ outputMode: 'raw' }))).toEqual([
			{ ip: '9.9.9.9', ports: [], cpes: [], hostnames: [], tags: [], vulns: [], found: false },
		]);
	});

	it('emits nothing for 404 with skip', () => {
		expect(shapeOutcome(notFound, opts({ outputMode: 'raw', noDataBehavior: 'skip' }))).toEqual([]);
	});

	it('emits nothing for non-public IPs', () => {
		expect(shapeOutcome(nonPublic, opts({ outputMode: 'raw' }))).toEqual([]);
	});
});

describe('toExecutionData', () => {
	it('pairs every item to the given input index', () => {
		expect(toExecutionData([{ a: 1 }, { a: 2 }], 3)).toEqual([
			{ json: { a: 1 }, pairedItem: { item: 3 } },
			{ json: { a: 2 }, pairedItem: { item: 3 } },
		]);
	});
});
