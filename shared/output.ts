import type { IDataObject, INodeExecutionData } from 'n8n-workflow';
import { SOURCE } from './constants';
import { getServiceName } from './ports';
import type { InternetDbHost, LookupResult, NoDataBehavior, OutputMode } from './types';

export interface OutputOptions {
	outputMode: OutputMode;
	/** `error` is handled by the caller before shaping; here it behaves like `skip`. */
	noDataBehavior: NoDataBehavior;
	includeSummary: boolean;
	includePortNames: boolean;
}

/** What happened for one IP: a lookup result, or a non-public IP that was never sent. */
export type IpOutcome =
	| {
			kind: 'lookup';
			result: LookupResult;
			/** ISO timestamp of the request. */ lookedUpAt: string;
	  }
	| { kind: 'nonPublic'; ip: string };

export function sortPorts(ports: readonly number[]): number[] {
	return [...ports].sort((a, b) => a - b);
}

const CVE_PATTERN = /^CVE-(\d+)-(\d+)$/i;

/** Orders CVE IDs by year, then number (CVE-2021-9999 before CVE-2021-10000). Unknown formats go last. */
export function compareCve(a: string, b: string): number {
	const ma = CVE_PATTERN.exec(a);
	const mb = CVE_PATTERN.exec(b);
	if (ma && mb) return Number(ma[1]) - Number(mb[1]) || Number(ma[2]) - Number(mb[2]);
	if (ma) return -1;
	if (mb) return 1;
	return a < b ? -1 : a > b ? 1 : 0;
}

export function sortCves(vulns: readonly string[]): string[] {
	return [...vulns].sort(compareCve);
}

export function emptyHost(ip: string): InternetDbHost {
	return { ip, ports: [], cpes: [], hostnames: [], tags: [], vulns: [] };
}

function hostItem(
	host: InternetDbHost,
	found: boolean,
	lookedUpAt: string,
	opts: OutputOptions,
): IDataObject {
	const ports = sortPorts(host.ports);
	const vulns = sortCves(host.vulns);
	const item: IDataObject = {
		ip: host.ip,
		ports,
		cpes: host.cpes,
		hostnames: host.hostnames,
		tags: host.tags,
		vulns,
		found,
	};
	if (opts.includePortNames) {
		item.services = ports.map((port) => ({ port, name: getServiceName(port) }));
	}
	if (opts.includeSummary) {
		Object.assign(item, {
			portCount: ports.length,
			vulnCount: vulns.length,
			hasVulns: vulns.length > 0,
			hasEolProduct: host.tags.includes('eol-product'),
			lookedUpAt,
			source: SOURCE,
		});
	}
	return item;
}

/** Shapes one IP's outcome into output objects according to `outputMode`. */
export function shapeOutcome(outcome: IpOutcome, opts: OutputOptions): IDataObject[] {
	if (outcome.kind === 'nonPublic') {
		return opts.outputMode === 'host'
			? [{ ip: outcome.ip, found: false, skipped: 'non_public' }]
			: [];
	}

	const { result, lookedUpAt } = outcome;
	if (result.status === 'not_found' && opts.noDataBehavior !== 'returnEmpty') return [];

	const found = result.status === 'found';
	const host = result.status === 'found' ? result.host : emptyHost(result.ip);

	switch (opts.outputMode) {
		case 'raw':
			return [found ? { ...host } : { ...host, found: false }];
		case 'ports':
			return sortPorts(host.ports).map((port) =>
				opts.includePortNames
					? { ip: host.ip, port, serviceName: getServiceName(port) }
					: { ip: host.ip, port },
			);
		case 'vulns':
			return sortCves(host.vulns).map((cve) => ({ ip: host.ip, cve }));
		case 'host':
		default:
			return [hostItem(host, found, lookedUpAt, opts)];
	}
}

/** Wraps output objects as execution items paired to input item `itemIndex`. */
export function toExecutionData(objects: IDataObject[], itemIndex: number): INodeExecutionData[] {
	return objects.map((json) => ({ json, pairedItem: { item: itemIndex } }));
}
