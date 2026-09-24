import type { INodeProperties } from 'n8n-workflow';
import { DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_MS } from '../../../shared/constants';

export const ipOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['ip'] } },
		options: [
			{
				name: 'Lookup',
				value: 'lookup',
				description:
					'Get open ports, CPEs, hostnames, tags, and known CVEs for a single public IP address',
				action: 'Look up an IP address',
			},
		],
		default: 'lookup',
	},
];

const outputModeField: INodeProperties = {
	displayName: 'Output Mode',
	name: 'outputMode',
	type: 'options',
	options: [
		{
			name: 'Host',
			value: 'host',
			description: 'One item per IP with ports, CPEs, hostnames, tags, CVEs, and summary fields',
		},
		{
			name: 'Ports',
			value: 'ports',
			description: 'One item per open port',
		},
		{
			name: 'Raw',
			value: 'raw',
			description: 'One item per IP with the exact InternetDB response and no derived fields',
		},
		{
			name: 'Vulnerabilities',
			value: 'vulns',
			description: 'One item per CVE. IPs without known CVEs produce no items.',
		},
	],
	default: 'host',
	description: 'How to shape the output items',
};

/** Options shared by Lookup and Lookup Many, sorted by display name. */
export const commonOptions: INodeProperties[] = [
	{
		displayName: 'Include Port Names',
		name: 'includePortNames',
		type: 'boolean',
		default: false,
		description:
			'Whether to add well-known IANA service names for open ports (for example 22 → ssh). Unknown ports get a null name.',
	},
	{
		displayName: 'Include Summary',
		name: 'includeSummary',
		type: 'boolean',
		default: true,
		description:
			'Whether to add derived fields in Host mode: portCount, vulnCount, hasVulns, hasEolProduct, lookedUpAt, and source',
	},
	{
		displayName: 'Max Retries',
		name: 'maxRetries',
		type: 'number',
		typeOptions: { minValue: 0, maxValue: 10 },
		default: DEFAULT_MAX_RETRIES,
		description: 'How many times to retry rate-limited (429), server (5xx), and network errors',
	},
	{
		displayName: 'No Data Behavior',
		name: 'noDataBehavior',
		type: 'options',
		options: [
			{
				name: 'Return Empty Result',
				value: 'returnEmpty',
				description: 'Emit the IP with empty arrays and found set to false',
			},
			{
				name: 'Skip',
				value: 'skip',
				description: 'Emit nothing for the IP',
			},
			{
				name: 'Throw Error',
				value: 'error',
				description: 'Fail the node',
			},
		],
		default: 'returnEmpty',
		description: 'What to do when InternetDB has no data for an IP',
	},
	{
		displayName: 'Non-Public IP Behavior',
		name: 'nonPublicBehavior',
		type: 'options',
		options: [
			{
				name: 'Skip',
				value: 'skip',
				description:
					'Do not query the API. In Host mode, emit the IP with found set to false and skipped set to non_public.',
			},
			{
				name: 'Throw Error',
				value: 'error',
				description: 'Fail the node',
			},
		],
		default: 'skip',
		description:
			'What to do with private, loopback, link-local, CGNAT, multicast, documentation, and reserved addresses, which never have InternetDB data',
	},
	{
		displayName: 'Timeout (Ms)',
		name: 'timeoutMs',
		type: 'number',
		typeOptions: { minValue: 1000 },
		default: DEFAULT_TIMEOUT_MS,
		description: 'Per-request timeout in milliseconds',
	},
];

export const ipFields: INodeProperties[] = [
	{
		displayName: 'IP Address',
		name: 'ip',
		type: 'string',
		required: true,
		default: '',
		placeholder: '1.1.1.1',
		displayOptions: { show: { resource: ['ip'], operation: ['lookup'] } },
		description:
			'The public IPv4 or IPv6 address to look up. Hostnames, URLs, ports, and ranges are not accepted.',
	},
	{
		...outputModeField,
		displayOptions: { show: { resource: ['ip'], operation: ['lookup'] } },
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: { resource: ['ip'], operation: ['lookup'] } },
		options: commonOptions,
	},
];
