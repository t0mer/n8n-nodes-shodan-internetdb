import {
	NodeApiError,
	NodeConnectionTypes,
	NodeOperationError,
	type IDataObject,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
	type IPollFunctions,
	type JsonObject,
} from 'n8n-workflow';
import { lookup, runPool } from '../../shared/client';
import {
	DEFAULT_CONCURRENCY,
	DEFAULT_DELAY_MS,
	DEFAULT_MAX_ADDRESSES,
	DEFAULT_MAX_RETRIES,
	DEFAULT_TIMEOUT_MS,
	MANUAL_SAMPLE_SIZE,
	MAX_CONCURRENCY,
	TRIGGER_MAX_ADDRESSES_LIMIT,
} from '../../shared/constants';
import {
	TRIGGER_EVENTS,
	allLookupsFailed,
	emptyChanges,
	hostItem,
	isTriggerState,
	reconcileState,
	toSnapshot,
	type EmitMode,
	type TriggerEvent,
} from '../../shared/diff';
import { hashTargets } from '../../shared/hash';
import { expandTargets, normalizeTargetList, type ResolvedTarget } from '../../shared/ip';
import type { LookupResult } from '../../shared/types';

interface TriggerOptions {
	concurrency?: number;
	delayMs?: number;
	emitCurrentOnFirstRun?: boolean;
	maxRetries?: number;
	timeoutMs?: number;
}

function clamp(value: number, min: number, max: number): number {
	return Math.min(max, Math.max(min, Math.floor(value)));
}

/** Parses the target list, converting validation problems into a NodeOperationError. */
function resolveTargets(
	ctx: IPollFunctions,
	rawTargets: string,
	maxAddresses: number,
): { targets: ResolvedTarget[]; normalized: string[] } {
	let parsed: { targets: ResolvedTarget[]; normalized: string[] } | Error;
	try {
		parsed = {
			targets: expandTargets(rawTargets, maxAddresses),
			normalized: normalizeTargetList(rawTargets),
		};
	} catch (error) {
		parsed = error as Error;
	}
	if (parsed instanceof Error) throw new NodeOperationError(ctx.getNode(), parsed.message);
	return parsed;
}

/** Looks up every IP. Failures are recorded as `Error` values instead of aborting. */
async function lookupAll(
	ctx: IPollFunctions,
	ips: string[],
	options: TriggerOptions,
): Promise<Map<string, LookupResult | Error>> {
	const lookups = new Map<string, LookupResult | Error>();
	await runPool(
		ips,
		clamp(options.concurrency ?? DEFAULT_CONCURRENCY, 1, MAX_CONCURRENCY),
		Math.max(0, options.delayMs ?? DEFAULT_DELAY_MS),
		async (ip) => {
			const result = await lookup(ctx, ip, {
				timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
				maxRetries: options.maxRetries ?? DEFAULT_MAX_RETRIES,
			}).then(
				(value) => value,
				(error: unknown) => (error instanceof Error ? error : new Error(String(error))),
			);
			lookups.set(ip, result);
		},
	);
	return lookups;
}

/** Throws the first lookup error when every lookup failed, so n8n shows the trigger error. */
function assertSomeLookupSucceeded(
	ctx: IPollFunctions,
	ips: string[],
	lookups: Map<string, LookupResult | Error>,
): void {
	if (!allLookupsFailed(ips, lookups)) return;
	const first = lookups.get(ips[0]) as Error;
	if (first instanceof NodeApiError)
		throw new NodeApiError(ctx.getNode(), first as unknown as JsonObject);
	throw new NodeOperationError(ctx.getNode(), first, {
		message: `All ${ips.length} InternetDB lookups failed: ${first.message}`,
	});
}

const toItems = (objects: IDataObject[]): INodeExecutionData[] => objects.map((json) => ({ json }));

export class ShodanInternetDbTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Shodan InternetDB Trigger',
		name: 'shodanInternetDbTrigger',
		icon: { light: 'file:internetdb.svg', dark: 'file:internetdb.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{"Watch: " + $parameter["targets"]}}',
		description:
			'Watch public IP addresses and ranges with Shodan InternetDB and trigger when open ports, CVEs, tags, hostnames, or CPEs change',
		defaults: { name: 'Shodan InternetDB Trigger' },
		polling: true,
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		properties: [
			{
				displayName:
					'InternetDB updates about once a week. Polling more than once a day wastes requests; every 12–24 hours is recommended. Free for non-commercial use only.',
				name: 'pollNotice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Targets',
				name: 'targets',
				type: 'string',
				typeOptions: { rows: 3 },
				required: true,
				default: '',
				placeholder: '203.0.113.10, 198.51.100.0/28',
				description:
					'Your public IPv4 addresses, IPv4 CIDR ranges, and single IPv6 addresses, separated by commas, spaces, or new lines. Non-public addresses are ignored.',
			},
			{
				displayName: 'Events',
				name: 'events',
				type: 'multiOptions',
				options: [
					{ name: 'CPEs Changed', value: 'cpesChanged' },
					{
						name: 'Data Appeared',
						value: 'dataAppeared',
						description: 'An IP without data now has data',
					},
					{
						name: 'Data Disappeared',
						value: 'dataDisappeared',
						description: 'An IP with data no longer has any',
					},
					{ name: 'Hostnames Changed', value: 'hostnamesChanged' },
					{ name: 'Port Closed', value: 'portClosed' },
					{ name: 'Port Opened', value: 'portOpened' },
					{ name: 'Tags Changed', value: 'tagsChanged' },
					{
						name: 'Vulnerability Added',
						value: 'vulnAdded',
						description: 'A new CVE was reported',
					},
					{
						name: 'Vulnerability Resolved',
						value: 'vulnResolved',
						description: 'A CVE is no longer reported',
					},
				],
				default: [...TRIGGER_EVENTS],
				description: 'Which changes trigger the workflow. State is always tracked for all fields.',
			},
			{
				displayName: 'Emit Mode',
				name: 'emitMode',
				type: 'options',
				options: [
					{
						name: 'Per Change',
						value: 'perChange',
						description: 'One item per individual change, such as one opened port',
					},
					{
						name: 'Per Host',
						value: 'perHost',
						description: 'One item per changed IP with its current state and a changes object',
					},
				],
				default: 'perChange',
				description: 'How to group the emitted changes',
			},
			{
				displayName: 'Max Addresses',
				name: 'maxAddresses',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: TRIGGER_MAX_ADDRESSES_LIMIT },
				default: DEFAULT_MAX_ADDRESSES,
				description: `Maximum number of unique addresses the targets may expand to (hard max ${TRIGGER_MAX_ADDRESSES_LIMIT})`,
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Concurrency',
						name: 'concurrency',
						type: 'number',
						typeOptions: { minValue: 1, maxValue: MAX_CONCURRENCY },
						default: DEFAULT_CONCURRENCY,
						description: `How many lookups to run in parallel (max ${MAX_CONCURRENCY})`,
					},
					{
						displayName: 'Delay Between Requests (Ms)',
						name: 'delayMs',
						type: 'number',
						typeOptions: { minValue: 0 },
						default: DEFAULT_DELAY_MS,
						description:
							'Pause in milliseconds between consecutive requests of each parallel worker',
					},
					{
						displayName: 'Emit Current State on First Run',
						name: 'emitCurrentOnFirstRun',
						type: 'boolean',
						default: false,
						description:
							'Whether to emit the current state of every IP (as Per Host items) the first time the trigger runs, instead of only recording it',
					},
					{
						displayName: 'Max Retries',
						name: 'maxRetries',
						type: 'number',
						typeOptions: { minValue: 0, maxValue: 10 },
						default: DEFAULT_MAX_RETRIES,
						description:
							'How many times to retry rate-limited (429), server (5xx), and network errors',
					},
					{
						displayName: 'Timeout (Ms)',
						name: 'timeoutMs',
						type: 'number',
						typeOptions: { minValue: 1000 },
						default: DEFAULT_TIMEOUT_MS,
						description: 'Per-request timeout in milliseconds',
					},
				],
			},
		],
	};

	async poll(this: IPollFunctions): Promise<INodeExecutionData[][] | null> {
		const rawTargets = String(this.getNodeParameter('targets', ''));
		const maxAddresses = clamp(
			this.getNodeParameter('maxAddresses', DEFAULT_MAX_ADDRESSES) as number,
			1,
			TRIGGER_MAX_ADDRESSES_LIMIT,
		);
		const events = new Set(this.getNodeParameter('events', [...TRIGGER_EVENTS]) as TriggerEvent[]);
		const emitMode = this.getNodeParameter('emitMode', 'perChange') as EmitMode;
		const options = this.getNodeParameter('options', {}) as TriggerOptions;

		const { targets, normalized } = resolveTargets(this, rawTargets, maxAddresses);
		const ips = targets.filter((t) => !t.nonPublic).map((t) => t.ip);
		if (ips.length === 0) {
			throw new NodeOperationError(
				this.getNode(),
				'All targets are non-public addresses, which never have InternetDB data. Add public IPs or ranges.',
			);
		}
		const now = new Date().toISOString();

		// Manual test: show sample data without reading or writing state.
		if (this.getMode() === 'manual') {
			const sample = ips.slice(0, MANUAL_SAMPLE_SIZE);
			const lookups = await lookupAll(this, sample, options);
			assertSomeLookupSucceeded(this, sample, lookups);
			const items = sample.flatMap((ip) => {
				const result = lookups.get(ip);
				if (result === undefined || result instanceof Error) return [];
				const meta = { previousSeenAt: null, detectedAt: now };
				return [hostItem(ip, toSnapshot(result, now), emptyChanges(), meta)];
			});
			return [toItems(items)];
		}

		const staticData = this.getWorkflowStaticData('node');
		const previous = isTriggerState(staticData) ? staticData : undefined;

		const lookups = await lookupAll(this, ips, options);
		assertSomeLookupSucceeded(this, ips, lookups);

		const { state, items } = reconcileState(previous, hashTargets(normalized), ips, lookups, {
			events,
			emitMode,
			emitCurrentOnFirstRun: options.emitCurrentOnFirstRun ?? false,
			now,
		});
		staticData.version = state.version;
		staticData.targetsHash = state.targetsHash;
		staticData.snapshots = state.snapshots as unknown as IDataObject;

		return items.length > 0 ? [toItems(items)] : null;
	}
}
