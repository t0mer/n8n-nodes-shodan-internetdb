import {
	NodeApiError,
	NodeConnectionTypes,
	NodeOperationError,
	type IDataObject,
	type IExecuteFunctions,
	type INode,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
} from 'n8n-workflow';
import { lookup, runPool } from '../../shared/client';
import {
	ACTION_MAX_ADDRESSES_LIMIT,
	DEFAULT_CONCURRENCY,
	DEFAULT_DELAY_MS,
	DEFAULT_MAX_ADDRESSES,
	DEFAULT_MAX_RETRIES,
	DEFAULT_TIMEOUT_MS,
	MAX_CONCURRENCY,
} from '../../shared/constants';
import { expandTargets, parseSingleIp, type ResolvedTarget } from '../../shared/ip';
import { shapeOutcome, toExecutionData, type IpOutcome } from '../../shared/output';
import type { NoDataBehavior, NonPublicBehavior, OutputMode } from '../../shared/types';
import { ipFields, ipOperations } from './descriptions/IpDescription';

interface LookupNodeOptions {
	includePortNames?: boolean;
	includeSummary?: boolean;
	maxRetries?: number;
	noDataBehavior?: NoDataBehavior;
	nonPublicBehavior?: NonPublicBehavior;
	timeoutMs?: number;
}

interface LookupManyNodeOptions extends LookupNodeOptions {
	concurrency?: number;
	delayMs?: number;
	maxAddresses?: number;
}

type IpResult = { ip: string; outcome: IpOutcome } | { ip: string; error: unknown };

function clamp(value: number, min: number, max: number): number {
	return Math.min(max, Math.max(min, Math.floor(value)));
}

/** Attaches the item index to an error, keeping NodeApiError / NodeOperationError instances intact. */
function asNodeError(
	node: INode,
	error: unknown,
	itemIndex: number,
): NodeApiError | NodeOperationError {
	const nodeError =
		error instanceof NodeApiError || error instanceof NodeOperationError
			? error
			: new NodeOperationError(node, error as Error, { itemIndex });
	nodeError.context.itemIndex = itemIndex;
	return nodeError;
}

/** Continue-on-fail output for one IP. */
function errorJson(ip: string, error: unknown): IDataObject {
	const json: IDataObject = { ip, error: (error as Error).message };
	if (error instanceof NodeApiError && error.httpCode) json.statusCode = Number(error.httpCode);
	return json;
}

/** Looks up one resolved target, applying the non-public and no-data behaviors. */
async function lookupTarget(
	ctx: IExecuteFunctions,
	target: ResolvedTarget,
	options: LookupNodeOptions,
): Promise<IpOutcome> {
	if (target.nonPublic) {
		if (options.nonPublicBehavior === 'error') {
			throw new NodeOperationError(
				ctx.getNode(),
				`${target.ip} is a non-public address (private, loopback, reserved, or similar) and never has InternetDB data`,
			);
		}
		return { kind: 'nonPublic', ip: target.ip };
	}
	const result = await lookup(ctx, target.ip, {
		timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		maxRetries: options.maxRetries ?? DEFAULT_MAX_RETRIES,
	});
	if (result.status === 'not_found' && options.noDataBehavior === 'error') {
		throw new NodeOperationError(ctx.getNode(), `InternetDB has no data for ${target.ip}`);
	}
	return { kind: 'lookup', result };
}

function shape(outcome: IpOutcome, outputMode: OutputMode, options: LookupNodeOptions) {
	return shapeOutcome(outcome, {
		outputMode,
		noDataBehavior: options.noDataBehavior ?? 'returnEmpty',
		includeSummary: options.includeSummary ?? true,
		includePortNames: options.includePortNames ?? false,
		lookedUpAt: new Date().toISOString(),
	});
}

export class ShodanInternetDb implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Shodan InternetDB',
		name: 'shodanInternetDb',
		icon: { light: 'file:internetdb.svg', dark: 'file:internetdb.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description:
			'Look up open ports, CPEs, hostnames, tags, and known CVEs for public IP addresses with the free Shodan InternetDB API',
		defaults: { name: 'Shodan InternetDB' },
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		properties: [
			{
				displayName:
					'InternetDB is free for non-commercial use; commercial use requires a Shodan enterprise license. Data is refreshed about weekly and contains no banners.',
				name: 'usageNotice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [{ name: 'IP', value: 'ip' }],
				default: 'ip',
			},
			...ipOperations,
			...ipFields,
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const operation = this.getNodeParameter('operation', 0) as string;
		if (operation === 'lookupMany') return [await executeLookupMany(this)];
		return [await executeLookup(this)];
	}
}

async function executeLookup(ctx: IExecuteFunctions): Promise<INodeExecutionData[]> {
	const items = ctx.getInputData();
	const returnData: INodeExecutionData[] = [];

	for (let i = 0; i < items.length; i++) {
		const rawIp = String(ctx.getNodeParameter('ip', i, ''));
		try {
			const outputMode = ctx.getNodeParameter('outputMode', i, 'host') as OutputMode;
			const options = ctx.getNodeParameter('options', i, {}) as LookupNodeOptions;

			const outcome = await lookupTarget(ctx, parseSingleIp(rawIp), options);
			returnData.push(...toExecutionData(shape(outcome, outputMode, options), i));
		} catch (error) {
			if (ctx.continueOnFail()) {
				returnData.push({ json: errorJson(rawIp.trim(), error), pairedItem: { item: i } });
				continue;
			}
			throw asNodeError(ctx.getNode(), error, i);
		}
	}

	return returnData;
}

async function executeLookupMany(ctx: IExecuteFunctions): Promise<INodeExecutionData[]> {
	const runOnce = ctx.getNodeParameter('runOnce', 0, true) as boolean;
	const itemCount = runOnce ? 1 : ctx.getInputData().length;
	const returnData: INodeExecutionData[] = [];

	for (let i = 0; i < itemCount; i++) {
		const rawTargets = String(ctx.getNodeParameter('targets', i, ''));
		try {
			returnData.push(...(await lookupMany(ctx, rawTargets, i)));
		} catch (error) {
			if (ctx.continueOnFail()) {
				returnData.push({
					json: { targets: rawTargets, error: (error as Error).message },
					pairedItem: { item: i },
				});
				continue;
			}
			throw asNodeError(ctx.getNode(), error, i);
		}
	}

	return returnData;
}

/** Looks up every address `rawTargets` expands to. Output is in input order and paired to `itemIndex`. */
async function lookupMany(
	ctx: IExecuteFunctions,
	rawTargets: string,
	itemIndex: number,
): Promise<INodeExecutionData[]> {
	const outputMode = ctx.getNodeParameter('outputMode', itemIndex, 'host') as OutputMode;
	const options = ctx.getNodeParameter('options', itemIndex, {}) as LookupManyNodeOptions;
	const continueOnFail = ctx.continueOnFail();

	const maxAddresses = clamp(
		options.maxAddresses ?? DEFAULT_MAX_ADDRESSES,
		1,
		ACTION_MAX_ADDRESSES_LIMIT,
	);
	const targets = expandTargets(rawTargets, maxAddresses);

	// Fail before sending any request rather than part-way through the batch.
	const firstNonPublic = targets.find((t) => t.nonPublic);
	if (firstNonPublic && options.nonPublicBehavior === 'error' && !continueOnFail) {
		throw new NodeOperationError(
			ctx.getNode(),
			`${firstNonPublic.ip} (address ${targets.indexOf(firstNonPublic) + 1} of ${targets.length}) is a non-public address and never has InternetDB data`,
			{ itemIndex },
		);
	}

	const results = await runPool<ResolvedTarget, IpResult>(
		targets,
		clamp(options.concurrency ?? DEFAULT_CONCURRENCY, 1, MAX_CONCURRENCY),
		Math.max(0, options.delayMs ?? DEFAULT_DELAY_MS),
		async (target) =>
			await lookupTarget(ctx, target, options).then(
				(outcome) => ({ ip: target.ip, outcome }),
				// With continue-on-fail, one failed IP must not abort the batch.
				async (error: unknown) =>
					continueOnFail ? { ip: target.ip, error } : await Promise.reject(error),
			),
	);

	return results.flatMap((result) =>
		'error' in result
			? [{ json: errorJson(result.ip, result.error), pairedItem: { item: itemIndex } }]
			: toExecutionData(shape(result.outcome, outputMode, options), itemIndex),
	);
}
