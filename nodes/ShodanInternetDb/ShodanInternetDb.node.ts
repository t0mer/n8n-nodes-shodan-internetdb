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
import { lookup } from '../../shared/client';
import { DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_MS } from '../../shared/constants';
import { parseSingleIp, type ResolvedTarget } from '../../shared/ip';
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
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			const rawIp = String(this.getNodeParameter('ip', i, ''));
			try {
				const outputMode = this.getNodeParameter('outputMode', i, 'host') as OutputMode;
				const options = this.getNodeParameter('options', i, {}) as LookupNodeOptions;

				const outcome = await lookupTarget(this, parseSingleIp(rawIp), options);
				returnData.push(...toExecutionData(shape(outcome, outputMode, options), i));
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: errorJson(rawIp.trim(), error), pairedItem: { item: i } });
					continue;
				}
				throw asNodeError(this.getNode(), error, i);
			}
		}

		return [returnData];
	}
}
