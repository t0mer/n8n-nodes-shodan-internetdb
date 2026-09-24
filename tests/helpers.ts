import type { IDataObject, IExecuteFunctions, INode, INodeExecutionData } from 'n8n-workflow';
import { vi } from 'vitest';

export const testNode = {
	id: 'node-1',
	name: 'Shodan InternetDB',
	type: 'shodanInternetDb',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
} as unknown as INode;

export type Reply =
	| { statusCode: number; body?: unknown; headers?: Record<string, string> }
	| Error;

/** Mock `httpRequest` answering by IP from the request URL. Unknown IPs get a 404. */
export function httpByIp(replies: Record<string, Reply | Reply[]>) {
	return vi.fn(async (options: { url: string }) => {
		const ip = decodeURIComponent(options.url.split('/').pop() as string);
		const entry = replies[ip];
		const reply = Array.isArray(entry) ? entry.shift() : entry;
		if (reply instanceof Error) throw reply;
		return {
			headers: {},
			...(reply ?? { statusCode: 404, body: { detail: 'No information available' } }),
		};
	});
}

export function executeContext(opts: {
	items?: number;
	params: (name: string, itemIndex: number) => unknown;
	httpRequest: ReturnType<typeof httpByIp>;
	continueOnFail?: boolean;
}): IExecuteFunctions {
	const items: INodeExecutionData[] = Array.from({ length: opts.items ?? 1 }, (_, i) => ({
		json: { i } as IDataObject,
	}));
	return {
		getInputData: () => items,
		getNodeParameter: (name: string, itemIndex: number, fallback?: unknown) => {
			const value = opts.params(name, itemIndex);
			return value === undefined ? fallback : value;
		},
		getNode: () => testNode,
		continueOnFail: () => opts.continueOnFail ?? false,
		helpers: { httpRequest: opts.httpRequest },
	} as unknown as IExecuteFunctions;
}
