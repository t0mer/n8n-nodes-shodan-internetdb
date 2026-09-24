import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import { describe, expect, it } from 'vitest';
import { ShodanInternetDb } from '../nodes/ShodanInternetDb/ShodanInternetDb.node';
import { HOSTNAME_MESSAGE } from '../shared/ip';
import { executeContext, httpByIp } from './helpers';
import host from './fixtures/host-51.83.59.99.json';

const node = new ShodanInternetDb();

function lookupParams(ips: string[], extra: Record<string, unknown> = {}) {
	return (name: string, i: number) => {
		if (name === 'operation') return 'lookup';
		if (name === 'ip') return ips[i];
		return extra[name];
	};
}

describe('ShodanInternetDb description', () => {
	it('is usable as an AI tool and has no credentials', () => {
		expect(node.description.usableAsTool).toBe(true);
		expect(node.description.credentials).toBeUndefined();
	});
});

describe('Lookup', () => {
	it('emits one host item per input item, paired to its input', async () => {
		const httpRequest = httpByIp({ '51.83.59.99': { statusCode: 200, body: host } });
		const ctx = executeContext({
			items: 2,
			params: lookupParams(['51.83.59.99', '9.9.9.9']),
			httpRequest,
		});
		const [out] = await node.execute.call(ctx);
		expect(out).toHaveLength(2);
		expect(out[0]).toMatchObject({
			json: { ip: '51.83.59.99', found: true, portCount: 4 },
			pairedItem: { item: 0 },
		});
		expect(out[1]).toMatchObject({
			json: { ip: '9.9.9.9', found: false },
			pairedItem: { item: 1 },
		});
	});

	it('pairs every per-port item to its input in ports mode', async () => {
		const httpRequest = httpByIp({ '51.83.59.99': { statusCode: 200, body: host } });
		const ctx = executeContext({
			items: 2,
			params: lookupParams(['9.9.9.9', '51.83.59.99'], { outputMode: 'ports' }),
			httpRequest,
		});
		const [out] = await node.execute.call(ctx);
		expect(out.map((item) => item.pairedItem)).toEqual(
			Array.from({ length: 4 }, () => ({ item: 1 })),
		);
	});

	it('never sends non-public IPs to the API', async () => {
		const httpRequest = httpByIp({});
		const ctx = executeContext({ params: lookupParams(['10.0.0.1']), httpRequest });
		const [out] = await node.execute.call(ctx);
		expect(out[0].json).toEqual({ ip: '10.0.0.1', found: false, skipped: 'non_public' });
		expect(httpRequest).not.toHaveBeenCalled();
	});

	it('throws for non-public IPs with nonPublicBehavior=error', async () => {
		const ctx = executeContext({
			params: lookupParams(['192.168.1.1'], { options: { nonPublicBehavior: 'error' } }),
			httpRequest: httpByIp({}),
		});
		await expect(node.execute.call(ctx)).rejects.toThrow(/192.168.1.1 is a non-public address/);
	});

	it('throws for 404 with noDataBehavior=error', async () => {
		const ctx = executeContext({
			params: lookupParams(['9.9.9.9'], { options: { noDataBehavior: 'error' } }),
			httpRequest: httpByIp({}),
		});
		const error = await node.execute.call(ctx).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as NodeOperationError).message).toBe('InternetDB has no data for 9.9.9.9');
		expect((error as NodeOperationError).context.itemIndex).toBe(0);
	});

	it('rejects hostnames with a NodeOperationError naming the item', async () => {
		const ctx = executeContext({
			items: 2,
			params: lookupParams(['1.1.1.1', 'example.com']),
			httpRequest: httpByIp({}),
		});
		const error = await node.execute.call(ctx).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as Error).message).toBe(HOSTNAME_MESSAGE);
		expect((error as NodeOperationError).context.itemIndex).toBe(1);
	});

	it('rejects ranges and points to Lookup Many', async () => {
		const ctx = executeContext({ params: lookupParams(['1.1.1.0/24']), httpRequest: httpByIp({}) });
		await expect(node.execute.call(ctx)).rejects.toThrow(/Lookup Many/);
	});

	it('surfaces API errors as NodeApiError', async () => {
		const ctx = executeContext({
			params: lookupParams(['1.1.1.1'], { options: { maxRetries: 0 } }),
			httpRequest: httpByIp({ '1.1.1.1': { statusCode: 503 } }),
		});
		await expect(node.execute.call(ctx)).rejects.toBeInstanceOf(NodeApiError);
	});

	it('emits an error item and continues with continueOnFail', async () => {
		const ctx = executeContext({
			items: 3,
			params: lookupParams(['1.1.1.1', 'nope', '51.83.59.99'], { options: { maxRetries: 0 } }),
			httpRequest: httpByIp({
				'1.1.1.1': { statusCode: 503 },
				'51.83.59.99': { statusCode: 200, body: host },
			}),
			continueOnFail: true,
		});
		const [out] = await node.execute.call(ctx);
		expect(out).toHaveLength(3);
		expect(out[0]).toMatchObject({
			json: { ip: '1.1.1.1', statusCode: 503 },
			pairedItem: { item: 0 },
		});
		expect(out[0].json.error).toMatch(/503/);
		expect(out[1]).toMatchObject({
			json: { ip: 'nope', error: HOSTNAME_MESSAGE },
			pairedItem: { item: 1 },
		});
		expect(out[2]).toMatchObject({
			json: { ip: '51.83.59.99', found: true },
			pairedItem: { item: 2 },
		});
	});
});
