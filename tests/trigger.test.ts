import { NodeOperationError } from 'n8n-workflow';
import type { IDataObject, IPollFunctions } from 'n8n-workflow';
import { describe, expect, it } from 'vitest';
import { ShodanInternetDbTrigger } from '../nodes/ShodanInternetDbTrigger/ShodanInternetDbTrigger.node';
import { httpByIp, testNode, type Reply } from './helpers';
import host from './fixtures/host-51.83.59.99.json';

const trigger = new ShodanInternetDbTrigger();

function pollContext(opts: {
	params?: Record<string, unknown>;
	replies: Record<string, Reply | Reply[]>;
	staticData?: IDataObject;
	mode?: 'manual' | 'trigger';
}) {
	const staticData = opts.staticData ?? {};
	const httpRequest = httpByIp(opts.replies);
	const params: Record<string, unknown> = {
		targets: '51.83.59.99',
		options: { delayMs: 0 },
		...opts.params,
	};
	const ctx = {
		getNodeParameter: (name: string, fallback?: unknown) => params[name] ?? fallback,
		getMode: () => opts.mode ?? 'trigger',
		getWorkflowStaticData: () => staticData,
		getNode: () => testNode,
		helpers: { httpRequest },
	} as unknown as IPollFunctions;
	return { ctx, staticData, httpRequest };
}

const ok = (body: object): Reply => ({ statusCode: 200, body });

describe('ShodanInternetDbTrigger', () => {
	it('is a polling trigger that is not usable as a tool', () => {
		expect(trigger.description.polling).toBe(true);
		expect(trigger.description.inputs).toEqual([]);
		expect(trigger.description.usableAsTool).toBeUndefined();
	});

	it('emits nothing on first activation and seeds state', async () => {
		const { ctx, staticData } = pollContext({ replies: { '51.83.59.99': ok(host) } });
		await expect(trigger.poll.call(ctx)).resolves.toBeNull();
		expect(staticData).toMatchObject({
			version: 1,
			targetsHash: expect.stringMatching(/^[0-9a-f]{8}$/),
			snapshots: { '51.83.59.99': { found: true, ports: [22, 80, 443, 500] } },
		});
	});

	it('emits current state on first run when emitCurrentOnFirstRun is on', async () => {
		const { ctx } = pollContext({
			params: { options: { delayMs: 0, emitCurrentOnFirstRun: true } },
			replies: { '51.83.59.99': ok(host) },
		});
		const out = await trigger.poll.call(ctx);
		expect(out?.[0]).toEqual([
			{ json: expect.objectContaining({ ip: '51.83.59.99', found: true, previousSeenAt: null }) },
		]);
	});

	it('returns null when nothing changed', async () => {
		const staticData: IDataObject = {};
		await trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx);
		await expect(
			trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx),
		).resolves.toBeNull();
	});

	it('emits the right events after a simulated change in static data', async () => {
		const staticData: IDataObject = {};
		await trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx);

		// Simulate an older snapshot: port 8080 was open, port 443 was not, and a CVE was unknown.
		const snapshot = (staticData.snapshots as IDataObject)['51.83.59.99'] as IDataObject;
		snapshot.ports = [22, 80, 500, 8080];
		snapshot.vulns = [];

		const out = await trigger.poll.call(
			pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx,
		);
		expect(out?.[0].map((item) => [item.json.event, item.json.value])).toEqual([
			['portOpened', 443],
			['portClosed', 8080],
			['vulnAdded', 'CVE-2017-15906'],
		]);
		expect(out?.[0][0].json.previousSeenAt).toEqual(expect.any(String));
	});

	it('emits perHost items and filters by selected events', async () => {
		const staticData: IDataObject = {};
		await trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx);
		const out = await trigger.poll.call(
			pollContext({
				params: { emitMode: 'perHost', events: ['vulnResolved'] },
				replies: { '51.83.59.99': ok({ ...host, ports: [22], vulns: [] }) },
				staticData,
			}).ctx,
		);
		expect(out?.[0]).toHaveLength(1);
		expect(out?.[0][0].json).toMatchObject({
			ip: '51.83.59.99',
			changes: { vulnsResolved: ['CVE-2017-15906'], portsClosed: [] },
		});
		// State still tracks every field.
		expect(((staticData.snapshots as IDataObject)['51.83.59.99'] as IDataObject).ports).toEqual([
			22,
		]);
	});

	it('drops removed targets and seeds new ones silently', async () => {
		const staticData: IDataObject = {};
		await trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx);
		const firstHash = staticData.targetsHash;
		const out = await trigger.poll.call(
			pollContext({
				params: { targets: '1.1.1.1' },
				replies: { '1.1.1.1': ok({ ...host, ip: '1.1.1.1' }) },
				staticData,
			}).ctx,
		);
		expect(out).toBeNull();
		expect(Object.keys(staticData.snapshots as IDataObject)).toEqual(['1.1.1.1']);
		expect(staticData.targetsHash).not.toBe(firstHash);
	});

	it('keeps the previous snapshot of a failed lookup and continues with others', async () => {
		const staticData: IDataObject = {};
		const targets = '51.83.59.99, 1.1.1.1';
		await trigger.poll.call(
			pollContext({ params: { targets }, replies: { '51.83.59.99': ok(host) }, staticData }).ctx,
		);
		const before = (staticData.snapshots as IDataObject)['51.83.59.99'];
		const out = await trigger.poll.call(
			pollContext({
				params: { targets, options: { delayMs: 0, maxRetries: 0 } },
				replies: { '51.83.59.99': { statusCode: 503 }, '1.1.1.1': ok({ ...host, ip: '1.1.1.1' }) },
				staticData,
			}).ctx,
		);
		expect(out?.[0].map((item) => [item.json.ip, item.json.event])).toEqual([
			['1.1.1.1', 'dataAppeared'],
			...[22, 80, 443, 500].map(() => ['1.1.1.1', 'portOpened']),
			['1.1.1.1', 'vulnAdded'],
			['1.1.1.1', 'tagsChanged'],
			['1.1.1.1', 'hostnamesChanged'],
			['1.1.1.1', 'cpesChanged'],
		]);
		expect((staticData.snapshots as IDataObject)['51.83.59.99']).toEqual(before);
	});

	it('throws when every lookup fails and leaves state untouched', async () => {
		const staticData: IDataObject = {};
		await trigger.poll.call(pollContext({ replies: { '51.83.59.99': ok(host) }, staticData }).ctx);
		const snapshot = JSON.stringify(staticData);
		const { ctx } = pollContext({
			params: { options: { delayMs: 0, maxRetries: 0 } },
			replies: { '51.83.59.99': { statusCode: 500 } },
			staticData,
		});
		const error = await trigger.poll.call(ctx).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as Error).message).toMatch(
			/^All 1 InternetDB lookups failed\. First error \(51\.83\.59\.99\): .*HTTP 500/,
		);
		expect(JSON.stringify(staticData)).toBe(snapshot);
	});

	it('returns up to 5 samples in manual mode without touching state', async () => {
		const staticData: IDataObject = {};
		const { ctx, httpRequest } = pollContext({
			params: { targets: '8.8.8.0/29' },
			replies: { '8.8.8.1': ok({ ...host, ip: '8.8.8.1' }) },
			staticData,
			mode: 'manual',
		});
		const out = await trigger.poll.call(ctx);
		expect(httpRequest).toHaveBeenCalledTimes(5);
		expect(out?.[0]).toHaveLength(5);
		expect(out?.[0][0].json).toMatchObject({
			ip: '8.8.8.1',
			found: true,
			changes: { portsOpened: [], vulnsAdded: [] },
		});
		expect(staticData).toEqual({});
	});

	it('never sends non-public targets and refuses a list with only non-public targets', async () => {
		const { ctx, httpRequest } = pollContext({
			params: { targets: '10.0.0.1, 51.83.59.99' },
			replies: { '51.83.59.99': ok(host) },
		});
		await trigger.poll.call(ctx);
		expect(httpRequest).toHaveBeenCalledTimes(1);

		const onlyPrivate = pollContext({ params: { targets: '10.0.0.0/30' }, replies: {} });
		await expect(trigger.poll.call(onlyPrivate.ctx)).rejects.toThrow(/All targets are non-public/);
	});

	it('enforces the 1024 address hard limit', async () => {
		const { ctx, httpRequest } = pollContext({
			params: { targets: '8.8.0.0/20', maxAddresses: 5000 },
			replies: {},
		});
		await expect(trigger.poll.call(ctx)).rejects.toThrow(/Max Addresses limit of 1024/);
		expect(httpRequest).not.toHaveBeenCalled();
	});
});
