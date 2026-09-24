import { describe, expect, it } from 'vitest';
import {
	TRIGGER_EVENTS,
	allLookupsFailed,
	diffSnapshots,
	isTriggerState,
	reconcileState,
	toSnapshot,
	type ReconcileOptions,
	type TriggerEvent,
} from '../shared/diff';
import { fnv1a, hashTargets } from '../shared/hash';
import type { InternetDbHost, LookupResult, TriggerState } from '../shared/types';

const T0 = '2026-09-01T00:00:00.000Z';
const T1 = '2026-09-02T00:00:00.000Z';

const hostA: InternetDbHost = {
	ip: '1.1.1.1',
	ports: [443, 80],
	cpes: ['cpe:/a:b', 'cpe:/a:a'],
	hostnames: ['one.example'],
	tags: ['cdn'],
	vulns: ['CVE-2021-10000', 'CVE-2021-9999'],
};

const found = (host: InternetDbHost): LookupResult => ({ status: 'found', host });
const notFound = (ip: string): LookupResult => ({ status: 'not_found', ip });

const opts = (overrides: Partial<ReconcileOptions> = {}): ReconcileOptions => ({
	events: new Set<TriggerEvent>(TRIGGER_EVENTS),
	emitMode: 'perChange',
	emitCurrentOnFirstRun: false,
	now: T1,
	...overrides,
});

function stateWith(snapshots: TriggerState['snapshots']): TriggerState {
	return { version: 1, targetsHash: 'old', snapshots };
}

describe('hash', () => {
	it('matches FNV-1a 32-bit reference vectors', () => {
		expect(fnv1a('')).toBe('811c9dc5');
		expect(fnv1a('a')).toBe('e40c292c');
		expect(fnv1a('foobar')).toBe('bf9cf968');
	});

	it('hashes target lists deterministically', () => {
		expect(hashTargets(['1.1.1.1', '8.8.8.8/30'])).toBe(hashTargets(['1.1.1.1', '8.8.8.8/30']));
		expect(hashTargets(['1.1.1.1'])).not.toBe(hashTargets(['1.1.1.2']));
	});
});

describe('toSnapshot', () => {
	it('stores sorted, de-duplicated arrays', () => {
		expect(toSnapshot(found({ ...hostA, ports: [443, 80, 443] }), T0)).toEqual({
			found: true,
			ports: [80, 443],
			vulns: ['CVE-2021-9999', 'CVE-2021-10000'],
			tags: ['cdn'],
			hostnames: ['one.example'],
			cpes: ['cpe:/a:a', 'cpe:/a:b'],
			seenAt: T0,
		});
	});

	it('stores an empty snapshot for not_found', () => {
		expect(toSnapshot(notFound('1.1.1.1'), T0)).toMatchObject({
			found: false,
			ports: [],
			vulns: [],
		});
	});
});

describe('diffSnapshots', () => {
	it('computes set differences per field', () => {
		const prev = toSnapshot(found(hostA), T0);
		const curr = toSnapshot(
			found({
				...hostA,
				ports: [80, 22],
				vulns: ['CVE-2021-9999', 'CVE-2024-1'],
				tags: ['cdn', 'eol-product'],
				hostnames: [],
				cpes: ['cpe:/a:a', 'cpe:/a:c'],
			}),
			T1,
		);
		expect(diffSnapshots(prev, curr)).toEqual({
			dataAppeared: false,
			dataDisappeared: false,
			portsOpened: [22],
			portsClosed: [443],
			vulnsAdded: ['CVE-2024-1'],
			vulnsResolved: ['CVE-2021-10000'],
			tags: { added: ['eol-product'], removed: [] },
			hostnames: { added: [], removed: ['one.example'] },
			cpes: { added: ['cpe:/a:c'], removed: ['cpe:/a:b'] },
		});
	});

	it('detects data appearing and disappearing', () => {
		const empty = toSnapshot(notFound('1.1.1.1'), T0);
		const full = toSnapshot(found(hostA), T1);
		expect(diffSnapshots(empty, full)).toMatchObject({
			dataAppeared: true,
			portsOpened: [80, 443],
		});
		expect(diffSnapshots(full, empty)).toMatchObject({
			dataDisappeared: true,
			portsClosed: [80, 443],
		});
	});
});

describe('reconcileState', () => {
	it('seeds silently on first run', () => {
		const lookups = new Map([['1.1.1.1', found(hostA)]]);
		const { state, items } = reconcileState(undefined, 'h1', ['1.1.1.1'], lookups, opts());
		expect(items).toEqual([]);
		expect(state).toEqual({
			version: 1,
			targetsHash: 'h1',
			snapshots: { '1.1.1.1': toSnapshot(found(hostA), T1) },
		});
	});

	it('emits current state as perHost items on first run when asked', () => {
		const lookups = new Map([['1.1.1.1', found(hostA)]]);
		const { items } = reconcileState(
			undefined,
			'h1',
			['1.1.1.1'],
			lookups,
			opts({ emitCurrentOnFirstRun: true }),
		);
		expect(items).toEqual([
			expect.objectContaining({
				ip: '1.1.1.1',
				found: true,
				current: expect.objectContaining({ ports: [80, 443] }),
				changes: expect.objectContaining({ portsOpened: [], vulnsAdded: [] }),
				previousSeenAt: null,
				detectedAt: T1,
			}),
		]);
	});

	it('emits nothing when nothing changed', () => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const { items, state } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', found(hostA)]]),
			opts(),
		);
		expect(items).toEqual([]);
		expect(state.snapshots['1.1.1.1'].seenAt).toBe(T1);
	});

	it('emits one perChange item per individual change', () => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const changed = found({
			...hostA,
			ports: [80, 22, 8080],
			vulns: [...hostA.vulns, 'CVE-2024-1'],
			tags: [],
		});
		const { items } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', changed]]),
			opts(),
		);
		const meta = { previousSeenAt: T0, detectedAt: T1 };
		expect(items).toEqual([
			{ ip: '1.1.1.1', event: 'portOpened', value: 22, ...meta },
			{ ip: '1.1.1.1', event: 'portOpened', value: 8080, ...meta },
			{ ip: '1.1.1.1', event: 'portClosed', value: 443, ...meta },
			{ ip: '1.1.1.1', event: 'vulnAdded', value: 'CVE-2024-1', ...meta },
			{ ip: '1.1.1.1', event: 'tagsChanged', added: [], removed: ['cdn'], ...meta },
		]);
	});

	it.each([
		[
			'hostnamesChanged',
			{ hostnames: ['two.example'] },
			{ added: ['two.example'], removed: ['one.example'] },
		],
		['cpesChanged', { cpes: ['cpe:/a:a'] }, { added: [], removed: ['cpe:/a:b'] }],
	] as const)('emits %s with added and removed', (event, patch, expected) => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const { items } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', found({ ...hostA, ...patch })]]),
			opts(),
		);
		expect(items).toEqual([expect.objectContaining({ event, ...expected })]);
	});

	it('emits vulnResolved', () => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const { items } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', found({ ...hostA, vulns: ['CVE-2021-9999'] })]]),
			opts(),
		);
		expect(items).toEqual([
			expect.objectContaining({ event: 'vulnResolved', value: 'CVE-2021-10000' }),
		]);
	});

	it('emits dataAppeared and dataDisappeared', () => {
		const prev = stateWith({
			'1.1.1.1': toSnapshot(notFound('1.1.1.1'), T0),
			'2.2.2.2': toSnapshot(
				found({ ...hostA, ip: '2.2.2.2', ports: [], vulns: [], tags: [], hostnames: [], cpes: [] }),
				T0,
			),
		});
		const lookups = new Map([
			['1.1.1.1', found({ ...hostA, ports: [], vulns: [], tags: [], hostnames: [], cpes: [] })],
			['2.2.2.2', notFound('2.2.2.2')],
		]);
		const { items } = reconcileState(prev, 'h1', ['1.1.1.1', '2.2.2.2'], lookups, opts());
		expect(items.map((i) => [i.ip, i.event])).toEqual([
			['1.1.1.1', 'dataAppeared'],
			['2.2.2.2', 'dataDisappeared'],
		]);
	});

	it('only emits selected events but always updates state', () => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const changed = found({ ...hostA, ports: [80, 22], vulns: [...hostA.vulns, 'CVE-2024-1'] });
		const { items, state } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', changed]]),
			opts({ events: new Set<TriggerEvent>(['vulnAdded']) }),
		);
		expect(items.map((i) => i.event)).toEqual(['vulnAdded']);
		expect(state.snapshots['1.1.1.1'].ports).toEqual([22, 80]);
	});

	it('emits one perHost item with a changes object', () => {
		const prev = stateWith({ '1.1.1.1': toSnapshot(found(hostA), T0) });
		const changed = found({ ...hostA, ports: [80, 22], tags: ['cdn', 'vpn'] });
		const { items } = reconcileState(
			prev,
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', changed]]),
			opts({ emitMode: 'perHost' }),
		);
		expect(items).toEqual([
			{
				ip: '1.1.1.1',
				found: true,
				current: {
					ports: [22, 80],
					vulns: ['CVE-2021-9999', 'CVE-2021-10000'],
					tags: ['cdn', 'vpn'],
					hostnames: ['one.example'],
					cpes: ['cpe:/a:a', 'cpe:/a:b'],
				},
				changes: {
					dataAppeared: false,
					dataDisappeared: false,
					portsOpened: [22],
					portsClosed: [443],
					vulnsAdded: [],
					vulnsResolved: [],
					tags: { added: ['vpn'], removed: [] },
					hostnames: { added: [], removed: [] },
					cpes: { added: [], removed: [] },
				},
				previousSeenAt: T0,
				detectedAt: T1,
			},
		]);
	});

	it('drops removed targets and seeds new targets silently', () => {
		const prev = stateWith({
			'1.1.1.1': toSnapshot(found(hostA), T0),
			'9.9.9.9': toSnapshot(notFound('9.9.9.9'), T0),
		});
		const lookups = new Map([
			['1.1.1.1', found(hostA)],
			['8.8.8.8', found({ ...hostA, ip: '8.8.8.8', ports: [53] })],
		]);
		const { items, state } = reconcileState(prev, 'h2', ['1.1.1.1', '8.8.8.8'], lookups, opts());
		expect(items).toEqual([]);
		expect(Object.keys(state.snapshots).sort()).toEqual(['1.1.1.1', '8.8.8.8']);
		expect(state.targetsHash).toBe('h2');
	});

	it('keeps the previous snapshot when a lookup fails', () => {
		const snapshot = toSnapshot(found(hostA), T0);
		const prev = stateWith({ '1.1.1.1': snapshot });
		const lookups = new Map<string, LookupResult | Error>([
			['1.1.1.1', new Error('HTTP 503')],
			['8.8.8.8', found({ ...hostA, ip: '8.8.8.8' })],
		]);
		const { items, state } = reconcileState(prev, 'h1', ['1.1.1.1', '8.8.8.8'], lookups, opts());
		expect(items).toEqual([]);
		expect(state.snapshots['1.1.1.1']).toBe(snapshot);
	});

	it('does not seed a new target whose lookup failed', () => {
		const { state } = reconcileState(
			stateWith({}),
			'h1',
			['1.1.1.1'],
			new Map([['1.1.1.1', new Error('boom')]]),
			opts(),
		);
		expect(state.snapshots).toEqual({});
	});
});

describe('allLookupsFailed', () => {
	it('is true only when every target failed', () => {
		const ips = ['1.1.1.1', '8.8.8.8'];
		expect(allLookupsFailed(ips, new Map([['1.1.1.1', new Error('x')]]))).toBe(true);
		expect(
			allLookupsFailed(
				ips,
				new Map<string, LookupResult | Error>([
					['1.1.1.1', new Error('x')],
					['8.8.8.8', notFound('8.8.8.8')],
				]),
			),
		).toBe(false);
		expect(allLookupsFailed([], new Map())).toBe(false);
	});
});

describe('isTriggerState', () => {
	it('accepts a valid state and rejects empty or foreign data', () => {
		expect(isTriggerState(stateWith({}))).toBe(true);
		expect(isTriggerState({})).toBe(false);
		expect(isTriggerState({ version: 2, snapshots: {} })).toBe(false);
		expect(isTriggerState(undefined)).toBe(false);
	});
});
