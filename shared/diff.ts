import type { IDataObject } from 'n8n-workflow';
import { sortCves, sortPorts } from './output';
import type { HostSnapshot, LookupResult, TriggerState } from './types';

export const TRIGGER_EVENTS = [
	'portOpened',
	'portClosed',
	'vulnAdded',
	'vulnResolved',
	'tagsChanged',
	'hostnamesChanged',
	'cpesChanged',
	'dataAppeared',
	'dataDisappeared',
] as const;

export type TriggerEvent = (typeof TRIGGER_EVENTS)[number];
export type EmitMode = 'perChange' | 'perHost';

export interface SetChange<T> {
	added: T[];
	removed: T[];
}

export interface HostChanges {
	dataAppeared: boolean;
	dataDisappeared: boolean;
	portsOpened: number[];
	portsClosed: number[];
	vulnsAdded: string[];
	vulnsResolved: string[];
	tags: SetChange<string>;
	hostnames: SetChange<string>;
	cpes: SetChange<string>;
}

const sortStrings = (values: readonly string[]) => [...values].sort();

/** Converts a lookup result into a snapshot with sorted arrays. */
export function toSnapshot(result: LookupResult, seenAt: string): HostSnapshot {
	if (result.status === 'not_found') {
		return { found: false, ports: [], vulns: [], tags: [], hostnames: [], cpes: [], seenAt };
	}
	const { host } = result;
	return {
		found: true,
		ports: sortPorts([...new Set(host.ports)]),
		vulns: sortCves([...new Set(host.vulns)]),
		tags: sortStrings([...new Set(host.tags)]),
		hostnames: sortStrings([...new Set(host.hostnames)]),
		cpes: sortStrings([...new Set(host.cpes)]),
		seenAt,
	};
}

function setDiff<T>(prev: readonly T[], curr: readonly T[]): SetChange<T> {
	const before = new Set(prev);
	const after = new Set(curr);
	return {
		added: curr.filter((v) => !before.has(v)),
		removed: prev.filter((v) => !after.has(v)),
	};
}

export function emptyChanges(): HostChanges {
	return {
		dataAppeared: false,
		dataDisappeared: false,
		portsOpened: [],
		portsClosed: [],
		vulnsAdded: [],
		vulnsResolved: [],
		tags: { added: [], removed: [] },
		hostnames: { added: [], removed: [] },
		cpes: { added: [], removed: [] },
	};
}

/** Set difference per field between two snapshots of the same IP. */
export function diffSnapshots(prev: HostSnapshot, curr: HostSnapshot): HostChanges {
	const ports = setDiff(prev.ports, curr.ports);
	const vulns = setDiff(prev.vulns, curr.vulns);
	return {
		dataAppeared: !prev.found && curr.found,
		dataDisappeared: prev.found && !curr.found,
		portsOpened: ports.added,
		portsClosed: ports.removed,
		vulnsAdded: vulns.added,
		vulnsResolved: vulns.removed,
		tags: setDiff(prev.tags, curr.tags),
		hostnames: setDiff(prev.hostnames, curr.hostnames),
		cpes: setDiff(prev.cpes, curr.cpes),
	};
}

const noSetChange = (): SetChange<string> => ({ added: [], removed: [] });
const hasSetChange = (change: SetChange<unknown>) =>
	change.added.length > 0 || change.removed.length > 0;

/** Keeps only the changes for the selected events. */
export function filterChanges(
	changes: HostChanges,
	events: ReadonlySet<TriggerEvent>,
): HostChanges {
	return {
		dataAppeared: events.has('dataAppeared') && changes.dataAppeared,
		dataDisappeared: events.has('dataDisappeared') && changes.dataDisappeared,
		portsOpened: events.has('portOpened') ? changes.portsOpened : [],
		portsClosed: events.has('portClosed') ? changes.portsClosed : [],
		vulnsAdded: events.has('vulnAdded') ? changes.vulnsAdded : [],
		vulnsResolved: events.has('vulnResolved') ? changes.vulnsResolved : [],
		tags: events.has('tagsChanged') ? changes.tags : noSetChange(),
		hostnames: events.has('hostnamesChanged') ? changes.hostnames : noSetChange(),
		cpes: events.has('cpesChanged') ? changes.cpes : noSetChange(),
	};
}

export function hasChanges(changes: HostChanges): boolean {
	return (
		changes.dataAppeared ||
		changes.dataDisappeared ||
		changes.portsOpened.length > 0 ||
		changes.portsClosed.length > 0 ||
		changes.vulnsAdded.length > 0 ||
		changes.vulnsResolved.length > 0 ||
		hasSetChange(changes.tags) ||
		hasSetChange(changes.hostnames) ||
		hasSetChange(changes.cpes)
	);
}

interface EventMeta {
	previousSeenAt: string | null;
	detectedAt: string;
}

/** One item per individual change (`perChange` mode). */
export function changeItems(ip: string, changes: HostChanges, meta: EventMeta): IDataObject[] {
	const items: IDataObject[] = [];
	const push = (event: TriggerEvent, fields: IDataObject = {}) =>
		items.push({
			ip,
			event,
			...fields,
			previousSeenAt: meta.previousSeenAt,
			detectedAt: meta.detectedAt,
		});

	if (changes.dataAppeared) push('dataAppeared');
	if (changes.dataDisappeared) push('dataDisappeared');
	for (const port of changes.portsOpened) push('portOpened', { value: port });
	for (const port of changes.portsClosed) push('portClosed', { value: port });
	for (const cve of changes.vulnsAdded) push('vulnAdded', { value: cve });
	for (const cve of changes.vulnsResolved) push('vulnResolved', { value: cve });
	if (hasSetChange(changes.tags)) push('tagsChanged', { ...changes.tags });
	if (hasSetChange(changes.hostnames)) push('hostnamesChanged', { ...changes.hostnames });
	if (hasSetChange(changes.cpes)) push('cpesChanged', { ...changes.cpes });
	return items;
}

/** One item per IP with all its changes (`perHost` mode, manual samples, first-run output). */
export function hostItem(
	ip: string,
	snapshot: HostSnapshot,
	changes: HostChanges,
	meta: EventMeta,
): IDataObject {
	return {
		ip,
		found: snapshot.found,
		current: {
			ports: snapshot.ports,
			vulns: snapshot.vulns,
			tags: snapshot.tags,
			hostnames: snapshot.hostnames,
			cpes: snapshot.cpes,
		},
		changes: { ...changes },
		previousSeenAt: meta.previousSeenAt,
		detectedAt: meta.detectedAt,
	};
}

export interface ReconcileOptions {
	events: ReadonlySet<TriggerEvent>;
	emitMode: EmitMode;
	emitCurrentOnFirstRun: boolean;
	/** ISO timestamp of this poll. */
	now: string;
}

export interface ReconcileResult {
	state: TriggerState;
	items: IDataObject[];
}

/** Returns true if `value` is a valid, current-version trigger state. */
export function isTriggerState(value: unknown): value is TriggerState {
	const state = value as TriggerState | undefined;
	return (
		state !== undefined &&
		state !== null &&
		state.version === 1 &&
		typeof state.snapshots === 'object' &&
		state.snapshots !== null
	);
}

/**
 * Builds the next state and the items to emit from this poll's lookups.
 *
 * - No previous state: seed every snapshot and emit nothing (or the current state if
 *   `emitCurrentOnFirstRun`).
 * - IPs no longer in `targetIps` are dropped; new IPs are seeded silently.
 * - A failed lookup (`Error`, or missing) keeps that IP's previous snapshot unchanged.
 * - Callers must not call this when every lookup failed; see `allLookupsFailed`.
 */
export function reconcileState(
	previous: TriggerState | undefined,
	targetsHash: string,
	targetIps: readonly string[],
	lookups: ReadonlyMap<string, LookupResult | Error>,
	opts: ReconcileOptions,
): ReconcileResult {
	const firstRun = previous === undefined;
	const snapshots: Record<string, HostSnapshot> = {};
	const items: IDataObject[] = [];

	for (const ip of targetIps) {
		const prev = previous?.snapshots[ip];
		const result = lookups.get(ip);
		if (result === undefined || result instanceof Error) {
			if (prev) snapshots[ip] = prev;
			continue;
		}

		const curr = toSnapshot(result, opts.now);
		snapshots[ip] = curr;

		if (firstRun) {
			if (opts.emitCurrentOnFirstRun) {
				items.push(
					hostItem(ip, curr, emptyChanges(), { previousSeenAt: null, detectedAt: opts.now }),
				);
			}
			continue;
		}
		if (!prev) continue;

		const changes = filterChanges(diffSnapshots(prev, curr), opts.events);
		if (!hasChanges(changes)) continue;
		const meta = { previousSeenAt: prev.seenAt, detectedAt: opts.now };
		if (opts.emitMode === 'perHost') items.push(hostItem(ip, curr, changes, meta));
		else items.push(...changeItems(ip, changes, meta));
	}

	return { state: { version: 1, targetsHash, snapshots }, items };
}

/** True when there was at least one target and every lookup failed. */
export function allLookupsFailed(
	targetIps: readonly string[],
	lookups: ReadonlyMap<string, LookupResult | Error>,
): boolean {
	return (
		targetIps.length > 0 &&
		targetIps.every((ip) => {
			const result = lookups.get(ip);
			return result === undefined || result instanceof Error;
		})
	);
}
