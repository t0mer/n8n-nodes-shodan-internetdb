import { describe, expect, it } from 'vitest';
import { WELL_KNOWN_PORTS, getServiceName } from '../shared/ports';

describe('getServiceName', () => {
	it.each([
		[22, 'ssh'],
		[80, 'http'],
		[443, 'https'],
		[3389, 'ms-wbt-server'],
		[5432, 'postgresql'],
	])('maps %i to %s', (port, name) => {
		expect(getServiceName(port)).toBe(name);
	});

	it('returns null for unknown ports', () => {
		expect(getServiceName(65000)).toBeNull();
		expect(getServiceName(0)).toBeNull();
	});

	it('does not leak Object prototype keys', () => {
		expect(getServiceName('constructor' as unknown as number)).toBeNull();
	});

	it('covers about 80 common ports with valid port numbers', () => {
		const ports = Object.keys(WELL_KNOWN_PORTS).map(Number);
		expect(ports.length).toBeGreaterThanOrEqual(80);
		for (const port of ports) {
			expect(Number.isInteger(port) && port > 0 && port < 65536).toBe(true);
		}
	});
});
