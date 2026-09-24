import { describe, expect, it } from 'vitest';
import { INTERNETDB_HOST_KEYS } from '../shared/types';
import openapi from './fixtures/openapi.json';
import notFound from './fixtures/404.json';

describe('InternetDB OpenAPI contract', () => {
	const hostSchema = openapi.components.schemas.Host;

	it('Host.required matches the keys of InternetDbHost', () => {
		expect([...hostSchema.required].sort()).toEqual([...INTERNETDB_HOST_KEYS].sort());
	});

	it('Host property types match InternetDbHost', () => {
		const { properties } = hostSchema;
		expect(properties.ip.type).toBe('string');
		expect(properties.ports).toMatchObject({ type: 'array', items: { type: 'integer' } });
		for (const key of ['cpes', 'hostnames', 'tags', 'vulns'] as const) {
			expect(properties[key]).toMatchObject({ type: 'array', items: { type: 'string' } });
		}
	});

	it('exposes a single GET /{ip} endpoint', () => {
		expect(Object.keys(openapi.paths)).toEqual(['/{ip}']);
		expect(Object.keys(openapi.paths['/{ip}'])).toEqual(['get']);
	});

	it('the recorded 404 body matches the live API', () => {
		expect(notFound).toEqual({ detail: 'No information available' });
	});
});
