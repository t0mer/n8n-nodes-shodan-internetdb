import { describe, expect, it } from 'vitest';
import pkg from '../package.json';
import { PACKAGE_VERSION, USER_AGENT } from '../shared/constants';

describe('constants', () => {
	it('keeps the User-Agent version in sync with package.json', () => {
		expect(PACKAGE_VERSION).toBe(pkg.version);
		expect(USER_AGENT).toBe(`n8n-nodes-shodan-internetdb/${pkg.version}`);
	});
});
