import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import type { INode } from 'n8n-workflow';
import { describe, expect, it, vi } from 'vitest';
import { lookup, retryDelayMs, runPool } from '../shared/client';
import { USER_AGENT } from '../shared/constants';
import host from './fixtures/host-51.83.59.99.json';
import notFound from './fixtures/404.json';
import validation from './fixtures/422.json';

const node = {
	name: 'InternetDB',
	type: 'test',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
} as unknown as INode;

type Reply = { statusCode: number; body?: unknown; headers?: Record<string, string> } | Error;

function makeCtx(replies: Reply[]) {
	const httpRequest = vi.fn(async () => {
		const reply = replies.shift();
		if (!reply) throw new Error('no more replies');
		if (reply instanceof Error) throw reply;
		return { headers: {}, ...reply };
	});
	return { ctx: { getNode: () => node, helpers: { httpRequest } }, httpRequest };
}

const opts = (sleep = vi.fn(async () => {})) => ({
	timeoutMs: 1000,
	maxRetries: 3,
	sleep,
	random: () => 0,
});

describe('lookup', () => {
	it('returns the host on 200 and sends the right request', async () => {
		const { ctx, httpRequest } = makeCtx([{ statusCode: 200, body: host }]);
		await expect(lookup(ctx, '51.83.59.99', opts())).resolves.toEqual({ status: 'found', host });
		expect(httpRequest).toHaveBeenCalledWith(
			expect.objectContaining({
				method: 'GET',
				url: 'https://internetdb.shodan.io/51.83.59.99',
				headers: expect.objectContaining({ 'User-Agent': USER_AGENT }),
				json: true,
				returnFullResponse: true,
				ignoreHttpStatusErrors: true,
				timeout: 1000,
			}),
		);
	});

	it('parses a string body', async () => {
		const { ctx } = makeCtx([{ statusCode: 200, body: JSON.stringify(host) }]);
		await expect(lookup(ctx, '51.83.59.99', opts())).resolves.toEqual({ status: 'found', host });
	});

	it('URL-encodes IPv6 addresses', async () => {
		const { ctx, httpRequest } = makeCtx([{ statusCode: 404, body: notFound }]);
		await lookup(ctx, '2001:db8::1', opts());
		expect(httpRequest).toHaveBeenCalledWith(
			expect.objectContaining({ url: 'https://internetdb.shodan.io/2001%3Adb8%3A%3A1' }),
		);
	});

	it('maps 404 to not_found without retrying', async () => {
		const sleep = vi.fn(async () => {});
		const { ctx, httpRequest } = makeCtx([{ statusCode: 404, body: notFound }]);
		await expect(lookup(ctx, '1.2.3.4', opts(sleep))).resolves.toEqual({
			status: 'not_found',
			ip: '1.2.3.4',
		});
		expect(httpRequest).toHaveBeenCalledTimes(1);
		expect(sleep).not.toHaveBeenCalled();
	});

	it('throws NodeOperationError with the detail text on 422, without retrying', async () => {
		const { ctx, httpRequest } = makeCtx([{ statusCode: 422, body: validation }]);
		const error = await lookup(ctx, 'bad', opts()).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeOperationError);
		expect((error as Error).message).toContain(validation.detail[0].msg);
		expect(httpRequest).toHaveBeenCalledTimes(1);
	});

	it('retries 429 with Retry-After', async () => {
		const sleep = vi.fn(async () => {});
		const { ctx } = makeCtx([
			{ statusCode: 429, headers: { 'retry-after': '7' } },
			{ statusCode: 200, body: host },
		]);
		await expect(lookup(ctx, '51.83.59.99', opts(sleep))).resolves.toMatchObject({
			status: 'found',
		});
		expect(sleep).toHaveBeenCalledWith(7000);
	});

	it('retries 429 without Retry-After using exponential backoff', async () => {
		const sleep = vi.fn(async () => {});
		const { ctx } = makeCtx([
			{ statusCode: 429 },
			{ statusCode: 429 },
			{ statusCode: 200, body: host },
		]);
		await lookup(ctx, '51.83.59.99', opts(sleep));
		expect(sleep.mock.calls).toEqual([[500], [1000]]);
	});

	it('retries 5xx then succeeds', async () => {
		const { ctx, httpRequest } = makeCtx([{ statusCode: 503 }, { statusCode: 200, body: host }]);
		await expect(lookup(ctx, '51.83.59.99', opts())).resolves.toMatchObject({ status: 'found' });
		expect(httpRequest).toHaveBeenCalledTimes(2);
	});

	it('retries network errors then succeeds', async () => {
		const { ctx } = makeCtx([new Error('ETIMEDOUT'), { statusCode: 200, body: host }]);
		await expect(lookup(ctx, '51.83.59.99', opts())).resolves.toMatchObject({ status: 'found' });
	});

	it('throws NodeApiError with the status after retries are exhausted', async () => {
		const { ctx, httpRequest } = makeCtx(Array.from({ length: 4 }, () => ({ statusCode: 502 })));
		const error = await lookup(ctx, '1.1.1.1', opts()).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeApiError);
		expect((error as NodeApiError).httpCode).toBe('502');
		expect((error as Error).message).toContain('HTTP 502 after 3 retries');
		expect(httpRequest).toHaveBeenCalledTimes(4);
	});

	it('throws NodeApiError after repeated network errors', async () => {
		const { ctx } = makeCtx(Array.from({ length: 4 }, () => new Error('ECONNRESET')));
		const error = await lookup(ctx, '1.1.1.1', opts()).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(NodeApiError);
		expect((error as NodeApiError).description).toBe(
			'Could not reach InternetDB for 1.1.1.1 after 3 retries.',
		);
	});

	it('does not retry other 4xx statuses', async () => {
		const { ctx, httpRequest } = makeCtx([{ statusCode: 403, body: { detail: 'Forbidden' } }]);
		await expect(lookup(ctx, '1.1.1.1', opts())).rejects.toBeInstanceOf(NodeApiError);
		expect(httpRequest).toHaveBeenCalledTimes(1);
	});

	it('rejects a malformed 200 body', async () => {
		const { ctx } = makeCtx([{ statusCode: 200, body: '<html>' }]);
		await expect(lookup(ctx, '1.1.1.1', opts())).rejects.toThrow(/unexpected response/);
	});
});

describe('retryDelayMs', () => {
	it('caps exponential backoff at 10s and adds jitter', () => {
		expect(retryDelayMs(0, undefined, () => 1)).toBe(750);
		expect(retryDelayMs(10, undefined, () => 1)).toBe(10000);
	});

	it('caps Retry-After at 60s', () => {
		expect(retryDelayMs(0, { 'retry-after': '3600' }, () => 0)).toBe(60000);
	});

	it('falls back to backoff for a non-numeric Retry-After', () => {
		expect(retryDelayMs(1, { 'retry-after': 'Wed, 21 Oct 2015 07:28:00 GMT' }, () => 0)).toBe(1000);
	});
});

describe('runPool', () => {
	it('never exceeds the concurrency limit and preserves order', async () => {
		let active = 0;
		let peak = 0;
		const items = Array.from({ length: 20 }, (_, i) => i);
		const results = await runPool(items, 3, 0, async (n) => {
			active++;
			peak = Math.max(peak, active);
			await new Promise((resolve) => queueMicrotask(() => resolve(undefined)));
			await Promise.resolve();
			active--;
			return n * 2;
		});
		expect(peak).toBe(3);
		expect(results).toEqual(items.map((n) => n * 2));
	});

	it('pauses between requests of each worker', async () => {
		const wait = vi.fn(async () => {});
		await runPool([1, 2, 3], 1, 250, async (n) => n, wait);
		expect(wait.mock.calls).toEqual([[250], [250]]);
	});

	it('stops picking up items after a failure', async () => {
		const seen: number[] = [];
		const pool = runPool([1, 2, 3, 4], 1, 0, async (n) => {
			seen.push(n);
			if (n === 2) throw new Error('boom');
			return n;
		});
		await expect(pool).rejects.toThrow('boom');
		expect(seen).toEqual([1, 2]);
	});

	it('handles an empty list', async () => {
		await expect(runPool([], 3, 0, async (n) => n)).resolves.toEqual([]);
	});
});
