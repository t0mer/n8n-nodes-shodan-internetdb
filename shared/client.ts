import { NodeApiError, NodeOperationError, sleep } from 'n8n-workflow';
import type { IDataObject, IHttpRequestOptions, INode, JsonObject } from 'n8n-workflow';
import {
	BACKOFF_BASE_MS,
	BACKOFF_CAP_MS,
	BACKOFF_JITTER_MS,
	INTERNETDB_BASE_URL,
	RETRY_AFTER_CAP_MS,
	USER_AGENT,
} from './constants';
import type { InternetDbHost, LookupResult } from './types';

/** The parts of IExecuteFunctions / IPollFunctions the client needs. */
export interface LookupContext {
	getNode(): INode;
	helpers: { httpRequest(options: IHttpRequestOptions): Promise<unknown> };
}

export interface LookupOptions {
	timeoutMs: number;
	maxRetries: number;
	/** Cancels the in-flight request and any pending retry. */
	abortSignal?: AbortSignal;
	/** Injectable for tests. Defaults to n8n's `sleep`. */
	sleep?: (ms: number, abortSignal?: AbortSignal) => Promise<void>;
	/** Injectable for tests. Defaults to `Math.random`. */
	random?: () => number;
}

interface FullResponse {
	statusCode: number;
	headers?: IDataObject;
	body?: unknown;
}

function parseBody(body: unknown): unknown {
	if (typeof body !== 'string') return body;
	try {
		return JSON.parse(body);
	} catch {
		return body;
	}
}

function asJsonObject(body: unknown): JsonObject {
	return body !== null && typeof body === 'object'
		? (body as JsonObject)
		: { body: String(body ?? '') };
}

function stringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.map(String) : [];
}

function toHost(node: INode, ip: string, body: unknown): InternetDbHost {
	if (body === null || typeof body !== 'object' || !Array.isArray((body as IDataObject).ports)) {
		throw new NodeApiError(node, asJsonObject(body), {
			message: `InternetDB returned an unexpected response for ${ip}`,
		});
	}
	const data = body as IDataObject;
	return {
		ip: typeof data.ip === 'string' ? data.ip : ip,
		ports: (data.ports as unknown[]).map(Number),
		cpes: stringArray(data.cpes),
		hostnames: stringArray(data.hostnames),
		tags: stringArray(data.tags),
		vulns: stringArray(data.vulns),
	};
}

/** Extracts the FastAPI `HTTPValidationError` messages from a 422 body. */
function validationMessage(body: unknown): string {
	const detail = (body as IDataObject | undefined)?.detail;
	if (Array.isArray(detail)) {
		const messages = detail
			.map((d) => (d as IDataObject)?.msg)
			.filter((m) => typeof m === 'string');
		if (messages.length > 0) return messages.join('; ');
	}
	return typeof detail === 'string' ? detail : 'validation error';
}

function isRetryable(statusCode: number): boolean {
	return statusCode === 429 || statusCode >= 500;
}

/** Delay before retry number `attempt + 1`. Honors `Retry-After` (seconds) when present. */
export function retryDelayMs(
	attempt: number,
	headers: IDataObject | undefined,
	random: () => number,
): number {
	const retryAfter = headers?.['retry-after'];
	const seconds = Number(Array.isArray(retryAfter) ? retryAfter[0] : retryAfter);
	if (retryAfter !== undefined && Number.isFinite(seconds) && seconds >= 0) {
		return Math.min(seconds * 1000, RETRY_AFTER_CAP_MS);
	}
	return Math.min(BACKOFF_BASE_MS * 2 ** attempt + random() * BACKOFF_JITTER_MS, BACKOFF_CAP_MS);
}

/**
 * Looks up one IP. 404 → `not_found`. 422 → NodeOperationError.
 * 429, 5xx and network errors are retried up to `maxRetries` times, then NodeApiError.
 */
export async function lookup(
	ctx: LookupContext,
	ip: string,
	opts: LookupOptions,
): Promise<LookupResult> {
	const wait = opts.sleep ?? sleep;
	const random = opts.random ?? Math.random;
	const node = ctx.getNode();

	for (let attempt = 0; ; attempt++) {
		if (opts.abortSignal?.aborted) {
			throw new NodeOperationError(node, `InternetDB lookup of ${ip} was cancelled`);
		}
		let response: FullResponse | undefined;
		let networkError: Error | undefined;
		try {
			response = (await ctx.helpers.httpRequest({
				method: 'GET',
				url: `${INTERNETDB_BASE_URL}/${encodeURIComponent(ip)}`,
				headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
				json: true,
				returnFullResponse: true,
				ignoreHttpStatusErrors: true,
				timeout: opts.timeoutMs,
				abortSignal: opts.abortSignal,
			})) as FullResponse;
		} catch (error) {
			networkError = error as Error;
		}

		if (response) {
			const { statusCode } = response;
			const body = parseBody(response.body);
			if (statusCode === 200) return { status: 'found', host: toHost(node, ip, body) };
			if (statusCode === 404) return { status: 'not_found', ip };
			if (statusCode === 422) {
				throw new NodeOperationError(
					node,
					`InternetDB rejected "${ip}": ${validationMessage(body)}`,
				);
			}
			if (!isRetryable(statusCode) || attempt >= opts.maxRetries) {
				const retried = isRetryable(statusCode) ? ` after ${attempt} retries` : '';
				throw new NodeApiError(node, asJsonObject(body), {
					httpCode: String(statusCode),
					message: `InternetDB request for ${ip} failed with HTTP ${statusCode}${retried}`,
				});
			}
		} else if (attempt >= opts.maxRetries) {
			throw new NodeApiError(node, (networkError ?? { message: 'unknown error' }) as JsonObject, {
				description: `Could not reach InternetDB for ${ip} after ${attempt} retries.`,
			});
		}

		await wait(retryDelayMs(attempt, response?.headers, random), opts.abortSignal);
	}
}

/**
 * Runs `worker` over `items` with at most `concurrency` in flight, pausing `delayMs`
 * between consecutive requests of each worker. Results keep input order.
 * The first rejection aborts the signal passed to every worker, stops workers from picking up
 * new items, waits for in-flight work to wind down, then rejects the pool with that error.
 */
export async function runPool<T, R>(
	items: readonly T[],
	concurrency: number,
	delayMs: number,
	worker: (item: T, index: number, abortSignal: AbortSignal) => Promise<R>,
	wait: (ms: number) => Promise<void> = sleep,
): Promise<R[]> {
	const results = new Array<R>(items.length);
	const controller = new AbortController();
	let next = 0;
	let failure: { error: unknown } | undefined;

	const run = async () => {
		for (let first = true; !controller.signal.aborted && next < items.length; first = false) {
			if (!first && delayMs > 0) {
				await wait(delayMs);
				if (controller.signal.aborted || next >= items.length) return;
			}
			const index = next++;
			try {
				results[index] = await worker(items[index], index, controller.signal);
			} catch (error) {
				failure = failure ?? { error };
				controller.abort();
			}
		}
	};

	const workerCount = Math.max(1, Math.min(concurrency, items.length));
	await Promise.all(Array.from({ length: workerCount }, run));
	if (failure) return await Promise.reject(failure.error);
	return results;
}
