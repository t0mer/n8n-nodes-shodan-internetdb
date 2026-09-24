import { PACKAGE_VERSION } from './version';

export { PACKAGE_VERSION };

export const INTERNETDB_BASE_URL = 'https://internetdb.shodan.io';

export const USER_AGENT = `n8n-nodes-shodan-internetdb/${PACKAGE_VERSION}`;

export const SOURCE = 'shodan-internetdb';

export const DEFAULT_MAX_ADDRESSES = 256;
export const ACTION_MAX_ADDRESSES_LIMIT = 4096;
export const TRIGGER_MAX_ADDRESSES_LIMIT = 1024;

export const DEFAULT_CONCURRENCY = 1;
export const MAX_CONCURRENCY = 5;
export const DEFAULT_DELAY_MS = 250;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_RETRIES = 3;

export const BACKOFF_BASE_MS = 500;
export const BACKOFF_JITTER_MS = 250;
export const BACKOFF_CAP_MS = 10_000;
export const RETRY_AFTER_CAP_MS = 60_000;

/** Targets looked up when the trigger is tested manually. */
export const MANUAL_SAMPLE_SIZE = 5;
