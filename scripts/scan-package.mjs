#!/usr/bin/env node
// Runs the @n8n/scan-community-package checks against a local `npm pack` tarball.
// The published CLI only scans packages already on the npm registry.
// Usage: node scripts/scan-package.mjs <package.tgz>
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
	SOURCE_FILE_PATTERNS,
	analyzePackage,
} from '@n8n/scan-community-package/scanner/scanner.mjs';

const tarball = process.argv[2];
if (!tarball) {
	console.error('Usage: node scripts/scan-package.mjs <package.tgz>');
	process.exit(1);
}

const packageDir = mkdtempSync(join(tmpdir(), 'scan-package-'));
try {
	execFileSync('tar', ['-xzf', resolve(tarball), '-C', packageDir, '--strip-components=1']);

	// Same two legs as the registry scan: sources from the repo, compiled output from the tarball.
	const legs = [
		['source', await analyzePackage(process.cwd(), SOURCE_FILE_PATTERNS)],
		['tarball', await analyzePackage(packageDir, ['**/*.js', 'package.json'])],
	];

	let passed = true;
	for (const [name, result] of legs) {
		console.log(`${result.passed ? '✅' : '❌'} ${name}: ${result.passed ? 'passed' : result.message}`);
		if (result.details) console.log(result.details);
		passed &&= result.passed;
	}
	process.exitCode = passed ? 0 : 1;
} finally {
	rmSync(packageDir, { recursive: true, force: true });
}
