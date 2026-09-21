/**
 * Runs the test suite and reports which acceptance criteria it establishes.
 *
 *   npm run acceptance
 *
 * Fails if a criterion's evidence has gone missing, become ambiguous, or
 * started failing — so renaming a test drops its criterion loudly rather than
 * quietly.
 *
 * It deliberately cannot mark everything green. Several criteria in spec
 * section 12 need a person with a host account or a physical device, and the
 * report says so rather than leaving a green suite to imply otherwise. The
 * iOS suite is listed but not run here; it needs xcodebuild and a simulator.
 */

import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { CRITERIA } from './criteria.ts';

function runSuite() {
  const files = readdirSync('test')
    .filter((name) => name.endsWith('.test.ts'))
    .map((name) => `test/${name}`)
    .sort();

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...files]);

    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', () => {});
    child.on('error', reject);
    child.on('close', () => {
      const results = new Map();
      for (const line of out.split('\n')) {
        // Subtests are indented; only top-level results are criteria evidence.
        const match = /^(not ok|ok) \d+ - (.+?)\s*$/.exec(line);
        if (!match) continue;
        results.set(match[2].replace(/\s+#.*$/, ''), match[1] === 'ok');
      }
      resolve(results);
    });
  });
}

const results = await runSuite();
const total = results.size;
const failed = [...results.values()].filter((passed) => !passed).length;

const problems = [];
const rows = [];

for (const criterion of CRITERIA) {
  let matched = 0;

  for (const fragment of criterion.evidence) {
    const hits = [...results.keys()].filter((name) => name.includes(fragment));
    if (hits.length === 0) {
      problems.push(`${criterion.id}: no test matches "${fragment}"`);
    } else if (hits.length > 1) {
      problems.push(`${criterion.id}: "${fragment}" matches ${hits.length} tests; make it distinctive`);
    } else if (!results.get(hits[0])) {
      problems.push(`${criterion.id}: evidence is failing — "${hits[0]}"`);
    } else {
      matched += 1;
    }
  }

  rows.push({
    criterion,
    status: criterion.evidence.length === 0 ? 'open' : criterion.gap ? 'partial' : 'proven',
    matched
  });
}

const width = Math.max(...CRITERIA.map((criterion) => criterion.scenario.length));

process.stdout.write('\nIoT Switch — acceptance report\n');
process.stdout.write(`requirement.md section 12, ${CRITERIA.length} criteria\n\n`);

for (const { criterion, status, matched } of rows) {
  const detail = status === 'open'
    ? 'needs a host or a device'
    : `${matched} test${matched === 1 ? '' : 's'}${criterion.gap ? ', plus a host' : ''}`;
  process.stdout.write(
    `  ${criterion.id}  ${criterion.scenario.padEnd(width)}  ${status.padEnd(7)}  ${detail}\n`
  );
}

const counts = {};
for (const row of rows) counts[row.status] = (counts[row.status] ?? 0) + 1;

process.stdout.write(
  `\n  ${counts.proven ?? 0} proven, ${counts.partial ?? 0} partial, ${counts.open ?? 0} open`
  + `   (${total} tests ran, ${total - failed} passed)\n`
);

const outstanding = rows.filter((row) => row.criterion.gap);
if (outstanding.length > 0) {
  process.stdout.write('\nWhat no test here can establish\n\n');
  for (const { criterion } of outstanding) {
    process.stdout.write(`  ${criterion.id}  ${criterion.gap}\n`);
  }
  process.stdout.write('\n  These close in spike/FINDINGS.md, with a host and a phone.\n');
}

if (failed > 0) problems.push(`${failed} test${failed === 1 ? '' : 's'} failing`);

if (problems.length > 0) {
  process.stdout.write('\nProblems\n\n');
  for (const problem of problems) process.stdout.write(`  ${problem}\n`);
  process.stdout.write('\n');
  process.exit(1);
}

process.stdout.write('\n');
