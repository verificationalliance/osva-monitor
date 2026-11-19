// Runs the site's own lockfile parser (parseDeps in site/formalinformer/app.js) over every fixture in lockfiles/ and
// writes what it finds to lockfiles-expected.json. LockfileParserTests checks that the app's Swift port agrees.
//
//   node make-lockfile-expectations.mjs <path to site/formalinformer/app.js>
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(process.argv[2], 'utf8');
const start = app.indexOf('let SKIPPED = [];'), end = app.indexOf('async function scanText');
if (start < 0 || end < 0) throw new Error('parseDeps not found in app.js');
const parseDeps = new Function(app.slice(start, end) + '\nreturn (t, f) => ({ deps: parseDeps(t, f), skipped: SKIPPED.slice() });')();

const out = {};
for (const dir of readdirSync(join(here, 'lockfiles')).sort()) {
  for (const stored of readdirSync(join(here, 'lockfiles', dir)).sort()) {
    const file = stored.replace(/\.fixture$/, '');   // stored as <name>.fixture so GitHub does not read test data as dependencies
    const { deps, skipped } = parseDeps(readFileSync(join(here, 'lockfiles', dir, stored), 'utf8'), file);
    out[`${dir}/${file}`] = { dependencies: deps.map(d => [d.eco, d.name, d.version]).sort(), skipped };
  }
}
writeFileSync(join(here, 'lockfiles-expected.json'), JSON.stringify(out, null, 1) + '\n');
console.log(Object.entries(out).map(([k, v]) => `${k}: ${v.dependencies.length}`).join('\n'));
