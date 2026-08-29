'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = '4.1.3';
const SCHEMA = 'attestor-vscode-server-bundle/1.0';
const ENTRYPOINT = 'attestor_lsp41.py';
const SOURCE_FILES = Object.freeze([
  'advanced_rules.py',
  'deepscan.py',
  'detect.py',
  'multilang.py',
  'nativepool.py',
  'nativescan.py',
  'attestor_lsp.py',
  'attestor_lsp41.py',
  'patchguard.py',
  'polyglot.py',
  'precision_catalog.py',
  'rarebugs.py',
  'runtime_lab.py',
  'scanengine.py',
  'verified_remediation.py'
]);

function option(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return null;
  if (index + 1 >= process.argv.length) throw new Error(`${name} requires a path`);
  return process.argv[index + 1];
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

const extensionRoot = path.resolve(__dirname, '..');
const sourceRoot = path.resolve(option('--source') || path.join(extensionRoot, '..', '..', 'detector'));
const destinationRoot = path.resolve(option('--destination') || path.join(extensionRoot, 'server'));

if (!fs.statSync(sourceRoot).isDirectory()) throw new Error('detector source directory is unavailable');
fs.mkdirSync(destinationRoot, { recursive: true });

const allowedOutput = new Set([...SOURCE_FILES, 'server-manifest.json']);
for (const name of fs.readdirSync(destinationRoot)) {
  if (!allowedOutput.has(name)) {
    throw new Error(`refusing unexpected server bundle entry: ${name}`);
  }
}

const files = [];
for (const name of SOURCE_FILES) {
  const source = path.resolve(sourceRoot, name);
  const destination = path.resolve(destinationRoot, name);
  if (path.dirname(source) !== sourceRoot || path.dirname(destination) !== destinationRoot) {
    throw new Error('bundle path escaped its approved root');
  }
  const sourceStat = fs.lstatSync(source);
  if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || sourceStat.size < 1 ||
      sourceStat.size > 2 * 1024 * 1024) {
    throw new Error(`invalid detector source: ${name}`);
  }
  const data = fs.readFileSync(source);
  fs.copyFileSync(source, destination);
  files.push({ path: name, sha256: sha256(data), size: data.length });
}

const manifest = {
  schema: SCHEMA,
  version: VERSION,
  entrypoint: ENTRYPOINT,
  analysis_engine: 'deterministic-live-core/4.1',
  files
};
fs.writeFileSync(
  path.join(destinationRoot, 'server-manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
  { encoding: 'utf8', mode: 0o644 }
);
process.stdout.write(`Staged ${files.length} verified Attestor server files in ${destinationRoot}\n`);
