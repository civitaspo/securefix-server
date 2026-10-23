import { strict as assert } from 'node:assert';
import { cp, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { runCompositeScript } from './composite-harness.mjs';

const SOURCE = 'civitaspo/securefix-server';
const DESTINATION = 'civitaspo/testing-securefix-server';
const SOURCE_SHA = '95520b982c915e8a7c20d6a8464aa9d926216573';
const PUBLISHER_SHA = '39e7cd4bc3a9988f20357704ba00a7746750e522';
const ASSET_BYTES = Buffer.from('verified test package fixture');
const ASSET_SHA = createHash('sha256').update(ASSET_BYTES).digest('hex');
const SOURCE_MANIFEST = Buffer.from(JSON.stringify({
  schema_version: 2,
  component: 'securefix-server',
  protocol: 'securefix-native-request/v1',
  version: '0.2.45-pre.38',
  producer_workflow: '.github/workflows/native-package-build.yml',
  publisher_workflow: '.github/workflows/publish-native-package.yml',
  max_bytes: 134217728,
  assets: { 'linux-x86_64': 'securefix-linux-x86_64' },
}));
const MAPPING = {
  schema_version: 3,
  channel: 'scratch',
  component: 'securefix-server',
  protocol: 'securefix-native-request/v1',
  version: '0.2.45-pre.38',
  max_bytes: 134217728,
  source_repository: SOURCE,
  source_repository_id: 1250079425,
  source_sha: SOURCE_SHA,
  source_branch: 'integration/native-server-approve-pre35-20261023',
  source_default_branch: 'main',
  source_manifest_path: '.github/actions/load-package/source-package.json',
  source_manifest_sha256: createHash('sha256').update(SOURCE_MANIFEST).digest('hex'),
  destination_repository: DESTINATION,
  destination_repository_id: 1410312556,
  tag: 'v0.2.45-pre.38',
  release_id: 421371928,
  target_branch: 'main',
  immutable: true,
  prerelease: true,
  asset_id: 667664206,
  asset_name: 'securefix-linux-x86_64',
  asset_size: ASSET_BYTES.byteLength,
  asset_sha256: ASSET_SHA,
  producer_workflow: '.github/workflows/native-package-build.yml',
  producer_run_id: 39885673712,
  producer_run_attempt: 1,
  publisher_workflow: '.github/workflows/publish-native-package.yml',
  publisher_sha: PUBLISHER_SHA,
  publisher_branch: 'main',
  publisher_run_id: 39886040299,
  publisher_run_attempt: 1,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const SOURCE_RUN = {
  id: MAPPING.producer_run_id,
  run_attempt: 1,
  status: 'completed',
  conclusion: 'success',
  event: 'workflow_dispatch',
  head_sha: SOURCE_SHA,
  head_branch: MAPPING.source_branch,
  path: MAPPING.producer_workflow,
  repository: { id: MAPPING.source_repository_id, full_name: SOURCE },
  head_repository: { id: MAPPING.source_repository_id, full_name: SOURCE },
};
const PUBLISHER_RUN = {
  id: MAPPING.publisher_run_id,
  run_attempt: 1,
  status: 'completed',
  conclusion: 'success',
  event: 'workflow_dispatch',
  head_sha: PUBLISHER_SHA,
  head_branch: 'main',
  path: MAPPING.publisher_workflow,
  repository: { id: MAPPING.source_repository_id, full_name: SOURCE },
  head_repository: { id: MAPPING.source_repository_id, full_name: SOURCE },
};

function releaseRecord(): string {
  return JSON.stringify({
    schema_version: 1,
    source_sha: SOURCE_SHA,
    source_manifest_sha256: MAPPING.source_manifest_sha256,
    producer_workflow: MAPPING.producer_workflow,
    producer_run_id: MAPPING.producer_run_id,
    producer_run_attempt: 1,
    publisher_workflow: MAPPING.publisher_workflow,
    publisher_sha: PUBLISHER_SHA,
    publisher_run_id: MAPPING.publisher_run_id,
    publisher_run_attempt: 1,
    tag: MAPPING.tag,
    asset_name: MAPPING.asset_name,
    asset_size: MAPPING.asset_size,
    asset_sha256: ASSET_SHA,
  });
}

function verifierOutput(overrides: Record<string, unknown> = {}): string {
  const signer = 'https://github.com/' + SOURCE + '/' + MAPPING.producer_workflow + '@refs/heads/' + MAPPING.source_branch;
  const certificate: Record<string, unknown> = {
    issuer: 'https://token.actions.githubusercontent.com',
    runnerEnvironment: 'github-hosted',
    githubWorkflowRepository: SOURCE,
    githubWorkflowSHA: SOURCE_SHA,
    githubWorkflowRef: 'refs/heads/' + MAPPING.source_branch,
    buildSignerURI: signer,
    buildSignerDigest: SOURCE_SHA,
    buildConfigURI: signer,
    buildConfigDigest: SOURCE_SHA,
    sourceRepositoryURI: 'https://github.com/' + SOURCE,
    sourceRepositoryDigest: SOURCE_SHA,
    sourceRepositoryRef: 'refs/heads/' + MAPPING.source_branch,
    sourceRepositoryIdentifier: String(MAPPING.source_repository_id),
    sourceRepositoryOwnerIdentifier: '4525500',
    buildTrigger: 'workflow_dispatch',
    githubWorkflowTrigger: 'workflow_dispatch',
    runInvocationURI: 'https://github.com/' + SOURCE + '/actions/runs/' + MAPPING.producer_run_id + '/attempts/1',
  };
  Object.assign(certificate, overrides);
  return JSON.stringify([{
    verificationResult: {
      signature: { certificate },
      statement: {
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: [{ name: MAPPING.asset_name, digest: { sha256: ASSET_SHA } }],
      },
    },
  }]);
}

interface FixtureOptions {
  corruptAsset?: boolean;
  corruptSourceManifest?: boolean;
  sourceManifestPath?: string;
  sourceManifestResponsePath?: string;
  immutable?: boolean;
  targetCommitish?: string;
  verifierOverrides?: Record<string, unknown>;
  verifierFailure?: boolean;
  verifierThrows?: boolean;
  token?: string;
  platform?: string;
  arch?: string;
  duplicateAsset?: boolean;
  producerOverrides?: Record<string, unknown>;
  publisherOverrides?: Record<string, unknown>;
  apiFailure?: string;
}

async function invokeCopiedAction(options: FixtureOptions = {}): Promise<{
  outputs: Map<string, string>;
  paths: string[];
  ghCalls: string[][];
  apiRoutes: string[];
  root: string;
  error: unknown;
}> {
  const root = await mkdtemp(join(tmpdir(), 'securefix loader test with spaces '));
  const actionDirectory = join(root, 'different nesting', 'renamed action with spaces');
  await mkdir(dirname(actionDirectory), { recursive: true });
  const originalDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
  await cp(originalDirectory, actionDirectory, { recursive: true, filter: (source) => basename(source) !== 'node_modules' });
  await writeFile(join(actionDirectory, 'package.json'), JSON.stringify({
    ...MAPPING,
    source_manifest_path: options.sourceManifestPath ?? MAPPING.source_manifest_path,
  }));

  const outputs = new Map<string, string>();
  const paths: string[] = [];
  const ghCalls: string[][] = [];
  const apiRoutes: string[] = [];
  const sourceManifest = options.corruptSourceManifest ? Buffer.from('{"wrong":true}') : SOURCE_MANIFEST;
  const binary = options.corruptAsset ? Buffer.from('wrong executable bytes') : ASSET_BYTES;
  const github = {
    async request(route: string, parameters: Record<string, unknown>): Promise<{ data: unknown }> {
      apiRoutes.push(route);
      if (options.apiFailure === route) throw new Error('fixture API failure');
      if (route === 'GET /repos/{owner}/{repo}') {
        const repository = String(parameters.owner) + '/' + String(parameters.repo);
        if (repository === SOURCE) {
          return { data: { full_name: SOURCE, id: MAPPING.source_repository_id, default_branch: 'main', owner: { id: 4525500 } } };
        }
        if (repository === DESTINATION) {
          return { data: { full_name: DESTINATION, id: MAPPING.destination_repository_id, default_branch: 'main' } };
        }
      }
      if (route.includes('/contents/')) {
        return { data: {
          path: options.sourceManifestResponsePath ?? options.sourceManifestPath ?? MAPPING.source_manifest_path,
          type: 'file',
          encoding: 'base64',
          size: sourceManifest.byteLength,
          content: sourceManifest.toString('base64'),
        } };
      }
      if (route === 'GET /repos/{owner}/{repo}/releases/{release_id}') {
        return { data: {
          id: MAPPING.release_id,
          tag_name: MAPPING.tag,
          draft: false,
          prerelease: true,
          immutable: options.immutable ?? true,
          target_commitish: options.targetCommitish ?? 'main',
          body: releaseRecord(),
        } };
      }
      if (route === 'GET /repos/{owner}/{repo}/releases/{release_id}/assets') {
        const asset = {
          id: MAPPING.asset_id,
          name: MAPPING.asset_name,
          size: MAPPING.asset_size,
          state: 'uploaded',
          digest: 'sha256:' + ASSET_SHA,
        };
        return { data: options.duplicateAsset ? [asset, asset] : [asset] };
      }
      if (route === 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}') {
        return { data: parameters.run_id === MAPPING.producer_run_id
          ? { ...SOURCE_RUN, ...options.producerOverrides }
          : { ...PUBLISHER_RUN, ...options.publisherOverrides } };
      }
      if (route === 'GET /repos/{owner}/{repo}/attestations/{subject_digest}') {
        return { data: { attestations: [{ repository_id: MAPPING.source_repository_id, bundle: { fixture: true } }] } };
      }
      if (route === 'GET /repos/{owner}/{repo}/releases/assets/{asset_id}') return { data: binary };
      throw new Error('unexpected GitHub request: ' + route);
    },
  };
  const core = {
    addPath(path: string): void { paths.push(path); },
    setOutput(name: string, value: string | number): void { outputs.set(name, String(value)); },
  };
  const exec = {
    async getExecOutput(command: string, args: string[], execOptions: { env: Record<string, string> }): Promise<{ exitCode: number; stdout: string; stderr: string }> {
      ghCalls.push([command, ...args]);
      assert.ok(execOptions.env.PATH);
      assert.equal(execOptions.env.HTTPS_PROXY, 'https://runner-proxy.invalid:8443');
      assert.equal(execOptions.env.NO_PROXY, 'localhost,.github.com');
      assert.equal(execOptions.env.SSL_CERT_FILE, '/runner/certs/ca-bundle.pem');
      assert.equal(execOptions.env.HOME, dirname(args[2] ?? ''));
      assert.equal(execOptions.env.GH_CONFIG_DIR, join(execOptions.env.HOME, 'gh-config'));
      assert.equal('GH_TOKEN' in execOptions.env, false);
      assert.equal('GITHUB_TOKEN' in execOptions.env, false);
      assert.equal('INPUT_GITHUB_TOKEN' in execOptions.env, false);
      if (options.verifierThrows) throw new Error('fixture command invocation failure');
      if (options.verifierFailure) return { exitCode: 1, stdout: '', stderr: 'verification rejected' };
      const binaryPath = args[2];
      if (binaryPath === undefined) throw new Error('attestation command has no subject path');
      const downloaded = await readFile(binaryPath);
      assert.equal(downloaded.byteLength, ASSET_BYTES.byteLength);
      if (options.corruptAsset) assert.notEqual(createHash('sha256').update(downloaded).digest('hex'), ASSET_SHA);
      return { exitCode: 0, stdout: verifierOutput(options.verifierOverrides), stderr: '' };
    },
  };
  let error: unknown;
  const savedProxy = process.env.HTTPS_PROXY;
  const savedNoProxy = process.env.NO_PROXY;
  const savedCertificate = process.env.SSL_CERT_FILE;
  process.env.HTTPS_PROXY = 'https://runner-proxy.invalid:8443';
  process.env.NO_PROXY = 'localhost,.github.com';
  process.env.SSL_CERT_FILE = '/runner/certs/ca-bundle.pem';
  try {
    const originalDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
    const action = await readFile(join(actionDirectory, 'action.yml'), 'utf8');
    const script = extractCompositeScript(action);
    const previousActionPath = process.env.GITHUB_ACTION_PATH;
    process.env.GITHUB_ACTION_PATH = actionDirectory;
    try {
      await runCompositeScript(script, github, { repository: 'arbitrary/caller', eventName: 'push', actor: 'any-reader', runAttempt: 3 }, core, exec, {
        env: { ...process.env, LOAD_PACKAGE_TOKEN: options.token ?? 'fixture-read-only-token' },
        platform: options.platform ?? 'linux', arch: options.arch ?? 'x64',
      });
    } finally {
      if (previousActionPath === undefined) delete process.env.GITHUB_ACTION_PATH;
      else process.env.GITHUB_ACTION_PATH = previousActionPath;
    }
  } catch (caught) {
    error = caught;
  } finally {
    if (savedProxy === undefined) delete process.env.HTTPS_PROXY;
    else process.env.HTTPS_PROXY = savedProxy;
    if (savedNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = savedNoProxy;
    if (savedCertificate === undefined) delete process.env.SSL_CERT_FILE;
    else process.env.SSL_CERT_FILE = savedCertificate;
  }
  return { outputs, paths, ghCalls, apiRoutes, root, error };
}

function extractCompositeScript(action: string): string {
  const marker = '        script: |\n';
  const start = action.indexOf(marker);
  assert.ok(start >= 0, 'composite action must define a github-script body');
  const lines = action.slice(start + marker.length).split('\n');
  const body: string[] = [];
  for (const line of lines) {
    if (line.length === 0) {
      body.push('');
    } else if (line.startsWith('          ')) {
      body.push(line.slice(10));
    } else {
      break;
    }
  }
  assert.ok(body.length > 0, 'composite github-script body must not be empty');
  return body.join('\n');
}

test('verified package is added to PATH and outputs without executing the candidate', async () => {
  const result = await invokeCopiedAction();
  try {
    assert.equal(result.error, undefined);
    assert.equal(result.paths.length, 1);
    const binary = result.outputs.get('binary');
    assert.ok(binary);
    assert.equal(result.paths[0], dirname(binary));
    assert.equal(basename(binary), 'securefix', 'PATH exposes the CLI under its documented command name');
    assert.equal(result.outputs.get('version'), MAPPING.version);
    assert.equal(result.outputs.get('source-sha'), SOURCE_SHA);
    assert.equal(result.outputs.get('producer-run-id'), String(MAPPING.producer_run_id));
    assert.equal(result.ghCalls.length, 1);
    assert.equal(result.ghCalls[0]?.[0], 'gh');
    assert.deepEqual(result.ghCalls[0]?.slice(1, 3), ['attestation', 'verify']);
    assert.equal((await stat(binary)).mode & 0o111, 0o111);
    assert.equal(await readFile(binary, 'utf8'), ASSET_BYTES.toString('utf8'));
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('bad downloaded digest fails before attestation or PATH publication', async () => {
  const result = await invokeCopiedAction({ corruptAsset: true });
  try {
    assert.match(String(result.error), /downloaded package bytes differ/);
    assert.equal(result.ghCalls.length, 0);
    assert.equal(result.paths.length, 0);
    assert.equal(result.outputs.size, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('source manifest digest mismatch fails before package download', async () => {
  const result = await invokeCopiedAction({ corruptSourceManifest: true });
  try {
    assert.match(String(result.error), /source package manifest digest differs/);
    assert.equal(result.ghCalls.length, 0);
    assert.equal(result.paths.length, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('source manifest path is safe, repository-relative, and encoded per segment', async () => {
  for (const sourceManifestPath of ['../package.json', 'folder//file.json', 'folder/./file.json', 'folder/../file.json', '/absolute/file.json', 'C:/file.json', 'folder\\file.json', 'folder/file.json?x=1', 'folder/file.json#fragment', 'folder/line\nfeed.json', `folder/${'é'.repeat(100)}.json`]) {
    const rejected = await invokeCopiedAction({ sourceManifestPath });
    try {
      assert.match(String(rejected.error), /invalid source_manifest_path/);
      assert.equal(rejected.apiRoutes.some((route) => route.includes('/contents/')), false);
      assert.deepEqual(rejected.paths, []);
    } finally {
      await rm(rejected.root, { recursive: true, force: true });
    }
  }

  for (const [sourceManifestPath, encodedPath] of [
    ['docs with spaces/nested source/source package.json', 'docs%20with%20spaces/nested%20source/source%20package.json'],
    [`${'a'.repeat(195)}.json`, `${'a'.repeat(195)}.json`],
  ]) {
    const accepted = await invokeCopiedAction({ sourceManifestPath });
    try {
      assert.equal(accepted.error, undefined);
      assert.ok(accepted.apiRoutes.includes(`GET /repos/civitaspo/securefix-server/contents/${encodedPath}`));
      assert.equal(accepted.outputs.get('version'), MAPPING.version);
    } finally {
      await rm(accepted.root, { recursive: true, force: true });
    }
  }
});

test('a bad provenance source identity fails before PATH publication', async () => {
  const result = await invokeCopiedAction({ verifierOverrides: { sourceRepositoryDigest: 'a'.repeat(40) } });
  try {
    assert.match(String(result.error), /certificate differs/);
    assert.equal(result.paths.length, 0);
    assert.equal(result.outputs.size, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('mutable release is rejected before binary download', async () => {
  const result = await invokeCopiedAction({ immutable: false });
  try {
    assert.match(String(result.error), /not the exact immutable release/);
    assert.equal(result.ghCalls.length, 0);
    assert.equal(result.paths.length, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('release targeting a different commit is rejected before asset access', async () => {
  const result = await invokeCopiedAction({ targetCommitish: 'a'.repeat(40) });
  try {
    assert.match(String(result.error), /release target differs/);
    assert.equal(result.ghCalls.length, 0);
    assert.equal(result.paths.length, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('API failures propagate without publishing outputs', async () => {
  const result = await invokeCopiedAction({ apiFailure: 'GET /repos/{owner}/{repo}/releases/{release_id}' });
  try {
    assert.match(String(result.error), /fixture API failure/);
    assert.equal(result.outputs.size, 0);
    assert.equal(result.paths.length, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('attestation command failure never publishes the package', async () => {
  const result = await invokeCopiedAction({ verifierFailure: true });
  try {
    assert.match(String(result.error), /attestation verification failed/);
    assert.equal(result.ghCalls.length, 1);
    assert.equal(result.paths.length, 0);
    assert.equal(result.outputs.size, 0);
  } finally {
    await rm(result.root, { recursive: true, force: true });
  }
});

test('bundled mapping matches the immutable pre88 package receipt', async () => {
  const originalDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
  const parsed: unknown = JSON.parse(await readFile(join(originalDirectory, 'package.json'), 'utf8'));
  assert.ok(isRecord(parsed));
  const mapping = parsed;
  assert.equal(mapping.schema_version, 3);
  assert.equal(mapping.channel, 'scratch');
  assert.equal(mapping.source_sha, '667678dd7399d04e0ad1679db545081bd0ac7ab9');
  assert.equal(mapping.source_manifest_sha256, 'db366d7bc299aa398175e3fb923b08cdaf5f0a81419fcf9639e1c0ae27ceb451');
  assert.equal(mapping.tag, 'v0.2.45-pre.88');
  assert.equal(mapping.release_id, 422043976);
  assert.equal(mapping.asset_id, 669648936);
  assert.equal(mapping.asset_size, 12547144);
  assert.equal(mapping.asset_sha256, 'a5b261b9fba63e521a8ec7ba9db97ddc8bc6084d18c11189de667d85b0f9619b');
  assert.equal(mapping.producer_run_id, 39982985784);
  assert.equal(mapping.publisher_run_id, 39983672658);
  assert.equal(mapping.publisher_sha, 'b12771802cfae6875f6231832d33520ecc8395fd');
});

test('composite metadata exposes only token and invokes the tested Node 24 entry module', async () => {
  const originalDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
  const action = await readFile(join(originalDirectory, 'action.yml'), 'utf8');
  const inputStart = action.indexOf('inputs:\n');
  const outputStart = action.indexOf('outputs:\n');
  assert.ok(inputStart >= 0 && outputStart > inputStart);
  assert.equal(action.slice(inputStart, outputStart),
    'inputs:\n  token:\n    description: Read-only token for the package source and destination repositories\n    required: true\n');
  assert.match(action, /actions\/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8\.0\.0/);
  assert.match(action, /join\(actionPath, 'entry\.mts'\)/);
  assert.match(action, /entry\.run\(\{ github, context, core, exec, runtime:/);
  assert.doesNotMatch(action, /load\.sh|validate\.sh|action-sha|manifest-source-sha|publication-source-sha/);
});

for (const [name, options, message] of [
  ['missing token', { token: '' }, /requires a nonempty token/],
  ['blank token', { token: '  ' }, /requires a nonempty token/],
  ['unsupported OS', { platform: 'darwin' }, /runner platform/],
  ['unsupported architecture', { arch: 'arm64' }, /runner platform/],
  ['duplicate selected asset', { duplicateAsset: true }, /exactly one selected asset/],
  ['wrong producer source', { producerOverrides: { head_sha: 'a'.repeat(40) } }, /producer workflow run differs/],
  ['wrong publisher source', { publisherOverrides: { head_sha: 'a'.repeat(40) } }, /publisher workflow run differs/],
  ['external command exception', { verifierThrows: true }, /fixture command invocation failure/],
] satisfies [string, FixtureOptions, RegExp][]) {
  test(`${name} rejects without executing or publishing a binary`, async () => {
    const result = await invokeCopiedAction(options);
    try {
      assert.match(String(result.error), message);
      assert.deepEqual(result.paths, []);
      assert.equal(result.outputs.size, 0);
      assert.ok(result.ghCalls.every((args) => args[0] === 'gh' && args[1] === 'attestation'));
      if (options.token !== undefined || options.platform !== undefined || options.arch !== undefined) {
        assert.deepEqual(result.apiRoutes, []);
      }
    } finally {
      await rm(result.root, { recursive: true, force: true });
    }
  });
}
