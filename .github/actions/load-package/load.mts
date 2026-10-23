import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ATTESTATION_ISSUER = 'https://token.actions.githubusercontent.com';
const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';
const MANIFEST_FIELDS = [
  'schema_version', 'channel', 'component', 'protocol', 'version', 'max_bytes',
  'source_repository', 'source_repository_id', 'source_sha', 'source_branch',
  'source_default_branch', 'source_manifest_path', 'source_manifest_sha256', 'destination_repository',
  'destination_repository_id', 'tag', 'release_id', 'target_branch', 'immutable',
  'prerelease', 'asset_id', 'asset_name', 'asset_size', 'asset_sha256',
  'producer_workflow', 'producer_run_id', 'producer_run_attempt',
  'publisher_workflow', 'publisher_sha', 'publisher_branch', 'publisher_run_id',
  'publisher_run_attempt',
].sort();

export interface GitHubScriptArguments {
  github: Octokit;
  context: unknown;
  core: ActionsCore;
  exec: ActionsExec;
  runtime: { platform: string; arch: string };
}

interface Octokit {
  request(route: string, parameters: Record<string, unknown>): Promise<{ data: unknown }>;
}

interface ActionsCore {
  addPath(path: string): void;
  setOutput(name: string, value: string | number): void;
}

interface ActionsExec {
  getExecOutput(
    command: string,
    args: string[],
    options: {
      env: Record<string, string>;
      silent: boolean;
      ignoreReturnCode: boolean;
    },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

interface PackageMapping {
  channel: 'stable' | 'scratch';
  component: string;
  protocol: string;
  version: string;
  maxBytes: number;
  sourceRepository: string;
  sourceRepositoryId: number;
  sourceSha: string;
  sourceBranch: string;
  sourceDefaultBranch: string;
  sourceManifestPath: string;
  sourceManifestSha256: string;
  destinationRepository: string;
  destinationRepositoryId: number;
  tag: string;
  releaseId: number;
  targetBranch: string;
  immutable: true;
  prerelease: boolean;
  assetId: number;
  assetName: string;
  assetSize: number;
  assetSha256: string;
  producerWorkflow: string;
  producerRunId: number;
  producerRunAttempt: number;
  publisherWorkflow: string;
  publisherSha: string;
  publisherBranch: string;
  publisherRunId: number;
  publisherRunAttempt: number;
}

interface SourceManifest {
  component: string;
  protocol: string;
  version: string;
  producerWorkflow: string;
  publisherWorkflow: string;
  maxBytes: number;
  assetName: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(record: Record<string, unknown>, key: string, pattern?: RegExp): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0 || (pattern !== undefined && !pattern.test(value))) {
    throw new Error('package mapping has invalid ' + key);
  }
  return value;
}

function requirePositiveInteger(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error('package mapping has invalid ' + key);
  }
  return value;
}

function requireBoolean(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') throw new Error('package mapping has invalid ' + key);
  return value;
}

function requireRepositoryRelativeJsonPath(record: Record<string, unknown>, key: string): string {
  const value = requireString(record, key);
  const segments = value.split('/');
  if (
    value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.includes('\\') ||
    /[\u0000-\u001f\u007f?#]/.test(value) ||
    new TextEncoder().encode(value).byteLength > 200 ||
    segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..') ||
    !segments[segments.length - 1]?.endsWith('.json')
  ) {
    throw new Error('package mapping has invalid ' + key);
  }
  return value;
}

function parseMapping(value: unknown): PackageMapping {
  if (!isRecord(value)) throw new Error('package mapping must be a JSON object');
  const actualKeys = Object.keys(value).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(MANIFEST_FIELDS)) {
    throw new Error('package mapping does not match the exact schema-v3 field set');
  }
  if (value.schema_version !== 3) throw new Error('unsupported package mapping schema');
  const channel = value.channel;
  if (channel !== 'stable' && channel !== 'scratch') throw new Error('package mapping has invalid channel');
  if (!requireBoolean(value, 'immutable')) throw new Error('package mapping must select an immutable release');
  const mapping: PackageMapping = {
    channel,
    component: requireString(value, 'component'),
    protocol: requireString(value, 'protocol'),
    version: requireString(value, 'version', /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/),
    maxBytes: requirePositiveInteger(value, 'max_bytes'),
    sourceRepository: requireString(value, 'source_repository', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    sourceRepositoryId: requirePositiveInteger(value, 'source_repository_id'),
    sourceSha: requireString(value, 'source_sha', /^[0-9a-f]{40}$/),
    sourceBranch: requireString(value, 'source_branch', /^(?!.*(?:\.\.|\/\/|\/$))[A-Za-z0-9._/-]+$/),
    sourceDefaultBranch: requireString(value, 'source_default_branch', /^(?!.*(?:\.\.|\/\/|\/$))[A-Za-z0-9._/-]+$/),
    sourceManifestPath: requireRepositoryRelativeJsonPath(value, 'source_manifest_path'),
    sourceManifestSha256: requireString(value, 'source_manifest_sha256', /^[0-9a-f]{64}$/),
    destinationRepository: requireString(value, 'destination_repository', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    destinationRepositoryId: requirePositiveInteger(value, 'destination_repository_id'),
    tag: requireString(value, 'tag', /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/),
    releaseId: requirePositiveInteger(value, 'release_id'),
    targetBranch: requireString(value, 'target_branch', /^(?!.*(?:\.\.|\/\/|\/$))[A-Za-z0-9._/-]+$/),
    immutable: true,
    prerelease: requireBoolean(value, 'prerelease'),
    assetId: requirePositiveInteger(value, 'asset_id'),
    assetName: requireString(value, 'asset_name', /^[A-Za-z0-9._-]+$/),
    assetSize: requirePositiveInteger(value, 'asset_size'),
    assetSha256: requireString(value, 'asset_sha256', /^[0-9a-f]{64}$/),
    producerWorkflow: requireString(value, 'producer_workflow', /^\.github\/workflows\/[A-Za-z0-9._/-]+\.yml$/),
    producerRunId: requirePositiveInteger(value, 'producer_run_id'),
    producerRunAttempt: requirePositiveInteger(value, 'producer_run_attempt'),
    publisherWorkflow: requireString(value, 'publisher_workflow', /^\.github\/workflows\/[A-Za-z0-9._/-]+\.yml$/),
    publisherSha: requireString(value, 'publisher_sha', /^[0-9a-f]{40}$/),
    publisherBranch: requireString(value, 'publisher_branch', /^(?!.*(?:\.\.|\/\/|\/$))[A-Za-z0-9._/-]+$/),
    publisherRunId: requirePositiveInteger(value, 'publisher_run_id'),
    publisherRunAttempt: requirePositiveInteger(value, 'publisher_run_attempt'),
  };
  if (mapping.maxBytes > 536870912 || mapping.assetSize > mapping.maxBytes) {
    throw new Error('package mapping exceeds the supported asset size');
  }
  if (mapping.tag !== 'v' + mapping.version) throw new Error('package tag and version differ');
  if (mapping.channel === 'stable' && (mapping.prerelease || mapping.version.includes('-'))) {
    throw new Error('stable package mapping cannot select a prerelease');
  }
  if (mapping.channel === 'scratch' && (!mapping.prerelease || !mapping.version.includes('-'))) {
    throw new Error('scratch package mapping must select a prerelease');
  }
  if (mapping.channel === 'stable' &&
      (mapping.sourceBranch !== mapping.sourceDefaultBranch ||
       mapping.sourceRepository !== mapping.destinationRepository ||
       mapping.sourceRepositoryId !== mapping.destinationRepositoryId ||
       mapping.publisherBranch !== mapping.sourceDefaultBranch)) {
    throw new Error('stable package mapping differs from the source default-branch release path');
  }
  return mapping;
}

function parseSourceManifest(value: unknown, mapping: PackageMapping): SourceManifest {
  if (!isRecord(value)) throw new Error('source package manifest must be a JSON object');
  const requiredKeys = ['assets', 'component', 'max_bytes', 'producer_workflow', 'protocol', 'publisher_workflow', 'schema_version', 'version'];
  const sourceKeys = Object.keys(value).sort();
  const optionalSourceSha = sourceKeys.length === requiredKeys.length + 1 && sourceKeys.includes('source_sha');
  const expectedKeys = optionalSourceSha ? [...requiredKeys, 'source_sha'].sort() : requiredKeys.sort();
  if (sourceKeys.join('\0') !== expectedKeys.join('\0') || value.schema_version !== 2) {
    throw new Error('source package manifest does not match schema 2');
  }
  if (optionalSourceSha && value.source_sha !== mapping.sourceSha) {
    throw new Error('source package manifest selects a different binary source revision');
  }
  if (!isRecord(value.assets) || Object.keys(value.assets).length !== 1 || value.assets['linux-x86_64'] !== mapping.assetName) {
    throw new Error('source package manifest selects a different asset');
  }
  if (
    value.component !== mapping.component || value.protocol !== mapping.protocol || value.version !== mapping.version ||
    value.producer_workflow !== mapping.producerWorkflow || value.publisher_workflow !== mapping.publisherWorkflow ||
    value.max_bytes !== mapping.maxBytes
  ) {
    throw new Error('source package manifest differs from the bundled package mapping');
  }
  return {
    component: mapping.component,
    protocol: mapping.protocol,
    version: mapping.version,
    producerWorkflow: mapping.producerWorkflow,
    publisherWorkflow: mapping.publisherWorkflow,
    maxBytes: mapping.maxBytes,
    assetName: mapping.assetName,
  };
}

function nestedRecord(value: unknown, key: string): Record<string, unknown> {
  if (!isRecord(value) || !isRecord(value[key])) throw new Error('attestation verifier output has invalid ' + key);
  const nested = value[key];
  if (!isRecord(nested)) throw new Error('attestation verifier output has invalid ' + key);
  return nested;
}

function stringAt(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return String(value);
  throw new Error('attestation verifier output has invalid ' + key);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function attestationEnvironment(workspace: string): Record<string, string> {
  const environment: Record<string, string> = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: workspace,
    TMPDIR: workspace,
    GH_CONFIG_DIR: join(workspace, 'gh-config'),
    GH_PROMPT: 'disabled',
    GH_NO_UPDATE_NOTIFIER: '1',
  };
  for (const key of ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']) {
    const value = process.env[key];
    if (value !== undefined && value.length > 0) environment[key] = value;
  }
  return environment;
}

function bytesFrom(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error('GitHub API did not return binary release asset bytes');
}

async function apiData(github: Octokit, route: string, parameters: Record<string, unknown>): Promise<unknown> {
  return (await github.request(route, parameters)).data;
}

function ownerAndName(repository: string): { owner: string; repo: string } {
  const [owner, repo] = repository.split('/');
  if (owner === undefined || repo === undefined) throw new Error('repository identity is invalid');
  return { owner, repo };
}

async function getSourceManifest(github: Octokit, mapping: PackageMapping): Promise<Uint8Array> {
  const source = ownerAndName(mapping.sourceRepository);
  const encodedPath = mapping.sourceManifestPath.split('/').map(encodeURIComponent).join('/');
  const response = await apiData(github, `GET /repos/${source.owner}/${source.repo}/contents/${encodedPath}`, {
    ref: mapping.sourceSha,
    headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
  });
  if (!isRecord(response) || response.path !== mapping.sourceManifestPath || response.type !== 'file' || response.encoding !== 'base64') {
    throw new Error('source package manifest response has invalid metadata');
  }
  if (typeof response.size !== 'number' || response.size <= 0 || response.size > 16384 || typeof response.content !== 'string') {
    throw new Error('source package manifest response is missing or too large');
  }
  const encoded = response.content.replace(/[\r\n]/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error('source package manifest response has invalid base64');
  }
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.toString('base64') !== encoded) throw new Error('source package manifest response has noncanonical base64');
  if (decoded.byteLength !== response.size || decoded.byteLength > 16384) throw new Error('source package manifest response has an invalid size');
  return decoded;
}

function canonicalReleaseRecord(body: unknown, mapping: PackageMapping): void {
  if (typeof body !== 'string' || body.length === 0 || body.length > 16384) {
    throw new Error('package release is missing its bounded publication record');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('package release publication record is invalid JSON');
  }
  if (!isRecord(parsed)) throw new Error('package release publication record must be an object');
  const expected: Record<string, unknown> = {
    schema_version: 1,
    source_sha: mapping.sourceSha,
    source_manifest_sha256: mapping.sourceManifestSha256,
    producer_workflow: mapping.producerWorkflow,
    producer_run_id: mapping.producerRunId,
    producer_run_attempt: mapping.producerRunAttempt,
    publisher_workflow: mapping.publisherWorkflow,
    publisher_sha: mapping.publisherSha,
    publisher_run_id: mapping.publisherRunId,
    publisher_run_attempt: mapping.publisherRunAttempt,
    tag: mapping.tag,
    asset_name: mapping.assetName,
    asset_size: mapping.assetSize,
    asset_sha256: mapping.assetSha256,
  };
  const keys = Object.keys(expected);
  if (Object.keys(parsed).join('\0') !== keys.join('\0')) throw new Error('package release publication record is not canonical');
  for (const key of keys) {
    if (parsed[key] !== expected[key]) throw new Error('package release record differs at ' + key);
  }
  if (JSON.stringify(parsed) !== body) throw new Error('package release publication record is not compact canonical JSON');
}

function validateAttestationOutput(stdout: string, mapping: PackageMapping, sourceOwnerId: number, producerEvent: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('attestation verifier did not return JSON');
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) throw new Error('attestation verifier did not return exactly one result');
  const result = parsed[0];
  const verification = nestedRecord(result, 'verificationResult');
  const signature = nestedRecord(verification, 'signature');
  const certificate = nestedRecord(signature, 'certificate');
  const statement = nestedRecord(verification, 'statement');
  const signer = 'https://github.com/' + mapping.sourceRepository + '/' + mapping.producerWorkflow + '@refs/heads/' + mapping.sourceBranch;
  const expected = new Map<string, string>([
    ['issuer', ATTESTATION_ISSUER],
    ['runnerEnvironment', 'github-hosted'],
    ['githubWorkflowRepository', mapping.sourceRepository],
    ['githubWorkflowSHA', mapping.sourceSha],
    ['githubWorkflowRef', 'refs/heads/' + mapping.sourceBranch],
    ['buildSignerURI', signer],
    ['buildSignerDigest', mapping.sourceSha],
    ['buildConfigURI', signer],
    ['buildConfigDigest', mapping.sourceSha],
    ['sourceRepositoryURI', 'https://github.com/' + mapping.sourceRepository],
    ['sourceRepositoryDigest', mapping.sourceSha],
    ['sourceRepositoryRef', 'refs/heads/' + mapping.sourceBranch],
    ['sourceRepositoryIdentifier', String(mapping.sourceRepositoryId)],
    ['sourceRepositoryOwnerIdentifier', String(sourceOwnerId)],
    ['buildTrigger', producerEvent],
    ['githubWorkflowTrigger', producerEvent],
  ]);
  for (const [key, wanted] of expected) {
    if (stringAt(certificate, key) !== wanted) throw new Error('verified attestation certificate differs at ' + key);
  }
  if (stringAt(statement, 'predicateType') !== PREDICATE_TYPE) throw new Error('attestation predicate type differs');
  const subject = statement.subject;
  if (!Array.isArray(subject) || subject.length !== 1 || !isRecord(subject[0])) throw new Error('attestation subject is invalid');
  const digest = subject[0].digest;
  if (subject[0].name !== mapping.assetName || !isRecord(digest) || digest.sha256 !== mapping.assetSha256) {
    throw new Error('attestation subject differs from the selected package asset');
  }
  const expectedRunUri = 'https://github.com/' + mapping.sourceRepository + '/actions/runs/' + mapping.producerRunId + '/attempts/' + mapping.producerRunAttempt;
  if (stringAt(certificate, 'runInvocationURI') !== expectedRunUri) throw new Error('attestation names a different producer run attempt');
}

function assertRun(value: unknown, mapping: PackageMapping, expected: 'producer' | 'publisher'): void {
  if (!isRecord(value)) throw new Error(expected + ' run response must be an object');
  const producer = expected === 'producer';
  const runId = producer ? mapping.producerRunId : mapping.publisherRunId;
  const attempt = producer ? mapping.producerRunAttempt : mapping.publisherRunAttempt;
  const workflow = producer ? mapping.producerWorkflow : mapping.publisherWorkflow;
  const sha = producer ? mapping.sourceSha : mapping.publisherSha;
  const branch = producer ? mapping.sourceBranch : mapping.publisherBranch;
  const repository = mapping.sourceRepository;
  const repositoryId = mapping.sourceRepositoryId;
  if (
    value.id !== runId || value.run_attempt !== attempt || value.status !== 'completed' || value.conclusion !== 'success' ||
    value.head_sha !== sha || value.head_branch !== branch ||
    (value.path !== workflow && value.path !== workflow + '@refs/heads/' + branch) ||
    !isRecord(value.repository) || value.repository.full_name !== repository || value.repository.id !== repositoryId ||
    !isRecord(value.head_repository) || value.head_repository.full_name !== repository || value.head_repository.id !== repositoryId
  ) {
    throw new Error(expected + ' workflow run differs from the bundled package mapping');
  }
}

export async function loadPackage(args: GitHubScriptArguments): Promise<void> {
  const actionDirectory = dirname(fileURLToPath(import.meta.url));
  const manifestBytes = await readFile(join(actionDirectory, 'package.json'));
  if (manifestBytes.byteLength > 16384) throw new Error('bundled package mapping exceeds the metadata limit');
  let rawMapping: unknown;
  try {
    rawMapping = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    throw new Error('bundled package mapping is invalid JSON');
  }
  const mapping = parseMapping(rawMapping);
  if (args.runtime.platform !== 'linux' || args.runtime.arch !== 'x64') {
    throw new Error('package supports only the linux-x86_64 runner platform');
  }
  const source = ownerAndName(mapping.sourceRepository);
  const destination = ownerAndName(mapping.destinationRepository);
  const sourceRepository = await apiData(args.github, 'GET /repos/{owner}/{repo}', source);
  const destinationRepository = await apiData(args.github, 'GET /repos/{owner}/{repo}', destination);
  if (
    !isRecord(sourceRepository) || sourceRepository.full_name !== mapping.sourceRepository ||
    sourceRepository.id !== mapping.sourceRepositoryId || sourceRepository.default_branch !== mapping.sourceDefaultBranch ||
    !isRecord(destinationRepository) || destinationRepository.full_name !== mapping.destinationRepository ||
    destinationRepository.id !== mapping.destinationRepositoryId || destinationRepository.default_branch !== mapping.targetBranch
  ) {
    throw new Error('package repository identity or default branch differs from the bundled mapping');
  }
  if (!isRecord(sourceRepository.owner) || typeof sourceRepository.owner.id !== 'number' ||
      !Number.isSafeInteger(sourceRepository.owner.id) || sourceRepository.owner.id <= 0) {
    throw new Error('package source owner identity is invalid');
  }

  const sourceManifestBytes = await getSourceManifest(args.github, mapping);
  if (sha256(sourceManifestBytes) !== mapping.sourceManifestSha256) throw new Error('source package manifest digest differs from the bundled mapping');
  let sourceManifestJson: unknown;
  try {
    sourceManifestJson = JSON.parse(new TextDecoder().decode(sourceManifestBytes));
  } catch {
    throw new Error('source package manifest is invalid JSON');
  }
  parseSourceManifest(sourceManifestJson, mapping);

  const releaseValue = await apiData(args.github, 'GET /repos/{owner}/{repo}/releases/{release_id}', {
    ...destination,
    release_id: mapping.releaseId,
  });
  if (
    !isRecord(releaseValue) || releaseValue.id !== mapping.releaseId || releaseValue.tag_name !== mapping.tag ||
    releaseValue.draft !== false || releaseValue.prerelease !== mapping.prerelease || releaseValue.immutable !== mapping.immutable
  ) {
    throw new Error('package release is not the exact immutable release in the bundled mapping');
  }
  if (releaseValue.target_commitish !== mapping.targetBranch) {
    throw new Error('package release target differs from the configured destination branch');
  }
  canonicalReleaseRecord(releaseValue.body, mapping);

  const assetsValue = await apiData(args.github, 'GET /repos/{owner}/{repo}/releases/{release_id}/assets', {
    ...destination,
    release_id: mapping.releaseId,
    per_page: 100,
  });
  if (!Array.isArray(assetsValue) || assetsValue.length === 0 || assetsValue.length >= 100) {
    throw new Error('package release assets are missing or exceed the bounded listing');
  }
  const matchingAssets = assetsValue.filter((candidate) => isRecord(candidate) && candidate.id === mapping.assetId);
  if (matchingAssets.length !== 1) throw new Error('package release must contain exactly one selected asset');
  const asset = matchingAssets[0];
  if (!isRecord(asset) || asset.name !== mapping.assetName || asset.size !== mapping.assetSize || asset.state !== 'uploaded') {
    throw new Error('package release asset differs from the bundled mapping');
  }
  if (asset.digest !== 'sha256:' + mapping.assetSha256) throw new Error('release asset digest differs from the bundled mapping');

  const producer = await apiData(args.github, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}', {
    ...source,
    run_id: mapping.producerRunId,
    attempt_number: mapping.producerRunAttempt,
  });
  assertRun(producer, mapping, 'producer');
  if (!isRecord(producer) || typeof producer.event !== 'string' || producer.event.length === 0) {
    throw new Error('producer run event is missing');
  }
  const publisher = await apiData(args.github, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}', {
    ...source,
    run_id: mapping.publisherRunId,
    attempt_number: mapping.publisherRunAttempt,
  });
  assertRun(publisher, mapping, 'publisher');

  const attestationsValue = await apiData(args.github, 'GET /repos/{owner}/{repo}/attestations/{subject_digest}', {
    ...source,
    subject_digest: 'sha256:' + mapping.assetSha256,
    per_page: 100,
  });
  if (
    !isRecord(attestationsValue) || !Array.isArray(attestationsValue.attestations) ||
    attestationsValue.attestations.length === 0 || attestationsValue.attestations.length >= 100
  ) {
    throw new Error('source package attestation list is missing or exceeds the bound');
  }
  const bundles: string[] = [];
  for (const item of attestationsValue.attestations) {
    if (!isRecord(item) || item.repository_id !== mapping.sourceRepositoryId || !isRecord(item.bundle)) {
      throw new Error('source package attestation metadata is incomplete');
    }
    bundles.push(JSON.stringify(item.bundle));
  }

  const workspace = await mkdtemp(join(tmpdir(), 'securefix-verified-package-'));
  try {
    const binaryPath = join(workspace, mapping.assetName);
    const bundlePath = join(workspace, 'attestations.jsonl');
    await mkdir(join(workspace, 'gh-config'), { mode: 0o700 });
    const assetResponse = await args.github.request('GET /repos/{owner}/{repo}/releases/assets/{asset_id}', {
      ...destination,
      asset_id: mapping.assetId,
      headers: { accept: 'application/octet-stream', 'x-github-api-version': '2022-11-28' },
    });
    const assetBytes = bytesFrom(assetResponse.data);
    if (assetBytes.byteLength !== mapping.assetSize || sha256(assetBytes) !== mapping.assetSha256) {
      throw new Error('downloaded package bytes differ from the immutable release asset');
    }
    await writeFile(binaryPath, assetBytes, { flag: 'wx', mode: 0o600 });
    await writeFile(bundlePath, bundles.join('\n') + '\n', { flag: 'wx', mode: 0o600 });
    const verification = await args.exec.getExecOutput('gh', [
      'attestation', 'verify', binaryPath,
      '--bundle', bundlePath,
      '--repo', mapping.sourceRepository,
      '--signer-workflow', mapping.sourceRepository + '/' + mapping.producerWorkflow,
      '--signer-digest', mapping.sourceSha,
      '--source-digest', mapping.sourceSha,
      '--source-ref', 'refs/heads/' + mapping.sourceBranch,
      '--cert-oidc-issuer', ATTESTATION_ISSUER,
      '--predicate-type', PREDICATE_TYPE,
      '--deny-self-hosted-runners',
      '--format', 'json',
    ], {
      env: attestationEnvironment(workspace),
      silent: true,
      ignoreReturnCode: false,
    });
    if (verification.exitCode !== 0) throw new Error('package attestation verification failed');
    validateAttestationOutput(verification.stdout, mapping, sourceRepository.owner.id, producer.event);
    const installedPath = join(workspace, 'securefix');
    await rename(binaryPath, installedPath);
    await chmod(installedPath, 0o755);

    await rm(bundlePath, { force: true });
    args.core.addPath(workspace);
    args.core.setOutput('binary', installedPath);
    args.core.setOutput('version', mapping.version);
    args.core.setOutput('asset-id', mapping.assetId);
    args.core.setOutput('release-id', mapping.releaseId);
    args.core.setOutput('source-sha', mapping.sourceSha);
    args.core.setOutput('source-branch', mapping.sourceBranch);
    args.core.setOutput('producer-run-id', mapping.producerRunId);
    args.core.setOutput('producer-run-attempt', mapping.producerRunAttempt);
  } catch (error) {
    await rm(workspace, { recursive: true, force: true });
    throw error;
  }
}
