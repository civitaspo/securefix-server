import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import test from 'node:test'
import vm from 'node:vm'

const root = new URL('..', import.meta.url)
const require = createRequire(import.meta.url)

function scriptFor(path, stepName) {
  const lines = readFileSync(new URL(path, root), 'utf8').split('\n')
  const step = lines.findIndex(line => line.trim() === `- name: ${stepName}`)
  assert.notEqual(step, -1, `workflow step exists: ${stepName}`)
  const script = lines.findIndex((line, index) => index > step && line.trim() === 'script: |')
  assert.notEqual(script, -1, `inline script exists: ${stepName}`)
  const indent = lines[script].match(/^\s*/)[0].length + 2
  const body = []
  for (const line of lines.slice(script + 1)) {
    if (line.trim() && line.match(/^\s*/)[0].length < indent) break
    body.push(line.slice(indent))
  }
  return body.join('\n')
}

async function run(script, { github, context = {}, env = {}, core = {}, clock } = {}) {
  const errors = []
  const outputs = {}
  const actionCore = {
    setFailed(message) { errors.push(message) },
    setOutput(name, value) { outputs[name] = value },
    info() {},
    warning() {},
    summary: { addHeading() { return this }, addText() { return this }, async write() {} },
    ...core,
  }
  const actionProcess = { env: { ...env } }
  const clockDate = clock?.Date || Date
  const timeout = clock?.setTimeout || setTimeout
  await vm.runInNewContext(`(async () => {\n${script}\n})()`, {
    github,
    context,
    core: actionCore,
    process: actionProcess,
    require,
    Buffer,
    Date: clockDate,
    setTimeout: timeout,
    console,
  })
  return { errors, outputs }
}

const sha = 'a'.repeat(40)
const workflowSha = 'c'.repeat(40)

function manifestFixture(overrides = {}) {
  return {
    version: 1,
    repository: { id: 5, fullName: 'civitaspo/example' },
    pullRequest: { number: 7, headSha: sha, baseRef: 'main' },
    comment: { id: 11, authorId: 4525500, updatedAt: null },
    acceptedAt: new Date().toISOString(),
    runId: 9,
    runAttempt: 1,
    workflowSha,
    ...overrides,
  }
}

function writeManifest(directory, manifest) {
  const path = join(directory, 'manifest.json')
  writeFileSync(path, JSON.stringify(manifest))
  return path
}

function validationGithub({ pr = {}, comment = {}, events = [], comments = [] } = {}) {
  return {
    rest: {
      repos: { get: async () => ({ data: { id: 5, default_branch: 'main' } }) },
      pulls: { get: async () => ({ data: {
        state: 'open', draft: false,
        base: { ref: 'main', repo: { full_name: 'civitaspo/example' } },
        head: { sha, repo: { full_name: 'civitaspo/example' } },
        ...pr,
      } }) },
      issues: {
        getComment: async () => ({ data: {
          issue_url: 'https://api.github.com/repos/civitaspo/example/issues/7',
          body: '/merge', user: { id: 4525500 }, updated_at: null,
          ...comment,
        } }),
        listComments: async () => ({ data: comments }),
        listEventsForTimeline: async () => ({ data: events }),
      },
    },
    paginate: async method => {
      const response = await method()
      return Array.isArray(response) ? response : response.data
    },
  }
}

function validateManifestEnv(manifestPath) {
  return {
    SOURCE_REPOSITORY: 'civitaspo/example',
    SOURCE_RUN_ID: '9',
    SOURCE_HEAD_SHA: workflowSha,
    MANIFEST_PATH: manifestPath,
  }
}

function sourceRunGithub({ run = {}, workflow = {}, wrapperPin = 'b'.repeat(40), artifacts = [] } = {}) {
  const wrapper = `name: Merge\nuses: civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@${wrapperPin}\n`
  return {
    rest: {
      actions: {
        getWorkflowRun: async () => ({ data: {
          id: 9,
          status: 'completed', conclusion: 'success', run_attempt: 1, event: 'issue_comment',
          repository: { full_name: 'civitaspo/example' },
          workflow_id: 3, path: '.github/workflows/merge-request.yml@refs/heads/main',
          head_branch: 'main', head_sha: workflowSha,
          referenced_workflows: [{
            path: `civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@${wrapperPin}`,
            sha: wrapperPin,
          }],
          ...run,
        } }),
        getWorkflow: async () => ({ data: {
          path: '.github/workflows/merge-request.yml', ...workflow,
        } }),
        listWorkflowRunArtifacts: async () => ({ data: { artifacts } }),
      },
      repos: {
        get: async ({ owner }) => ({ data: { id: 5, default_branch: 'main' } }),
        getContent: async () => ({ data: { encoding: 'base64', content: Buffer.from(wrapper).toString('base64') } }),
      },
    },
    request: async () => ({ data: { status: 'identical' } }),
  }
}

const validArtifact = { id: 42, name: 'securefix-merge-request-9', expired: false, size_in_bytes: 100 }

async function validateRequestManifest(manifest, github = validationGithub()) {
  const directory = mkdtempSync(join(tmpdir(), 'merge-workflow-'))
  try {
    const manifestPath = writeManifest(directory, manifest)
    return await run(scriptFor('.github/workflows/merge.yml', 'Validate the request record and current pull request'), {
      env: validateManifestEnv(manifestPath), github,
    })
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

test('intake rejects an unauthorized commenter before reading the pull request', async () => {
  const workspace = mkdtempSync(join(tmpdir(), 'merge-workflow-'))
  try {
    const result = await run(scriptFor('.github/workflows/reusable-merge-request.yml', 'Capture the merge request'), {
      context: {
        payload: {
          comment: { id: 11, body: '/merge', user: { id: 42 } },
          repository: { id: 5, full_name: 'civitaspo/example', name: 'example', owner: { login: 'civitaspo' } },
          issue: { number: 7 },
        },
        runId: 9,
        runAttempt: 1,
        sha,
      },
      env: { GITHUB_WORKSPACE: workspace },
      github: { rest: { pulls: { get: async () => { throw new Error('must not fetch the PR') } } } },
    })
    assert.deepEqual(result.errors, ['Only civitaspo can request a merge with an exact /merge comment.'])
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
})

test('intake records the request snapshot before creating a server label', async () => {
  const workspace = mkdtempSync(join(tmpdir(), 'merge-workflow-'))
  try {
    const workflowSha = 'c'.repeat(40)
    const repository = { id: 5, full_name: 'civitaspo/example', name: 'example', owner: { login: 'civitaspo' } }
    const comment = { id: 11, body: '/merge', user: { id: 4525500 }, updated_at: null }
    const github = {
      rest: {
        pulls: { get: async () => ({ data: { state: 'open', draft: false, head: { sha }, base: { ref: 'main' } } }) },
        repos: { get: async () => ({ data: { default_branch: 'main' } }) },
        issues: { getComment: async () => ({ data: comment }) },
      },
    }
    const result = await run(scriptFor('.github/workflows/reusable-merge-request.yml', 'Capture the merge request'), {
      context: { payload: { comment, repository, issue: { number: 7 } }, runId: 9, runAttempt: 1, sha: workflowSha },
      env: { GITHUB_WORKSPACE: workspace },
      github,
    })
    const manifest = JSON.parse(readFileSync(join(workspace, 'merge-request', 'manifest.json'), 'utf8'))
    assert.deepEqual(result.errors, [])
    assert.equal(manifest.repository.id, 5)
    assert.equal(manifest.pullRequest.number, 7)
    assert.equal(manifest.pullRequest.headSha, sha)
    assert.equal(manifest.pullRequest.baseRef, 'main')
    assert.equal(manifest.comment.id, 11)
    assert.equal(manifest.comment.authorId, 4525500)
    assert.equal(manifest.runId, 9)
    assert.equal(manifest.runAttempt, 1)
    assert.equal(manifest.workflowSha, workflowSha)
    assert.ok(Number.isFinite(Date.parse(manifest.acceptedAt)))
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
})

test('server rejects a source workflow rerun', async () => {
  const github = {
    rest: {
      actions: {
        getWorkflowRun: async () => ({ data: {
          status: 'completed', conclusion: 'success', run_attempt: 2, event: 'issue_comment',
          repository: { full_name: 'civitaspo/example' },
        } }),
      },
    },
  }
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Validate the source run'), {
    env: { SOURCE_REPOSITORY: 'civitaspo/example', SOURCE_RUN_ID: '9' },
    context: { payload: { repository: { id: 1 } } },
    github,
  })
  assert.deepEqual(result.errors, ['The source run is a rerun or did not originate from the expected repository event.'])
})

test('server rejects an unexpected source event, workflow path, or reusable pin', async t => {
  const cases = [
    {
      name: 'event',
      github: sourceRunGithub({ run: { event: 'workflow_dispatch' } }),
      expected: 'The source run is a rerun or did not originate from the expected repository event.',
    },
    {
      name: 'source workflow path',
      github: sourceRunGithub({ workflow: { path: '.github/workflows/other.yml' } }),
      expected: 'The source run did not use the approved default-branch intake workflow.',
    },
    {
      name: 'reusable workflow SHA',
      github: sourceRunGithub({ run: { referenced_workflows: [] } }),
      expected: 'The source workflow must call the approved Securefix merge reusable commit SHA.',
    },
    {
      name: 'referenced workflow SHA mismatch',
      github: sourceRunGithub({ run: { referenced_workflows: [{
        path: `civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@${'f'.repeat(40)}`,
        sha: 'f'.repeat(40),
      }] } }),
      expected: 'The source workflow must call the approved Securefix merge reusable commit SHA.',
    },
    {
      name: 'duplicate reusable workflow references',
      github: sourceRunGithub({ run: { referenced_workflows: [
        {
          path: `civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@${'b'.repeat(40)}`,
          sha: 'b'.repeat(40),
        },
        {
          path: `civitaspo/securefix-server/.github/workflows/reusable-merge-request.yml@${'f'.repeat(40)}`,
          sha: 'f'.repeat(40),
        },
      ] } }),
      expected: 'The source workflow must call the approved Securefix merge reusable commit SHA.',
    },
  ]
  for (const item of cases) await t.test(item.name, async () => {
    const result = await run(scriptFor('.github/workflows/merge.yml', 'Validate the source run'), {
      env: {
        SOURCE_REPOSITORY: 'civitaspo/example', SOURCE_RUN_ID: '9',
      },
      github: item.github,
    })
    assert.deepEqual(result.errors, [item.expected])
  })
})

test('server rejects missing, duplicate, or expired source artifacts', async t => {
  const cases = [
    { name: 'missing', artifacts: [] },
    { name: 'unknown artifact name', artifacts: [{ ...validArtifact, name: 'unrelated-artifact' }] },
    { name: 'duplicate', artifacts: [validArtifact, { ...validArtifact, id: 43 }] },
    { name: 'expired', artifacts: [{ ...validArtifact, expired: true }] },
    { name: 'oversized', artifacts: [{ ...validArtifact, size_in_bytes: 16_385 }] },
  ]
  for (const item of cases) await t.test(item.name, async () => {
    const result = await run(scriptFor('.github/workflows/merge.yml', 'Validate the source run'), {
      env: {
        SOURCE_REPOSITORY: 'civitaspo/example', SOURCE_RUN_ID: '9',
      },
      github: sourceRunGithub({ artifacts: item.artifacts }),
    })
    assert.deepEqual(result.errors, ['The source run must have exactly one small, unexpired merge request artifact.'])
  })
})

test('server rejects a label created by a human', async () => {
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Resolve the source run locator'), {
    env: { VERIFICATION_REPOSITORY: '' },
    context: { payload: {
      label: { name: 'merge-request-9', description: 'civitaspo/example/9' },
      sender: { id: 4525500, type: 'User' },
    }, runAttempt: 1 },
    github: {},
  })
  assert.equal(result.errors.length, 1)
  assert.equal(result.outputs.repository, undefined)
})

test('server rejects a label workflow rerun', async () => {
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Resolve the source run locator'), {
    env: { VERIFICATION_REPOSITORY: '' },
    context: { payload: {
      label: { name: 'merge-request-9', description: 'civitaspo/example/9' },
      sender: { id: 288068203, type: 'Bot' },
    }, runAttempt: 2 },
    github: {},
  })
  assert.deepEqual(result.errors, ['The merge label must contain only a valid source repository and run locator.'])
})

test('server history rejects replays even when no terminal comment exists', async () => {
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Reject a previously handled source request'), {
    env: { SOURCE_RUN_ID: '9' },
    context: { runId: 10, repo: { owner: 'civitaspo', repo: 'securefix-server' } },
    github: {
      rest: { actions: { listWorkflowRuns: async () => ({ data: { workflow_runs: [
        { id: 8, display_title: 'Merge Pull Request (merge-request-9)' },
      ] } }) } },
      paginate: async method => (await method()).data.workflow_runs,
    },
  })
  assert.deepEqual(result.errors, ['This source request already has a server workflow run. Post a fresh /merge comment to retry.'])
})

test('server rejects a pull request whose head changed after acceptance', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'merge-workflow-'))
  try {
    const acceptedAt = new Date().toISOString()
    const workflowSha = 'c'.repeat(40)
    const manifest = {
      version: 1,
      repository: { id: 5, fullName: 'civitaspo/example' },
      pullRequest: { number: 7, headSha: sha, baseRef: 'main' },
      comment: { id: 11, authorId: 4525500, updatedAt: null },
      acceptedAt,
      runId: 9,
      runAttempt: 1,
      workflowSha,
    }
    const manifestPath = join(directory, 'manifest.json')
    const { writeFileSync } = await import('node:fs')
    writeFileSync(manifestPath, JSON.stringify(manifest))
    const github = {
      rest: {
        repos: { get: async () => ({ data: { id: 5, default_branch: 'main' } }) },
        pulls: { get: async () => ({ data: {
          state: 'open', draft: false, base: { ref: 'main', repo: { full_name: 'civitaspo/example' } },
          head: { sha: 'b'.repeat(40), repo: { full_name: 'someone/fork' } },
        } }) },
        issues: { getComment: async () => ({ data: {
          issue_url: 'https://api.github.com/repos/civitaspo/example/issues/7',
          body: '/merge', user: { id: 4525500 }, updated_at: null,
        } }) },
      },
      paginate: async () => [],
    }
    const result = await run(scriptFor('.github/workflows/merge.yml', 'Validate the request record and current pull request'), {
      env: {
        SOURCE_REPOSITORY: 'civitaspo/example', SOURCE_RUN_ID: '9', SOURCE_HEAD_SHA: workflowSha,
        MANIFEST_PATH: manifestPath,
      },
      github,
    })
    assert.deepEqual(result.errors, ['The comment or pull request no longer matches the accepted request.'])
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('server rejects expired requests, edited comments, closed or draft PRs, and retargeted PRs', async t => {
  const expired = manifestFixture({ acceptedAt: new Date(Date.now() - 61 * 60 * 1000).toISOString() })
  const cases = [
    { name: 'expired request', manifest: expired, expected: 'The request manifest has invalid fields or an expired deadline.' },
    { name: 'edited comment body', github: validationGithub({ comment: { body: '/merge\nchanged' } }) },
    { name: 'edited comment timestamp', github: validationGithub({ comment: { updated_at: new Date().toISOString() } }) },
    { name: 'closed pull request', github: validationGithub({ pr: { state: 'closed' } }) },
    { name: 'draft pull request', github: validationGithub({ pr: { draft: true } }) },
    { name: 'retargeted pull request', github: validationGithub({ pr: { base: { ref: 'release', repo: { full_name: 'civitaspo/example' } } } }) },
  ]
  for (const item of cases) await t.test(item.name, async () => {
    const result = await validateRequestManifest(item.manifest || manifestFixture(), item.github)
    assert.deepEqual(result.errors, [item.expected || 'The comment or pull request no longer matches the accepted request.'])
  })
})

test('server rejects a deleted request comment', async () => {
  const github = validationGithub()
  github.rest.issues.getComment = async () => { throw Object.assign(new Error('Not Found'), { status: 404 }) }
  await assert.rejects(validateRequestManifest(manifestFixture(), github), /Not Found/)
})

test('force-push followed by return to the accepted head is invalidated by timeline history', async () => {
  const manifest = manifestFixture()
  const result = await validateRequestManifest(manifest, validationGithub({
    events: [{ event: 'head_ref_force_pushed', created_at: new Date(Date.now() + 1000).toISOString() }],
  }))
  assert.deepEqual(result.errors, ['The pull request changed after the merge request was accepted.'])
})

test('timeline events truncated to the acceptance second are conservatively invalidated', async () => {
  const now = Date.now()
  const manifest = manifestFixture({ acceptedAt: new Date(now).toISOString() })
  const sameSecond = new Date(Math.floor(now / 1000) * 1000).toISOString()
  const result = await validateRequestManifest(manifest, validationGithub({
    events: [{ event: 'head_ref_force_pushed', created_at: sameSecond }],
  }))
  assert.deepEqual(result.errors, ['The pull request changed after the merge request was accepted.'])
})

test('transient close/reopen and draft/ready transitions invalidate restored pull requests', async t => {
  const scenarios = [
    { name: 'close then reopen', events: ['closed', 'reopened'] },
    { name: 'convert to draft then ready', events: ['convert_to_draft', 'ready_for_review'] },
  ]
  for (const scenario of scenarios) await t.test(scenario.name, async () => {
    const manifest = manifestFixture()
    const events = scenario.events.map((event, index) => ({
      event,
      created_at: new Date(Date.now() + index + 1000).toISOString(),
    }))
    const result = await validateRequestManifest(manifest, validationGithub({
      pr: { state: 'open', draft: false },
      events,
    }))
    assert.deepEqual(result.errors, ['The pull request changed after the merge request was accepted.'])
  })
})

test('server rejects a terminal request replay before checking the timeline', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'merge-workflow-'))
  try {
    const manifest = {
      version: 1,
      repository: { id: 5, fullName: 'civitaspo/example' },
      pullRequest: { number: 7, headSha: sha, baseRef: 'main' },
      comment: { id: 11, authorId: 4525500, updatedAt: null },
      acceptedAt: new Date().toISOString(),
      runId: 9,
      runAttempt: 1,
      workflowSha: sha,
    }
    const manifestPath = join(directory, 'manifest.json')
    const { writeFileSync } = await import('node:fs')
    writeFileSync(manifestPath, JSON.stringify(manifest))
    let timelineRead = false
    const github = {
      rest: {
        repos: { get: async () => ({ data: { id: 5, default_branch: 'main' } }) },
        pulls: { get: async () => ({ data: {
          state: 'open', draft: false, base: { ref: 'main', repo: { full_name: 'civitaspo/example' } },
          head: { sha, repo: { full_name: 'civitaspo/example' } },
        } }) },
        issues: {
        getComment: async () => ({ data: {
          issue_url: 'https://api.github.com/repos/civitaspo/example/issues/7',
          body: '/merge', user: { id: 4525500 }, updated_at: null,
        } }),
          listComments: async () => ({ data: [] }),
          listEventsForTimeline: async () => { timelineRead = true; return { data: [] } },
        },
      },
      paginate: async method => {
        if (method === github.rest.issues.listComments) {
          return [{ user: { id: 288069019 }, body: '<!-- securefix-merge-request:9 -->\ncompleted' }]
        }
        const response = await method()
        return Array.isArray(response) ? response : response.data
      },
    }
    const result = await run(scriptFor('.github/workflows/merge.yml', 'Validate the request record and current pull request'), {
      env: {
        SOURCE_REPOSITORY: 'civitaspo/example', SOURCE_RUN_ID: '9', SOURCE_HEAD_SHA: sha,
        MANIFEST_PATH: manifestPath,
      },
      github,
    })
    assert.deepEqual(result.errors, ['This source request has already reached a terminal result.'])
    assert.equal(timelineRead, false)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('readiness waits on the fixed deadline instead of accepting pending CI and review', async () => {
  const start = Date.now()
  const manifest = {
    repository: { id: 5, fullName: 'civitaspo/example' },
    pullRequest: { number: 7, headSha: sha, baseRef: 'main' },
    comment: { id: 11, updatedAt: null },
    acceptedAt: new Date(start).toISOString(),
  }
  let now = start
  const fakeDate = class extends Date {
    static now() { return now }
  }
  const github = {
    rest: {
      repos: {
        get: async () => ({ data: { id: 5, default_branch: 'main' } }),
        getCombinedStatusForRef: async () => ({ data: { statuses: [{ context: 'status-check', state: 'pending' }] } }),
      },
      pulls: { get: async () => ({ data: {
        state: 'open', draft: false, base: { ref: 'main' }, head: { sha, repo: { full_name: 'civitaspo/example' } },
      } }) },
      issues: {
        getComment: async () => ({ data: { body: '/merge', user: { id: 4525500 }, updated_at: null } }),
        listEventsForTimeline: async () => ({ data: [] }),
      },
      checks: { listForRef: async () => ({ data: { check_runs: [{
        name: 'status-check', status: 'in_progress', conclusion: null,
      }] } }) },
    },
    paginate: async method => {
      const response = await method()
      return Array.isArray(response.data) ? response.data : response.data.check_runs
    },
    graphql: async () => ({ repository: { pullRequest: { reviewDecision: 'CHANGES_REQUESTED' } } }),
  }
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Wait for required checks and approval'), {
    env: { SOURCE_REPOSITORY: 'civitaspo/example', MANIFEST: JSON.stringify(manifest) },
    github,
    clock: {
      Date: fakeDate,
      setTimeout: (callback, ms) => { now += ms; callback() },
    },
  })
  assert.deepEqual(result.errors, ['Required checks and review did not become ready within the fixed 60-minute deadline.'])
  assert.equal(result.outputs.head_sha, undefined)
  assert.ok(now >= start + 60 * 60 * 1000)
})

test('the contents-write token is created only after readiness succeeds', () => {
  const workflow = readFileSync(new URL('../.github/workflows/merge.yml', import.meta.url), 'utf8')
  const readiness = workflow.indexOf('- name: Wait for required checks and approval')
  const mergeToken = workflow.indexOf('- name: Create a merge token after readiness')
  const mergeCall = workflow.indexOf('- name: Merge the accepted head SHA')
  assert.ok(readiness >= 0 && mergeToken > readiness && mergeCall > mergeToken)
  const tokenStep = workflow.slice(mergeToken, mergeCall)
  assert.match(tokenStep, /permission-contents: write/)
  assert.match(tokenStep, /if: steps\.ready\.outcome == 'success'/)
  const mergeScript = scriptFor('.github/workflows/merge.yml', 'Merge the accepted head SHA')
  assert.match(mergeScript, /sha: manifest\.pullRequest\.headSha/)
  assert.match(mergeScript, /merge_method: 'squash'/)
  assert.doesNotMatch(mergeScript, /commit_title/)
})

test('merge sends the accepted pull-request head SHA and preserves the description', async () => {
  const manifest = {
    repository: { id: 5, fullName: 'civitaspo/example' },
    pullRequest: { number: 7, headSha: sha, baseRef: 'main' },
    comment: { id: 11, updatedAt: null },
    acceptedAt: new Date().toISOString(),
    runId: 9,
  }
  let mergeInput
  const github = {
    rest: {
      repos: {
        get: async () => ({ data: { id: 5, default_branch: 'main' } }),
        getCombinedStatusForRef: async () => ({ data: { statuses: [] } }),
      },
      pulls: {
        get: async () => ({ data: {
          state: 'open', draft: false, body: 'A useful PR description.',
          base: { ref: 'main' }, head: { sha, repo: { full_name: 'civitaspo/example' } },
        } }),
        listCommits: async () => ({ data: [{ commit: { message: 'change\n\nCo-authored-by: Ada <ada@example.com>' } }] }),
        merge: async input => { mergeInput = input; return { data: { merged: true, sha: 'd'.repeat(40) } } },
      },
      issues: {
        getComment: async () => ({ data: { body: '/merge', user: { id: 4525500 }, updated_at: null } }),
        listEventsForTimeline: async () => ({ data: [] }),
      },
      checks: { listForRef: async () => ({ data: { check_runs: [{
        name: 'status-check', status: 'completed', conclusion: 'success',
      }] } }) },
    },
    paginate: async method => {
      const response = await method()
      return Array.isArray(response) ? response : response.data?.check_runs || response.data
    },
    graphql: async () => ({ repository: { pullRequest: { reviewDecision: 'APPROVED' } } }),
  }
  const result = await run(scriptFor('.github/workflows/merge.yml', 'Merge the accepted head SHA'), {
    env: { SOURCE_REPOSITORY: 'civitaspo/example', MANIFEST: JSON.stringify(manifest) },
    github,
  })
  assert.deepEqual(result.errors, [])
  assert.equal(result.outputs.merge_sha, 'd'.repeat(40))
  assert.equal(mergeInput.sha, sha)
  assert.equal(mergeInput.merge_method, 'squash')
  assert.equal(mergeInput.commit_title, undefined)
  assert.match(mergeInput.commit_message, /A useful PR description\./)
  assert.match(mergeInput.commit_message, /Co-authored-by: Ada <ada@example\.com>/)
})

test('merge rejects a head change observed by the Merge API SHA precondition', async () => {
  const manifest = manifestFixture()
  const github = {
    rest: {
      repos: {
        get: async () => ({ data: { id: 5, default_branch: 'main' } }),
        getCombinedStatusForRef: async () => ({ data: { statuses: [] } }),
      },
      pulls: {
        get: async () => ({ data: {
          state: 'open', draft: false, body: 'Description.',
          base: { ref: 'main' }, head: { sha, repo: { full_name: 'civitaspo/example' } },
        } }),
        listCommits: async () => ({ data: [] }),
        merge: async () => { throw Object.assign(new Error('head changed'), { status: 409 }) },
      },
      issues: {
        getComment: async () => ({ data: { body: '/merge', user: { id: 4525500 }, updated_at: null } }),
        listEventsForTimeline: async () => ({ data: [] }),
      },
      checks: { listForRef: async () => ({ data: { check_runs: [{
        name: 'status-check', status: 'completed', conclusion: 'success',
      }] } }) },
    },
    paginate: async method => {
      const response = await method()
      return Array.isArray(response) ? response : response.data?.check_runs || response.data
    },
    graphql: async () => ({ repository: { pullRequest: { reviewDecision: 'APPROVED' } } }),
  }
  await assert.rejects(run(scriptFor('.github/workflows/merge.yml', 'Merge the accepted head SHA'), {
    env: { SOURCE_REPOSITORY: 'civitaspo/example', MANIFEST: JSON.stringify(manifest) },
    github,
  }), /The accepted head SHA changed before GitHub merged it/)
})
