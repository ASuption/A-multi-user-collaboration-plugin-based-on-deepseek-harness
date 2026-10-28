/**
 * node:test suite for lib/workspace.js.
 * Plain ESM, Node builtins only. Run with:
 *   node --test tests/workspace.test.mjs
 */
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

import {
  LAYOUT,
  backupDir,
  compareTrees,
  copyTree,
  diffOfManifests,
  ensureLayout,
  formatDiff,
  listFiles,
  ownDir,
  readSnapshotFiles,
  readState,
  readmeDir,
  sharedDir,
  writeFiles,
  writeState,
} from '../lib/workspace.js'
import { CollabError, decodeFile, encodeFile, fileSha256 } from '../lib/protocol.js'

async function makeTempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-group-workspace-'))
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true })
  })
  return root
}

async function exists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

test('ensureLayout creates the documented layout and dir helpers point at it', async (t) => {
  const root = await makeTempRoot(t)
  await ensureLayout(root)
  await ensureLayout(root) // idempotent

  assert.deepEqual({ ...LAYOUT }, {
    stateDir: '.dsh-group',
    own: 'own',
    shared: 'shared',
    backup: 'backup',
    readme: 'readme',
  })
  assert.equal(path.basename(ownDir(root)), 'own')
  assert.equal(path.basename(sharedDir(root)), 'shared')
  assert.equal(path.basename(backupDir(root)), 'backup')
  assert.equal(readmeDir(root), path.join(sharedDir(root), 'readme'))

  const expected = [
    ownDir(root),
    sharedDir(root),
    readmeDir(root),
    path.join(readmeDir(root), 'members'),
    backupDir(root),
    path.join(root, LAYOUT.stateDir),
  ]
  for (const directory of expected) {
    const stat = await fs.stat(directory)
    assert.equal(stat.isDirectory(), true, `missing directory: ${directory}`)
  }
})

test('writeFiles/readSnapshotFiles roundtrip preserves utf8, binary and empty files', async (t) => {
  const root = await makeTempRoot(t)
  await ensureLayout(root)

  const utf8 = '你好，DSH 群组协作！\n第二行\t带制表符\n'
  const binary = Buffer.from([0, 1, 2, 3, 127, 128, 200, 255, 10, 13, 0])
  const result = await writeFiles(sharedDir(root), [
    { path: 'src/问候.txt', content: utf8 },
    { path: 'assets/logo.bin', bytes: binary },
    { path: 'empty.txt', bytes: Buffer.alloc(0) },
  ])
  assert.deepEqual([...result.written].sort(), ['assets/logo.bin', 'empty.txt', 'src/问候.txt'])

  const manifest = await listFiles(sharedDir(root))
  assert.deepEqual(manifest.map((file) => file.path), ['assets/logo.bin', 'empty.txt', 'src/问候.txt'])
  const binaryEntry = manifest.find((file) => file.path === 'assets/logo.bin')
  assert.equal(binaryEntry.size, binary.byteLength)
  assert.equal(binaryEntry.sha256, fileSha256(binary))

  const snapshot = await readSnapshotFiles(sharedDir(root))
  assert.deepEqual(snapshot.map((entry) => entry.path), ['assets/logo.bin', 'empty.txt', 'src/问候.txt'])
  for (const entry of snapshot) {
    const decoded = decodeFile(entry) // validates base64 size + sha256
    if (entry.path === 'assets/logo.bin') assert.deepEqual(decoded.bytes, binary)
    if (entry.path === 'src/问候.txt') assert.equal(decoded.bytes.toString('utf8'), utf8)
    if (entry.path === 'empty.txt') assert.equal(decoded.bytes.byteLength, 0)
  }
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'src', '问候.txt'), 'utf8'), utf8)

  // Base64 snapshot entries can be written back losslessly into another tree.
  const copyTarget = path.join(root, 'snapshot-copy')
  await writeFiles(copyTarget, snapshot, { clean: true })
  assert.deepEqual(await listFiles(copyTarget), manifest)
  assert.deepEqual(await readSnapshotFiles(copyTarget), snapshot)

  // Every write is atomic: no temp files are left behind.
  const leftovers = (await fs.readdir(path.join(copyTarget, 'assets'))).filter((name) => name.includes('.tmp'))
  assert.deepEqual(leftovers, [])
})

test('writeFiles rejects traversal, absolute, backslash and NUL paths', async (t) => {
  const root = await makeTempRoot(t)
  const target = path.join(root, 'safe-target')

  const badPaths = [
    '../escape.txt',
    'a/../../escape.txt',
    '/absolute.txt',
    'C:/windows.txt',
    'a\\b.txt',
    'nul\u0000byte.txt',
    '',
  ]
  for (const badPath of badPaths) {
    await assert.rejects(
      writeFiles(target, [{ path: badPath, content: 'x' }]),
      (error) => error instanceof CollabError && error.code === 'BAD_PATH',
      `expected BAD_PATH for ${JSON.stringify(badPath)}`,
    )
  }
  assert.equal(await exists(path.join(root, 'escape.txt')), false)
  assert.equal(await exists(path.join(path.dirname(root), 'escape.txt')), false)
  // Nothing was written for invalid input.
  assert.equal(await exists(target), false)

  // Normalized duplicates are rejected before anything is written.
  await assert.rejects(
    writeFiles(target, [
      { path: 'a/b.txt', content: '1' },
      { path: 'a/./b.txt', content: '2' },
    ]),
    (error) => error instanceof CollabError && error.code === 'BAD_SNAPSHOT',
  )
})

test('writeFiles clean removes stale files, keeps keep-prefixes and excluded dirs', async (t) => {
  const root = await makeTempRoot(t)
  await ensureLayout(root)
  const shared = sharedDir(root)

  await writeFiles(shared, [
    { path: 'src/old.js', content: 'old' },
    { path: 'src/keep.js', content: 'keep' },
    { path: 'docs/guide.md', content: 'guide' },
    { path: 'readme/README.md', content: '# readme' },
    { path: 'readme/members/Alice.md', content: '# alice' },
    { path: '.git/config', content: '[core]' },
    { path: 'node_modules/pkg/index.js', content: 'module' },
  ])

  const { deleted } = await writeFiles(shared, [
    { path: 'src/new.js', content: 'new' },
    { path: 'readme/README.md', content: '# updated' },
  ], { keep: ['readme/'] })

  assert.deepEqual(deleted, ['docs/guide.md', 'src/keep.js', 'src/old.js'])
  assert.equal(await fs.readFile(path.join(shared, 'readme', 'README.md'), 'utf8'), '# updated')
  assert.equal(await fs.readFile(path.join(shared, 'readme', 'members', 'Alice.md'), 'utf8'), '# alice')
  assert.equal(await fs.readFile(path.join(shared, 'src', 'new.js'), 'utf8'), 'new')
  assert.equal(await exists(path.join(shared, 'docs')), false, 'empty directories are pruned')
  // Excluded dirs are never traversed or deleted.
  assert.equal(await fs.readFile(path.join(shared, '.git', 'config'), 'utf8'), '[core]')
  assert.equal(await fs.readFile(path.join(shared, 'node_modules', 'pkg', 'index.js'), 'utf8'), 'module')

  // Without a keep prefix, stale readme files are cleaned too.
  const second = await writeFiles(shared, [{ path: 'readme/README.md', content: '# final' }], { clean: true })
  // node_modules is excluded, so it is neither deleted nor reported.
  assert.deepEqual(second.deleted, ['readme/members/Alice.md', 'src/new.js'])
  assert.equal(await exists(path.join(shared, 'readme', 'members')), false)
  assert.equal(await fs.readFile(path.join(shared, 'node_modules', 'pkg', 'index.js'), 'utf8'), 'module')
})

test('writeFiles clean never deletes own/, backup/ or .dsh-group/', async (t) => {
  const root = await makeTempRoot(t)
  await ensureLayout(root)
  await fs.writeFile(path.join(ownDir(root), 'private.txt'), 'mine')
  await fs.writeFile(path.join(backupDir(root), 'index.json'), '{}')
  await fs.writeFile(path.join(root, LAYOUT.stateDir, 'member.json'), '{"id":"x"}')

  await writeFiles(root, [
    { path: 'shared/x.txt', content: 'x' },
    { path: 'README.md', content: 'root file' },
  ], { clean: true })

  assert.equal(await fs.readFile(path.join(ownDir(root), 'private.txt'), 'utf8'), 'mine')
  assert.equal(await fs.readFile(path.join(backupDir(root), 'index.json'), 'utf8'), '{}')
  assert.equal(await fs.readFile(path.join(root, LAYOUT.stateDir, 'member.json'), 'utf8'), '{"id":"x"}')
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'x.txt'), 'utf8'), 'x')
})

test('listFiles/readSnapshotFiles skip excluded dirs and symlinks', async (t) => {
  const root = await makeTempRoot(t)
  const content = path.join(root, 'content')
  await fs.mkdir(path.join(content, 'nested'), { recursive: true })
  await fs.writeFile(path.join(content, 'a.txt'), 'a')
  await fs.writeFile(path.join(content, 'nested', 'b.txt'), 'b')
  await fs.mkdir(path.join(content, '.git'), { recursive: true })
  await fs.writeFile(path.join(content, '.git', 'config'), 'git')
  await fs.mkdir(path.join(content, 'node_modules', 'pkg'), { recursive: true })
  await fs.writeFile(path.join(content, 'node_modules', 'pkg', 'index.js'), 'pkg')
  await fs.mkdir(path.join(content, '.dsh-group'), { recursive: true })
  await fs.writeFile(path.join(content, '.dsh-group', 'member.json'), '{}')
  await fs.mkdir(path.join(content, 'private'), { recursive: true })
  await fs.writeFile(path.join(content, 'private', 'secret.txt'), 'private')

  const outside = path.join(root, 'outside')
  await fs.mkdir(outside, { recursive: true })
  await fs.writeFile(path.join(outside, 'secret.txt'), 'outside-secret')
  let junctionCreated = false
  try {
    await fs.symlink(outside, path.join(content, 'link'), 'junction')
    junctionCreated = true
  } catch (error) {
    t.diagnostic(`junction symlink unavailable: ${error.code ?? error.message}`)
  }

  const manifest = await listFiles(content)
  assert.deepEqual(manifest.map((file) => file.path), ['a.txt', 'nested/b.txt', 'private/secret.txt'])

  const custom = await listFiles(content, { exclude: ['private'] })
  assert.deepEqual(custom.map((file) => file.path), ['a.txt', 'nested/b.txt'])

  const snapshot = await readSnapshotFiles(content)
  assert.deepEqual(snapshot.map((entry) => entry.path), ['a.txt', 'nested/b.txt', 'private/secret.txt'])
  if (junctionCreated) {
    assert.equal(manifest.some((file) => file.path.startsWith('link/')), false)
    assert.equal(snapshot.some((entry) => entry.path.startsWith('link/')), false)
  }
})

test('copyTree copies regular files only and supports clean/keep', async (t) => {
  const root = await makeTempRoot(t)
  const source = path.join(root, 'source')
  await fs.mkdir(path.join(source, 'sub'), { recursive: true })
  await fs.writeFile(path.join(source, 'one.txt'), 'one')
  await fs.writeFile(path.join(source, 'sub', 'two.txt'), 'two')

  const outside = path.join(root, 'outside')
  await fs.mkdir(outside, { recursive: true })
  await fs.writeFile(path.join(outside, 'secret.txt'), 'outside-secret')
  let junctionCreated = false
  try {
    await fs.symlink(outside, path.join(source, 'link'), 'junction')
    junctionCreated = true
  } catch (error) {
    t.diagnostic(`junction symlink unavailable: ${error.code ?? error.message}`)
  }

  const destination = path.join(root, 'destination')
  await copyTree(source, destination)
  assert.deepEqual((await listFiles(destination)).map((file) => file.path), ['one.txt', 'sub/two.txt'])
  assert.equal(await exists(path.join(destination, 'link')), false)
  if (junctionCreated) assert.equal(await exists(path.join(destination, 'link', 'secret.txt')), false)

  // Stale files are removed with clean, keep prefixes survive.
  await writeFiles(destination, [{ path: 'stale.txt', content: 'stale' }, { path: 'readme/keep.md', content: 'keep' }])
  await copyTree(source, destination, { clean: true, keep: ['readme/'] })
  const after = (await listFiles(destination)).map((file) => file.path)
  assert.deepEqual(after, ['one.txt', 'readme/keep.md', 'sub/two.txt'])
})

test('readState/writeState roundtrip atomically and quarantine corrupt state', async (t) => {
  const root = await makeTempRoot(t)
  await ensureLayout(root)

  assert.equal(await readState(root), null)
  const state = {
    id: 'abcdef123456',
    name: 'Alice',
    room: '123456',
    origin: 'http://127.0.0.1:45890',
    token: 'deadbeef',
    rememberPassword: true,
  }
  await writeState(root, state)
  assert.deepEqual(await readState(root), state)
  assert.deepEqual(await fs.readdir(path.join(root, LAYOUT.stateDir)), ['member.json'])

  await assert.rejects(writeState(root, null), (error) => error instanceof CollabError && error.code === 'BAD_REQUEST')
  await assert.rejects(writeState(root, []), (error) => error instanceof CollabError && error.code === 'BAD_REQUEST')

  // Corrupt state is quarantined and reported as missing instead of crashing.
  await fs.writeFile(path.join(root, LAYOUT.stateDir, 'member.json'), '{this is not json', 'utf8')
  assert.equal(await readState(root), null)
  const remaining = await fs.readdir(path.join(root, LAYOUT.stateDir))
  assert.deepEqual([...remaining].sort(), ['member.json.corrupt'])
})

test('diffOfManifests/compareTrees/formatDiff produce sorted human diffs', () => {
  const before = [
    { path: 'a.js', sha256: '1' },
    { path: 'b.js', sha256: '2' },
  ]
  const after = [
    { path: 'a.js', sha256: '1' },
    { path: 'b.js', sha256: '3' },
    { path: 'c.js', sha256: '4' },
  ]
  const diff = diffOfManifests(before, after)
  assert.deepEqual(diff, { added: ['c.js'], modified: ['b.js'], deleted: [] })
  assert.deepEqual(compareTrees(after, before), { added: [], modified: ['b.js'], deleted: ['c.js'] })
  assert.deepEqual(diffOfManifests(null, null), { added: [], modified: [], deleted: [] })
  assert.equal(formatDiff(diff), '+c.js ~b.js')
  assert.equal(
    formatDiff({ added: ['b', 'a'], modified: ['c'], deleted: [] }, { limit: 2 }),
    '+a +b …（其余 1 项）',
  )
  assert.equal(formatDiff({ added: [], modified: [], deleted: [] }), '')
  assert.equal(formatDiff({ added: ['a'], modified: [], deleted: [] }, { limit: 0 }), '…（共 1 项改动）')
})

test('writeFiles enforces snapshot limits and digest validation', async (t) => {
  const root = await makeTempRoot(t)
  const target = path.join(root, 'data')
  const bytes = Buffer.from('hello')

  await assert.rejects(
    writeFiles(target, [{ path: 'a.txt', data: bytes.toString('base64'), size: bytes.length, sha256: '0'.repeat(64) }]),
    (error) => error instanceof CollabError && error.code === 'BAD_SNAPSHOT',
  )
  await assert.rejects(
    writeFiles(target, [{ path: 'a.txt', data: bytes.toString('base64'), size: 999, sha256: fileSha256(bytes) }]),
    (error) => error instanceof CollabError && error.code === 'BAD_SNAPSHOT',
  )
  await assert.rejects(
    writeFiles(target, [{ path: 'missing-content.txt' }]),
    (error) => error instanceof CollabError && error.code === 'BAD_SNAPSHOT',
  )

  const tooMany = Array.from({ length: 2001 }, (_, index) => ({ path: `f${index}.txt`, content: '' }))
  await assert.rejects(
    writeFiles(target, tooMany),
    (error) => error instanceof CollabError && error.code === 'TOO_LARGE',
  )

  // Valid encoded entries roundtrip (encodeFile -> writeFiles).
  const encoded = encodeFile('ok.txt', Buffer.from('ok'))
  await writeFiles(target, [encoded])
  assert.equal(await fs.readFile(path.join(target, 'ok.txt'), 'utf8'), 'ok')
})

test('listFiles returns [] for a missing directory and rejects a file root', async (t) => {
  const root = await makeTempRoot(t)
  assert.deepEqual(await listFiles(path.join(root, 'does-not-exist')), [])
  assert.deepEqual(await readSnapshotFiles(path.join(root, 'does-not-exist')), [])

  await fs.writeFile(path.join(root, 'file.txt'), 'x')
  await assert.rejects(
    listFiles(path.join(root, 'file.txt')),
    (error) => error instanceof CollabError && error.code === 'BAD_REQUEST',
  )
})
