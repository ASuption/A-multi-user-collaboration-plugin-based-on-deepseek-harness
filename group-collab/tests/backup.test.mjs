/**
 * node:test suite for lib/backup.js.
 * Plain ESM, Node builtins only. Run with:
 *   node --test tests/backup.test.mjs
 */
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

import { listVersions, pruneVersions, recordVersion, restoreVersion } from '../lib/backup.js'
import { CollabError } from '../lib/protocol.js'
import { backupDir, ensureLayout, listFiles, sharedDir, writeFiles } from '../lib/workspace.js'

async function makeWorkspace(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-group-backup-'))
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true })
  })
  await ensureLayout(root)
  return root
}

async function writeShared(root, files) {
  return writeFiles(sharedDir(root), files, { clean: true })
}

async function readIndexJson(root) {
  return JSON.parse(await fs.readFile(path.join(backupDir(root), 'index.json'), 'utf8'))
}

async function exists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

test('recordVersion mirrors shared/ into a version dir and appends index.json', async (t) => {
  const root = await makeWorkspace(t)
  const binary = Buffer.from([1, 2, 3, 255, 0])
  await writeShared(root, [
    { path: 'src/a.js', content: 'console.log(1)\n' },
    { path: 'assets/pic.bin', bytes: binary },
    { path: 'readme/README.md', content: '# hi' },
  ])
  const sharedManifest = await listFiles(sharedDir(root))
  const totalBytes = sharedManifest.reduce((sum, file) => sum + file.size, 0)

  const record = await recordVersion(root, {
    reason: 'upload',
    member: { id: 'abcdef123456', name: 'Alice' },
    note: '首次上传',
    rev: 1,
    changes: {
      added: ['src/a.js', 'assets/pic.bin', 'readme/README.md'],
      modified: [],
      deleted: [],
    },
  })

  assert.equal(record.version, 1)
  assert.match(record.dir, /^v0001-\d{8}T\d{9}Z-upload$/u)
  assert.equal(Number.isNaN(Date.parse(record.at)), false)
  assert.equal(record.reason, 'upload')
  assert.deepEqual(record.member, { id: 'abcdef123456', name: 'Alice' })
  assert.equal(record.note, '首次上传')
  assert.equal(record.rev, 1)
  assert.deepEqual(record.changes.added, ['assets/pic.bin', 'readme/README.md', 'src/a.js'])
  assert.equal(record.fileCount, 3)
  assert.equal(record.totalBytes, totalBytes)

  const index = await readIndexJson(root)
  assert.equal(index.version, 1)
  assert.equal(index.keepVersions, 50)
  assert.deepEqual(index.versions, [record])

  const versionDir = path.join(backupDir(root), record.dir)
  assert.deepEqual((await listFiles(versionDir)).map((file) => file.path), [
    'assets/pic.bin',
    'readme/README.md',
    'src/a.js',
  ])
  assert.deepEqual(
    await fs.readFile(path.join(versionDir, 'assets', 'pic.bin')),
    binary,
    'binary content is mirrored losslessly',
  )
  assert.equal(await fs.readFile(path.join(versionDir, 'src', 'a.js'), 'utf8'), 'console.log(1)\n')

  // The index write is atomic: no temp files are left behind.
  const leftovers = (await fs.readdir(backupDir(root))).filter((name) => name.includes('.tmp'))
  assert.deepEqual(leftovers, [])
})

test('recordVersion works for an empty shared folder and rejects invalid changes', async (t) => {
  const root = await makeWorkspace(t)
  const record = await recordVersion(root, { reason: 'init' })
  assert.equal(record.fileCount, 0)
  assert.equal(record.totalBytes, 0)
  assert.deepEqual(record.changes, { added: [], modified: [], deleted: [] })
  assert.equal(await exists(path.join(backupDir(root), record.dir)), true)

  await assert.rejects(
    recordVersion(root, { reason: 'upload', changes: { added: ['../escape.txt'] } }),
    (error) => error instanceof CollabError && error.code === 'BAD_PATH',
  )
  await assert.rejects(
    recordVersion(root, { reason: 'upload', changes: { added: 'not-an-array' } }),
    (error) => error instanceof CollabError && error.code === 'BAD_REQUEST',
  )
})

test('listVersions returns an empty index first, then ascending versions newest last', async (t) => {
  const root = await makeWorkspace(t)
  const empty = await listVersions(root)
  assert.equal(Array.isArray(empty), true)
  assert.deepEqual([...empty], [])
  assert.equal(empty.length, 0)
  assert.equal(empty.index, empty) // DESIGN-compatible { index } alias

  for (let index = 0; index < 3; index += 1) {
    await writeShared(root, [{ path: `f${index}.txt`, content: `v${index}` }])
    await recordVersion(root, { reason: 'sync', note: `第 ${index + 1} 版` })
  }
  const { index: versions } = await listVersions(root)
  assert.deepEqual(versions.map((record) => record.version), [1, 2, 3])
  assert.deepEqual(versions.map((record) => record.note), ['第 1 版', '第 2 版', '第 3 版'])
  assert.equal(new Set(versions.map((record) => record.dir)).size, 3)
})

test('listVersions is array-compatible and restoreVersion accepts records/dir names', async (t) => {
  const root = await makeWorkspace(t)
  await writeShared(root, [{ path: 'a.txt', content: 'one' }])
  const first = await recordVersion(root, { reason: 'upload', member: 'Alice', note: 'first' })
  assert.equal(first.member, 'Alice', 'string member names are preserved for display')
  await writeShared(root, [{ path: 'a.txt', content: 'two' }])
  await recordVersion(root, { reason: 'sync', member: { id: 'abc', name: 'Bob' } })

  const versions = await listVersions(root)
  assert.equal(Array.isArray(versions), true)
  assert.deepEqual(versions.map((record) => record.version), [1, 2])
  assert.equal(versions.index, versions)
  assert.equal(JSON.parse(JSON.stringify(versions)).length, 2, 'serializes as a plain array')
  assert.equal(versions[0].member, 'Alice')
  assert.deepEqual(versions[1].member, { id: 'abc', name: 'Bob' })

  // restoreVersion accepts a version record (as the runtime passes it)...
  const byRecord = await restoreVersion(root, versions[0])
  assert.equal(byRecord.restored.version, 1)
  assert.equal(byRecord.restored.member, 'Alice', 'string member names survive the restore result')
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'a.txt'), 'utf8'), 'one')

  // ...a version directory name...
  await writeShared(root, [{ path: 'a.txt', content: 'three' }])
  const byDir = await restoreVersion(root, versions[1].dir)
  assert.equal(byDir.restored.version, 2)
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'a.txt'), 'utf8'), 'two')

  // ...and a numeric string.
  const byString = await restoreVersion(root, '1')
  assert.equal(byString.restored.version, 1)
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'a.txt'), 'utf8'), 'one')
})

test('pruneVersions keeps the newest N versions and deletes old directories', async (t) => {
  const root = await makeWorkspace(t)
  for (let index = 0; index < 5; index += 1) {
    await writeShared(root, [{ path: 'data.txt', content: `v${index}` }])
    await recordVersion(root, { reason: 'change' })
  }
  const before = await listVersions(root)
  assert.deepEqual(before.index.map((record) => record.version), [1, 2, 3, 4, 5])

  const result = await pruneVersions(root, 2)
  assert.equal(result.keepVersions, 2)
  assert.deepEqual(result.index.map((record) => record.version), [4, 5])
  assert.deepEqual(result.pruned.map((dir) => before.index.find((record) => record.dir === dir).version), [1, 2, 3])
  for (const dir of result.pruned) assert.equal(await exists(path.join(backupDir(root), dir)), false)
  for (const record of result.index) assert.equal(await exists(path.join(backupDir(root), record.dir)), true)

  const index = await readIndexJson(root)
  assert.equal(index.keepVersions, 2)
  assert.deepEqual(index.versions.map((record) => record.version), [4, 5])

  // Default keep value (50) leaves a small history untouched.
  const defaultPrune = await pruneVersions(root)
  assert.equal(defaultPrune.keepVersions, 50)
  assert.deepEqual(defaultPrune.index.map((record) => record.version), [4, 5])
})

test('recordVersion continues numbering after prune and honors stored keepVersions', async (t) => {
  const root = await makeWorkspace(t)
  for (let index = 0; index < 3; index += 1) {
    await writeShared(root, [{ path: 'data.txt', content: `v${index}` }])
    await recordVersion(root, { reason: 'change' })
  }
  await pruneVersions(root, 2) // keeps versions 2 and 3

  await writeShared(root, [{ path: 'data.txt', content: 'v3' }])
  const record = await recordVersion(root, { reason: 'upload' })
  assert.equal(record.version, 4)
  assert.match(record.dir, /^v0004-/u)

  const { index: versions } = await listVersions(root)
  assert.deepEqual(versions.map((entry) => entry.version), [3, 4])
})

test('restoreVersion records pre-restore first, then restores shared/ cleanly', async (t) => {
  const root = await makeWorkspace(t)
  await writeShared(root, [{ path: 'a.txt', content: 'version one' }])
  const v1 = await recordVersion(root, { reason: 'upload', note: 'v1', rev: 1 })

  await writeShared(root, [
    { path: 'a.txt', content: 'version two' },
    { path: 'extra.txt', content: 'extra' },
  ])
  const v2 = await recordVersion(root, { reason: 'sync', note: 'v2', rev: 2 })

  const outcome = await restoreVersion(root, 1)
  assert.equal(outcome.restored.version, v1.version)
  assert.equal(outcome.restored.dir, v1.dir)
  assert.equal(outcome.savedCurrent.reason, 'pre-restore')
  assert.deepEqual(outcome.written.written, ['a.txt'])

  const manifest = await listFiles(sharedDir(root))
  assert.deepEqual(manifest.map((file) => file.path), ['a.txt'])
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'a.txt'), 'utf8'), 'version one')
  assert.equal(await exists(path.join(sharedDir(root), 'extra.txt')), false, 'restore is a clean overwrite')

  const { index: versions } = await listVersions(root)
  assert.deepEqual(versions.map((record) => record.version), [1, 2, 3])
  assert.deepEqual(versions.map((record) => record.reason), ['upload', 'sync', 'pre-restore'])
  assert.equal(versions[1].dir, v2.dir)
  const preRestoreDir = path.join(backupDir(root), versions[2].dir)
  assert.equal(await fs.readFile(path.join(preRestoreDir, 'a.txt'), 'utf8'), 'version two')
  assert.equal(await fs.readFile(path.join(preRestoreDir, 'extra.txt'), 'utf8'), 'extra')

  await assert.rejects(
    restoreVersion(root, 99),
    (error) => error instanceof CollabError && error.code === 'NOT_FOUND',
  )
  await assert.rejects(
    restoreVersion(root, 'not-a-version'),
    (error) => error instanceof CollabError && error.code === 'NOT_FOUND',
  )
})

test('restoreVersion works even when pre-restore pruning removes the target version', async (t) => {
  const root = await makeWorkspace(t)
  await writeShared(root, [{ path: 'a.txt', content: 'one' }])
  await recordVersion(root, { reason: 'upload' })
  await writeShared(root, [{ path: 'a.txt', content: 'two' }])
  await recordVersion(root, { reason: 'sync' })
  await pruneVersions(root, 1) // keepVersions=1: only version 2 remains

  const outcome = await restoreVersion(root, 2)
  assert.equal(outcome.restored.version, 2)
  assert.equal(await fs.readFile(path.join(sharedDir(root), 'a.txt'), 'utf8'), 'two')
  // The pre-restore record (version 3) prunes version 2 out of the index, but
  // the restore itself already succeeded from memory.
  const { index: versions } = await listVersions(root)
  assert.deepEqual(versions.map((record) => record.reason), ['pre-restore'])
})

test('listVersions quarantines a corrupt index and rebuilds from version dirs', async (t) => {
  const root = await makeWorkspace(t)
  await writeShared(root, [{ path: 'file.txt', content: 'x' }])
  await recordVersion(root, { reason: 'upload', note: 'first' })
  await recordVersion(root, { reason: 'sync', note: 'second' })

  const indexPath = path.join(backupDir(root), 'index.json')
  await fs.writeFile(indexPath, '{ definitely not json', 'utf8')

  const { index: versions } = await listVersions(root)
  assert.deepEqual(versions.map((record) => record.version), [1, 2])
  assert.deepEqual(versions.map((record) => record.reason), ['upload', 'sync'])
  assert.equal(await exists(`${indexPath}.corrupt`), true)
})
