/**
 * End-to-end verification for the DSH Group Collaboration plugin.
 *
 * These tests use ONLY the real modules — a real `RoomServer` on ephemeral
 * ports, real `CollabRuntime` instances (lib/member.js) in isolated temp
 * workspaces and real HTTP/JSON sync traffic. Nothing is mocked.
 *
 * Run with the bundled node binary from `Z:\try\work\group-collab`:
 *   node --test tests/
 *
 * Covered here:
 *   - room creation/join, upload -> tick/sync replication with exact byte
 *     equality for text, UTF-8 and binary files,
 *   - Chinese update notices delivered through the injected notify hook
 *     (`{ root, text, wake }`) containing 共享文件夹已更新 / 房间 / 变更,
 *   - generated `shared/readme/README.md` listing every member readme,
 *   - append-only `backup/index.json` versions and backup restore with the
 *     implicit `pre-restore` version,
 *   - stale-uploader conflict: upload throws CONFLICT only AFTER auto-syncing
 *     the receiver to the uploader's latest shared content, retry succeeds,
 *   - a late third member: immediate snapshot application + stale local
 *     content recorded as a deleted entry in its join backup version,
 *   - `CollabRuntime.createRoom` (runtime-owned RoomServer) + UDP discovery.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { promises as fs } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

import { CollabRuntime } from '../lib/member.js'
import { RoomServer } from '../lib/room-server.js'
import { discoverRoom } from '../lib/room-client.js'
import { CollabError, safeMemberFileName } from '../lib/protocol.js'
import { backupDir, ownDir, sharedDir } from '../lib/workspace.js'

const ROOM_MAIN = '620101'
const ROOM_CREATED = '730202'
const PASSWORD = 'e2e-secret-42'
const WRONG_PASSWORD = 'wrong-pass-9'

const silentLogger = Object.freeze({ log() {}, info() {}, warn() {}, error() {}, debug() {} })

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/* ------------------------------------------------------------------ */
/* filesystem helpers                                                 */
/* ------------------------------------------------------------------ */

async function makeBaseDir() {
  return await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-group-e2e-'))
}

async function cleanupDir(directory) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      await fs.rm(directory, { recursive: true, force: true })
      return
    } catch {
      await delay(100)
    }
  }
}

async function pathExists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

/** Recursively read every regular file below `rootDir` into a Map<posixPath, Buffer>. */
async function readTree(rootDir) {
  const files = new Map()
  async function visit(directoryAbs, relativeDir) {
    let entries
    try {
      entries = await fs.readdir(directoryAbs, { withFileTypes: true })
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    for (const entry of entries) {
      const relativePath = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`
      const absolutePath = path.join(directoryAbs, entry.name)
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        await visit(absolutePath, relativePath)
        continue
      }
      if (!entry.isFile()) continue
      files.set(relativePath, await fs.readFile(absolutePath))
    }
  }
  await visit(rootDir, '')
  return files
}

/** Assert two directory trees are byte-identical (file list + every byte). */
async function assertTreesEqual(actualRoot, expectedRoot, label) {
  const actual = await readTree(actualRoot)
  const expected = await readTree(expectedRoot)
  assert.deepEqual(
    [...actual.keys()].sort(),
    [...expected.keys()].sort(),
    `${label}: 文件列表不一致\nactual=${JSON.stringify([...actual.keys()].sort())}\nexpected=${JSON.stringify([...expected.keys()].sort())}`,
  )
  for (const [relativePath, bytes] of expected) {
    assert.deepEqual(actual.get(relativePath), bytes, `${label}: ${relativePath} 字节不一致`)
  }
}

/* ------------------------------------------------------------------ */
/* ports                                                              */
/* ------------------------------------------------------------------ */

/** Reserve one currently-free TCP port (probe-then-release idiom). */
async function reserveTcpPort() {
  const probe = net.createServer()
  await new Promise((resolve, reject) => {
    probe.once('error', reject)
    probe.listen(0, '0.0.0.0', resolve)
  })
  const port = probe.address().port
  await new Promise((resolve) => probe.close(resolve))
  return port
}

/** Reserve one currently-free UDP port (probe-then-release idiom). */
async function reserveUdpPort() {
  const socket = createSocket('udp4')
  await new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, '0.0.0.0', resolve)
  })
  const port = socket.address().port
  await new Promise((resolve) => {
    try {
      socket.close(resolve)
    } catch {
      resolve()
    }
  })
  return port
}

/* ------------------------------------------------------------------ */
/* notify / assertions helpers                                        */
/* ------------------------------------------------------------------ */

/** Notify hook that records exactly `{ root, text, wake }` and claims delivery. */
function makeNotifyRecorder() {
  const records = []
  return {
    records,
    notify(notice) {
      records.push({ root: notice.root, text: notice.text, wake: notice.wake })
      return true
    },
  }
}

function workspaceKey(root) {
  const resolved = path.resolve(root)
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved
}

function recordsFor(records, root) {
  return records.filter((record) => workspaceKey(record.root) === workspaceKey(root))
}

function assertNoticeTokens(record, label) {
  assert.ok(record !== undefined, `${label}: 没有捕获到通知`)
  assert.deepEqual(Object.keys(record).sort(), ['root', 'text', 'wake'], `${label}: 通知字段应为 {root,text,wake}`)
  assert.equal(typeof record.text, 'string')
  assert.ok(record.text.includes('共享文件夹已更新'), `${label}: 通知缺少“共享文件夹已更新”:\n${record.text}`)
  assert.ok(record.text.includes('房间'), `${label}: 通知缺少“房间”:\n${record.text}`)
  assert.ok(record.text.includes('变更'), `${label}: 通知缺少“变更”:\n${record.text}`)
}

function expectRejectsCollab(promise, code) {
  return assert.rejects(promise, (error) => {
    assert.ok(error instanceof CollabError, `expected CollabError, got: ${error}`)
    assert.equal(error.code, code)
    return true
  })
}

/* ------------------------------------------------------------------ */
/* Test 1: bare RoomServer + three CollabRuntime members              */
/* ------------------------------------------------------------------ */

test('e2e：真实 RoomServer + 两成员上传/同步/冲突/readme/备份/通知 + 晚加入成员 + 备份恢复', async () => {
  const base = await makeBaseDir()
  const rootA = path.join(base, 'workspace-a')
  const rootB = path.join(base, 'workspace-b')
  const rootC = path.join(base, 'workspace-c')
  const recorderA = makeNotifyRecorder()
  const recorderB = makeNotifyRecorder()
  const recorderC = makeNotifyRecorder()
  const runtimeA = new CollabRuntime({
    config: { dataDir: path.join(base, 'runtime-a'), pollMs: 1_000_000, enableDiscovery: false },
    logger: silentLogger,
    notify: recorderA.notify,
  })
  const runtimeB = new CollabRuntime({
    config: { dataDir: path.join(base, 'runtime-b'), pollMs: 1_000_000, enableDiscovery: false },
    logger: silentLogger,
    notify: recorderB.notify,
  })
  const runtimeC = new CollabRuntime({
    config: { dataDir: path.join(base, 'runtime-c'), pollMs: 1_000_000, enableDiscovery: false },
    logger: silentLogger,
    notify: recorderC.notify,
  })
  // Real room server on ephemeral TCP/UDP ports (0 = OS assigned).
  const server = new RoomServer({
    dataDir: path.join(base, 'server-data'),
    tcpPort: 0,
    udpPort: 0,
    enableDiscovery: false,
    logger: silentLogger,
    hostName: 'e2e-host',
  })

  try {
    const serverInfo = await server.listen()
    assert.ok(Number.isInteger(serverInfo.tcpPort) && serverInfo.tcpPort > 0)
    assert.equal(server.origin, serverInfo.origin)
    await server.createLocalRoom({ number: ROOM_MAIN, password: PASSWORD, name: '端到端验证房间' })
    assert.equal(server.hasRoom(ROOM_MAIN), true)

    /* -------- A creates membership on the pre-created room (readme init) - */
    const aJoin = await runtimeA.joinRoom(rootA, {
      room: ROOM_MAIN,
      password: PASSWORD,
      address: server.origin,
      memberName: 'Alice',
    })
    assert.equal(aJoin.joined, true)
    assert.equal(aJoin.snapshotApplied, false)
    assert.equal(aJoin.initPublished, true)
    assert.equal(aJoin.rev, 1)
    assert.equal(server.listRooms()[0].rev, 1)

    /* -------- B joins with the password; receives the initial snapshot --- */
    const bJoin = await runtimeB.joinRoom(rootB, {
      room: ROOM_MAIN,
      password: PASSWORD,
      address: server.origin,
      memberName: 'Bob',
    })
    assert.equal(bJoin.snapshotApplied, true)
    // B applied A's readme snapshot (rev 1) and published its own member readme (rev 2).
    assert.equal(bJoin.rev, 2)
    assert.equal(bJoin.readmePublished, true)
    const bReadmeAfterJoin = await fs.readFile(path.join(sharedDir(rootB), 'readme', 'README.md'), 'utf8')
    assert.ok(bReadmeAfterJoin.includes(`${safeMemberFileName('Alice')}.md`), 'B 加入后项目 readme 应列出 A')
    assert.ok(bReadmeAfterJoin.includes(`${safeMemberFileName('Bob')}.md`), 'B 加入后项目 readme 应列出 B 自己')
    const bJoinVersions = (await runtimeB.backups(rootB)).versions
    assert.deepEqual(
      bJoinVersions.map((record) => record.reason),
      ['join', 'member-readme'],
      'B 加入应记录 join 快照与自己的成员 readme 两个版本',
    )

    // A refreshes presence and applies B's member-readme revision.
    await runtimeA.tick()
    assert.equal((await runtimeA.status(rootA)).rev, 2)
    assert.equal((await runtimeA.status(rootA)).online, 2)
    const readmeAfterBJoin = await fs.readFile(path.join(sharedDir(rootA), 'readme', 'README.md'), 'utf8')
    assert.ok(readmeAfterBJoin.includes('Alice.md') && readmeAfterBJoin.includes('Bob.md'))

    /* -------- A uploads text + UTF-8 + binary own/ content --------------- */
    const firstMainJs = 'export const version = 1\n// 第一版共享内容：文本文件同步验证\n'
    const firstBinary = Buffer.from(Array.from({ length: 2048 }, (_unused, index) => (index * 131) % 256))
    const firstDoc = '第一版说明：中文文本也需要原样同步。\n'
    await fs.mkdir(path.join(ownDir(rootA), 'src'), { recursive: true })
    await fs.mkdir(path.join(ownDir(rootA), 'assets'), { recursive: true })
    await fs.mkdir(path.join(ownDir(rootA), 'docs'), { recursive: true })
    await fs.writeFile(path.join(ownDir(rootA), 'src', 'main.js'), firstMainJs)
    await fs.writeFile(path.join(ownDir(rootA), 'assets', 'logo.bin'), firstBinary)
    await fs.writeFile(path.join(ownDir(rootA), 'docs', '说明.txt'), firstDoc)

    const uploadFirst = await runtimeA.upload(rootA, 'first upload')
    assert.equal(uploadFirst.ok, true)
    // rev 1 = initial readme, rev 2 = B's member readme, rev 3 = A's first upload.
    assert.equal(uploadFirst.rev, 3)
    assert.ok(uploadFirst.changes.added.includes('src/main.js'))
    assert.ok(uploadFirst.changes.added.includes('assets/logo.bin'))
    assert.ok(uploadFirst.changes.added.includes('docs/说明.txt'))
    const localUploadNotice = recordsFor(recorderA.records, rootA).find((record) => record.text.includes('本机上传'))
    assert.ok(localUploadNotice !== undefined)
    assert.equal(localUploadNotice.wake, false)

    /* -------- B polls (tick) and applies the snapshot -------------------- */
    await runtimeB.tick()
    assert.equal((await runtimeB.status(rootB)).rev, 3)
    await assertTreesEqual(sharedDir(rootB), sharedDir(rootA), 'B tick 后应与 A 的 shared 完全一致')
    const bTreeAfterSync = await readTree(sharedDir(rootB))
    assert.deepEqual(bTreeAfterSync.get('src/main.js'), Buffer.from(firstMainJs, 'utf8'), '文本文件必须逐字节一致')
    assert.deepEqual(bTreeAfterSync.get('assets/logo.bin'), firstBinary, '二进制文件必须逐字节一致')
    assert.deepEqual(bTreeAfterSync.get('docs/说明.txt'), Buffer.from(firstDoc, 'utf8'), 'UTF-8 文件必须逐字节一致')

    const bSyncNotices = recordsFor(recorderB.records, rootB).filter((record) => record.text.includes('共享文件夹已更新'))
    assert.ok(bSyncNotices.length >= 1, 'B 应通过 notify hook 收到共享文件夹更新通知')
    assertNoticeTokens(bSyncNotices[bSyncNotices.length - 1], 'B tick 同步通知')
    assert.equal(bSyncNotices[bSyncNotices.length - 1].wake, true)

    const readmeAfterSync = await fs.readFile(path.join(sharedDir(rootB), 'readme', 'README.md'), 'utf8')
    assert.ok(readmeAfterSync.startsWith('# 群组协作项目'))
    assert.ok(readmeAfterSync.includes(ROOM_MAIN), '项目 readme 应包含房间号')
    assert.ok(readmeAfterSync.includes(`${safeMemberFileName('Alice')}.md`), '项目 readme 应列出 A 的成员 readme')
    assert.ok(readmeAfterSync.includes('readme'))

    const bVersionsAfterSync = (await runtimeB.backups(rootB)).versions
    assert.ok(bVersionsAfterSync.length >= 3, 'B backup/ 应有多个版本（join + member-readme + sync）')
    for (let index = 1; index < bVersionsAfterSync.length; index += 1) {
      assert.ok(bVersionsAfterSync[index].version > bVersionsAfterSync[index - 1].version, '备份版本号必须递增')
    }
    for (const record of bVersionsAfterSync) {
      assert.equal(await pathExists(path.join(backupDir(rootB), record.dir)), true, `备份目录缺失: ${record.dir}`)
    }

    /* -------- conflict: stale B upload must sync BEFORE failing ---------- */
    const secondMainJs = 'export const version = 2\n// 第二版共享内容：冲突前由 A 更新\n'
    const secondDoc = '第二版说明：用于验证上传冲突。\n'
    await fs.writeFile(path.join(ownDir(rootA), 'src', 'main.js'), secondMainJs)
    await fs.writeFile(path.join(ownDir(rootA), 'docs', '说明.txt'), secondDoc)
    await fs.writeFile(path.join(ownDir(rootA), 'src', 'extra.js'), 'export const extra = true\n')
    const uploadSecond = await runtimeA.upload(rootA, 'second upload')
    assert.equal(uploadSecond.rev, 4)

    await fs.writeFile(path.join(ownDir(rootB), 'b-notes.md'), 'Bob 的本地内容\n')
    let conflictError
    try {
      await runtimeB.upload(rootB, 'stale upload')
      assert.fail('B 使用过期 rev 上传时必须抛出 CONFLICT')
    } catch (error) {
      conflictError = error
    }
    assert.ok(conflictError instanceof CollabError, `expected CollabError, got: ${conflictError}`)
    assert.equal(conflictError.code, 'CONFLICT')

    // The key assertion: B auto-synced A's latest BEFORE the CONFLICT error.
    await assertTreesEqual(sharedDir(rootB), sharedDir(rootA), '冲突后 B 必须已自动同步 A 的最新内容')
    const bTreeAfterConflict = await readTree(sharedDir(rootB))
    assert.deepEqual(bTreeAfterConflict.get('src/main.js'), Buffer.from(secondMainJs, 'utf8'))
    assert.ok(bTreeAfterConflict.has('src/extra.js'), '冲突后应包含 A 第二次上传的新文件')
    assert.equal(bTreeAfterConflict.has('b-notes.md'), false, '冲突前写入的 own 文件不应残留在共享目录')
    assert.equal((await runtimeB.status(rootB)).rev, 4)
    const conflictNotice = recordsFor(recorderB.records, rootB).find((record) => record.text.includes('上传前同步'))
    assert.ok(conflictNotice !== undefined, '冲突自动同步也应产生通知')
    assert.equal(conflictNotice.wake, true)

    /* -------- retry after sync succeeds and publishes B's readme --------- */
    const uploadRetry = await runtimeB.upload(rootB, 'retry after sync')
    assert.equal(uploadRetry.ok, true)
    assert.equal(uploadRetry.rev, 5)
    const bTreeAfterRetry = await readTree(sharedDir(rootB))
    assert.ok(bTreeAfterRetry.has('b-notes.md'))
    assert.ok(bTreeAfterRetry.has('readme/members/Alice.md'), 'B 上传后 shared 应保留 A 的成员 readme')
    assert.ok(bTreeAfterRetry.has('readme/members/Bob.md'), 'B 上传后应有自己的成员 readme')
    const readmeAfterRetry = bTreeAfterRetry.get('readme/README.md').toString('utf8')
    assert.ok(readmeAfterRetry.includes('Alice.md'))
    assert.ok(readmeAfterRetry.includes('Bob.md'))

    await runtimeA.tick()
    assert.equal((await runtimeA.status(rootA)).rev, 5)
    await assertTreesEqual(sharedDir(rootA), sharedDir(rootB), 'A 同步 B 的上传后应完全一致')
    const readmeA = await fs.readFile(path.join(sharedDir(rootA), 'readme', 'README.md'), 'utf8')
    assert.ok(readmeA.includes('Alice.md') && readmeA.includes('Bob.md'), 'A 的项目 readme 应列出两个成员的 readme')
    const aSyncNotices = recordsFor(recorderA.records, rootA).filter((record) => record.text.includes('共享文件夹已更新'))
    assert.ok(aSyncNotices.length >= 1)
    assert.ok(
      aSyncNotices.some((record) => record.text.includes('房间') && record.text.includes('变更')),
      'A 的同步通知应包含房间与变更信息',
    )

    /* -------- late member C: stale local content + join + own readme ----- */
    await fs.mkdir(sharedDir(rootC), { recursive: true })
    await fs.writeFile(path.join(sharedDir(rootC), 'old-stale.txt'), 'C 工作区在加入前遗留的旧内容\n')
    const cJoin = await runtimeC.joinRoom(rootC, {
      room: ROOM_MAIN,
      password: PASSWORD,
      address: server.origin,
      memberName: 'Carol',
    })
    assert.equal(cJoin.snapshotApplied, true)
    assert.equal(cJoin.readmePublished, true)
    assert.equal(cJoin.rev, 6)
    const cTreeAfterJoin = await readTree(sharedDir(rootC))
    assert.equal(cTreeAfterJoin.has('old-stale.txt'), false, '晚加入成员应被最新快照覆盖')
    assert.ok(cTreeAfterJoin.has('b-notes.md'), 'C 加入时应收到房间最新快照的内容')
    assert.ok(cTreeAfterJoin.has('readme/members/Alice.md'))
    assert.ok(cTreeAfterJoin.has('readme/members/Bob.md'))
    assert.ok(cTreeAfterJoin.has('readme/members/Carol.md'), 'C 加入后应已有自己的成员 readme')
    const cReadmeAfterJoin = cTreeAfterJoin.get('readme/README.md').toString('utf8')
    assert.ok(
      cReadmeAfterJoin.includes('Alice.md') && cReadmeAfterJoin.includes('Bob.md') && cReadmeAfterJoin.includes('Carol.md'),
      'C 加入后项目 readme 应列出全部三个成员的 readme',
    )
    const cVersionsAfterJoin = (await runtimeC.backups(rootC)).versions
    assert.deepEqual(
      cVersionsAfterJoin.map((record) => record.reason),
      ['join', 'member-readme'],
      'C 加入应记录 join 快照与自己的成员 readme 两个版本',
    )
    assert.ok(
      cVersionsAfterJoin[0].changes.deleted.includes('old-stale.txt'),
      'C 加入时的备份版本应记录被覆盖的旧文件',
    )
    const cJoinNotices = recordsFor(recorderC.records, rootC)
    assert.ok(cJoinNotices.length >= 1, 'C 加入并应用快照时应收到通知')
    assertNoticeTokens(cJoinNotices[0], 'C 加入同步通知')
    assert.equal(cJoinNotices[0].wake, true)

    await fs.writeFile(path.join(ownDir(rootC), 'c-notes.md'), 'Carol 的共享笔记\n')
    const uploadC = await runtimeC.upload(rootC, 'carol upload')
    assert.equal(uploadC.rev, 7)
    const cTreeAfterUpload = await readTree(sharedDir(rootC))
    assert.ok(cTreeAfterUpload.has('readme/members/Carol.md'), 'C 上传后应有自己的成员 readme')
    assert.ok(
      cTreeAfterUpload.get('readme/members/Carol.md').toString('utf8').includes('c-notes.md'),
      'C 的成员 readme 应包含自己的 own/ 文件清单',
    )
    const cReadme = cTreeAfterUpload.get('readme/README.md').toString('utf8')
    assert.ok(cReadme.includes('Alice.md') && cReadme.includes('Bob.md') && cReadme.includes('Carol.md'))

    /* -------- manual sync() + final replication checks ------------------- */
    const bSync = await runtimeB.sync(rootB)
    assert.equal(bSync.updated, true)
    assert.equal(bSync.rev, 7)
    assert.ok(Array.isArray(bSync.changes.deleted) && bSync.changes.deleted.includes('b-notes.md'))
    await assertTreesEqual(sharedDir(rootB), sharedDir(rootC), 'B 手动 sync 后应与 C 的最新内容一致')
    assert.ok(
      recordsFor(recorderB.records, rootB).some((record) => record.text.includes('手动同步')),
      'B 手动同步应产生通知（手动同步）',
    )

    await runtimeA.tick()
    assert.equal((await runtimeA.status(rootA)).rev, 7)
    await assertTreesEqual(sharedDir(rootA), sharedDir(rootC), 'A tick 后应与最新共享内容一致')

    /* -------- backup restore with implicit pre-restore version ----------- */
    const versionsBeforeRestore = (await runtimeB.backups(rootB)).versions
    for (let index = 1; index < versionsBeforeRestore.length; index += 1) {
      assert.ok(versionsBeforeRestore[index].version > versionsBeforeRestore[index - 1].version, '备份版本号必须递增')
    }
    const restoreTarget = versionsBeforeRestore.find((record) => record.reason === 'sync' && record.rev === 3)
    assert.ok(restoreTarget !== undefined, '应存在 A 第一次上传对应的 sync 备份版本')

    const beforeRestoreTree = await readTree(sharedDir(rootB))
    const backupIndexBefore = JSON.parse(await fs.readFile(path.join(backupDir(rootB), 'index.json'), 'utf8'))
    assert.equal(backupIndexBefore.versions.length, versionsBeforeRestore.length)
    assert.equal(backupIndexBefore.version, 1)

    const restoreResult = await runtimeB.restore(rootB, restoreTarget.version)
    assert.equal(restoreResult.ok, true)
    assert.equal(restoreResult.restored.version, restoreTarget.version)
    assert.equal(restoreResult.savedCurrent.reason, 'pre-restore')
    assert.equal(restoreResult.savedCurrent.fileCount, beforeRestoreTree.size, 'pre-restore 版本应保存恢复前的 shared 内容')

    await assertTreesEqual(
      sharedDir(rootB),
      path.join(backupDir(rootB), restoreTarget.dir),
      '恢复后 B 的 shared 应等于目标备份版本目录',
    )
    const restoredTree = await readTree(sharedDir(rootB))
    assert.deepEqual(restoredTree.get('src/main.js'), Buffer.from(firstMainJs, 'utf8'))
    assert.equal(restoredTree.has('b-notes.md'), false)
    assert.equal(restoredTree.has('c-notes.md'), false)
    const restoredReadme = restoredTree.get('readme/README.md').toString('utf8')
    assert.ok(restoredReadme.includes('Alice.md') && restoredReadme.includes('Bob.md'), '恢复版本的 readme 应保留当时两个成员的 readme')

    const versionsAfterRestore = (await runtimeB.backups(rootB)).versions
    assert.equal(versionsAfterRestore.length, versionsBeforeRestore.length + 1)
    assert.equal(versionsAfterRestore[versionsAfterRestore.length - 1].reason, 'pre-restore')
    const backupIndexAfter = JSON.parse(await fs.readFile(path.join(backupDir(rootB), 'index.json'), 'utf8'))
    assert.equal(backupIndexAfter.versions.length, versionsAfterRestore.length)
    for (let index = 1; index < backupIndexAfter.versions.length; index += 1) {
      assert.ok(backupIndexAfter.versions[index].version > backupIndexAfter.versions[index - 1].version, 'index.json 版本号必须递增')
    }
    assert.ok(
      versionsAfterRestore[versionsAfterRestore.length - 1].version > versionsBeforeRestore[versionsBeforeRestore.length - 1].version,
      '恢复后 backup/index.json 应追加更大的版本号',
    )
    for (const record of backupIndexAfter.versions) {
      assert.equal(await pathExists(path.join(backupDir(rootB), record.dir)), true, `备份目录缺失: ${record.dir}`)
    }
    assert.ok(
      recordsFor(recorderB.records, rootB).some((record) => record.text.includes('已恢复备份版本')),
      '恢复备份应产生通知',
    )
  } finally {
    for (const runtime of [runtimeC, runtimeB, runtimeA]) {
      try {
        await runtime.dispose()
      } catch {
        // Best-effort cleanup; the test assertion failure above is authoritative.
      }
    }
    try {
      await server.close()
    } catch {
      // Best-effort cleanup.
    }
    await cleanupDir(base)
  }

  // Reached only when every assertion above passed: the server must be closed.
  assert.equal(server.origin, undefined, '测试结束后 RoomServer 必须已关闭')
  assert.equal(runtimeA.disposed, true)
  assert.equal(runtimeB.disposed, true)
  assert.equal(runtimeC.disposed, true)
})

/* ------------------------------------------------------------------ */
/* Test 2: runtime-owned room server (createRoom) + UDP discovery      */
/* ------------------------------------------------------------------ */

test('e2e：CollabRuntime.createRoom 自建房间服务 + UDP 发现 + 真实同步 + 错误密码/不存在房间', async () => {
  const base = await makeBaseDir()
  const rootA = path.join(base, 'workspace-a')
  const rootB = path.join(base, 'workspace-b')
  const rootC = path.join(base, 'workspace-c')
  const recorderA = makeNotifyRecorder()
  const recorderB = makeNotifyRecorder()
  const tcpPort = await reserveTcpPort()
  const udpPort = await reserveUdpPort()
  // Spare ports for runtimeC's local discovery miss (it may start its own server).
  const localTcpPort = await reserveTcpPort()
  const localUdpPort = await reserveUdpPort()
  const runtimeA = new CollabRuntime({
    config: {
      dataDir: path.join(base, 'runtime-a'),
      tcpPort,
      udpPort,
      enableDiscovery: true,
      pollMs: 1_000_000,
      autoExplain: false,
    },
    logger: silentLogger,
    notify: recorderA.notify,
  })
  const runtimeB = new CollabRuntime({
    config: { dataDir: path.join(base, 'runtime-b'), pollMs: 1_000_000, enableDiscovery: false },
    logger: silentLogger,
    notify: recorderB.notify,
  })
  const runtimeC = new CollabRuntime({
    config: {
      dataDir: path.join(base, 'runtime-c'),
      tcpPort: localTcpPort,
      udpPort: localUdpPort,
      pollMs: 1_000_000,
      enableDiscovery: false,
    },
    logger: silentLogger,
    notify: () => false,
  })
  let server

  try {
    const created = await runtimeA.createRoom(rootA, {
      room: ROOM_CREATED,
      password: PASSWORD,
      roomName: '运行时创建房间',
      memberName: 'Alice',
    })
    server = runtimeA.server
    assert.ok(server instanceof RoomServer, 'createRoom 必须启动真实的 RoomServer')
    assert.equal(created.origin, server.origin)
    assert.equal(new URL(created.origin).port, String(tcpPort), '运行时房间服务应绑定预留给它的端口')
    assert.equal(created.roomServer, server.origin)
    assert.equal(created.initPublished, true)
    assert.equal(created.rev, 1)
    assert.equal(server.hasRoom(ROOM_CREATED), true)
    assert.equal(server.listRooms()[0].name, '运行时创建房间')
    assert.equal(server.listRooms()[0].rev, 1)

    // UDP discovery must find the room on loopback and return the real origin.
    let discovered
    for (let attempt = 0; attempt < 2 && discovered === undefined; attempt += 1) {
      discovered = await discoverRoom({
        room: ROOM_CREATED,
        udpPort,
        timeoutMs: 2500,
        broadcastAddresses: ['127.0.0.1'],
      })
    }
    assert.ok(discovered !== undefined, 'UDP 发现应能找到本机创建的房间')
    assert.equal(discovered.origin, created.origin)
    assert.equal(discovered.room, ROOM_CREATED)
    assert.equal(discovered.via, 'discovery')
    // v2 discovery is deliberately name-free: only {origin, room, via} is returned.
    assert.deepEqual(Object.keys(discovered).sort(), ['origin', 'room', 'via'])
    assert.equal('name' in discovered, false, '协议 v2 的 UDP 发现不得返回房间名')

    // Wrong password and missing room both surface typed CollabErrors.
    await expectRejectsCollab(
      runtimeC.joinRoom(rootC, {
        room: ROOM_CREATED,
        password: WRONG_PASSWORD,
        address: created.origin,
        memberName: 'Mallory',
      }),
      'UNAUTHORIZED',
    )
    await expectRejectsCollab(
      runtimeC.joinRoom(rootC, {
        room: '999998',
        password: PASSWORD,
        address: created.origin,
        memberName: 'Mallory',
      }),
      'UNAUTHORIZED',
    )
    // No address and nothing discoverable on this host: local NOT_FOUND (a client
    // cannot distinguish a missing room from a wrong password over the wire, but a
    // purely local discovery miss is still reported as NOT_FOUND).
    await expectRejectsCollab(
      runtimeC.joinRoom(rootC, {
        room: '999997',
        password: PASSWORD,
        memberName: 'Mallory',
      }),
      'NOT_FOUND',
    )

    // A second member joins using the origin returned by UDP discovery.
    const bJoin = await runtimeB.joinRoom(rootB, {
      room: ROOM_CREATED,
      password: PASSWORD,
      address: discovered.origin,
      memberName: 'Bob',
    })
    assert.equal(bJoin.snapshotApplied, true)
    assert.equal(bJoin.rev, 2)
    assert.equal(bJoin.readmePublished, true)
    await runtimeA.tick()
    assert.equal((await runtimeA.status(rootA)).rev, 2)
    await assertTreesEqual(sharedDir(rootB), sharedDir(rootA), 'B 通过发现地址加入后应与 A 一致')

    // Upload through the runtime-created room and replicate via tick().
    const payload = '由 createRoom 创建的房间内同步的文本内容\n'
    await fs.writeFile(path.join(ownDir(rootA), 'runtime-created.txt'), payload)
    const upload = await runtimeA.upload(rootA, 'create room sync')
    assert.equal(upload.rev, 3)
    await runtimeB.tick()
    assert.equal((await runtimeB.status(rootB)).rev, 3)
    await assertTreesEqual(sharedDir(rootB), sharedDir(rootA), 'B tick 后应与 A 一致')
    assert.deepEqual(
      (await readTree(sharedDir(rootB))).get('runtime-created.txt'),
      Buffer.from(payload, 'utf8'),
    )
    const runtimeNotices = recordsFor(recorderB.records, rootB).filter((record) => record.text.includes('共享文件夹已更新'))
    assert.ok(runtimeNotices.length >= 1)
    assertNoticeTokens(runtimeNotices[runtimeNotices.length - 1], '运行时房间同步通知')
    const readme = await fs.readFile(path.join(sharedDir(rootB), 'readme', 'README.md'), 'utf8')
    assert.ok(readme.includes(`${safeMemberFileName('Alice')}.md`))
  } finally {
    for (const runtime of [runtimeC, runtimeB, runtimeA]) {
      try {
        await runtime.dispose()
      } catch {
        // Best-effort cleanup; the assertion failure above is authoritative.
      }
    }
    await cleanupDir(base)
  }

  // Reached only when the test passed: dispose() must have closed the server.
  assert.ok(server !== undefined)
  assert.equal(server.origin, undefined, 'runtime.dispose() 必须关闭自建的房间服务')
  assert.equal(runtimeA.server, null)
})
