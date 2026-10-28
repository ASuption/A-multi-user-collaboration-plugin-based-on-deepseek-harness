/**
 * node:test suite for lib/readme.js.
 * Plain ESM, Node builtins only. Run with:
 *   node --test tests/readme.test.mjs
 */
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

import {
  ensureReadmeDir,
  generateMemberReadme,
  generateProjectReadme,
  refreshReadmes,
} from '../lib/readme.js'
import { ensureLayout, listFiles, ownDir, readmeDir, sharedDir, writeFiles } from '../lib/workspace.js'

async function makeWorkspace(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-group-readme-'))
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true })
  })
  await ensureLayout(root)
  return root
}

async function writeShared(root, files) {
  return writeFiles(sharedDir(root), files, { clean: true })
}

test('ensureReadmeDir creates shared/readme/members idempotently', async (t) => {
  const root = await makeWorkspace(t)
  const first = await ensureReadmeDir(root)
  const second = await ensureReadmeDir(root)
  assert.equal(first, readmeDir(root))
  assert.equal(second, first)
  const members = await fs.stat(path.join(first, 'members'))
  assert.equal(members.isDirectory(), true)
})

test('generateProjectReadme writes a deterministic Chinese readme with room/members/tree/docs', async (t) => {
  const root = await makeWorkspace(t)
  await writeShared(root, [
    { path: 'src/a.js', content: 'export const a = 1\n' },
    { path: '笔记/说明.md', content: '# 中文笔记\n' },
    { path: 'readme/members/Alice.md', content: '# Alice\n' },
    { path: 'readme/members/小明.md', content: '# 小明\n' },
  ])
  const sharedManifest = await listFiles(sharedDir(root))
  const lastUpdate = {
    by: { id: 'abcdef123456', name: 'Alice' },
    note: '新增 src/a.js',
    at: '2026-10-28T09:50:17.123Z',
    rev: 7,
  }
  const members = [
    { id: 'abcdef123456', name: 'Alice', online: true },
    { id: 'fedcba654321', name: '小明', online: false },
  ]

  const result = await generateProjectReadme(root, {
    room: '123456',
    roomName: '演示房间',
    members,
    sharedManifest,
    lastUpdate,
  })

  assert.equal(result.path, path.join(readmeDir(root), 'README.md'))
  const text = await fs.readFile(result.path, 'utf8')
  assert.equal(text, result.content)
  assert.ok(text.startsWith('# 群组协作项目：演示房间（房间 123456）\n'))
  assert.ok(text.includes('房间号：123456'))
  assert.ok(text.includes('房间名称：演示房间'))
  assert.ok(text.includes('rev 7'))
  assert.ok(text.includes('2026-10-28T09:50:17.123Z'))
  assert.ok(text.includes('Alice'))
  assert.ok(text.includes('小明'))
  assert.ok(text.includes('新增 src/a.js'))
  // The file tree renders nested names (not full paths).
  assert.ok(text.includes('├── readme/'))
  assert.ok(text.includes('├── src/'))
  assert.ok(text.includes('└── 笔记/'))
  assert.ok(text.includes('a.js'))
  assert.ok(text.includes('说明.md'))
  assert.ok(text.includes('README.md'))
  assert.ok(text.includes('members/Alice.md'))
  assert.ok(text.includes('members/小明.md'))
  assert.equal(text.includes(root), false, 'no absolute workspace path leaks into the readme')
  assert.ok(text.includes('```text'))

  // Deterministic: same inputs -> byte-identical output.
  const again = await generateProjectReadme(root, {
    room: '123456',
    roomName: '演示房间',
    members,
    sharedManifest: await listFiles(sharedDir(root)),
    lastUpdate,
  })
  assert.equal(again.content, result.content)

  // Member docs are listed from disk even when the provided manifest is stale.
  const stale = await generateProjectReadme(root, { room: '123456', members, sharedManifest: [] })
  assert.ok(stale.content.includes('members/Alice.md'))
  assert.ok(stale.content.includes('members/小明.md'))
})

test('generateMemberReadme includes own/ manifest, note, upload time and unicode filename', async (t) => {
  const root = await makeWorkspace(t)
  await writeFiles(ownDir(root), [
    { path: 'src/main.js', content: 'main' },
    { path: 'docs/说明.md', content: '说明' },
  ])
  const ownManifest = await listFiles(ownDir(root))
  const member = { id: 'abcdef123456', name: '小明' }
  const args = {
    member,
    room: '123456',
    note: '修复了登录问题\n\n请同步',
    ownManifest,
    sharedManifest: [{ path: 'src/a.js', size: 1, sha256: 'x' }],
    lastUploadAt: '2026-10-28T10:00:00.000Z',
  }

  const result = await generateMemberReadme(root, args)
  assert.equal(result.fileName, '小明.md')
  assert.equal(result.path, path.join(readmeDir(root), 'members', '小明.md'))
  const text = await fs.readFile(result.path, 'utf8')
  assert.equal(text, result.content)
  assert.ok(text.startsWith('# 成员：小明\n'))
  assert.ok(text.includes('abcdef123456'))
  assert.ok(text.includes('房间号：123456'))
  assert.ok(text.includes('2026-10-28T10:00:00.000Z'))
  assert.ok(text.includes('修复了登录问题 请同步'), 'note is flattened to one line')
  assert.ok(text.includes('src/main.js'))
  assert.ok(text.includes('docs/说明.md'))
  assert.ok(text.includes('own/ 文件数：2'))
  assert.ok(text.includes('共享文件数：1'))

  // Deterministic second generation.
  const again = await generateMemberReadme(root, args)
  assert.equal(again.content, text)

  // Unsafe characters are sanitized for the filename; unicode survives.
  const sanitized = await generateMemberReadme(root, {
    member: { id: 'x', name: 'a/b:c*d' },
    room: '123456',
    ownManifest: [],
  })
  assert.equal(sanitized.fileName, 'a-b-c-d.md')
  assert.equal(path.basename(sanitized.path), 'a-b-c-d.md')
  assert.ok(sanitized.content.includes('（own/ 暂无文件）'))
  assert.ok(sanitized.content.includes('上传说明：暂无'))
  assert.ok(sanitized.content.includes('最近上传时间：暂无'))
})

test('refreshReadmes writes the member readme first, then a project readme listing it', async (t) => {
  const root = await makeWorkspace(t)
  await writeFiles(ownDir(root), [{ path: 'src/own.js', content: 'own work' }])
  await writeShared(root, [{ path: 'src/shared.js', content: 'shared work' }])

  const args = {
    room: '123456',
    roomName: '演示项目',
    member: { id: 'abcdef123456', name: '小明' },
    members: [
      { id: 'abcdef123456', name: '小明', online: true },
      { id: 'fedcba654321', name: 'Alice', online: false },
    ],
    note: '首次上传',
    lastUpdate: {
      by: { id: 'abcdef123456', name: '小明' },
      note: '首次上传',
      at: '2026-10-28T10:00:00.000Z',
      rev: 1,
    },
  }
  const first = await refreshReadmes(root, args)
  const memberText = await fs.readFile(first.member.path, 'utf8')
  const projectText = await fs.readFile(first.project.path, 'utf8')

  assert.equal(first.member.path, path.join(readmeDir(root), 'members', '小明.md'))
  assert.equal(first.project.path, path.join(readmeDir(root), 'README.md'))
  assert.ok(memberText.includes('src/own.js'))
  assert.ok(projectText.includes('members/小明.md'))
  assert.ok(projectText.includes('shared.js'))
  assert.ok(projectText.includes('src/'))
  assert.ok(projectText.includes('Alice'))
  assert.equal(projectText.includes('src/own.js'), false, 'own/ is not part of the shared tree')

  // Regeneration with unchanged inputs is stable (the generated README is
  // included in the tree without a size, so it does not oscillate).
  const second = await refreshReadmes(root, args)
  assert.equal(second.member.content, first.member.content)
  assert.equal(second.project.content, first.project.content)
})

test('project readme regenerates when a member doc disappears', async (t) => {
  const root = await makeWorkspace(t)
  await generateMemberReadme(root, { member: { id: 'aaa111', name: 'Alice' }, room: '123456' })
  await generateMemberReadme(root, { member: { id: 'bbb222', name: '小明' }, room: '123456' })

  const first = await generateProjectReadme(root, { room: '123456', members: [] })
  assert.ok(first.content.includes('members/Alice.md'))
  assert.ok(first.content.includes('members/小明.md'))

  await fs.rm(path.join(readmeDir(root), 'members', '小明.md'))
  const second = await generateProjectReadme(root, { room: '123456', members: [] })
  assert.ok(second.content.includes('members/Alice.md'))
  assert.equal(second.content.includes('members/小明.md'), false)
})

test('generateProjectReadme handles a fresh workspace without members or docs', async (t) => {
  const root = await makeWorkspace(t)
  const result = await generateProjectReadme(root, {})
  assert.ok(result.content.startsWith('# 群组协作项目\n'))
  assert.ok(result.content.includes('（暂无成员信息）'))
  assert.ok(result.content.includes('（暂无成员说明文档）'))
  assert.ok(result.content.includes('shared/'))
  assert.ok(result.content.includes('readme/'))
  assert.ok(result.content.includes('README.md'))
  const stat = await fs.stat(path.join(readmeDir(root), 'README.md'))
  assert.equal(stat.isFile(), true)

  // A room record object is accepted in place of a bare room number.
  const fromRecord = await generateProjectReadme(root, { room: { number: '654321', name: '对象房间' } })
  assert.ok(fromRecord.content.startsWith('# 群组协作项目：对象房间（房间 654321）\n'))
})
