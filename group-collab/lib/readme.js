/**
 * Chinese markdown readmes for the DSH Group Collaboration plugin.
 *
 * Generated files:
 *   shared/readme/README.md                 project-wide readme
 *   shared/readme/members/<name>.md         one readme per member
 *
 * Output is deterministic: every list is sorted, no timestamps are generated
 * locally (callers pass `lastUpdate` / `lastUploadAt`), so re-generating with
 * the same inputs produces byte-identical files (covered by tests).
 *
 * Member readmes are normal files inside shared/, so they survive syncs; the
 * project readme lists every `shared/readme/members/*.md` currently on disk.
 *
 * Plain ESM, Node builtins only.
 */
import { randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import { assertSafeRelativePath, CollabError, safeMemberFileName, sanitizeMemberName } from './protocol.js'
import { listFiles, ownDir, readmeDir, sharedDir } from './workspace.js'

const MEMBERS_SUBDIR = 'members'
const PROJECT_README = 'README.md'
const GENERATED_NOTICE = '> 本文件由 DSH 群组协作插件自动生成，请勿手动编辑。'

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

function normalizeRoot(root) {
  if (typeof root !== 'string' || root.trim().length === 0) {
    throw new CollabError('BAD_REQUEST', '工作目录路径不合法')
  }
  return path.resolve(root)
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

async function writeFileAtomic(targetPath, text) {
  const directory = path.dirname(targetPath)
  await fs.mkdir(directory, { recursive: true })
  const tempPath = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid.toString(36)}.${randomBytes(6).toString('hex')}.tmp`,
  )
  try {
    await fs.writeFile(tempPath, text, 'utf8')
    await fs.rename(tempPath, targetPath)
  } catch (error) {
    await fs.rm(tempPath, { force: true }).catch(() => {})
    throw error
  }
}

/** Human size, deterministic (B / KB / MB with one decimal for KB+). */
function formatBytes(size) {
  if (!Number.isInteger(size) || size < 0) return ''
  if (size < 1024) return `${size} B`
  const units = ['KB', 'MB', 'GB']
  let value = size / 1024
  let unitIndex = 0
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`
}

function codeSpan(value) {
  const text = String(value)
  const runs = text.match(/`+/gu) ?? []
  const longest = runs.reduce((maximum, run) => Math.max(maximum, run.length), 0)
  const fence = '`'.repeat(longest + 1)
  const needsPad = text.startsWith('`') || text.endsWith('`')
  return needsPad ? `${fence} ${text} ${fence}` : `${fence}${text}${fence}`
}

function escapeMarkdownText(value) {
  return String(value).replace(/([\\[\]|])/gu, '\\$1')
}

function flattenLine(value) {
  return String(value).replace(/\s+/gu, ' ').trim()
}

function normalizeTimeValue(value) {
  if (typeof value === 'string') return value.trim()
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString()
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString()
  return ''
}

/** Normalize a manifest (listFiles / snapshot entries) into a sorted copy. */
function normalizeManifest(manifest) {
  if (manifest === null || manifest === undefined) return []
  if (!Array.isArray(manifest)) throw new CollabError('BAD_REQUEST', '文件清单必须是数组')
  const entries = []
  for (const entry of manifest) {
    if (entry === null || typeof entry !== 'object') continue
    const safePath = assertSafeRelativePath(entry.path)
    entries.push({
      path: safePath,
      size: Number.isInteger(entry.size) && entry.size >= 0 ? entry.size : null,
      sha256: typeof entry.sha256 === 'string' ? entry.sha256 : '',
    })
  }
  entries.sort((left, right) => compareStrings(left.path, right.path))
  return entries
}

/**
 * Build the shared/ tree text. The project readme itself is always included
 * (without a size) so the output is stable before/after it is written.
 */
function renderFileTree(manifest) {
  const entries = normalizeManifest(manifest)
  const root = { dirs: new Map(), files: new Map() }
  let hasProjectReadme = false
  for (const entry of entries) {
    if (entry.path === `readme/${PROJECT_README}`) {
      hasProjectReadme = true
      entry.size = null // never embed a self-referential size
    }
    const segments = entry.path.split('/')
    let node = root
    for (const segment of segments.slice(0, -1)) {
      if (!node.dirs.has(segment)) node.dirs.set(segment, { dirs: new Map(), files: new Map() })
      node = node.dirs.get(segment)
    }
    node.files.set(segments[segments.length - 1], entry)
  }
  if (!hasProjectReadme) {
    let node = root
    for (const segment of ['readme']) {
      if (!node.dirs.has(segment)) node.dirs.set(segment, { dirs: new Map(), files: new Map() })
      node = node.dirs.get(segment)
    }
    node.files.set(PROJECT_README, { path: `readme/${PROJECT_README}`, size: null, sha256: '' })
  }

  const lines = ['shared/']
  function visit(node, prefix) {
    const dirNames = [...node.dirs.keys()].sort(compareStrings)
    const fileNames = [...node.files.keys()].sort(compareStrings)
    const items = [
      ...dirNames.map((name) => ({ name, directory: true })),
      ...fileNames.map((name) => ({ name, directory: false })),
    ]
    items.forEach((item, index) => {
      const last = index === items.length - 1
      const branch = last ? '└── ' : '├── '
      if (item.directory) {
        lines.push(`${prefix}${branch}${item.name}/`)
        visit(node.dirs.get(item.name), `${prefix}${last ? '    ' : '│   '}`)
      } else {
        const file = node.files.get(item.name)
        const size = formatBytes(file.size)
        lines.push(`${prefix}${branch}${item.name}${size === '' ? '' : ` (${size})`}`)
      }
    })
  }
  if (root.dirs.size === 0 && root.files.size === 0) {
    lines.push('└── （暂无文件）')
  } else {
    visit(root, '')
  }
  return lines.join('\n')
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

/** Create shared/readme/members (idempotent) and return the readme directory. */
export async function ensureReadmeDir(root) {
  const directory = readmeDir(normalizeRoot(root))
  await fs.mkdir(path.join(directory, MEMBERS_SUBDIR), { recursive: true })
  return directory
}

/** List the member readme filenames currently present, sorted. */
async function listMemberReadmeFiles(rootAbs) {
  const directory = path.join(readmeDir(rootAbs), MEMBERS_SUBDIR)
  let entries
  try {
    entries = await fs.readdir(directory, { withFileTypes: true })
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }
  return entries
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.md'))
    .map((entry) => entry.name)
    .sort(compareStrings)
}

function normalizeMembers(members) {
  if (members === null || members === undefined) return []
  if (!Array.isArray(members)) throw new CollabError('BAD_REQUEST', '成员列表必须是数组')
  const result = []
  for (const member of members) {
    if (member === null || typeof member !== 'object') continue
    const name = sanitizeMemberName(typeof member.name === 'string' ? member.name : '', '成员')
    const id = typeof member.id === 'string' ? member.id : ''
    result.push({ id, name, online: member.online === true ? true : member.online === false ? false : null })
  }
  result.sort((left, right) => compareStrings(left.name, right.name) || compareStrings(left.id, right.id))
  return result
}

function normalizeLastUpdate(lastUpdate) {
  if (lastUpdate === null || lastUpdate === undefined || typeof lastUpdate !== 'object') {
    return { at: '', byName: '', byId: '', note: '', rev: null }
  }
  const by = lastUpdate.by
  const byName = typeof by === 'string' ? by : typeof by?.name === 'string' ? by.name : ''
  const byId = typeof by?.id === 'string' ? by.id : ''
  return {
    at: normalizeTimeValue(lastUpdate.at),
    byName: sanitizeMemberName(byName, ''),
    byId,
    note: flattenLine(typeof lastUpdate.note === 'string' ? lastUpdate.note : ''),
    rev: Number.isInteger(lastUpdate.rev) && lastUpdate.rev >= 0 ? lastUpdate.rev : null,
  }
}

/**
 * Accept `room` as a number/string (room number) or as a room record object
 * ({ number, name }) so callers can pass either representation.
 */
function normalizeRoom(room, roomName) {
  let number = ''
  let name = typeof roomName === 'string' ? roomName.trim() : ''
  if (room !== null && room !== undefined && typeof room === 'object') {
    const value = room.number ?? room.room
    if (value !== null && value !== undefined) number = String(value).trim()
    if (name.length === 0 && typeof room.name === 'string') name = room.name.trim()
  } else if (room !== null && room !== undefined) {
    number = String(room).trim()
  }
  return { number, name }
}

function projectTitle(room, roomName) {
  const number = room === null || room === undefined ? '' : String(room).trim()
  const name = typeof roomName === 'string' ? roomName.trim() : ''
  if (name.length > 0 && number.length > 0) return `群组协作项目：${name}（房间 ${number}）`
  if (name.length > 0) return `群组协作项目：${name}`
  if (number.length > 0) return `群组协作项目：房间 ${number}`
  return '群组协作项目'
}

/**
 * Generate `shared/readme/README.md` (Chinese, deterministic).
 *
 * @returns `{ path, content }`
 */
export async function generateProjectReadme(root, {
  room,
  roomName = '',
  members = [],
  sharedManifest = [],
  lastUpdate = null,
} = {}) {
  const rootAbs = normalizeRoot(root)
  await ensureReadmeDir(rootAbs)

  const roomContext = normalizeRoom(room, roomName)
  const update = normalizeLastUpdate(lastUpdate)
  const memberRows = normalizeMembers(members)
  const memberFiles = await listMemberReadmeFiles(rootAbs)
  const manifest = normalizeManifest(sharedManifest)

  const lines = []
  lines.push(`# ${projectTitle(roomContext.number, roomContext.name)}`)
  lines.push('')
  lines.push(GENERATED_NOTICE + '共享内容更新后会自动刷新。')
  lines.push('')
  lines.push('## 房间信息')
  lines.push('')
  lines.push(`- 房间号：${roomContext.number.length > 0 ? roomContext.number : '—'}`)
  lines.push(`- 房间名称：${roomContext.name.length > 0 ? roomContext.name : '—'}`)
  lines.push(`- 当前版本：${update.rev === null ? '—' : `rev ${update.rev}`}`)
  lines.push(`- 最近更新时间：${update.at.length > 0 ? update.at : '—'}`)
  lines.push(
    `- 最近更新成员：${update.byName.length > 0
      ? `${update.byName}${update.byId.length > 0 ? `（id: ${update.byId}）` : ''}`
      : '—'}`,
  )
  lines.push(`- 更新说明：${update.note.length > 0 ? update.note : '—'}`)
  lines.push('')
  lines.push('## 成员')
  lines.push('')
  if (memberRows.length === 0) {
    lines.push('（暂无成员信息）')
  } else {
    lines.push('| 成员 | 成员 ID | 状态 |')
    lines.push('| --- | --- | --- |')
    for (const member of memberRows) {
      const status = member.online === true ? '在线' : member.online === false ? '离线' : '—'
      const id = member.id.length > 0 ? codeSpan(member.id) : '—'
      lines.push(`| ${escapeMarkdownText(member.name)} | ${id} | ${status} |`)
    }
  }
  lines.push('')
  lines.push('## 成员说明文档')
  lines.push('')
  if (memberFiles.length === 0) {
    lines.push('（暂无成员说明文档）')
  } else {
    for (const fileName of memberFiles) {
      const label = fileName.slice(0, -3)
      lines.push(`- [${escapeMarkdownText(label)}](<${MEMBERS_SUBDIR}/${fileName}>)`)
    }
  }
  lines.push('')
  lines.push('## 共享文件树')
  lines.push('')
  lines.push('```text')
  lines.push(renderFileTree(manifest))
  lines.push('```')
  lines.push('')
  lines.push('## 常用命令')
  lines.push('')
  lines.push('- `/group status`：查看房间号、同步状态与成员列表')
  lines.push('- `/group upload [说明]`：把 own/ 的改动上传为新的共享版本')
  lines.push('- `/group sync`：拉取并应用最新的共享版本')
  lines.push('- `/group backup list`：查看历史备份版本')
  lines.push('- `/group backup restore <版本号>`：回滚到指定备份版本')
  lines.push('')
  lines.push('> 提示：own/ 是个人工作区，不会同步；shared/ 由群组同步维护。')
  lines.push('')

  const content = lines.join('\n')
  const targetPath = path.join(readmeDir(rootAbs), PROJECT_README)
  await writeFileAtomic(targetPath, content)
  return { path: targetPath, content }
}

/**
 * Generate `shared/readme/members/<safeMemberFileName(name)>.md`.
 *
 * @returns `{ path, content, fileName }`
 */
export async function generateMemberReadme(root, {
  member,
  room,
  note = '',
  ownManifest = [],
  sharedManifest = null,
  lastUploadAt = '',
} = {}) {
  const rootAbs = normalizeRoot(root)
  await ensureReadmeDir(rootAbs)

  const displayName = sanitizeMemberName(
    member !== null && member !== undefined && typeof member.name === 'string' ? member.name : '',
    '成员',
  )
  const memberId = typeof member?.id === 'string' ? member.id : ''
  const roomNumber = normalizeRoom(room, '').number
  const uploadAt = normalizeTimeValue(lastUploadAt)
  const noteText = flattenLine(typeof note === 'string' ? note : '')
  const ownFiles = normalizeManifest(ownManifest)
  const fileName = `${safeMemberFileName(displayName)}.md`

  const lines = []
  lines.push(`# 成员：${displayName}`)
  lines.push('')
  lines.push('- 角色：共享项目协作者')
  lines.push(`- 房间号：${roomNumber.length > 0 ? roomNumber : '—'}`)
  lines.push(`- 成员 ID：${memberId.length > 0 ? codeSpan(memberId) : '—'}`)
  lines.push(`- 最近上传时间：${uploadAt.length > 0 ? uploadAt : '暂无'}`)
  lines.push(`- 上传说明：${noteText.length > 0 ? noteText : '暂无'}`)
  lines.push(`- own/ 文件数：${ownFiles.length}`)
  if (Array.isArray(sharedManifest)) lines.push(`- 共享文件数：${sharedManifest.length}`)
  lines.push('')
  lines.push('## own/ 文件清单')
  lines.push('')
  if (ownFiles.length === 0) {
    lines.push('（own/ 暂无文件）')
  } else {
    for (const entry of ownFiles) {
      const size = formatBytes(entry.size)
      lines.push(`- ${codeSpan(entry.path)}${size === '' ? '' : `（${size}）`}`)
    }
  }
  lines.push('')
  lines.push(GENERATED_NOTICE)
  lines.push('')

  const content = lines.join('\n')
  const targetPath = path.join(readmeDir(rootAbs), MEMBERS_SUBDIR, fileName)
  await writeFileAtomic(targetPath, content)
  return { path: targetPath, content, fileName }
}

/**
 * Convenience used by the uploader (and by a joining member before its first
 * publish): regenerate the member readme first, then the project readme from
 * the refreshed shared manifest.
 *
 * Accepts `{ room, roomName, member, members, note, lastUpdate, lastUploadAt,
 * ownManifest?, sharedManifest? }`. Missing manifests are read from disk;
 * `sharedManifest` supplied by the caller is only a hint (the project readme is
 * always generated from the current shared/ tree after writing the member
 * readme, so newly created member docs are listed).
 *
 * @returns `{ member: {path, content, fileName}, project: {path, content} }`
 */
export async function refreshReadmes(root, context = {}) {
  const rootAbs = normalizeRoot(root)
  const {
    room,
    roomName = '',
    member,
    members = [],
    note = '',
    lastUpdate = null,
    lastUploadAt,
    ownManifest,
  } = context ?? {}
  await ensureReadmeDir(rootAbs)

  const ownFiles = Array.isArray(ownManifest) ? ownManifest : await listFiles(ownDir(rootAbs))
  const memberReadme = await generateMemberReadme(rootAbs, {
    member,
    room,
    note,
    ownManifest: ownFiles,
    sharedManifest: Array.isArray(context?.sharedManifest) ? context.sharedManifest : null,
    lastUploadAt: lastUploadAt ?? lastUpdate?.at ?? '',
  })
  const sharedManifest = await listFiles(sharedDir(rootAbs))
  const projectReadme = await generateProjectReadme(rootAbs, {
    room,
    roomName,
    members,
    sharedManifest,
    lastUpdate,
  })
  return { member: memberReadme, project: projectReadme }
}
