/**
 * Append-only backup history for the DSH Group Collaboration plugin.
 *
 * Layout:
 *   <root>/backup/index.json                     { version: 1, versions: [...], keepVersions: 50 }
 *   <root>/backup/v<NNNN>-<UTC stamp>-<reason>/   full mirror of shared/ at that version
 *
 * Version directories are immutable once written; the index is written
 * atomically (temp file + rename) and versions are ordered newest last.
 * `restoreVersion()` first records the current shared tree with reason
 * "pre-restore", then writes the requested version back over shared/ (clean).
 *
 * Plain ESM, Node builtins only.
 */
import { randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import { assertSafeRelativePath, CollabError, LIMITS } from './protocol.js'
import { backupDir, listFiles, readSnapshotFiles, sharedDir, writeFiles } from './workspace.js'

const INDEX_VERSION = 1
const INDEX_FILE = 'index.json'
const DEFAULT_KEEP_VERSIONS = 50
const VERSION_DIR_PATTERN = /^v(\d{4,})-(\d{8}T\d{9}Z)-(.+)$/u
const REASON_MAX_LENGTH = 120

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

function normalizeRoot(root) {
  if (typeof root !== 'string' || root.trim().length === 0) {
    throw new CollabError('BAD_REQUEST', '工作目录路径不合法')
  }
  return path.resolve(root)
}

function compareVersions(left, right) {
  return left.version - right.version
}

function utcStamp(isoString) {
  // 2026-10-28T09:50:17.123Z -> 20261028T095017123Z (filesystem safe everywhere)
  return isoString.replace(/[-:]/gu, '').replace(/\./gu, '')
}

function stampToIso(stamp) {
  const match = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(\d{3})Z$/u.exec(stamp)
  if (match === null) return null
  const iso = `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}.${match[7]}Z`
  return Number.isNaN(Date.parse(iso)) ? null : iso
}

function normalizeReason(reason) {
  const text = typeof reason === 'string' ? reason.trim() : ''
  const base = text.length > 0 ? text : 'change'
  return base.slice(0, REASON_MAX_LENGTH)
}

/** Filesystem-safe ASCII slug for the version directory name. */
function reasonSlug(reason) {
  const slug = reason
    .replace(/[^A-Za-z0-9._-]+/gu, '-')
    .replace(/-+/gu, '-')
    .replace(/^[-.]+|[-.]+$/gu, '')
    .slice(0, 32)
  return slug.length > 0 ? slug : 'change'
}

function normalizeNote(note) {
  if (typeof note !== 'string') return ''
  return note.trim().slice(0, LIMITS.maxNoteLength)
}

function normalizeMember(member) {
  if (member === null || member === undefined) return null
  // The runtime records the display name as a plain string; keep it as such so
  // `/group backup list` can render it directly. Structured {id,name} input is
  // preserved too, which is what the DESIGN record implies.
  if (typeof member === 'string') {
    const name = member.trim()
    return name.length > 0 ? name : null
  }
  if (typeof member !== 'object') return null
  const id = typeof member.id === 'string' ? member.id : ''
  const name = typeof member.name === 'string' ? member.name : ''
  if (id.length === 0 && name.length === 0) return null
  return { id, name }
}

function normalizeChanges(changes) {
  const result = { added: [], modified: [], deleted: [] }
  if (changes === null || changes === undefined) return result
  if (typeof changes !== 'object' || Array.isArray(changes)) {
    throw new CollabError('BAD_REQUEST', '变更摘要不合法')
  }
  for (const key of ['added', 'modified', 'deleted']) {
    const list = changes[key]
    if (list === undefined) continue
    if (!Array.isArray(list)) throw new CollabError('BAD_REQUEST', '变更摘要不合法')
    result[key] = list.map((value) => assertSafeRelativePath(value)).sort()
  }
  return result
}

function normalizeRev(rev) {
  return Number.isInteger(rev) && rev >= 0 ? rev : null
}

function isSafeVersionDirName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 200) return false
  if (name === '.' || name === '..') return false
  if (name.includes('/') || name.includes('\\') || name.includes('\u0000')) return false
  return path.basename(name) === name
}

async function pathExists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

async function writeFileAtomic(targetPath, bytes) {
  const directory = path.dirname(targetPath)
  await fs.mkdir(directory, { recursive: true })
  const tempPath = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid.toString(36)}.${randomBytes(6).toString('hex')}.tmp`,
  )
  try {
    await fs.writeFile(tempPath, bytes)
    await fs.rename(tempPath, targetPath)
  } catch (error) {
    await fs.rm(tempPath, { force: true }).catch(() => {})
    throw error
  }
}

/* ------------------------------------------------------------------ */
/* index                                                              */
/* ------------------------------------------------------------------ */

function normalizeRecord(record) {
  if (record === null || typeof record !== 'object') return null
  if (!Number.isSafeInteger(record.version) || record.version < 1) return null
  if (!isSafeVersionDirName(record.dir)) return null
  const at = typeof record.at === 'string' && !Number.isNaN(Date.parse(record.at))
    ? new Date(record.at).toISOString()
    : new Date(0).toISOString()
  return {
    version: record.version,
    dir: record.dir,
    at,
    reason: typeof record.reason === 'string' ? record.reason : 'change',
    member: normalizeMember(record.member),
    note: normalizeNote(record.note),
    rev: normalizeRev(record.rev),
    changes: normalizeChanges(record.changes),
    fileCount: Number.isInteger(record.fileCount) && record.fileCount >= 0 ? record.fileCount : 0,
    totalBytes: Number.isInteger(record.totalBytes) && record.totalBytes >= 0 ? record.totalBytes : 0,
  }
}

function emptyIndex() {
  return { version: INDEX_VERSION, versions: [], keepVersions: DEFAULT_KEEP_VERSIONS }
}

/** Rebuild the index from version directories (used when index.json is lost). */
async function scanIndex(backupRoot) {
  const index = emptyIndex()
  let names
  try {
    names = await fs.readdir(backupRoot)
  } catch (error) {
    if (error?.code === 'ENOENT') return index
    throw error
  }
  for (const name of names.sort()) {
    const match = VERSION_DIR_PATTERN.exec(name)
    if (match === null) continue
    const version = Number(match[1])
    if (!Number.isSafeInteger(version) || version < 1) continue
    const directory = path.join(backupRoot, name)
    const stat = await fs.lstat(directory).catch(() => null)
    if (stat === null || !stat.isDirectory()) continue
    const files = await listFiles(directory).catch(() => [])
    index.versions.push({
      version,
      dir: name,
      at: stampToIso(match[2]) ?? new Date(stat.mtimeMs).toISOString(),
      reason: match[3],
      member: null,
      note: '',
      rev: null,
      changes: { added: [], modified: [], deleted: [] },
      fileCount: files.length,
      totalBytes: files.reduce((sum, file) => sum + file.size, 0),
    })
  }
  index.versions.sort(compareVersions)
  return index
}

/** Read backup/index.json; corrupt indexes are quarantined and rebuilt. */
async function readIndex(backupRoot) {
  const indexPath = path.join(backupRoot, INDEX_FILE)
  let text
  try {
    text = await fs.readFile(indexPath, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return scanIndex(backupRoot)
    throw error
  }
  try {
    const parsed = JSON.parse(text)
    if (parsed === null || typeof parsed !== 'object' || !Array.isArray(parsed.versions)) {
      throw new Error('invalid index')
    }
    const versions = parsed.versions.map(normalizeRecord).filter((record) => record !== null)
    versions.sort(compareVersions)
    const keepVersions = Number.isInteger(parsed.keepVersions) && parsed.keepVersions >= 0
      ? parsed.keepVersions
      : DEFAULT_KEEP_VERSIONS
    return { version: INDEX_VERSION, versions, keepVersions }
  } catch {
    const corruptPath = `${indexPath}.corrupt`
    await fs.rm(corruptPath, { force: true }).catch(() => {})
    await fs.rename(indexPath, corruptPath).catch(() => {})
    return scanIndex(backupRoot)
  }
}

async function writeIndex(backupRoot, index) {
  const payload = { version: INDEX_VERSION, versions: index.versions, keepVersions: index.keepVersions }
  const text = `${JSON.stringify(payload, null, 2)}\n`
  await writeFileAtomic(path.join(backupRoot, INDEX_FILE), Buffer.from(text, 'utf8'))
}

/**
 * Drop the oldest records so at most `keepVersions` remain (newest last).
 * Mutates `index` and returns the removed records.
 */
function applyPrune(index, keepVersions) {
  const keep = Number.isInteger(keepVersions) && keepVersions >= 0 ? keepVersions : DEFAULT_KEEP_VERSIONS
  index.keepVersions = keep
  index.versions.sort(compareVersions)
  const removeCount = Math.max(0, index.versions.length - keep)
  const pruned = removeCount > 0 ? index.versions.splice(0, removeCount) : []
  return pruned
}

async function removeVersionDirs(backupRoot, records) {
  for (const record of records) {
    const name = typeof record?.dir === 'string' ? record.dir : ''
    if (!isSafeVersionDirName(name)) continue
    const target = path.resolve(backupRoot, name)
    const relative = path.relative(backupRoot, target)
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) continue
    await fs.rm(target, { recursive: true, force: true }).catch(() => {})
  }
}

function nextVersion(index) {
  let highest = 0
  for (const record of index.versions) if (record.version > highest) highest = record.version
  return highest + 1
}

async function uniqueDirName(backupRoot, baseName) {
  let candidate = baseName
  for (let attempt = 2; attempt < 1000; attempt += 1) {
    if (!(await pathExists(path.join(backupRoot, candidate)))) return candidate
    candidate = `${baseName}-${attempt}`
  }
  throw new CollabError('CONFLICT', '无法创建唯一的备份版本目录')
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Snapshot the current `shared/` tree into a new immutable backup version and
 * append it to `backup/index.json`, pruning versions beyond keepVersions.
 *
 * @returns the new version record
 *   `{ version, dir, at, reason, member, note, rev, changes, fileCount, totalBytes }`
 */
export async function recordVersion(root, { reason, member = null, note = '', rev = null, changes = null } = {}) {
  const rootAbs = normalizeRoot(root)
  const reasonText = normalizeReason(reason)
  const noteText = normalizeNote(note)
  const memberRef = normalizeMember(member)
  const changesRef = normalizeChanges(changes)
  const revValue = normalizeRev(rev)

  const entries = await readSnapshotFiles(sharedDir(rootAbs))
  const backupRoot = backupDir(rootAbs)
  await fs.mkdir(backupRoot, { recursive: true })
  const index = await readIndex(backupRoot)

  const version = nextVersion(index)
  const at = new Date().toISOString()
  const baseDirName = `v${String(version).padStart(4, '0')}-${utcStamp(at)}-${reasonSlug(reasonText)}`
  const dir = await uniqueDirName(backupRoot, baseDirName)

  let totalBytes = 0
  for (const entry of entries) totalBytes += entry.size
  await writeFiles(path.join(backupRoot, dir), entries, { clean: true })

  const record = {
    version,
    dir,
    at,
    reason: reasonText,
    member: memberRef,
    note: noteText,
    rev: revValue,
    changes: changesRef,
    fileCount: entries.length,
    totalBytes,
  }

  index.versions.push(record)
  index.versions.sort(compareVersions)
  const pruned = applyPrune(index, index.keepVersions)
  await writeIndex(backupRoot, index)
  await removeVersionDirs(backupRoot, pruned)
  return record
}

/**
 * Resolve the `version` argument of restoreVersion().
 * Accepts a version number, a numeric string, a version directory name, or a
 * version record as returned by recordVersion()/listVersions().
 */
function resolveRestoreTarget(version) {
  if (version === null || version === undefined) return null
  if (typeof version === 'object') {
    if (Number.isSafeInteger(version.version) && version.version >= 1) return version.version
    if (typeof version.dir === 'string' && isSafeVersionDirName(version.dir)) return version.dir
    return null
  }
  if (typeof version === 'number') {
    return Number.isSafeInteger(version) && version >= 1 ? version : null
  }
  if (typeof version === 'string') {
    const trimmed = version.trim()
    if (trimmed.length === 0) return null
    if (/^[0-9]+$/u.test(trimmed)) {
      const parsed = Number(trimmed)
      return Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : null
    }
    return isSafeVersionDirName(trimmed) ? trimmed : null
  }
  return null
}

/**
 * Keep DESIGN's `{ index: [...] }` access while also being a real array, which
 * is how the runtime consumes it (`.length`, `.map`, `.find`, spread, JSON
 * serialization). `index` is a non-enumerable self alias so JSON output stays a
 * plain array of records.
 */
function asVersionArray(versions) {
  Object.defineProperty(versions, 'index', {
    value: versions,
    enumerable: false,
    configurable: true,
    writable: false,
  })
  return versions
}

/**
 * List backup versions, newest last.
 * @returns an array of records (`[]` when no backup exists) that also exposes
 *   the DESIGN-compatible `{ index: [...] }` alias property.
 */
export async function listVersions(root) {
  const rootAbs = normalizeRoot(root)
  const index = await readIndex(backupDir(rootAbs))
  index.versions.sort(compareVersions)
  return asVersionArray(index.versions.map((record) => ({ ...record })))
}

/**
 * Restore one backup version over `shared/`.
 *
 * The current shared tree is recorded first with reason "pre-restore" (read
 * before recording, so pruning cannot lose the target version), then the
 * version directory is copied back with clean semantics.
 *
 * @returns `{ restored, savedCurrent, written }` version records / write summary
 */
export async function restoreVersion(root, version) {
  const rootAbs = normalizeRoot(root)
  const wanted = resolveRestoreTarget(version)
  const label = version !== null && typeof version === 'object'
    ? String(version.version ?? version.dir ?? '')
    : String(version)
  if (wanted === null) throw new CollabError('NOT_FOUND', `备份版本不存在: ${label}`)
  const backupRoot = backupDir(rootAbs)
  const index = await readIndex(backupRoot)
  const target = typeof wanted === 'number'
    ? index.versions.find((record) => record.version === wanted)
    : index.versions.find((record) => record.dir === wanted)
  if (target === undefined) throw new CollabError('NOT_FOUND', `备份版本不存在: ${label}`)
  if (!isSafeVersionDirName(target.dir)) throw new CollabError('NOT_FOUND', `备份版本目录不合法: ${target.dir}`)

  const targetDir = path.resolve(backupRoot, target.dir)
  const relative = path.relative(backupRoot, targetDir)
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new CollabError('BAD_PATH', `备份版本目录越界: ${target.dir}`)
  }
  const stat = await fs.stat(targetDir).catch(() => null)
  if (stat === null || !stat.isDirectory()) {
    throw new CollabError('NOT_FOUND', `备份版本目录缺失: ${target.dir}`)
  }

  // Read the version into memory BEFORE recording anything, so a prune caused
  // by the pre-restore record can never delete the content we are restoring.
  const entries = await readSnapshotFiles(targetDir)

  const savedCurrent = await recordVersion(rootAbs, {
    reason: 'pre-restore',
    member: null,
    note: `回滚到备份版本 v${String(target.version).padStart(4, '0')} 前自动保存`,
    rev: target.rev,
    changes: null,
  })

  const written = await writeFiles(sharedDir(rootAbs), entries, { clean: true })
  return {
    restored: {
      ...target,
      changes: {
        added: [...target.changes.added],
        modified: [...target.changes.modified],
        deleted: [...target.changes.deleted],
      },
      member: target.member !== null && typeof target.member === 'object'
        ? { ...target.member }
        : target.member,
    },
    savedCurrent,
    written,
  }
}

/**
 * Keep only the newest `keepVersions` backup versions (default 50) and delete
 * the older version directories.
 *
 * @returns `{ index, keepVersions, pruned }`
 */
export async function pruneVersions(root, keepVersions = DEFAULT_KEEP_VERSIONS) {
  const rootAbs = normalizeRoot(root)
  const backupRoot = backupDir(rootAbs)
  const index = await readIndex(backupRoot)
  const pruned = applyPrune(index, keepVersions)
  await writeIndex(backupRoot, index)
  await removeVersionDirs(backupRoot, pruned)
  return {
    index: index.versions.map((record) => ({ ...record })),
    keepVersions: index.keepVersions,
    pruned: pruned.map((record) => record.dir),
  }
}
