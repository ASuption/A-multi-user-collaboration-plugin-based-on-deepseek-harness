/**
 * Filesystem layer for the DSH Group Collaboration plugin.
 *
 * Workspace layout (all paths relative to a member workspace root):
 *   own/                   developer's private work, never synced
 *   shared/                authoritative shared project (overwritten by sync)
 *   shared/readme/         generated project readme + members/<name>.md
 *   backup/                append-only backup history (see lib/backup.js)
 *   .dsh-group/member.json member identity/config state
 *
 * Every path that is written to disk is normalized and validated through
 * protocol.assertSafeRelativePath(); symlinks are never followed, so a
 * listing/write can never escape the target root through a link.
 *
 * Plain ESM, Node builtins only.
 */
import { randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import {
  assertSafeRelativePath,
  CollabError,
  decodeFile,
  diffSnapshots,
  encodeFile,
  fileSha256,
  LIMITS,
} from './protocol.js'

/** Names of the workspace layout entries. */
export const LAYOUT = Object.freeze({
  stateDir: '.dsh-group',
  own: 'own',
  shared: 'shared',
  backup: 'backup',
  readme: 'readme',
})

/** Directories that are never treated as user content (any depth). */
const DEFAULT_EXCLUDED_DIRS = Object.freeze([LAYOUT.stateDir, '.git', 'node_modules'])

const STATE_FILE = 'member.json'

/* ------------------------------------------------------------------ */
/* paths                                                              */
/* ------------------------------------------------------------------ */

function normalizeRoot(root) {
  if (typeof root !== 'string' || root.trim().length === 0) {
    throw new CollabError('BAD_REQUEST', '工作目录路径不合法')
  }
  return path.resolve(root)
}

/** Absolute path of the private work directory. */
export function ownDir(root) {
  return path.join(normalizeRoot(root), LAYOUT.own)
}

/** Absolute path of the shared project directory. */
export function sharedDir(root) {
  return path.join(normalizeRoot(root), LAYOUT.shared)
}

/** Absolute path of the backup history directory. */
export function backupDir(root) {
  return path.join(normalizeRoot(root), LAYOUT.backup)
}

/** Absolute path of the shared readme directory (shared/readme). */
export function readmeDir(root) {
  return path.join(sharedDir(root), LAYOUT.readme)
}

/** Create the complete workspace layout (idempotent). */
export async function ensureLayout(root) {
  const rootAbs = normalizeRoot(root)
  const shared = path.join(rootAbs, LAYOUT.shared)
  const readme = path.join(shared, LAYOUT.readme)
  const directories = [
    rootAbs,
    path.join(rootAbs, LAYOUT.own),
    shared,
    readme,
    path.join(readme, 'members'),
    path.join(rootAbs, LAYOUT.backup),
    path.join(rootAbs, LAYOUT.stateDir),
  ]
  for (const directory of directories) await fs.mkdir(directory, { recursive: true })
}

/**
 * Resolve a validated relative path inside `rootAbs` and double-check that the
 * resolved target really is a descendant of the root.
 */
function resolveInside(rootAbs, relativePath) {
  const safePath = assertSafeRelativePath(relativePath)
  const target = path.resolve(rootAbs, ...safePath.split('/'))
  const relative = path.relative(rootAbs, target)
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new CollabError('BAD_PATH', `文件路径越界: ${relativePath}`)
  }
  return { path: safePath, target }
}

/**
 * Refuse to write through an existing symlinked directory component.
 * Returns `{ target, safePath }` after checking every existing parent dir.
 */
async function resolveWritableTarget(rootAbs, relativePath) {
  const { path: safePath, target } = resolveInside(rootAbs, relativePath)
  const segments = safePath.split('/')
  let current = rootAbs
  for (let index = 0; index < segments.length - 1; index += 1) {
    current = path.join(current, segments[index])
    let stat
    try {
      stat = await fs.lstat(current)
    } catch (error) {
      if (error?.code === 'ENOENT') break
      throw error
    }
    if (stat.isSymbolicLink()) {
      throw new CollabError('BAD_PATH', `文件路径包含符号链接: ${segments.slice(0, index + 1).join('/')}`)
    }
    if (!stat.isDirectory()) {
      throw new CollabError('BAD_PATH', `文件路径的父级不是目录: ${segments.slice(0, index + 1).join('/')}`)
    }
  }
  return { target, safePath }
}

/* ------------------------------------------------------------------ */
/* traversal                                                          */
/* ------------------------------------------------------------------ */

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function normalizePrefixes(values) {
  if (!Array.isArray(values)) return []
  const prefixes = []
  for (const value of values) {
    if (typeof value !== 'string') continue
    const cleaned = value
      .trim()
      .replace(/\\/gu, '/')
      .replace(/^\.\//u, '')
      .replace(/\/+$/u, '')
    if (cleaned.length > 0) prefixes.push(cleaned)
  }
  return prefixes
}

function matchesAnyPrefix(relativePath, prefixes) {
  if (prefixes.length === 0) return false
  const segments = relativePath.split('/')
  for (const prefix of prefixes) {
    if (relativePath === prefix || relativePath.startsWith(`${prefix}/`)) return true
    // A bare name also matches at any depth ("private" matches "a/private/x").
    if (!prefix.includes('/') && segments.includes(prefix)) return true
  }
  return false
}

/**
 * Walk `rootDir` and collect regular files as `{ path, absolute }`, sorted by
 * relative POSIX path. Symlinks and special files are skipped entirely; default
 * excludes (.git, node_modules, .dsh-group) and caller excludes are pruned.
 */
async function walkRegularFiles(rootDir, exclude) {
  const rootAbs = normalizeRoot(rootDir)
  const prefixes = normalizePrefixes(exclude)
  const excludedNames = new Set(DEFAULT_EXCLUDED_DIRS)
  const files = []

  let rootStat
  try {
    rootStat = await fs.lstat(rootAbs)
  } catch (error) {
    if (error?.code === 'ENOENT') return files
    throw error
  }
  if (rootStat.isSymbolicLink()) throw new CollabError('BAD_REQUEST', '根目录不能是符号链接')
  if (!rootStat.isDirectory()) throw new CollabError('BAD_REQUEST', `不是目录: ${rootAbs}`)

  async function visit(directoryAbs, relativeDir) {
    const entries = await fs.readdir(directoryAbs, { withFileTypes: true })
    entries.sort((left, right) => compareStrings(left.name, right.name))
    for (const entry of entries) {
      const relativePath = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`
      // Never follow a link, not even to another place inside the root: the
      // snapshot domain only contains real files.
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        if (excludedNames.has(entry.name)) continue
        if (matchesAnyPrefix(relativePath, prefixes)) continue
        await visit(path.join(directoryAbs, entry.name), relativePath)
        continue
      }
      if (!entry.isFile()) continue
      if (matchesAnyPrefix(relativePath, prefixes)) continue
      // Rejects system-reserved names / over-long paths early with a clear code.
      assertSafeRelativePath(relativePath)
      files.push({ path: relativePath, absolute: path.join(directoryAbs, entry.name) })
    }
  }

  await visit(rootAbs, '')
  files.sort((left, right) => compareStrings(left.path, right.path))
  return files
}

/* ------------------------------------------------------------------ */
/* reads                                                              */
/* ------------------------------------------------------------------ */

/** List files below `rootDir` as `[{ path, size, sha256 }]`, sorted by path. */
export async function listFiles(rootDir, { exclude = [] } = {}) {
  const files = await walkRegularFiles(rootDir, exclude)
  const manifest = []
  for (const file of files) {
    let bytes
    try {
      bytes = await fs.readFile(file.absolute)
    } catch (error) {
      if (error?.code === 'ENOENT') continue // removed while walking
      throw error
    }
    manifest.push({ path: file.path, size: bytes.byteLength, sha256: fileSha256(bytes) })
  }
  return manifest
}

/**
 * Read files below `rootDir` as snapshot file entries:
 * `{ path, size, sha256, data }` with base64 `data` (sorted by path).
 */
export async function readSnapshotFiles(rootDir, { exclude = [] } = {}) {
  const files = await walkRegularFiles(rootDir, exclude)
  const entries = []
  let totalBytes = 0
  for (const file of files) {
    const bytes = await fs.readFile(file.absolute).catch((error) => {
      if (error?.code === 'ENOENT') return null
      throw error
    })
    if (bytes === null) continue
    if (entries.length >= LIMITS.maxFiles) throw new CollabError('TOO_LARGE', '文件数量超过上限')
    totalBytes += bytes.byteLength
    if (totalBytes > LIMITS.maxTotalBytes) throw new CollabError('TOO_LARGE', '共享文件夹总大小超过上限')
    entries.push(encodeFile(file.path, bytes)) // validates path + per-file size
  }
  return entries
}

/* ------------------------------------------------------------------ */
/* writes                                                             */
/* ------------------------------------------------------------------ */

/** Atomic write: write a sibling temp file, then rename over the target. */
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

/**
 * Normalize one writeFiles entry into `{ path, bytes }`.
 * Accepts snapshot entries (base64 `data`, verified with protocol.decodeFile),
 * raw buffers (`bytes`/`data`/`content`) and UTF-8 strings (`content`).
 */
function prepareEntry(entry) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new CollabError('BAD_SNAPSHOT', '文件条目不合法')
  }
  const safePath = assertSafeRelativePath(entry.path)
  if (typeof entry.data === 'string') {
    const decoded = decodeFile(entry) // verifies base64, size and sha256
    return { path: decoded.path, bytes: decoded.bytes }
  }
  let bytes = null
  if (Buffer.isBuffer(entry.data)) bytes = entry.data
  else if (entry.data instanceof Uint8Array) bytes = Buffer.from(entry.data)
  else if (Buffer.isBuffer(entry.bytes)) bytes = entry.bytes
  else if (entry.bytes instanceof Uint8Array) bytes = Buffer.from(entry.bytes)
  else if (Buffer.isBuffer(entry.content)) bytes = entry.content
  else if (typeof entry.content === 'string') bytes = Buffer.from(entry.content, 'utf8')
  if (bytes === null) throw new CollabError('BAD_SNAPSHOT', `缺少文件内容: ${safePath}`)
  if (bytes.byteLength > LIMITS.maxFileBytes) throw new CollabError('TOO_LARGE', `文件过大: ${safePath}`)
  if (Number.isInteger(entry.size) && entry.size !== bytes.byteLength) {
    throw new CollabError('BAD_SNAPSHOT', `文件大小不匹配: ${safePath}`)
  }
  if (typeof entry.sha256 === 'string' && entry.sha256.toLowerCase() !== fileSha256(bytes)) {
    throw new CollabError('BAD_SNAPSHOT', `文件摘要不匹配: ${safePath}`)
  }
  return { path: safePath, bytes }
}

/** Top-level layout directories that a clean write must never delete. */
async function protectedTopNames(rootAbs) {
  const stateDir = path.join(rootAbs, LAYOUT.stateDir)
  const names = new Set([LAYOUT.stateDir])
  const [hasState, hasOwn, hasBackup] = await Promise.all([
    pathExists(stateDir),
    pathExists(path.join(rootAbs, LAYOUT.own)),
    pathExists(path.join(rootAbs, LAYOUT.backup)),
  ])
  // Only treat "own/backup" as protected when this really looks like a
  // workspace root (`.dsh-group` present, or both layout dirs exist).
  if (hasState || (hasOwn && hasBackup)) {
    names.add(LAYOUT.own)
    names.add(LAYOUT.backup)
  }
  return names
}

async function pathExists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

async function depthOf(relativePath) {
  return relativePath.split('/').length
}

/**
 * Delete existing regular files not present in `targetSet`, then prune the
 * directories left empty. `keepPrefixes` entries (e.g. "readme/") are never
 * deleted; symlinks and default-excluded dirs are left untouched.
 */
async function cleanTree(rootAbs, targetSet, keepPrefixes) {
  const protectedTop = await protectedTopNames(rootAbs)
  const deleted = []
  const directories = []

  async function visit(directoryAbs, relativeDir) {
    let entries
    try {
      entries = await fs.readdir(directoryAbs, { withFileTypes: true })
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    for (const entry of entries) {
      const relativePath = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`
      if (entry.isSymbolicLink()) continue
      if (relativeDir === '' && protectedTop.has(entry.name)) continue
      if (entry.isDirectory()) {
        if (DEFAULT_EXCLUDED_DIRS.includes(entry.name)) continue
        if (matchesAnyPrefix(relativePath, keepPrefixes)) continue
        directories.push({ relativePath, absolute: path.join(directoryAbs, entry.name) })
        await visit(path.join(directoryAbs, entry.name), relativePath)
        continue
      }
      if (!entry.isFile()) continue
      if (targetSet.has(relativePath)) continue
      if (matchesAnyPrefix(relativePath, keepPrefixes)) continue
      try {
        assertSafeRelativePath(relativePath)
      } catch {
        continue // never touch a path we cannot represent securely
      }
      await fs.unlink(path.join(directoryAbs, entry.name))
      deleted.push(relativePath)
    }
  }

  await visit(rootAbs, '')

  const depths = new Map()
  for (const directory of directories) depths.set(directory.relativePath, await depthOf(directory.relativePath))
  directories.sort((left, right) => {
    const delta = depths.get(right.relativePath) - depths.get(left.relativePath)
    return delta !== 0 ? delta : compareStrings(right.relativePath, left.relativePath)
  })
  for (const directory of directories) {
    if (protectedTop.has(directory.relativePath)) continue
    try {
      await fs.rmdir(directory.absolute)
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTEMPTY' && error?.code !== 'EEXIST') throw error
    }
  }

  deleted.sort(compareStrings)
  return deleted
}

/**
 * Write snapshot-like file entries below `rootDir`.
 *
 * `clean: true` removes existing regular files that are not written, except
 * paths under a `keep` prefix (e.g. shared upload keeps `readme/`). `own/`,
 * `backup/` and `.dsh-group/` are never deleted; `.git`/`node_modules` and
 * symlinks are left untouched. Every file write is atomic (temp file + rename).
 */
export async function writeFiles(rootDir, files, { clean = true, keep = [] } = {}) {
  const rootAbs = normalizeRoot(rootDir)
  if (!Array.isArray(files)) throw new CollabError('BAD_REQUEST', '文件列表必须是数组')
  if (files.length > LIMITS.maxFiles) throw new CollabError('TOO_LARGE', '文件数量超过上限')

  const keepPrefixes = normalizePrefixes(keep)
  const entries = files.map(prepareEntry)

  const targetSet = new Set()
  let totalBytes = 0
  for (const entry of entries) {
    if (targetSet.has(entry.path)) throw new CollabError('BAD_SNAPSHOT', `重复文件路径: ${entry.path}`)
    targetSet.add(entry.path)
    totalBytes += entry.bytes.byteLength
    if (totalBytes > LIMITS.maxTotalBytes) throw new CollabError('TOO_LARGE', '共享文件夹总大小超过上限')
  }

  await fs.mkdir(rootAbs, { recursive: true })
  const written = []
  for (const entry of entries) {
    const { target, safePath } = await resolveWritableTarget(rootAbs, entry.path)
    await writeFileAtomic(target, entry.bytes)
    written.push(safePath)
  }

  const deleted = clean ? await cleanTree(rootAbs, targetSet, keepPrefixes) : []
  return { written, deleted }
}

/**
 * Copy a directory tree (regular files only, symlinks skipped).
 * `clean` defaults to false so this is a pure merge unless asked otherwise.
 */
export async function copyTree(srcDir, dstDir, { clean = false, keep = [] } = {}) {
  const srcAbs = normalizeRoot(srcDir)
  const entries = await readSnapshotFiles(srcAbs)
  return writeFiles(dstDir, entries, { clean, keep })
}

/* ------------------------------------------------------------------ */
/* state                                                              */
/* ------------------------------------------------------------------ */

function stateFilePath(root) {
  return path.join(normalizeRoot(root), LAYOUT.stateDir, STATE_FILE)
}

/**
 * Read `.dsh-group/member.json`.
 *
 * Returns `null` when the file does not exist. A corrupt state file is
 * quarantined as `member.json.corrupt` and also yields `null`, so the runtime
 * can recreate its state instead of failing to start.
 */
export async function readState(root) {
  const filePath = stateFilePath(root)
  let text
  try {
    text = await fs.readFile(filePath, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return null
    throw error
  }
  try {
    const parsed = JSON.parse(text)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid state')
    return parsed
  } catch {
    const corruptPath = `${filePath}.corrupt`
    await fs.rm(corruptPath, { force: true }).catch(() => {})
    await fs.rename(filePath, corruptPath).catch(() => {})
    return null
  }
}

/** Atomically write `.dsh-group/member.json` and return the state object. */
export async function writeState(root, state) {
  if (state === null || typeof state !== 'object' || Array.isArray(state)) {
    throw new CollabError('BAD_REQUEST', '成员状态必须是对象')
  }
  const filePath = stateFilePath(root)
  const text = `${JSON.stringify(state, null, 2)}\n`
  await writeFileAtomic(filePath, Buffer.from(text, 'utf8'))
  return state
}

/* ------------------------------------------------------------------ */
/* diff helpers                                                       */
/* ------------------------------------------------------------------ */

function manifestInput(value) {
  if (value === null || value === undefined) return []
  return value
}

/**
 * Diff two manifests (arrays of `{ path, sha256 }` or path->sha256 Maps).
 * Returns sorted `{ added, modified, deleted }` path arrays.
 */
export function diffOfManifests(before, after) {
  return diffSnapshots(manifestInput(before), manifestInput(after))
}

/** Same as diffOfManifests(source → target), kept as a named alias. */
export function compareTrees(sourceManifest, targetManifest) {
  return diffOfManifests(sourceManifest, targetManifest)
}

/** Short human diff text: `+a/x.js ~b/y.js -c/z.js`, capped at `limit` items. */
export function formatDiff(diff, { limit = 12 } = {}) {
  const added = [...(diff?.added ?? [])].sort(compareStrings)
  const modified = [...(diff?.modified ?? [])].sort(compareStrings)
  const deleted = [...(diff?.deleted ?? [])].sort(compareStrings)
  const items = [
    ...added.map((value) => `+${value}`),
    ...modified.map((value) => `~${value}`),
    ...deleted.map((value) => `-${value}`),
  ]
  if (items.length === 0) return ''
  const max = Number.isInteger(limit) && limit >= 0 ? limit : 12
  if (max === 0) return `…（共 ${items.length} 项改动）`
  if (items.length <= max) return items.join(' ')
  return `${items.slice(0, max).join(' ')} …（其余 ${items.length - max} 项）`
}
