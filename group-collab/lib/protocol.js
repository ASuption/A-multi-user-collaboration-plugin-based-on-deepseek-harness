/**
 * Shared protocol vocabulary and validation for the DSH Group Collaboration plugin.
 * Host-only, plain ESM, Node builtins only.
 *
 * Protocol v2: passwords never cross the wire (challenge-response, see crypto.js),
 * shared content is end-to-end encrypted, and the server stores ciphertext only.
 * This module keeps the unauthenticated wire vocabulary (rooms, members, snapshot
 * limits) plus every path/size validation helper used on both sides.
 */
import { createHash, randomBytes } from 'node:crypto'

export const PROTOCOL_VERSION = 2
export const DEFAULT_TCP_PORT = 45890
export const DEFAULT_UDP_PORT = 45891

export const LIMITS = Object.freeze({
  maxFiles: 2000,
  maxTotalBytes: 32 * 1024 * 1024,
  maxFileBytes: 8 * 1024 * 1024,
  maxPathLength: 400,
  maxNoteLength: 2000,
  minPasswordLength: 8,
  maxPasswordLength: 128,
  maxMemberNameLength: 40,
})

/** Error taxonomy shared by every module; `code` is stable wire vocabulary. */
export class CollabError extends Error {
  constructor(code, message, details) {
    super(message)
    this.name = 'CollabError'
    this.code = code
    this.details = details
  }
}
/** Coerce any thrown value into a CollabError without losing the code. */
export function asCollabError(error, fallbackCode = 'BAD_REQUEST') {
  if (error instanceof CollabError) return error
  const message = error instanceof Error ? error.message : String(error)
  return new CollabError(fallbackCode, message)
}

/** Normalize a room number: 4-8 decimal digits, returned as a string. */
export function normalizeRoomNumber(value) {
  const text = typeof value === 'number' ? String(value) : typeof value === 'string' ? value.trim() : ''
  if (!/^[0-9]{4,8}$/u.test(text)) {
    throw new CollabError('BAD_ROOM', '房间号必须是 4-8 位数字')
  }
  return text
}

/** Validate a room password (length 8..128) and return it unchanged. */
export function validatePassword(value) {
  const minimum = LIMITS.minPasswordLength
  const maximum = LIMITS.maxPasswordLength
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum) {
    throw new CollabError('BAD_PASSWORD', `密码长度必须为 ${minimum}-${maximum} 个字符`)
  }
  if (/[\u0000-\u001f]/u.test(value)) throw new CollabError('BAD_PASSWORD', '密码不能包含控制字符')
  return value
}

/** Bearer token issued by a room server for one member session. */
export function createToken() {
  return randomBytes(32).toString('hex')
}

/** Stable member identity generated once per workspace. */
export function makeMemberId() {
  return randomBytes(12).toString('hex')
}

/** Trim and bound a human member name; no path separators or control characters. */
export function sanitizeMemberName(value, fallback = 'member') {
  const base = typeof value === 'string' ? value : ''
  const cleaned = base
    .replace(/[\u0000-\u001f\u007f]/gu, ' ')
    .replace(/[\\/]/gu, '-')
    .replace(/\s+/gu, ' ')
    .trim()
  if (cleaned.length === 0) return fallback
  return cleaned.length <= LIMITS.maxMemberNameLength
    ? cleaned
    : cleaned.slice(0, LIMITS.maxMemberNameLength).trim() || fallback
}

/** A member display name safe to use as a filename in shared/readme/members/. */
export function safeMemberFileName(name) {
  const cleaned = sanitizeMemberName(name)
    .replace(/[<>:"|?*]/gu, '-')
    .replace(/^\.+/u, '')
    .replace(/[. ]+$/u, '')
    .trim()
  return cleaned.length > 0 ? cleaned.slice(0, LIMITS.maxMemberNameLength) : 'member'
}

/**
 * Validate and normalize one snapshot-relative path (POSIX separators only).
 * Rejects absolute paths, drive letters, `..` escapes, NUL and backslashes.
 */
export function assertSafeRelativePath(value) {
  if (typeof value !== 'string') throw new CollabError('BAD_PATH', '文件路径必须是字符串')
  if (value.length === 0 || value.length > LIMITS.maxPathLength) {
    throw new CollabError('BAD_PATH', '文件路径长度不合法')
  }
  if (value.includes('\u0000') || value.includes('\\')) {
    throw new CollabError('BAD_PATH', '文件路径不能包含反斜杠或 NUL')
  }
  if (value.startsWith('/') || /^[a-zA-Z]:/u.test(value)) {
    throw new CollabError('BAD_PATH', '文件路径必须是相对路径')
  }
  const segments = []
  for (const segment of value.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') throw new CollabError('BAD_PATH', '文件路径不能包含 ..')
    if (segment.toLowerCase() === 'con' || /^(?:aux|nul|prn|com[1-9]|lpt[1-9])(?:\..*)?$/iu.test(segment)) {
      throw new CollabError('BAD_PATH', '文件路径包含系统保留名')
    }
    segments.push(segment)
  }
  if (segments.length === 0) throw new CollabError('BAD_PATH', '文件路径为空')
  const normalized = segments.join('/')
  if (normalized.length > LIMITS.maxPathLength) throw new CollabError('BAD_PATH', '文件路径长度不合法')
  return normalized
}

/** Validate a wire member reference. */
export function validMember(member) {
  if (member === null || typeof member !== 'object') throw new CollabError('BAD_REQUEST', '成员信息缺失')
  const id = member.id
  const name = member.name
  if (typeof id !== 'string' || !/^[0-9a-zA-Z_-]{6,64}$/u.test(id)) {
    throw new CollabError('BAD_REQUEST', '成员 id 不合法')
  }
  if (typeof name !== 'string' || name.trim().length === 0 || name.length > 200) {
    throw new CollabError('BAD_REQUEST', '成员名称不合法')
  }
  return { id, name: sanitizeMemberName(name) }
}

/** sha256 hex of one file's bytes. */
export function fileSha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

/** Encode bytes into one snapshot file entry. */
export function encodeFile(path, buffer) {
  const normalized = assertSafeRelativePath(path)
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer)
  if (bytes.byteLength > LIMITS.maxFileBytes) {
    throw new CollabError('TOO_LARGE', `文件过大: ${normalized}`)
  }
  return {
    path: normalized,
    size: bytes.byteLength,
    sha256: fileSha256(bytes),
    data: bytes.toString('base64'),
  }
}

/** Decode one snapshot file entry, verifying size and digest. */
export function decodeFile(entry) {
  if (entry === null || typeof entry !== 'object') throw new CollabError('BAD_SNAPSHOT', '文件条目不合法')
  const path = assertSafeRelativePath(entry.path)
  if (!Number.isInteger(entry.size) || entry.size < 0 || entry.size > LIMITS.maxFileBytes) {
    throw new CollabError('BAD_SNAPSHOT', `文件大小不合法: ${path}`)
  }
  if (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/iu.test(entry.sha256)) {
    throw new CollabError('BAD_SNAPSHOT', `文件摘要不合法: ${path}`)
  }
  if (typeof entry.data !== 'string' || entry.data.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(entry.data)) {
    throw new CollabError('BAD_SNAPSHOT', `文件内容不合法: ${path}`)
  }
  const bytes = Buffer.from(entry.data, 'base64')
  if (bytes.byteLength !== entry.size) throw new CollabError('BAD_SNAPSHOT', `文件大小不匹配: ${path}`)
  if (fileSha256(bytes) !== entry.sha256.toLowerCase()) throw new CollabError('BAD_SNAPSHOT', `文件摘要不匹配: ${path}`)
  return { path, size: entry.size, sha256: entry.sha256.toLowerCase(), bytes }
}

/**
 * Fully validate and detach a snapshot received from the network.
 * Returns canonical entries (data remains base64).
 */
export function normalizeSnapshot(snapshot, { requireRev = true } = {}) {
  if (snapshot === null || typeof snapshot !== 'object') throw new CollabError('BAD_SNAPSHOT', '快照不合法')
  const rev = snapshot.rev
  if (requireRev && (!Number.isInteger(rev) || rev < 1)) throw new CollabError('BAD_SNAPSHOT', '快照版本号不合法')
  if (!Array.isArray(snapshot.files)) throw new CollabError('BAD_SNAPSHOT', '快照缺少文件列表')
  if (snapshot.files.length > LIMITS.maxFiles) throw new CollabError('TOO_LARGE', '文件数量超过上限')
  const seen = new Set()
  let total = 0
  const files = snapshot.files.map((entry) => {
    const decoded = decodeFile(entry)
    if (seen.has(decoded.path)) throw new CollabError('BAD_SNAPSHOT', `重复文件路径: ${decoded.path}`)
    seen.add(decoded.path)
    total += decoded.size
    if (total > LIMITS.maxTotalBytes) throw new CollabError('TOO_LARGE', '共享文件夹总大小超过上限')
    return { path: decoded.path, size: decoded.size, sha256: decoded.sha256, data: entry.data }
  })
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  const note = snapshot.note === undefined ? '' : snapshot.note
  if (typeof note !== 'string' || note.length > LIMITS.maxNoteLength) {
    throw new CollabError('BAD_SNAPSHOT', '更新说明不合法')
  }
  const by = snapshot.by === undefined ? { id: 'unknown', name: '未知成员' } : validMember(snapshot.by)
  const at = snapshot.at === undefined ? new Date().toISOString() : snapshot.at
  if (typeof at !== 'string' || at.length > 64 || Number.isNaN(Date.parse(at))) {
    throw new CollabError('BAD_SNAPSHOT', '快照时间不合法')
  }
  const changes = snapshot.changes
  let normalizedChanges = undefined
  if (changes !== undefined) {
    if (changes === null || typeof changes !== 'object') throw new CollabError('BAD_SNAPSHOT', '变更摘要不合法')
    const lists = {}
    for (const key of ['added', 'modified', 'deleted']) {
      const list = changes[key]
      if (list === undefined) { lists[key] = []; continue }
      if (!Array.isArray(list) || list.length > LIMITS.maxFiles) throw new CollabError('BAD_SNAPSHOT', '变更摘要不合法')
      lists[key] = list.map((pathValue) => assertSafeRelativePath(pathValue))
    }
    normalizedChanges = lists
  }
  return {
    ...(requireRev ? { rev } : {}),
    by,
    note,
    at: new Date(at).toISOString(),
    files,
    ...(normalizedChanges === undefined ? {} : { changes: normalizedChanges }),
  }
}

/** Digest over the sorted `path:sha256` file list; identifies snapshot content. */
export function snapshotDigest(snapshot) {
  const files = Array.isArray(snapshot) ? snapshot : snapshot?.files
  if (!Array.isArray(files)) throw new CollabError('BAD_SNAPSHOT', '快照缺少文件列表')
  const lines = files
    .map((entry) => `${assertSafeRelativePath(entry.path)}:${String(entry.sha256).toLowerCase()}`)
    .sort()
  return createHash('sha256').update(lines.join('\n')).digest('hex')
}

/** Diff two file arrays (or path->sha256 maps) and return changed path lists. */
export function diffSnapshots(previous, next) {
  const before = toDigestMap(previous)
  const after = toDigestMap(next)
  const added = []
  const modified = []
  const deleted = []
  for (const [pathValue, digest] of after) {
    const old = before.get(pathValue)
    if (old === undefined) added.push(pathValue)
    else if (old !== digest) modified.push(pathValue)
  }
  for (const pathValue of before.keys()) if (!after.has(pathValue)) deleted.push(pathValue)
  added.sort(); modified.sort(); deleted.sort()
  return { added, modified, deleted }
}

function toDigestMap(files) {
  const map = new Map()
  if (files instanceof Map) {
    for (const [pathValue, digest] of files) map.set(assertSafeRelativePath(pathValue), String(digest).toLowerCase())
    return map
  }
  if (!Array.isArray(files)) throw new CollabError('BAD_SNAPSHOT', '文件列表不合法')
  for (const entry of files) {
    map.set(assertSafeRelativePath(entry.path), String(entry.sha256).toLowerCase())
  }
  return map
}
