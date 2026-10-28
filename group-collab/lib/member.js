/**
 * Member runtime: per-workspace membership, upload/sync/backup orchestration and
 * chat-update notifications. Harness-agnostic: index.js supplies the notify hook.
 */
import { existsSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { hostname, networkInterfaces } from 'node:os'
import path from 'node:path'

import {
  CollabError,
  asCollabError,
  createToken,
  diffSnapshots,
  makeMemberId,
  normalizeRoomNumber,
  normalizeSnapshot,
  safeMemberFileName,
  sanitizeMemberName,
  validatePassword,
} from './protocol.js'
import { RoomServer } from './room-server.js'
import { RoomClient, discoverRoom } from './room-client.js'
import {
  backupDir,
  diffOfManifests,
  ensureLayout,
  formatDiff,
  listFiles,
  ownDir,
  readSnapshotFiles,
  readState,
  sharedDir,
  writeFiles,
  writeState,
} from './workspace.js'
import { listVersions, pruneVersions, recordVersion, restoreVersion } from './backup.js'
import { generateMemberReadme, generateProjectReadme } from './readme.js'

/** Files excluded when reading own/ or shared/ trees. */
const TREE_EXCLUDE = ['.dsh-group', '.git', 'node_modules', 'backup', '.dsh-group/**']
/** The shared/readme subtree is managed by the plugin and preserved during upload. */
const KEEP_PREFIXES = ['readme']

/** Defaults for the plugin config (config comes from cordis.patch.yml). */
export const DEFAULT_RUNTIME_CONFIG = Object.freeze({
  pollMs: 2500,
  autoExplain: true,
  autoRejoin: true,
  rememberPassword: true,
  keepVersions: 50,
  goalMode: 'auto',
  enableDiscovery: true,
  tcpPort: 45890,
  udpPort: 45891,
})

const MAX_PENDING_NOTICES = 20

function numberOption(value, fallback, min, max) {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(parsed)))
}

function booleanOption(value, fallback) {
  if (typeof value === 'boolean') return value
  if (value === 'false' || value === 'off' || value === 0 || value === '0') return false
  if (value === 'true' || value === 'on' || value === 1 || value === '1') return true
  return fallback
}

/** Normalize the raw Loader config into the runtime's options object. */
export function resolveRuntimeConfig(raw = {}) {
  const config = raw !== null && typeof raw === 'object' ? raw : {}
  return {
    ...DEFAULT_RUNTIME_CONFIG,
    ...(typeof config.dataDir === 'string' && config.dataDir.length > 0 ? { dataDir: config.dataDir } : {}),
    ...(typeof config.advertiseHost === 'string' && config.advertiseHost.length > 0 ? { advertiseHost: config.advertiseHost } : {}),
    pollMs: numberOption(config.pollMs, DEFAULT_RUNTIME_CONFIG.pollMs, 500, 60_000),
    autoExplain: booleanOption(config.autoExplain, DEFAULT_RUNTIME_CONFIG.autoExplain),
    autoRejoin: booleanOption(config.autoRejoin, DEFAULT_RUNTIME_CONFIG.autoRejoin),
    rememberPassword: booleanOption(config.rememberPassword, DEFAULT_RUNTIME_CONFIG.rememberPassword),
    keepVersions: numberOption(config.keepVersions, DEFAULT_RUNTIME_CONFIG.keepVersions, 1, 500),
    goalMode: config.goalMode === 'off' ? 'off' : 'auto',
    enableDiscovery: booleanOption(config.enableDiscovery, DEFAULT_RUNTIME_CONFIG.enableDiscovery),
    tcpPort: numberOption(config.tcpPort, DEFAULT_RUNTIME_CONFIG.tcpPort, 1, 65_535),
    udpPort: numberOption(config.udpPort, DEFAULT_RUNTIME_CONFIG.udpPort, 1, 65_535),
  }
}

/** Windows-aware canonical key for a workspace root path. */
export function workspaceKey(root) {
  const resolved = path.resolve(root)
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved
}

function nowIso() {
  return new Date().toISOString()
}

function newState(memberName, memberId = makeMemberId()) {
  return {
    version: 1,
    memberId,
    memberName: sanitizeMemberName(memberName, 'member'),
    room: null,
    roomName: '',
    origin: '',
    password: '',
    rev: 0,
    lastSyncAt: null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  }
}

/** Default member display name: workspace folder name + short id suffix (unique per workspace). */
function defaultMemberName(root, memberId) {
  const base = sanitizeMemberName(path.basename(path.resolve(root)), 'member')
  const suffix = memberId.slice(0, 4)
  return sanitizeMemberName(`${base}-${suffix}`, 'member')
}

/** Build the human-readable chat notice for one shared-folder update. */
export function buildUpdateNotice({ room, rev, by, note, changes, at, online, reasonLabel }) {
  const lines = []
  lines.push(`[群组协作] 共享文件夹已更新${reasonLabel ? `（${reasonLabel}）` : ''}`)
  lines.push(`房间: ${room}`)
  if (rev !== undefined) lines.push(`版本: rev ${rev}`)
  if (by?.name) lines.push(`更新者: ${by.name}${by.local ? '（本机成员）' : '（其他成员）'}`)
  if (at) lines.push(`时间: ${at}`)
  if (note) lines.push(`说明: ${note}`)
  if (changes) {
    const added = changes.added ?? []
    const modified = changes.modified ?? []
    const deleted = changes.deleted ?? []
    const fragment = []
    if (added.length > 0) fragment.push(`新增 ${added.length} 个`)
    if (modified.length > 0) fragment.push(`修改 ${modified.length} 个`)
    if (deleted.length > 0) fragment.push(`删除 ${deleted.length} 个`)
    lines.push(`变更: ${fragment.length > 0 ? fragment.join('，') : '无文件内容差异'}`)
    const detail = formatDiff({ added, modified, deleted }, { limit: 12 })
    if (detail) lines.push(`文件: ${detail}`)
  }
  if (online !== undefined) lines.push(`当前在线: ${online} 人`)
  lines.push('目标: 请用一两句话向用户解释本次共享文件夹更新内容（上面的变更与说明），不要修改文件。')
  return lines.join('\n')
}

/**
 * One host-wide collaboration runtime. Members are DSH workspaces; the room
 * server (when this host creates a room) is shared by all local members.
 */
export class CollabRuntime {
  constructor({ config = {}, logger = console, notify } = {}) {
    this.config = resolveRuntimeConfig(config)
    this.logger = logger
    this.notify = typeof notify === 'function' ? notify : async () => false
    this.members = new Map()
    this.server = null
    this.serverStarting = null
    this.disposed = false
    this.lastServerError = null
  }

  /** Make sure the local HTTP/UDP room server is listening. */
  async ensureServer() {
    if (this.server !== null) return this.server
    if (this.serverStarting !== null) return await this.serverStarting
    this.serverStarting = (async () => {
      const server = new RoomServer({
        dataDir: this.config.dataDir,
        tcpPort: this.config.tcpPort,
        udpPort: this.config.udpPort,
        enableDiscovery: this.config.enableDiscovery,
        ...(this.config.advertiseHost === undefined ? {} : { advertiseHost: this.config.advertiseHost }),
        hostName: hostname(),
        logger: this.logger,
      })
      try {
        await server.listen()
        this.server = server
        this.lastServerError = null
        this.logger.info?.(`[group-collab] room server listening at ${server.origin}`)
        return server
      } catch (error) {
        this.lastServerError = error instanceof Error ? error.message : String(error)
        this.logger.warn?.(`[group-collab] room server failed to start: ${this.lastServerError}`)
        throw new CollabError('OFFLINE', `无法启动本机房间服务: ${this.lastServerError}`)
      } finally {
        this.serverStarting = null
      }
    })()
    return await this.serverStarting
  }

  /** Load (or create) one workspace's member state and folder layout. */
  async ensureWorkspace(root, { memberName } = {}) {
    if (typeof root !== 'string' || root.length === 0) throw new CollabError('BAD_REQUEST', '找不到工作区目录')
    const absoluteRoot = path.resolve(root)
    await ensureLayout(absoluteRoot)
    let state = await readState(absoluteRoot)
    if (state === null || typeof state !== 'object' || typeof state.memberId !== 'string') {
      const memberId = makeMemberId()
      state = newState(memberName ?? defaultMemberName(absoluteRoot, memberId), memberId)
      await writeState(absoluteRoot, state)
    } else {
      state = { ...newState(state.memberName), ...state }
      if (memberName !== undefined) {
        state.memberName = sanitizeMemberName(memberName, state.memberName)
        state.updatedAt = nowIso()
        await writeState(absoluteRoot, state)
      }
    }
    const key = workspaceKey(absoluteRoot)
    let member = this.members.get(key)
    if (member === undefined) {
      member = {
        key,
        root: absoluteRoot,
        state,
        client: null,
        origin: '',
        knownMembers: [],
        onlineCount: 1,
        lastError: null,
        lastErrorLoggedAt: 0,
        pending: [],
        firstTickDone: false,
        rejoinAttemptedAt: 0,
      }
      this.members.set(key, member)
    } else {
      member.state = state
    }
    return member
  }

  /** Persist one member's state and refresh its in-memory copy. */
  async saveMember(member) {
    member.state.updatedAt = nowIso()
    await writeState(member.root, member.state)
  }

  /** Record one shared-folder version and apply the configured retention limit. */
  async recordSharedVersion(member, options) {
    const record = await recordVersion(member.root, options)
    try {
      await pruneVersions(member.root, this.config.keepVersions)
    } catch (error) {
      this.logger.warn?.(`[group-collab] backup prune failed: ${asCollabError(error).message}`)
    }
    return record
  }

  /** Workspace override for password persistence, falling back to the plugin config. */
  effectiveRememberPassword(member) {
    return typeof member.state.rememberPassword === 'boolean'
      ? member.state.rememberPassword
      : this.config.rememberPassword
  }

  memberFor(root) {
    return this.members.get(workspaceKey(root)) ?? undefined
  }

  /** All workspaces this process currently knows about. */
  entries() {
    return [...this.members.values()]
  }

  /** Public, JSON-safe status for the web status route and commands. */
  async listStatuses() {
    const result = []
    for (const member of this.members.values()) {
      result.push(await this.status(member.root, { heartbeat: false }))
    }
    return result
  }

  /** Resolve a member that is currently joined to a room, or throw a useful error. */
  requireJoined(root) {
    const member = this.memberFor(root)
    if (member === undefined) throw new CollabError('NOT_FOUND', '当前工作区还没有初始化群组协作，请先运行 /group init')
    if (member.state.room === null || member.client === null) {
      throw new CollabError('NOT_FOUND', '当前工作区还没有加入房间，请先 /group create 或 /group join')
    }
    return member
  }

  /** Create one room on this host and join it from the given workspace. */
  async createRoom(root, { room, password, roomName = '', memberName }) {
    const number = normalizeRoomNumber(room)
    const secret = validatePassword(password)
    const member = await this.ensureWorkspace(root, { memberName })
    if (member.state.room !== null) {
      throw new CollabError('CONFLICT', `当前工作区已在房间 ${member.state.room} 中，请先 /group leave`)
    }
    const server = await this.ensureServer()
    if (server.hasRoom(number)) {
      throw new CollabError('CONFLICT', `房间号 ${number} 已被本机占用，请换一个房间号或直接 /group join`)
    }
    await server.createLocalRoom({
      number,
      password: secret,
      name: sanitizeMemberName(roomName, `房间 ${number}`),
      createdBy: { id: member.state.memberId, name: member.state.memberName },
    })
    const joined = await this.joinRoom(root, {
      room: number,
      password: secret,
      address: server.origin,
      roomNameHint: roomName,
      memberName,
    })
    return { ...joined, roomServer: server.origin }
  }

  /** Normalize a user-supplied server address into an http(s) origin. */
  normalizeAddress(address) {
    if (typeof address !== 'string' || address.trim().length === 0) return undefined
    const text = address.trim()
    const withScheme = /^https?:\/\//iu.test(text) ? text : `http://${text}`
    let url
    try {
      url = new URL(withScheme)
    } catch {
      throw new CollabError('BAD_REQUEST', `房间服务地址不合法: ${address}`)
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new CollabError('BAD_REQUEST', `房间服务地址必须使用 http/https: ${address}`)
    }
    return `${url.protocol}//${url.host}`
  }

  /** Join (or create for the first time) a room from one workspace. */
  async joinRoom(root, { room, password, address, roomNameHint = '', memberName } = {}) {
    const number = normalizeRoomNumber(room)
    const secret = validatePassword(password)
    const member = await this.ensureWorkspace(root, { memberName })
    if (member.state.room !== null) {
      if (member.state.room === number) {
        if (member.client !== null) {
          const refreshed = await this.refreshStatus(member)
          if (refreshed.error === undefined) {
            if (this.effectiveRememberPassword(member)) member.state.password = secret
            await this.saveMember(member)
            return { room: number, origin: member.state.origin, joined: true, alreadyJoined: true, ...refreshed }
          }
        }
        // The server session expired (server restart): drop the stale client and
        // re-authenticate with the password supplied now.
        if (member.client !== null) {
          member.client.close()
          member.client = null
        }
        member.knownMembers = []
        member.lastMembers = []
      } else {
        throw new CollabError('CONFLICT', `当前工作区已在房间 ${member.state.room} 中，请先 /group leave`)
      }
    }
    let origin = this.normalizeAddress(address)
    if (origin === undefined && typeof member.state.origin === 'string' && member.state.origin.length > 0) {
      origin = this.normalizeAddress(member.state.origin)
    }
    if (origin === undefined) {
      const server = await this.ensureServer().catch(() => null)
      if (server !== null && server.hasRoom(number)) origin = server.origin
    }
    if (origin === undefined) {
      const discovered = await discoverRoom({
        room: number,
        udpPort: this.config.udpPort,
        timeoutMs: 1500,
        logger: this.logger,
      })
      if (discovered !== undefined) origin = discovered.origin
    }
    if (origin === undefined) {
      throw new CollabError(
        'NOT_FOUND',
        `局域网内没有发现房间 ${number}。请让房主把 /group address 得到的 http://IP:端口 地址发给你，然后 /group join ${number} <密码> <地址>`,
      )
    }
    const client = new RoomClient({
      origin,
      room: number,
      password: secret,
      member: { id: member.state.memberId, name: member.state.memberName },
    })
    let joined
    try {
      joined = await client.join()
    } catch (error) {
      client.close()
      throw asCollabError(error, 'OFFLINE')
    }
    const previousRev = Number.isInteger(member.state.rev) ? member.state.rev : 0
    member.client = client
    member.origin = origin
    member.lastMembers = joined.members ?? []
    member.knownMembers = (joined.members ?? []).map((entry) => entry.id)
    member.onlineCount = joined.members?.length ?? 1
    member.state.room = number
    member.state.roomName = roomNameHint || joined.room?.name || ''
    member.state.origin = origin
    if (this.effectiveRememberPassword(member)) member.state.password = secret
    else member.state.password = ''
    member.state.rev = Number.isInteger(joined.room?.rev) ? joined.room.rev : 0
    await this.saveMember(member)
    let snapshotApplied = false
    let initPublished = false
    if (joined.snapshot !== null && joined.snapshot !== undefined) {
      if (joined.snapshot.rev > previousRev) {
        const applied = await this.applyIncoming(member, joined.snapshot, {
          reason: 'join',
          reasonLabel: '加入房间时同步',
          wake: true,
        })
        snapshotApplied = applied.ok === true
      }
    } else if (previousRev === 0 && (joined.room?.rev ?? 0) === 0) {
      initPublished = await this.publishInitialReadmes(member, joined.room?.rev ?? 0)
    }
    let readmePublished = false
    if (!initPublished) {
      readmePublished = await this.ensureOwnMemberReadme(member).catch((error) => {
        this.logger.warn?.(`[group-collab] member readme publish failed: ${asCollabError(error).message}`)
        return false
      })
    }
    return {
      room: number,
      origin,
      joined: true,
      roomName: member.state.roomName,
      rev: member.state.rev,
      snapshotApplied,
      initPublished,
      readmePublished,
      members: joined.members ?? [],
    }
  }

  /** Ensure shared/readme/members/<this member>.md exists; publish it when missing. */
  async ensureOwnMemberReadme(member) {
    const fileName = `${safeMemberFileName(member.state.memberName)}.md`
    const target = path.join(member.root, 'shared', 'readme', 'members', fileName)
    if (existsSync(target)) return false
    const now = nowIso()
    const ownManifest = await listFiles(ownDir(member.root), { exclude: TREE_EXCLUDE })
    const sharedManifest = await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    await generateMemberReadme(member.root, {
      member: { id: member.state.memberId, name: member.state.memberName },
      room: member.state.room,
      note: '已加入房间，尚未上传开发内容',
      ownManifest,
      sharedManifest,
      lastUploadAt: now,
    })
    const revision = member.state.rev + 1
    await generateProjectReadme(member.root, {
      room: member.state.room,
      roomName: member.state.roomName,
      members: this.memberListForReadmes(member),
      sharedManifest: await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE }),
      lastUpdate: { by: { id: member.state.memberId, name: member.state.memberName }, note: '新成员加入房间，补充成员 readme', at: now, rev: revision },
    })
    const files = await readSnapshotFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    if (files.length === 0) return false
    const changes = { added: [`readme/members/${fileName}`], modified: ['readme/README.md'], deleted: [] }
    await this.recordSharedVersion(member, {
      reason: 'member-readme',
      member: member.state.memberName,
      note: '新成员加入房间，补充成员 readme',
      rev: revision,
      changes,
    })
    try {
      const published = await member.client.publish({
        baseRev: member.state.rev,
        snapshot: {
          rev: revision,
          by: { id: member.state.memberId, name: member.state.memberName },
          note: '新成员加入房间，补充成员 readme',
          at: now,
          files,
          changes,
        },
        note: '新成员加入房间，补充成员 readme',
      })
      member.state.rev = published.rev
      await this.saveMember(member)
      return true
    } catch (error) {
      const failure = asCollabError(error)
      if (failure.code === 'CONFLICT' && failure.details?.snapshot !== undefined) {
        await this.applyIncoming(member, failure.details.snapshot, {
          reason: 'sync',
          reasonLabel: '加入房间时同步',
          wake: true,
        })
      } else {
        member.lastError = failure.message
        this.logger.warn?.(`[group-collab] member readme publish failed: ${failure.message}`)
      }
      return false
    }
  }

  /** Generate the readmes and publish the first (readme-only) snapshot. */
  async publishInitialReadmes(member, baseRev) {
    const memberList = this.memberListForReadmes(member)
    const ownManifest = await listFiles(ownDir(member.root), { exclude: TREE_EXCLUDE })
    const sharedManifest = await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    const now = nowIso()
    await generateMemberReadme(member.root, {
      member: { id: member.state.memberId, name: member.state.memberName },
      room: member.state.room,
      note: '已加入房间，尚未上传开发内容',
      ownManifest,
      sharedManifest,
      lastUploadAt: now,
    })
    const revision = baseRev + 1
    await generateProjectReadme(member.root, {
      room: member.state.room,
      roomName: member.state.roomName,
      members: memberList,
      sharedManifest: await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE }),
      lastUpdate: { by: { id: member.state.memberId, name: member.state.memberName }, note: '新成员加入房间', at: now, rev: revision },
    })
    const files = await readSnapshotFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    if (files.length === 0) return false
    const changes = { added: files.map((entry) => entry.path), modified: [], deleted: [] }
    await this.recordSharedVersion(member, {
      reason: 'init',
      member: member.state.memberName,
      note: '新成员加入房间，生成 readme',
      rev: revision,
      changes,
    })
    try {
      const published = await member.client.publish({
        baseRev,
        snapshot: {
          rev: revision,
          by: { id: member.state.memberId, name: member.state.memberName },
          note: '新成员加入房间，生成 readme',
          at: now,
          files,
          changes,
        },
        note: '新成员加入房间，生成 readme',
      })
      member.state.rev = published.rev
      await this.saveMember(member)
      return true
    } catch (error) {
      const failure = asCollabError(error)
      if (failure.code === 'CONFLICT' && failure.details?.snapshot !== undefined) {
        await this.applyIncoming(member, failure.details.snapshot, {
          reason: 'join',
          reasonLabel: '加入房间时同步',
          wake: true,
        })
      } else {
        member.lastError = failure.message
        this.logger.warn?.(`[group-collab] initial readme publish failed: ${failure.message}`)
      }
      return false
    }
  }

  memberListForReadmes(member) {
    const map = new Map()
    const source = Array.isArray(member.lastMembers) ? member.lastMembers : []
    for (const entry of source) {
      if (entry !== null && typeof entry === 'object' && typeof entry.id === 'string') {
        map.set(entry.id, { name: entry.name ?? 'member', online: entry.online === false ? false : true })
      }
    }
    map.set(member.state.memberId, { name: member.state.memberName, online: true })
    const list = [...map].map(([id, value]) => ({ id, name: value.name, online: value.online }))
    list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    return list
  }

  /** Overwrite shared/ with an incoming snapshot, recording a backup version first. */
  async applyIncoming(member, rawSnapshot, { reason = 'sync', reasonLabel = '', wake = true } = {}) {
    const snapshot = normalizeSnapshot(rawSnapshot)
    const before = await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    const changes = diffOfManifests(before, snapshot.files)
    await writeFiles(sharedDir(member.root), snapshot.files, { clean: true })
    await this.recordSharedVersion(member, {
      reason,
      member: snapshot.by?.name ?? 'unknown',
      note: snapshot.note ?? '',
      rev: snapshot.rev,
      changes,
    })
    member.state.rev = snapshot.rev
    member.state.lastSyncAt = nowIso()
    await this.saveMember(member)
    const text = buildUpdateNotice({
      room: member.state.room,
      rev: snapshot.rev,
      by: { name: snapshot.by?.name ?? '未知成员', local: false },
      note: snapshot.note,
      changes,
      at: snapshot.at,
      online: member.onlineCount,
      reasonLabel,
    })
    const delivered = await this.notify({ root: member.root, text, wake })
    if (!delivered) this.queuePending(member, { text, wake })
    return { ok: true, rev: snapshot.rev, changes }
  }

  queuePending(member, notice) {
    member.pending.push(notice)
    while (member.pending.length > MAX_PENDING_NOTICES) member.pending.shift()
  }

  /** Copy own/ content (except managed readme) into shared/, rebuild readmes, publish. */
  async upload(root, note = '') {
    const member = this.requireJoined(root)
    const previousRev = member.state.rev
    const before = await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    const ownFiles = await readSnapshotFiles(ownDir(member.root), { exclude: [...TREE_EXCLUDE, 'readme'] })
    let totalBytes = 0
    for (const entry of ownFiles) {
      totalBytes += entry.size
      if (entry.size > 8 * 1024 * 1024) throw new CollabError('TOO_LARGE', `文件过大: ${entry.path}`)
    }
    if (ownFiles.length > 2000) throw new CollabError('TOO_LARGE', 'own 文件夹文件数量超过上限 2000')
    if (totalBytes > 32 * 1024 * 1024) throw new CollabError('TOO_LARGE', 'own 文件夹总大小超过上限 32 MiB')
    await writeFiles(sharedDir(member.root), ownFiles, { clean: true, keep: KEEP_PREFIXES })
    const memberList = this.memberListForReadmes(member)
    const ownManifest = await listFiles(ownDir(member.root), { exclude: TREE_EXCLUDE })
    const now = nowIso()
    await generateMemberReadme(member.root, {
      member: { id: member.state.memberId, name: member.state.memberName },
      room: member.state.room,
      note: note || '',
      ownManifest,
      sharedManifest: await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE }),
      lastUploadAt: now,
    })
    await generateProjectReadme(member.root, {
      room: member.state.room,
      roomName: member.state.roomName,
      members: memberList,
      sharedManifest: await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE }),
      lastUpdate: {
        by: { id: member.state.memberId, name: member.state.memberName },
        note: note || '上传开发内容',
        at: now,
        rev: previousRev + 1,
      },
    })
    const afterFiles = await readSnapshotFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    const changes = diffOfManifests(before, afterFiles)
    // Regenerate the project readme with the final revision. Upload never knows
    // the server revision before publishing, so refresh it once more after publish
    // only when the manifest changed (the readme itself is part of the snapshot).
    // Refuse to silently clobber a newer server revision.
    let latest
    try {
      latest = await member.client.latest(previousRev)
    } catch (error) {
      throw asCollabError(error, 'OFFLINE')
    }
    if (latest.rev !== previousRev) {
      if (latest.rev > previousRev && latest.snapshot !== undefined && latest.snapshot !== null) {
        await this.applyIncoming(member, latest.snapshot, {
          reason: 'sync-before-upload',
          reasonLabel: '上传前同步',
          wake: true,
        })
      }
      throw new CollabError(
        'CONFLICT',
        `共享文件夹已被其他成员更新（服务器 rev ${latest.rev}，本机 rev ${previousRev}），已先同步最新内容，请确认后重新上传`,
      )
    }
    const revision = latest.rev + 1
    await this.recordSharedVersion(member, {
      reason: 'upload',
      member: member.state.memberName,
      note: note || '',
      rev: revision,
      changes,
    })
    try {
      const published = await member.client.publish({
        baseRev: latest.rev,
        snapshot: {
          rev: revision,
          by: { id: member.state.memberId, name: member.state.memberName },
          note: note || '',
          at: now,
          files: afterFiles,
          changes,
        },
        note: note || '',
      })
      member.state.rev = published.rev
      member.state.lastSyncAt = now
      await this.saveMember(member)
      const text = buildUpdateNotice({
        room: member.state.room,
        rev: published.rev,
        by: { name: member.state.memberName, local: true },
        note: note || '',
        changes,
        at: now,
        online: member.onlineCount,
        reasonLabel: '本机上传',
      })
      const delivered = await this.notify({ root: member.root, text: text.replace('目标: 请用一两句话向用户解释本次共享文件夹更新内容（上面的变更与说明），不要修改文件。', '目标: 已上传到共享文件夹，其他在线成员会自动同步。'), wake: false })
      if (!delivered) this.queuePending(member, { text, wake: false })
      return {
        ok: true,
        rev: published.rev,
        changes,
        fileCount: afterFiles.length,
        totalBytes,
        online: member.onlineCount,
        summary: formatDiff(changes, { limit: 12 }),
      }
    } catch (error) {
      const failure = asCollabError(error)
      if (failure.code === 'CONFLICT' && failure.details?.snapshot !== undefined) {
        await this.applyIncoming(member, failure.details.snapshot, {
          reason: 'sync-conflict',
          reasonLabel: '上传冲突后同步',
          wake: true,
        })
        throw new CollabError('CONFLICT', '共享文件夹刚被其他成员更新，已同步最新内容，请确认后重新上传')
      }
      throw failure
    }
  }

  /** Pull the latest server snapshot (if newer) and apply it. */
  async sync(root) {
    const member = this.requireJoined(root)
    let latest
    try {
      latest = await member.client.latest(member.state.rev)
    } catch (error) {
      throw asCollabError(error, 'OFFLINE')
    }
    if (latest.rev > member.state.rev && latest.snapshot !== undefined && latest.snapshot !== null) {
      const result = await this.applyIncoming(member, latest.snapshot, {
        reason: 'sync',
        reasonLabel: '手动同步',
        wake: true,
      })
      return { ok: true, updated: true, rev: result.rev, changes: result.changes, online: member.onlineCount }
    }
    member.onlineCount = latest.members?.length ?? member.onlineCount
    member.lastMembers = latest.members
    return { ok: true, updated: false, rev: member.state.rev, online: member.onlineCount }
  }

  /** Leave the current room without touching folders. */
  async leaveRoom(root) {
    const member = this.memberFor(root)
    if (member === undefined) return { ok: true, left: false }
    if (member.client !== null) {
      try {
        await member.client.leave()
      } catch {
        // Leaving a room must work offline too.
      }
      member.client.close()
      member.client = null
    }
    const oldRoom = member.state.room
    member.state.room = null
    member.state.roomName = ''
    member.state.origin = ''
    member.state.password = ''
    // Revision numbers are room-scoped; a later join into another room must not
    // inherit this room's rev (it would skip applying the new room's snapshot).
    member.state.rev = 0
    member.state.lastSyncAt = null
    member.knownMembers = []
    member.lastMembers = []
    member.onlineCount = 0
    await this.saveMember(member)
    return { ok: true, left: true, room: oldRoom }
  }

  /** Rename this workspace's member identity. */
  async rename(root, name) {
    const member = await this.ensureWorkspace(root)
    const previousName = member.state.memberName
    const nextName = sanitizeMemberName(name, member.state.memberName)
    if (nextName === previousName) return { ok: true, memberName: nextName, changed: false }
    member.state.memberName = nextName
    await this.saveMember(member)
    if (member.client !== null) {
      member.client.member = { id: member.state.memberId, name: nextName }
      // The room may have advanced while the workspace was idle: a publish conflict
      // syncs the latest snapshot, which restores the old readme file. Remove it and
      // retry once so the rename is visibly reflected in the shared readmes.
      for (let attempt = 0; attempt < 2; attempt++) {
        const oldReadme = path.join(member.root, 'shared', 'readme', 'members', `${safeMemberFileName(previousName)}.md`)
        if (existsSync(oldReadme)) await rm(oldReadme, { force: true }).catch(() => {})
        member.readmeCheckedAt = Date.now()
        const published = await this.ensureOwnMemberReadme(member).catch((error) => {
          this.logger.warn?.(`[group-collab] readme rename refresh failed: ${asCollabError(error).message}`)
          return false
        })
        if (published) break
      }
    }
    return { ok: true, memberName: nextName, changed: true }
  }

  /** Change one runtime option persistently for this workspace. */
  async setOption(root, key, rawValue) {
    const member = await this.ensureWorkspace(root)
    const state = member.state
    switch (key) {
      case 'autoExplain':
        state.autoExplain = booleanOption(rawValue, this.config.autoExplain)
        break
      case 'rememberPassword':
        state.rememberPassword = booleanOption(rawValue, this.config.rememberPassword)
        if (state.rememberPassword === false) state.password = ''
        break
      default:
        throw new CollabError('BAD_REQUEST', `未知设置项: ${key}，可用 autoExplain / rememberPassword`)
    }
    await this.saveMember(member)
    return { ok: true, key, value: state[key] }
  }

  /** Refresh member/online counts for one member without applying files. */
  async refreshStatus(member) {
    if (member.client === null) return { members: member.lastMembers ?? [], online: 0, rev: member.state.rev }
    try {
      const beat = await member.client.heartbeat()
      member.lastMembers = beat.members ?? []
      member.knownMembers = (beat.members ?? []).map((entry) => entry.id)
      member.onlineCount = beat.members?.length ?? 0
      member.lastError = null
      return { members: member.lastMembers, online: member.onlineCount, rev: beat.rev }
    } catch (error) {
      const failure = asCollabError(error)
      member.lastError = failure.message
      this.logger.warn?.(`[group-collab] status heartbeat failed: ${failure.message}`)
      return { members: member.lastMembers ?? [], online: 0, rev: member.state.rev, error: failure.message }
    }
  }

  /** Detailed status for commands/tools/web route. */
  async status(root, { heartbeat = false } = {}) {
    const member = await this.ensureWorkspace(root)
    let sharedFiles = 0
    let sharedBytes = 0
    let ownFiles = 0
    let backupVersions = 0
    try {
      const shared = await listFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
      sharedFiles = shared.length
      sharedBytes = shared.reduce((sum, entry) => sum + entry.size, 0)
      ownFiles = (await listFiles(ownDir(member.root), { exclude: TREE_EXCLUDE })).length
      backupVersions = (await listVersions(member.root)).index.length
    } catch {
      // Folder problems are reported through the status text, never fatal.
    }
    const online = member.client !== null && heartbeat ? await this.refreshStatus(member) : null
    const status = {
      root: member.root,
      memberId: member.state.memberId,
      memberName: member.state.memberName,
      room: member.state.room,
      roomName: member.state.roomName,
      origin: member.state.origin,
      rev: member.state.rev,
      online: online?.online ?? member.onlineCount,
      members: (member.lastMembers ?? []).map((entry) => ({ id: entry.id, name: entry.name, online: entry.online !== false })),
      sharedFiles,
      sharedBytes,
      ownFiles,
      backupVersions,
      lastError: member.lastError,
      lastSyncAt: member.state.lastSyncAt,
    }
    return status
  }

  /** Recover an existing local room server address and room list. */
  async addressInfo(root) {
    const member = this.memberFor(root)
    let server = this.server
    if (server === null) {
      server = await this.ensureServer().catch(() => null)
    }
    const port = server?.origin === undefined ? undefined : Number(new URL(server.origin).port)
    const lanAddresses = []
    if (port !== undefined && Number.isInteger(port)) {
      for (const [iface, addresses] of Object.entries(networkInterfaces())) {
        for (const address of addresses ?? []) {
          if (address.family !== 'IPv4' || address.internal) continue
          lanAddresses.push({ iface, address: address.address, url: `http://${address.address}:${port}` })
        }
      }
    }
    return {
      origin: server?.origin ?? '',
      lanAddresses,
      rooms: server?.listRooms() ?? [],
      currentRoom: member?.state.room ?? null,
      currentOrigin: member?.state.origin ?? '',
    }
  }

  /** Backup listing for one workspace. */
  async backups(root) {
    const member = await this.ensureWorkspace(root)
    const { index } = await listVersions(member.root)
    // Copy the records into a fresh array: listVersions carries a non-enumerable
    // `.index` self-alias that is not lossless JSON for the tool output codec.
    const versions = index.map((record) => ({ ...record, changes: record.changes === null ? null : { ...record.changes } }))
    return { versions, dir: backupDir(member.root) }
  }

  /** Restore one backup version into shared/ (recording the pre-restore state). */
  async restore(root, version) {
    const member = await this.ensureWorkspace(root)
    const { index } = await listVersions(member.root)
    const target = index.find((entry) => String(entry.version) === String(version) || entry.dir === version)
    if (target === undefined) throw new CollabError('NOT_FOUND', `没有找到备份版本: ${version}`)
    const result = await restoreVersion(member.root, target.version)
    const text = `[群组协作] 已恢复备份版本 ${target.version}（${target.reason}，${target.at}）到共享文件夹。当前共享内容尚未推送到房间，如需分享请 /group upload 或 /group sync。`
    const delivered = await this.notify({ root: member.root, text, wake: false })
    if (!delivered) this.queuePending(member, { text, wake: false })
    return { ok: true, version: target, ...result }
  }

  /** One polling cycle for every active member. Called on an interval by index.js. */
  async tick() {
    if (this.disposed) return
    for (const member of this.members.values()) {
      if (member.client === null) {
        // Plugin reload / previous failure left a joined workspace without a live
        // client: reconnect on the poll loop instead of waiting for a new session.
        const now = Date.now()
        if (
          member.state.room !== null &&
          this.config.autoRejoin &&
          member.state.password &&
          now - (member.lastAutoRejoinAt ?? 0) > 15_000
        ) {
          member.lastAutoRejoinAt = now
          // A locally-hosted room lives behind this process's own server; start it
          // before reconnecting (the server reloads persisted rooms from disk).
          await this.ensureServer().catch(() => null)
          await this.rejoin(member).catch((error) => {
            this.logger.warn?.(`[group-collab] auto rejoin failed: ${asCollabError(error).message}`)
          })
        }
        if (member.client === null) continue
      }
      try {
        const beat = await member.client.heartbeat()
        const members = Array.isArray(beat.members) ? beat.members : []
        const newMember = this.detectNewMember(member, members)
        member.lastMembers = members
        member.knownMembers = members.map((entry) => entry.id)
        member.onlineCount = members.length
        member.lastError = null
        if (newMember !== undefined && member.firstTickDone) {
          const text = `[群组协作] 成员 ${newMember.name} 已上线（房间 ${member.state.room}，当前 ${members.length} 人在线）。`
          const delivered = await this.notify({ root: member.root, text, wake: false })
          if (!delivered) this.queuePending(member, { text, wake: false })
        }
        member.firstTickDone = true
        // The room server lost its snapshot (restart/corrupt file): a member whose
        // local shared content is newer republishes it so the room recovers.
        if (member.state.rev > beat.rev) {
          await this.republishLocal(member, beat.rev)
        }
        if (beat.rev > member.state.rev) {
          const latest = await member.client.latest(member.state.rev)
          if (latest.snapshot !== undefined && latest.snapshot !== null) {
            await this.applyIncoming(member, latest.snapshot, { reason: 'sync', reasonLabel: '同步其他成员更新', wake: true })
          }
        }
        const now = Date.now()
        if (now - (member.readmeCheckedAt ?? 0) > 60_000) {
          member.readmeCheckedAt = now
          await this.ensureOwnMemberReadme(member).catch((error) => {
            this.logger.warn?.(`[group-collab] member readme refresh failed: ${asCollabError(error).message}`)
          })
        }
      } catch (error) {
        const failure = asCollabError(error)
        member.lastError = failure.message
        const now = Date.now()
        if (failure.code === 'UNAUTHORIZED' && this.config.autoRejoin && member.state.password && now - member.rejoinAttemptedAt > 15_000) {
          member.rejoinAttemptedAt = now
          await this.rejoin(member).catch((rejoinError) => {
            this.logger.warn?.(`[group-collab] rejoin failed: ${String(rejoinError)}`)
          })
        } else if (now - member.lastErrorLoggedAt > 30_000) {
          member.lastErrorLoggedAt = now
          this.logger.warn?.(`[group-collab] sync tick failed for ${member.root}: ${failure.message}`)
        }
      }
    }
  }

  detectNewMember(member, members) {
    if (!Array.isArray(member.knownMembers)) member.knownMembers = []
    const known = new Set(member.knownMembers)
    for (const entry of members) {
      if (entry.id !== member.state.memberId && !known.has(entry.id)) return entry
    }
    return undefined
  }

  /** Re-authenticate a member whose session token expired (server restarted). */
  async rejoin(member) {
    const candidateOrigins = []
    if (member.state.origin) candidateOrigins.push(member.state.origin)
    if (this.server !== null && this.server.hasRoom(member.state.room)) candidateOrigins.push(this.server.origin)
    for (const origin of [...new Set(candidateOrigins)]) {
      const client = new RoomClient({
        origin,
        room: member.state.room,
        password: member.state.password,
        member: { id: member.state.memberId, name: member.state.memberName },
      })
      try {
        const joined = await client.join()
        if (member.client !== null) member.client.close()
        const previousRev = Number.isInteger(member.state.rev) ? member.state.rev : 0
        member.client = client
        member.origin = origin
        member.state.origin = origin
        member.knownMembers = (joined.members ?? []).map((entry) => entry.id)
        member.lastMembers = joined.members ?? []
        member.onlineCount = joined.members?.length ?? 1
        member.state.rev = Number.isInteger(joined.room?.rev) ? joined.room.rev : previousRev
        await this.saveMember(member)
        if (joined.snapshot !== null && joined.snapshot !== undefined && joined.snapshot.rev > previousRev) {
          await this.applyIncoming(member, joined.snapshot, { reason: 'rejoin', reasonLabel: '重新上线同步', wake: true })
        } else if (member.state.rev < previousRev) {
          // The server lost its snapshot while we were away: republish our local copy.
          await this.republishLocal(member, member.state.rev)
        }
        this.logger.info?.(`[group-collab] reconnected member ${member.state.memberName} to room ${member.state.room}`)
        return true
      } catch (error) {
        client.close()
        this.logger.warn?.(`[group-collab] rejoin attempt at ${origin} failed: ${asCollabError(error).message}`)
      }
    }
    return false
  }

  /** Push local shared content when the room server asks a returning member to republish. */
  async republishLocal(member, baseRev) {
    const files = await readSnapshotFiles(sharedDir(member.root), { exclude: TREE_EXCLUDE })
    if (files.length === 0) return
    const revision = baseRev + 1
    const changes = { added: files.map((entry) => entry.path), modified: [], deleted: [] }
    const published = await member.client.publish({
      baseRev,
      snapshot: {
        rev: revision,
        by: { id: member.state.memberId, name: member.state.memberName },
        note: '成员重新上线，补发本机共享内容',
        at: nowIso(),
        files,
        changes,
      },
      note: '成员重新上线，补发本机共享内容',
    })
    member.state.rev = published.rev
    await this.saveMember(member)
  }

  /**
   * Called when a session starts in a workspace: restore membership (auto-rejoin)
   * and flush notices that arrived while no session was open.
   */
  async attachWorkspace(root, agent) {
    const member = await this.ensureWorkspace(root)
    const pending = member.pending.splice(0, member.pending.length)
    for (const notice of pending) {
      const delivered = await this.notify({ root: member.root, text: notice.text, wake: notice.wake, agent })
      if (!delivered) member.pending.push(notice)
    }
    if (member.client === null && member.state.room !== null && this.config.autoRejoin && member.state.password) {
      await this.rejoin(member).catch((error) => {
        this.logger.warn?.(`[group-collab] auto-rejoin failed: ${asCollabError(error).message}`)
      })
    }
    return member
  }

  async dispose() {
    if (this.disposed) return
    this.disposed = true
    const active = [...this.members.values()].filter((member) => member.client !== null)
    const leaving = []
    for (const member of active) {
      // Let leave() finish before close() aborts in-flight requests.
      leaving.push(member.client.leave().catch(() => {}))
    }
    await Promise.allSettled(leaving)
    for (const member of active) {
      member.client.close()
      member.client = null
    }
    if (this.server !== null) {
      const server = this.server
      this.server = null
      await server.close().catch(() => {})
    }
  }
}
