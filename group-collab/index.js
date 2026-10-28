/**
 * DSH Group Collaboration — Host plugin entry.
 *
 * One DSH workspace is one group member. Members join a numbered + password
 * protected room; the shared folder of one member is broadcast through the
 * room server to every online member, every change is versioned into the local
 * backup folder, readmes are maintained under shared/readme/, and chat notices
 * explain updates to live conversations.
 */
import { existsSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'

import { CollabError, asCollabError } from './lib/protocol.js'
import { CollabRuntime, buildUpdateNotice, workspaceKey } from './lib/member.js'

export const name = 'group-collab'
export const inject = ['agents', 'commands', 'tools', 'workingDirectory']

const COMMAND_NAME = 'group'
const COMMAND_DESCRIPTION = '群组协作：创建/加入房间（房间号+密码）、上传共享文件夹、同步、备份与 readme 管理'
const COMMAND_USAGE =
  '/group help | init | create <房间号> <密码> [房间名] | join <房间号> <密码> [地址] | leave | status | members | upload [说明] | sync | backup list | backup restore <版本> | name <成员名> | set <autoExplain|rememberPassword> <on|off> | address'
const STATUS_ROUTE = '/group-collab/status'

const ROOM_ACTIONS = ['create', 'join', 'leave', 'status', 'members', 'address']
const SHARE_ACTIONS = ['upload', 'sync', 'status', 'backup_list', 'backup_restore']

function defaultDataDir() {
  const home = typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME.length > 0
    ? process.env.DSH_HOME
    : path.join(homedir(), '.dsh')
  return path.join(home, 'group-collab')
}

function sessionRoot(ctx, agent) {
  if (agent === null || agent === undefined || agent.session === undefined) {
    throw new CollabError('BAD_REQUEST', '该操作需要绑定一个会话（请在工作区会话内执行）')
  }
  const root = ctx.workingDirectory.get(agent.session)
  if (typeof root !== 'string' || root.length === 0) {
    throw new CollabError('BAD_REQUEST', '无法确定当前会话的工作区目录')
  }
  return root
}

function pathKey(value) {
  try {
    return workspaceKey(value)
  } catch {
    return undefined
  }
}

function agentsInWorkspace(ctx, root) {
  const key = pathKey(root)
  if (key === undefined) return []
  const agents = []
  for (const agent of ctx.agents.list()) {
    try {
      if (pathKey(ctx.workingDirectory.get(agent.session)) === key) agents.push(agent)
    } catch {
      // A disposed or directory-less session simply does not participate.
    }
  }
  return agents
}

function boundSummary(text) {
  const firstLine = text.split('\n').find((line) => line.trim().length > 0) ?? text
  const summary = firstLine.length <= 120 ? firstLine : `${firstLine.slice(0, 119)}…`
  return summary
}

function noticeMessage(text) {
  return {
    id: randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'group-collab', form: 'notice', summary: boundSummary(text) },
  }
}

function goalObjective(text) {
  const keep = text
    .split('\n')
    .filter((line) => /^(房间|版本|更新者|变更|说明):/u.test(line.trim()) || /^\[群组协作\]/u.test(line.trim()))
    .join('；')
  const objective = `向用户解释共享文件夹更新并结束目标：${keep || boundSummary(text)}`
  return objective.length <= 400 ? objective : `${objective.slice(0, 399)}…`
}

/**
 * Deliver one update notice to every live session of the workspace. With
 * `wake`, the primary session is asked to explain the update: the runtime
 * creates a short-lived DSH goal when none is current (the "目标" requirement),
 * otherwise it queues a normal follow-up turn.
 */
async function notifyUpdate(ctx, runtime, { root, text, wake, agent }) {
  let targets
  if (agent !== undefined) {
    targets = [agent]
  } else {
    targets = agentsInWorkspace(ctx, root)
  }
  if (targets.length === 0) return false
  const member = runtime.memberFor(root)
  const autoExplain = member?.state !== undefined && typeof member.state.autoExplain === 'boolean'
    ? member.state.autoExplain
    : runtime.config.autoExplain
  const shouldWake = wake === true && autoExplain === true
  const primary = targets.find((candidate) => candidate.status === 'running') ?? targets[targets.length - 1]
  let goalCreated = false
  if (shouldWake && runtime.config.goalMode !== 'off') {
    goalCreated = tryCreateGoal(ctx, primary, text)
  }
  for (const target of targets) {
    const message = noticeMessage(text)
    try {
      if (shouldWake && !goalCreated && target === primary) target.followup(message)
      else target.inject(message)
    } catch (error) {
      ctx.logger?.warn?.(`[group-collab] could not deliver update notice: ${String(error)}`)
    }
  }
  return true
}

function tryCreateGoal(ctx, agent, text) {
  const goals = ctx.get('goals')
  if (goals === undefined || goals === null) return false
  try {
    if (goals.get(agent) !== undefined) return false
    goals.create(agent, { objective: goalObjective(text), maxGoalRounds: 2 })
    return true
  } catch (error) {
    ctx.logger?.warn?.(`[group-collab] could not create update goal: ${String(error)}`)
    return false
  }
}

function formatMembers(status) {
  if (!Array.isArray(status.members) || status.members.length === 0) return '（暂无其他在线成员）'
  return status.members
    .map((entry) => `${entry.name}${entry.online === false ? '(离线)' : ''}`)
    .join('、')
}

function formatStatus(status) {
  const lines = [
    `工作区: ${status.root}`,
    `成员: ${status.memberName} (${status.memberId})`,
    status.room === null
      ? '房间: 未加入（/group create 或 /group join）'
      : `房间: ${status.room}${status.roomName ? `「${status.roomName}」` : ''}  rev=${status.rev}`,
  ]
  if (status.room !== null) {
    lines.push(`在线: ${status.online} 人  ${formatMembers(status)}`)
    if (status.origin) lines.push(`共享服务器: ${status.origin}`)
    if (status.lastSyncAt) lines.push(`最近同步: ${status.lastSyncAt}`)
  }
  lines.push(`目录: shared/ ${status.sharedFiles} 个文件 (${status.sharedBytes} 字节) · own/ ${status.ownFiles} 个文件 · backup/ ${status.backupVersions} 个版本`)
  if (status.lastError) lines.push(`最近错误: ${status.lastError}`)
  return lines.join('\n')
}

function formatUpload(result) {
  const lines = [`已上传到共享文件夹并推送房间（rev ${result.rev}）。`]
  if (result.summary) lines.push(`变更: ${result.summary}`)
  lines.push(`共享文件: ${result.fileCount} 个（own 总计 ${result.totalBytes} 字节）`)
  lines.push(`当前在线: ${result.online} 人；其他成员会在几秒内覆盖同步自己的 shared/ 目录。`)
  return lines.join('\n')
}

function formatJoin(result) {
  const lines = [`已加入房间 ${result.room}${result.roomName ? `「${result.roomName}」` : ''}（服务器 ${result.origin}）。`]
  if (result.alreadyJoined) lines.push('当前工作区已在该房间中，已刷新状态。')
  else if (result.snapshotApplied) lines.push('已把房间最新的共享文件夹同步到本工作区（旧内容已记入 backup/）。')
  else if (result.initPublished) lines.push('本机共享文件夹为空，已生成 readme 并作为初始版本发布。')
  else lines.push('房间当前没有共享内容；先在自己的 own/ 中开发，然后 /group upload。')
  if (Array.isArray(result.members) && result.members.length > 0) {
    lines.push(`在线成员: ${result.members.map((entry) => entry.name).join('、')}`)
  }
  lines.push('提示: 共享文件夹更新时会在对话中自动说明变更；/group status 查看详情。')
  return lines.join('\n')
}

function success(text, data) {
  return { kind: 'success', text, ...(data === undefined ? {} : { data }) }
}

function failure(error) {
  const failureValue = asCollabError(error)
  return { kind: 'error', text: failureValue.message }
}

function makeCommandHandler(ctx, runtime) {
  return async (invocation) => {
    const raw = typeof invocation.rawInput === 'string' ? invocation.rawInput.trim() : ''
    const parts = raw.length === 0 ? [] : raw.split(/\s+/u)
    const sub = (parts.shift() ?? 'help').toLowerCase()
    let root
    try {
      if (sub === 'help') {
        return success(
          [
            '群组协作命令（房间号 = 4-8 位数字，密码 >= 8 位且仅保存在本机/服务器 verifier 中）：',
            '  /group init                    初始化 own/ shared/ backup/ 与 readme',
            '  /group create <房间号> <密码> [房间名]   创建房间并加入（本机作为房间服务器）',
            '  /group join <房间号> <密码> [地址]     加入房间（局域网自动发现；失败时填 http://IP:端口）',
            '  /group leave                   离开房间',
            '  /group status                  查看房间/成员/目录/备份状态',
            '  /group members                 查看在线成员',
            '  /group upload [说明]           把 own/ 上传到 shared/，并同步给其他在线成员',
            '  /group sync                    手动拉取房间最新共享文件夹',
            '  /group backup list             列出备份版本',
            '  /group backup restore <版本>   恢复某个备份版本到 shared/',
            '  /group name <成员名>           修改本机成员显示名',
            '  /group set autoExplain on|off  共享更新时是否自动在对话中解释',
            '  /group set rememberPassword on|off  是否保存房间密码用于重新上线自动重连',
            '  /group address                 查看本机房间服务器地址与已创建房间',
            '',
            `共享文件夹: <工作区>/shared（含 shared/readme/README.md 与 readme/members/）· 私人文件夹: <工作区>/own · 备份: <工作区>/backup`,
          ].join('\n'),
        )
      }
      if (sub === 'init' || sub === 'status' || sub === 'members' || sub === 'backup' || sub === 'set' || sub === 'name') {
        root = sessionRoot(ctx, invocation.agent)
      }
      switch (sub) {
        case 'init': {
          const member = await runtime.ensureWorkspace(root)
          const status = await runtime.status(root)
          return success(
            [
              `已初始化群组协作目录（成员 ${member.state.memberName} / ${member.state.memberId}）：`,
              '  own/     私人开发目录（只在 /group upload 时复制到共享目录）',
              '  shared/  共享目录（随房间同步；readme/ 下是项目总 readme 与成员 readme）',
              '  backup/  共享目录每次变更的版本记录',
              `当前状态: ${status.room === null ? '未加入房间' : `房间 ${status.room} rev=${status.rev}`}`,
            ].join('\n'),
          )
        }
        case 'create': {
          const room = parts[0]
          const password = parts[1]
          if (room === undefined || password === undefined) {
            return { kind: 'error', text: `用法: /group create <房间号> <密码> [房间名]\n${COMMAND_USAGE}` }
          }
          const roomName = parts.slice(2).join(' ')
          const result = await runtime.createRoom(sessionRoot(ctx, invocation.agent), { room, password, roomName })
          return success(formatJoin(result), result)
        }
        case 'join': {
          const room = parts[0]
          const password = parts[1]
          if (room === undefined || password === undefined) {
            return { kind: 'error', text: `用法: /group join <房间号> <密码> [地址]\n${COMMAND_USAGE}` }
          }
          const address = parts.slice(2).join(' ')
          const result = await runtime.joinRoom(sessionRoot(ctx, invocation.agent), {
            room,
            password,
            address: address.length > 0 ? address : undefined,
          })
          return success(formatJoin(result), result)
        }
        case 'leave': {
          const result = await runtime.leaveRoom(sessionRoot(ctx, invocation.agent))
          return success(result.left ? `已离开房间 ${result.room}。shared/ 与 backup/ 保持不变。` : '当前工作区未加入任何房间。')
        }
        case 'status': {
          const status = await runtime.status(root, { heartbeat: true })
          return success(formatStatus(status), status)
        }
        case 'members': {
          const status = await runtime.status(root, { heartbeat: true })
          if (status.room === null) return { kind: 'error', text: '当前工作区还没有加入房间。' }
          const lines = [`房间 ${status.room}（rev ${status.rev}，在线 ${status.online} 人）：`]
          for (const entry of status.members) {
            const self = entry.id === status.memberId ? '（本机）' : ''
            lines.push(`  - ${entry.name}${self}${entry.online === false ? ' [离线]' : ' [在线]'}`)
          }
          return success(lines.join('\n'), status.members)
        }
        case 'upload': {
          const note = parts.join(' ')
          const result = await runtime.upload(sessionRoot(ctx, invocation.agent), note)
          return success(formatUpload(result), result)
        }
        case 'sync': {
          const result = await runtime.sync(sessionRoot(ctx, invocation.agent))
          if (result.updated) {
            const changes = result.changes ?? { added: [], modified: [], deleted: [] }
            return success(
              `已同步房间最新共享文件夹（rev ${result.rev}；新增 ${changes.added.length}、修改 ${changes.modified.length}、删除 ${changes.deleted.length}，旧内容已记入 backup/）。`,
              result,
            )
          }
          return success(`共享文件夹已是最新（rev ${result.rev}，在线 ${result.online} 人）。`, result)
        }
        case 'backup': {
          const action = (parts.shift() ?? 'list').toLowerCase()
          if (action === 'list') {
            const { versions, dir } = await runtime.backups(sessionRoot(ctx, invocation.agent))
            if (versions.length === 0) return success('还没有备份版本；上传或同步一次共享文件夹后会自动记录。')
            const lines = [`备份目录: ${dir}`, `共 ${versions.length} 个版本（新→旧）：`]
            for (const version of [...versions].reverse().slice(0, 20)) {
              lines.push(
                `  v${String(version.version).padStart(4, '0')} ${version.at} ${version.reason} by ${version.member}${version.note ? ` · ${version.note}` : ''}`,
              )
            }
            return success(lines.join('\n'), versions)
          }
          if (action === 'restore') {
            const version = parts[0]
            if (version === undefined) return { kind: 'error', text: '用法: /group backup restore <版本号>' }
            const result = await runtime.restore(sessionRoot(ctx, invocation.agent), version)
            return success(`已恢复备份版本 ${result.version.version} 到 shared/（旧版本也已记录到 backup/）。`, result)
          }
          return { kind: 'error', text: '用法: /group backup list | /group backup restore <版本>' }
        }
        case 'name': {
          const newName = parts.join(' ')
          if (newName.length === 0) return { kind: 'error', text: '用法: /group name <成员名>' }
          const result = await runtime.rename(sessionRoot(ctx, invocation.agent), newName)
          return success(`成员显示名已改为「${result.memberName}」。`)
        }
        case 'set': {
          const key = parts[0]
          const value = parts[1]
          if (key === undefined || value === undefined) {
            return { kind: 'error', text: '用法: /group set autoExplain on|off 或 /group set rememberPassword on|off' }
          }
          const result = await runtime.setOption(sessionRoot(ctx, invocation.agent), key, value)
          return success(`已设置 ${result.key} = ${String(result.value)}。`)
        }
        case 'address': {
          const info = await runtime.addressInfo(sessionRoot(ctx, invocation.agent))
          if (!info.origin) {
            return success('本机房间服务器尚未启动；运行 /group create 创建房间后即可用 http://IP:端口 让他人加入。')
          }
          const rooms = info.rooms.length === 0
            ? '（本机还没有创建房间）'
            : info.rooms.map((room) => `${room.number}${room.name ? `「${room.name}」` : ''} rev=${room.rev} 在线=${room.online}`).join('\n  ')
          const lanJoin = Array.isArray(info.lanAddresses) && info.lanAddresses.length > 0
            ? info.lanAddresses.map((entry) => `  ${entry.url}（${entry.iface}）`).join('\n')
            : '  （没有检测到局域网 IPv4 地址；同一台机器可直接用 127.0.0.1 地址）'
          const lines = [
            `本机房间服务器: ${info.origin}`,
            '局域网加入地址（让其他成员在 /group join 的地址参数中使用）:',
            lanJoin,
            `本机房间: ${rooms}`,
            info.currentRoom ? `当前工作区房间: ${info.currentRoom}（${info.currentOrigin}）` : '当前工作区未加入房间',
            '提示: 同一台机器上的其他 DSH 工作区可直接用 127.0.0.1 地址加入；局域网成员请用 /group join <房间号> <密码> <http://IP:端口>。',
          ]
          return success(lines.join('\n'), info)
        }
        default:
          return { kind: 'error', text: `未知子命令: ${sub}\n${COMMAND_USAGE}` }
      }
    } catch (error) {
      return failure(error)
    }
  }
}

const outputSchema = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    text: { type: 'string' },
    // Unconstrained JSON: actions return objects or arrays (e.g. members/backups).
    data: {},
  },
  required: ['ok', 'text'],
}

function createRoomTool(ctx, runtime) {
  return {
  name: 'group_room',
  description:
    'DSH 群组协作房间操作。一个工作区就是一个成员；创建或加入“房间号 + 密码”保护的房间后，共享文件夹会在在线成员之间同步。action=create 创建房间（本机作为房间服务器）；join 加入房间（局域网自动发现，找不到时用 address 指定 http://IP:端口）；leave 离开；status 查看房间/成员/目录/备份；members 查看在线成员；address 查看本机房间服务器地址与房间列表。',
  parameters: {
    type: 'object',
    additionalProperties: false,
    properties: {
      action: { type: 'string', enum: ROOM_ACTIONS, description: '要执行的房间操作' },
      room: { type: 'string', description: '4-8 位数字房间号（create/join 必填）' },
      password: { type: 'string', description: '房间密码（create/join 必填，至少 8 位；密码不会通过网络发送）' },
      name: { type: 'string', description: 'create 时为房间名；join 时可选成员显示名' },
      address: { type: 'string', description: 'join 时可选的房间服务器地址，如 http://192.168.1.5:45890' },
    },
    required: ['action'],
  },
  output: {
    schema: outputSchema,
    render(_args, value) {
      return [{ type: 'text', text: String(value?.text ?? '') }]
    },
  },
  async execute(args, exec) {
    const root = sessionRoot(ctx, exec.agent)
    const action = String(args.action ?? '')
    switch (action) {
      case 'create': {
        const result = await runtime.createRoom(root, {
          room: args.room,
          password: args.password,
          roomName: args.name ?? '',
        })
        return { ok: true, text: formatJoin(result), data: result }
      }
      case 'join': {
        const result = await runtime.joinRoom(root, {
          room: args.room,
          password: args.password,
          address: args.address,
          memberName: args.name,
        })
        return { ok: true, text: formatJoin(result), data: result }
      }
      case 'leave': {
        const result = await runtime.leaveRoom(root)
        return { ok: true, text: result.left ? `已离开房间 ${result.room}。` : '当前工作区未加入任何房间。', data: result }
      }
      case 'status': {
        const status = await runtime.status(root, { heartbeat: true })
        return { ok: true, text: formatStatus(status), data: status }
      }
      case 'members': {
        const status = await runtime.status(root, { heartbeat: true })
        return { ok: true, text: formatMembers(status), data: status.members }
      }
      case 'address': {
        const info = await runtime.addressInfo(root)
        return { ok: true, text: JSON.stringify(info, null, 2), data: info }
      }
      default:
        throw new Error(`unknown group_room action: ${action}`)
    }
  },
  }
}

function createShareTool(ctx, runtime) {
  return {
  name: 'group_share',
  description:
    'DSH 群组协作共享文件夹操作。upload 把当前工作区 own/ 的内容上传覆盖到 shared/，生成 readme、记录 backup 版本并推送给房间里的在线成员；sync 拉取房间最新 shared 内容覆盖本机（旧内容记入 backup）；status 查看共享/备份状态；backup_list 列出备份版本；backup_restore 恢复某个备份版本到 shared/。',
  parameters: {
    type: 'object',
    additionalProperties: false,
    properties: {
      action: { type: 'string', enum: SHARE_ACTIONS, description: '要执行的共享文件夹操作' },
      note: { type: 'string', description: 'upload 时写给其他成员的更新说明' },
      version: { type: 'integer', description: 'backup_restore 要恢复的备份版本号' },
    },
    required: ['action'],
  },
  output: {
    schema: outputSchema,
    render(_args, value) {
      return [{ type: 'text', text: String(value?.text ?? '') }]
    },
  },
  async execute(args, exec) {
    const root = sessionRoot(ctx, exec.agent)
    const action = String(args.action ?? '')
    switch (action) {
      case 'upload': {
        const result = await runtime.upload(root, typeof args.note === 'string' ? args.note : '')
        return { ok: true, text: formatUpload(result), data: result }
      }
      case 'sync': {
        const result = await runtime.sync(root)
        return { ok: true, text: JSON.stringify(result), data: result }
      }
      case 'status': {
        const status = await runtime.status(root, { heartbeat: true })
        return { ok: true, text: formatStatus(status), data: status }
      }
      case 'backup_list': {
        const { versions } = await runtime.backups(root)
        return { ok: true, text: versions.map((entry) => `v${entry.version} ${entry.at} ${entry.reason}`).join('\n') || '（无备份版本）', data: versions }
      }
      case 'backup_restore': {
        const result = await runtime.restore(root, args.version)
        return { ok: true, text: `已恢复备份版本 ${result.version.version}。`, data: result }
      }
      default:
        throw new Error(`unknown group_share action: ${action}`)
    }
  },
  }
}

/** Optional same-origin JSON status route used by the Web status check. */
function registerStatusRoute(ctx, runtime) {
  ctx.inject(['webServer'], (webCtx) => {
    webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path: STATUS_ROUTE,
      async handler(request, response) {
        try {
          const remote = typeof request.socket?.remoteAddress === 'string' ? request.socket.remoteAddress : ''
          const loopback = remote === '127.0.0.1' || remote === '::1' || /^::ffff:127\./u.test(remote)
          if (!loopback) {
            response.statusCode = 403
            response.setHeader('content-type', 'application/json; charset=utf-8')
            response.end(JSON.stringify({ ok: false, error: 'forbidden' }))
            return
          }
          if (request.method !== 'GET') {
            response.statusCode = 405
            response.setHeader('content-type', 'application/json; charset=utf-8')
            response.end(JSON.stringify({ ok: false, error: 'method not allowed' }))
            return
          }
          const members = await runtime.listStatuses()
          response.statusCode = 200
          response.setHeader('content-type', 'application/json; charset=utf-8')
          response.setHeader('cache-control', 'no-store')
          response.end(JSON.stringify({ ok: true, plugin: name, members }))
        } catch (error) {
          response.statusCode = 500
          response.setHeader('content-type', 'application/json; charset=utf-8')
          response.end(JSON.stringify({ ok: false, error: asCollabError(error).message }))
        }
      },
    }), 'group-collab.statusRoute')
  })
}

export function apply(ctx, configInput) {
  const config = configInput !== null && typeof configInput === 'object' ? configInput : {}
  const logger = ctx.logger ?? console
  const dataDir = typeof config.dataDir === 'string' && config.dataDir.length > 0 ? config.dataDir : defaultDataDir()
  try {
    mkdirSync(dataDir, { recursive: true })
  } catch (error) {
    logger.warn?.(`[group-collab] cannot create data directory ${dataDir}: ${String(error)}`)
  }
  const runtime = new CollabRuntime({
    config: { ...config, dataDir },
    logger,
    notify: (notice) => notifyUpdate(ctx, runtime, notice),
  })

  // Chat command: /group ...
  ctx.effect(() => ctx.commands.register({
    name: COMMAND_NAME,
    description: COMMAND_DESCRIPTION,
    input: { hint: 'help|init|create|join|leave|status|members|upload|sync|backup|name|set|address' },
    recordInput: false,
    handler: makeCommandHandler(ctx, runtime),
  }), 'group-collab.command')

  // Model-facing tools with the same operations.
  ctx.effect(() => ctx.tools.register(createRoomTool(ctx, runtime)), 'group-collab.tool-room')
  ctx.effect(() => ctx.tools.register(createShareTool(ctx, runtime)), 'group-collab.tool-share')

  // Re-attach a workspace whenever a session starts there (auto-rejoin + pending notices).
  ctx.on('agent/created', ({ agent }) => {
    let root
    try {
      root = ctx.workingDirectory.get(agent.session)
    } catch {
      return
    }
    if (typeof root !== 'string' || root.length === 0) return
    if (!existsSync(path.join(root, '.dsh-group', 'member.json'))) return
    void runtime.attachWorkspace(root, agent).catch((error) => {
      logger.warn?.(`[group-collab] workspace attach failed: ${String(error)}`)
    })
  })

  // Poll for room revisions / presence while the plugin is loaded.
  ctx.effect(() => {
    const timer = setInterval(() => {
      void runtime.tick().catch((error) => {
        logger.warn?.(`[group-collab] poll cycle failed: ${String(error)}`)
      })
    }, runtime.config.pollMs)
    if (typeof timer.unref === 'function') timer.unref()
    return () => clearInterval(timer)
  }, 'group-collab.poll')

  registerStatusRoute(ctx, runtime)

  ctx.effect(() => () => runtime.dispose(), 'group-collab.dispose')
}

export { buildUpdateNotice, COMMAND_NAME, COMMAND_USAGE, STATUS_ROUTE }
