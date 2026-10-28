/**
 * Fake-Cordis-ctx smoke test for the DSH Group Collaboration plugin entry
 * (`index.js`).
 *
 * The fake context implements exactly the Host services `apply()` touches:
 * `effect` (disposer collector), `on`, `inject`, `commands.register`,
 * `tools.register`, `agents.list`, `workingDirectory.get`, `logger` and
 * `get('goals')` / `get('webServer')`. It is used to verify registration,
 * command/tool handlers, JSON-safe tool results and clean unload ordering
 * without booting a real DSH instance.
 *
 * Run with the bundled node binary from `Z:\try\work\group-collab`:
 *   node --test tests/
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  apply,
  COMMAND_NAME,
  COMMAND_USAGE,
  inject as pluginInject,
  name as pluginName,
} from '../index.js'

const BUNDLE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const EXPECTED_ROOM_ACTIONS = ['create', 'join', 'leave', 'status', 'members', 'address']
const EXPECTED_SHARE_ACTIONS = ['upload', 'sync', 'status', 'backup_list', 'backup_restore']
const EXPECTED_EFFECT_LABELS = [
  'group-collab.command',
  'group-collab.dispose',
  'group-collab.poll',
  'group-collab.statusRoute',
  'group-collab.tool-room',
  'group-collab.tool-share',
]

const silentLogger = Object.freeze({ log() {}, info() {}, warn() {}, error() {}, debug() {} })
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function makeTempDir(prefix) {
  return await fs.mkdtemp(path.join(os.tmpdir(), prefix))
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

/**
 * Minimal hand-rolled Cordis context: records every effect disposer, command,
 * tool, event handler, injection and web route; every disposer is run by the
 * test to simulate plugin unload.
 */
function createFakeCtx({ root, logger = silentLogger }) {
  const disposers = []
  const registrations = { commands: [], tools: [], events: [], injects: [], webRoutes: [] }
  const notices = { injected: [], followedUp: [] }
  const agent = {
    session: { id: 'fake-session-1' },
    status: 'idle',
    inject(message) {
      notices.injected.push(message)
    },
    followup(message) {
      notices.followedUp.push(message)
    },
  }
  const goals = {
    created: [],
    get() {
      return undefined
    },
    create(target, options) {
      this.created.push({ target, options })
    },
  }
  const webServer = {
    routes: registrations.webRoutes,
    register(route) {
      registrations.webRoutes.push(route)
      return () => {
        const index = registrations.webRoutes.indexOf(route)
        if (index >= 0) registrations.webRoutes.splice(index, 1)
      }
    },
  }
  function effect(fn, label) {
    const produced = fn()
    let dispose = null
    if (typeof produced === 'function') dispose = produced
    else if (produced !== null && typeof produced === 'object' && typeof produced.dispose === 'function') {
      dispose = () => produced.dispose()
    }
    if (dispose !== null) disposers.push({ label, dispose })
    return produced
  }
  const webCtx = {
    effect,
    webServer,
    get(service) {
      return service === 'webServer' ? webServer : undefined
    },
  }
  const ctx = {
    logger,
    effect,
    commands: {
      register(definition) {
        registrations.commands.push(definition)
        return () => {
          const index = registrations.commands.indexOf(definition)
          if (index >= 0) registrations.commands.splice(index, 1)
        }
      },
    },
    tools: {
      register(definition) {
        registrations.tools.push(definition)
        return () => {
          const index = registrations.tools.indexOf(definition)
          if (index >= 0) registrations.tools.splice(index, 1)
        }
      },
    },
    on(name, handler) {
      registrations.events.push({ name, handler })
      return () => {
        registrations.events = registrations.events.filter((entry) => entry.handler !== handler)
      }
    },
    inject(dependencies, callback) {
      registrations.injects.push({ dependencies: [...dependencies], callback })
      callback(webCtx)
    },
    get(service) {
      if (service === 'goals') return goals
      if (service === 'webServer') return webServer
      return undefined
    },
    agents: {
      list() {
        return [agent]
      },
    },
    workingDirectory: {
      get(session) {
        if (session === undefined || session === null) throw new Error('会话不存在')
        return root
      },
    },
  }
  return { ctx, agent, goals, webServer, notices, registrations, disposers }
}

/* ------------------------------------------------------------------ */
/* apply + handlers + unload                                          */
/* ------------------------------------------------------------------ */

test('apply：注册 /group 命令与两个工具，命令/工具可执行，卸载时所有 disposer 正常运行', async () => {
  const base = await makeTempDir('dsh-group-fake-ctx-')
  const root = path.join(base, 'workspace')
  const dataDir = path.join(base, 'data')
  const fake = createFakeCtx({ root })
  const disposeErrors = []

  try {
    apply(fake.ctx, { pollMs: 1_000_000, dataDir })

    /* -------- registration contract -------------------------------- */
    assert.equal(pluginName, 'group-collab')
    assert.deepEqual(pluginInject, ['agents', 'commands', 'tools', 'workingDirectory'])
    assert.equal(COMMAND_NAME, 'group')
    assert.ok(COMMAND_USAGE.includes('join <房间号>'))
    assert.ok(COMMAND_USAGE.includes('upload [说明]'))

    const groupCommands = fake.registrations.commands.filter((definition) => definition.name === COMMAND_NAME)
    assert.equal(groupCommands.length, 1, '必须恰好注册一个 /group 命令')
    assert.equal(fake.registrations.commands.length, 1)
    const groupCommand = groupCommands[0]
    assert.equal(groupCommand.recordInput, false, '/group 命令不得记录输入（密码不能进入会话日志）')
    assert.equal(typeof groupCommand.handler, 'function')
    assert.ok(typeof groupCommand.description === 'string' && groupCommand.description.length > 0)

    const toolNames = fake.registrations.tools.map((definition) => definition.name).sort()
    assert.deepEqual(toolNames, ['group_room', 'group_share'])
    const roomTool = fake.registrations.tools.find((definition) => definition.name === 'group_room')
    const shareTool = fake.registrations.tools.find((definition) => definition.name === 'group_share')
    assert.ok(roomTool !== undefined && shareTool !== undefined)
    assert.deepEqual(roomTool.parameters.properties.action.enum, EXPECTED_ROOM_ACTIONS)
    assert.deepEqual(shareTool.parameters.properties.action.enum, EXPECTED_SHARE_ACTIONS)
    assert.equal(typeof roomTool.execute, 'function')
    assert.equal(typeof shareTool.execute, 'function')

    const events = fake.registrations.events.map((entry) => entry.name)
    assert.ok(events.includes('agent/created'), '应监听 agent/created 以自动重连并投递待发通知')
    assert.equal(fake.registrations.injects.length, 1)
    assert.deepEqual(fake.registrations.injects[0].dependencies, ['webServer'])
    assert.equal(fake.registrations.webRoutes.length, 1, '应注册同源状态路由')
    assert.equal(fake.registrations.webRoutes[0].path, '/group-collab/status')
    assert.equal(fake.registrations.webRoutes[0].kind, 'exact')

    /* -------- protocol v2 status route: loopback-only, no shared content ---- */
    const statusRoute = fake.registrations.webRoutes[0]
    const makeResponse = () => ({
      statusCode: 0,
      headers: {},
      body: '',
      setHeader(name, value) {
        this.headers[name] = value
      },
      end(chunk) {
        this.body = chunk ?? ''
      },
    })
    const forbidden = makeResponse()
    await statusRoute.handler({ method: 'GET', socket: { remoteAddress: '192.168.1.50' } }, forbidden)
    assert.equal(forbidden.statusCode, 403, '非 loopback 来源的状态路由必须 403')
    assert.deepEqual(JSON.parse(forbidden.body), { ok: false, error: 'forbidden' })
    assert.equal(JSON.parse(forbidden.body).ok, false)

    const loopback = makeResponse()
    await statusRoute.handler({ method: 'GET', socket: { remoteAddress: '::ffff:127.0.0.1' } }, loopback)
    assert.equal(loopback.statusCode, 200)
    const statusBody = JSON.parse(loopback.body)
    assert.deepEqual(statusBody, { ok: true, plugin: 'group-collab', members: [] })
    assert.equal(loopback.headers['cache-control'], 'no-store')

    const wrongMethod = makeResponse()
    await statusRoute.handler({ method: 'POST', socket: { remoteAddress: '127.0.0.1' } }, wrongMethod)
    assert.equal(wrongMethod.statusCode, 405)
    assert.equal(JSON.parse(wrongMethod.body).ok, false)

    /* -------- command handler behaviours ---------------------------- */
    const help = await groupCommand.handler({ rawInput: 'help', agent: fake.agent })
    assert.equal(help.kind, 'success')
    assert.match(help.text, /群组协作命令/u)
    assert.ok(help.text.includes('/group init'))

    const emptyInput = await groupCommand.handler({ rawInput: '', agent: fake.agent })
    assert.equal(emptyInput.kind, 'success', '空输入应回退到 help')
    assert.match(emptyInput.text, /群组协作命令/u)

    const unknown = await groupCommand.handler({ rawInput: 'definitely-unknown', agent: fake.agent })
    assert.equal(unknown.kind, 'error')
    assert.ok(unknown.text.includes('未知子命令'))

    const missingArgs = await groupCommand.handler({ rawInput: 'create 123456', agent: fake.agent })
    assert.equal(missingArgs.kind, 'error')
    assert.ok(missingArgs.text.includes('用法'))

    const badRoom = await groupCommand.handler({ rawInput: 'create 12 abc', agent: fake.agent })
    assert.equal(badRoom.kind, 'error')
    assert.ok(badRoom.text.includes('4-8 位数字'), '非法房间号应返回可读错误')

    const notJoinedUpload = await groupCommand.handler({ rawInput: 'upload note', agent: fake.agent })
    assert.equal(notJoinedUpload.kind, 'error')
    assert.match(notJoinedUpload.text, /\/group init/u, '未初始化时 upload 应提示先 /group init')

    // /group init creates own/, shared/, backup/ and persists member state.
    const init = await groupCommand.handler({ rawInput: 'init', agent: fake.agent })
    assert.equal(init.kind, 'success')
    assert.ok(init.text.includes('own/'))
    for (const directory of ['own', 'shared', 'backup']) {
      assert.equal(await pathExists(path.join(root, directory)), true, `${directory}/ 应已创建`)
    }
    assert.equal(await pathExists(path.join(root, '.dsh-group', 'member.json')), true, '成员状态应已持久化')
    assert.equal(await pathExists(path.join(root, 'shared', 'readme', 'members')), true, 'readme 目录应已创建')

    // /group status reports the workspace without a room, JSON-safe data.
    const status = await groupCommand.handler({ rawInput: 'status', agent: fake.agent })
    assert.equal(status.kind, 'success')
    assert.ok(status.text.includes('工作区:'))
    assert.ok(status.text.includes('未加入'))
    assert.equal(status.data.room, null)
    assert.equal(status.data.root, path.resolve(root))
    assert.deepEqual(JSON.parse(JSON.stringify(status.data)), status.data)

    const members = await groupCommand.handler({ rawInput: 'members', agent: fake.agent })
    assert.equal(members.kind, 'error')
    assert.ok(members.text.includes('还没有加入房间'))

    const backupList = await groupCommand.handler({ rawInput: 'backup list', agent: fake.agent })
    assert.equal(backupList.kind, 'success')
    assert.ok(backupList.text.includes('还没有备份版本'))

    const backupRestoreMissing = await groupCommand.handler({ rawInput: 'backup restore', agent: fake.agent })
    assert.equal(backupRestoreMissing.kind, 'error')
    assert.ok(backupRestoreMissing.text.includes('用法'))

    const uploadWithoutRoom = await groupCommand.handler({ rawInput: 'upload note', agent: fake.agent })
    assert.equal(uploadWithoutRoom.kind, 'error')
    assert.ok(uploadWithoutRoom.text.includes('还没有加入房间'), '初始化但未加入房间时 upload 应提示先加入房间')

    const setNameMissing = await groupCommand.handler({ rawInput: 'set autoExplain', agent: fake.agent })
    assert.equal(setNameMissing.kind, 'error')
    assert.ok(setNameMissing.text.includes('用法'))

    /* -------- model-facing tools ------------------------------------ */
    const shareStatus = await shareTool.execute({ action: 'status' }, { agent: fake.agent })
    assert.equal(shareStatus.ok, true)
    assert.equal(typeof shareStatus.text, 'string')
    assert.ok(shareStatus.text.includes('工作区:'))
    assert.deepEqual(JSON.parse(JSON.stringify(shareStatus)), shareStatus, 'group_share status 结果必须 JSON-safe')
    assert.equal(shareStatus.data.root, path.resolve(root))
    assert.equal(shareStatus.data.room, null)
    assert.match(shareStatus.data.memberId, /^[0-9a-f]{24}$/u)

    const shareBackupList = await shareTool.execute({ action: 'backup_list' }, { agent: fake.agent })
    assert.equal(shareBackupList.ok, true)
    assert.deepEqual(JSON.parse(JSON.stringify(shareBackupList)), shareBackupList)
    assert.deepEqual(shareBackupList.data, [])

    const roomStatus = await roomTool.execute({ action: 'status' }, { agent: fake.agent })
    assert.equal(roomStatus.ok, true)
    assert.ok(roomStatus.text.includes('工作区:'))
    assert.deepEqual(JSON.parse(JSON.stringify(roomStatus)), roomStatus)

    await assert.rejects(
      roomTool.execute({ action: 'not-an-action' }, { agent: fake.agent }),
      /unknown group_room action/u,
    )
    await assert.rejects(
      shareTool.execute({ action: 'not-an-action' }, { agent: fake.agent }),
      /unknown group_share action/u,
    )

    /* -------- every registered resource went through ctx.effect ----- */
    const labels = fake.disposers.map((entry) => entry.label).sort()
    assert.deepEqual(labels, [...EXPECTED_EFFECT_LABELS].sort())
  } finally {
    // Simulated unload: run every recorded disposer exactly once.
    for (const entry of [...fake.disposers].reverse()) {
      try {
        await entry.dispose()
      } catch (error) {
        disposeErrors.push(`${String(entry.label)}: ${String(error)}`)
      }
    }
    await cleanupDir(base)
  }

  assert.deepEqual(disposeErrors, [], `disposer 运行失败: ${disposeErrors.join('; ')}`)
  assert.equal(fake.registrations.commands.length, 0, '卸载后命令应被注销')
  assert.equal(fake.registrations.tools.length, 0, '卸载后工具应被注销')
  assert.equal(fake.registrations.webRoutes.length, 0, '卸载后状态路由应被注销')
})

/* ------------------------------------------------------------------ */
/* static source constraints                                          */
/* ------------------------------------------------------------------ */

test('源码约束：插件只依赖 node 内置模块、无 @deepseek-ai 导入、package.json 无依赖', async () => {
  const libDir = path.join(BUNDLE_ROOT, 'lib')
  const libFiles = (await fs.readdir(libDir)).filter((name) => name.endsWith('.js')).sort()
  assert.ok(libFiles.length >= 7, `lib/ 模块数量异常: ${libFiles.join(', ')}`)

  const sources = [
    { file: 'index.js', text: await fs.readFile(path.join(BUNDLE_ROOT, 'index.js'), 'utf8') },
  ]
  for (const fileName of libFiles) {
    sources.push({ file: `lib/${fileName}`, text: await fs.readFile(path.join(libDir, fileName), 'utf8') })
  }

  for (const source of sources) {
    assert.equal(source.text.includes('@deepseek-ai'), false, `${source.file} 不得引用 @deepseek-ai 包`)
    const specifiers = new Set()
    for (const match of source.text.matchAll(/\bfrom\s*['"]([^'"]+)['"]/gu)) specifiers.add(match[1])
    for (const match of source.text.matchAll(/(?:^|\n)\s*import\s*['"]([^'"]+)['"]/gu)) specifiers.add(match[1])
    for (const specifier of specifiers) {
      assert.ok(
        specifier.startsWith('node:') || specifier.startsWith('.'),
        `${source.file} 引用了非 Node 内置模块: ${specifier}`,
      )
    }
  }

  const pkg = JSON.parse(await fs.readFile(path.join(BUNDLE_ROOT, 'package.json'), 'utf8'))
  assert.equal(pkg.name, '@local/dsh-group-collab')
  assert.equal(pkg.type, 'module', '插件必须是 ESM (type=module)')
  assert.deepEqual(pkg.dependencies ?? {}, {}, '插件不得声明 npm 依赖')
  assert.deepEqual(pkg.devDependencies ?? {}, {})
  assert.deepEqual(pkg.peerDependencies ?? {}, {}, '插件不得声明 peer 依赖')
  assert.ok(pkg.dsh?.bundle?.patch, 'package.json 应声明 bundle patch')
  const patchFile = path.join(BUNDLE_ROOT, pkg.dsh.bundle.patch)
  assert.equal(await pathExists(patchFile), true, `bundle patch 文件不存在: ${pkg.dsh.bundle.patch}`)
})
