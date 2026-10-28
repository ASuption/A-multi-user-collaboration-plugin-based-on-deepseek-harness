# DSH Group Collaboration（群组协作插件）

一个 DeepSeek Harness（DSH）Host 插件：让**多个工作区 / 多个 DSH 实例**通过「房间号 + 密码」组成群组，在聊天框里完成加入房间、上传与同步共享文件夹、查看备份和 readme。

- 一个工作区 = 一个成员（member）；默认成员名为「工作区目录名-成员ID前4位」，可用 `/group name` 修改。
- 每个工作区自动拥有三个文件夹：`own/`（私人开发）、`shared/`（共享）、`backup/`（共享目录每次变更的版本记录）。
- 共享目录里有 `readme/`：`README.md` 是项目总 readme，`readme/members/<成员名>.md` 是每个成员自己的 readme。
- 共享目录更新时，房间内在线成员会自动覆盖同步，并在对话中收到「共享文件夹已更新」的说明目标（DSH Goal）/上下文消息。
- 新成员加入房间时，会立即向房间服务器请求并拉取最新共享目录（旧内容先记入 `backup/`）。
- 房间服务器与局域网发现都是插件自带的 Node 实现，没有外部服务、没有 npm 依赖。
- **协议 v2 内容端到端加密**：共享快照在成员端用密码派生的内容密钥 AES-256-GCM 加密后上传，房间服务器/抓包者/磁盘持有者只能看到密文，无法读取文件内容或更新说明；密码本身也从不经过网络（挑战应答认证）。

## 安装

在 DSH Web UI 的 Plugins 页面安装，或让 Agent 执行（`target` 必须是本仓库 `group-collab` 目录的**绝对路径**）：

```text
plugin_manager install_bundle target = <仓库路径>/group-collab
```

插件是一个 Host-only bundle（`@local/dsh-group-collab`），安装后出现在插件列表中（标题「群组协作 / Group Collaboration」）。安装/更新后按提示重启或由 HMR 生效。

### 可选配置

在 profile 的 `cordis.patch.yml` 中用 `id: group-collab` 覆盖默认值（也可在 `group-collab/cordis.patch.yml` 中改默认值后重装）：

```yaml
- id: group-collab
  name: '@local/dsh-group-collab'
  config:
    pollMs: 2500            # 心跳/拉取间隔
    autoExplain: true       # 共享更新时是否自动在对话中解释（创建短目标或 followup）
    goalMode: auto          # auto: 无进行中 goal 时创建“解释更新”短目标；off: 只注入消息
    rememberPassword: true  # 是否在本机 .dsh-group/member.json 保存密码用于重连
    keepVersions: 50        # backup/ 保留的版本数
    tcpPort: 45890          # 房间服务器 HTTP 端口（被占用时自动向后尝试）
    udpPort: 45891          # 局域网发现 UDP 端口（各实例需一致）
    enableDiscovery: true
    advertiseHost: ''       # 多网卡/特殊网络下强制广播的主机名或 IP
    dataDir: ''             # 房间服务器持久化目录，默认 $DSH_HOME/group-collab
```


## 聊天框命令

在任意会话的输入框里输入（密码不会写入会话日志，命令声明了 `recordInput: false`）：

| 命令 | 作用 |
|---|---|
| `/group help` | 查看全部用法 |
| `/group init` | 在当前工作区创建 `own/`、`shared/`、`backup/`、`shared/readme/` |
| `/group create <房间号> <密码> [房间名]` | 在本机创建房间（本机成为房间服务器）并加入 |
| `/group join <房间号> <密码> [地址]` | 加入房间；同机可直接加入，局域网自动发现；发现失败时传 `http://IP:端口` |
| `/group leave` | 离开房间（目录内容保留） |
| `/group status` | 房间、在线成员、rev、目录与备份统计 |
| `/group members` | 在线成员列表 |
| `/group upload [说明]` | 把 `own/` 的内容覆盖到 `shared/`，生成 readme、记录备份并推送给在线成员 |
| `/group sync` | 手动拉取房间最新共享目录 |
| `/group backup list` | 备份版本列表（新→旧） |
| `/group backup restore <版本>` | 恢复某个备份版本到 `shared/` |
| `/group name <成员名>` | 修改本机成员显示名 |
| `/group set autoExplain on\|off` | 共享更新时是否自动生成「解释更新」的目标/回合 |
| `/group set rememberPassword on\|off` | 是否在本机保存房间密码以便重新上线自动重连 |
| `/group address` | 查看本机房间服务器地址、加入地址和已创建房间 |

Agent 侧同样能力通过两个工具暴露：`group_room`（create/join/leave/status/members/address）与 `group_share`（upload/sync/status/backup_list/backup_restore）。

## 工作区布局

```text
<workspace>/
├─ own/                         私人开发目录（只有 /group upload 会复制到 shared/）
├─ shared/                      共享项目目录（同步时整体覆盖）
│  └─ readme/
│     ├─ README.md              项目总 readme（成员表、文件树、最近更新）
│     └─ members/<成员名>.md     每个成员的 readme（own/ 文件清单、最近上传说明）
├─ backup/
│  ├─ index.json                版本索引
│  └─ v0001-<时间戳>-<原因>/     每次 shared/ 变更的完整镜像（默认保留 50 版）
└─ .dsh-group/member.json       本工作区的成员身份、房间与同步状态
```

## 工作流程（对应需求）

1. **加入群组**：在聊天框 `/group create` 或 `/group join`，密码校验通过后加入房间。
2. **开发**：主要在 `own/` 中开发。共享目录只读使用，不直接修改。
3. **上传**：`/group upload` 把 `own/` 覆盖到 `shared/`，同时生成 `readme/`，在 `backup/` **追加**一个版本记录（不覆盖、不删除历史，也不把 backup 同步给其他成员），并推送到房间服务器。
4. **多成员在线同步**：房间内其他在线成员轮询到新 rev 后，先记录本地 `backup/` 版本，再用新快照整体覆盖自己的 `shared/`。
5. **新成员上线**：`join` 时立即拉取房间最新共享快照并覆盖本机 `shared/`（旧内容记入 `backup/`）；同时生成自己的成员 readme。
6. **备份**：`shared/` 的每次变更（上传、同步、恢复）都会在 `backup/` 追加一个完整版本目录与索引记录。
7. **对话说明**：共享目录更新时向当前工作区的在线会话注入说明；`autoExplain` 开启时自动生成一个短目标/回合，让对话解释更新内容。

## 同步机制（协议 v2）

- 房主所在 DSH 进程运行房间服务器：HTTP `45890`（端口被占用时自动 +1 试到 45899）+ UDP 发现 `45891`。
- **加入房间（挑战应答，密码不过网）**：客户端先请求 `challenge` 拿到随机盐与 nonce，本地用 `scrypt(密码, saltAuth)` 派生认证密钥并计算 `HMAC-SHA256` proof；服务器只保存 `authKey`（verifier）与盐，不保存密码，校验 proof 后签发会话 token。未知房间与错误密码返回相同的失败响应，无法枚举房间。
- **内容加密（服务器读不到内容）**：内容密钥 `scrypt(密码, saltContent)` 只在成员进程内存中派生；快照 payload（文件、更新说明、成员、变更）用 AES-256-GCM 加密，AAD 绑定 `房间号:rev`（防重放/换 rev）；服务器房间文件只存 `{v:2,iv,tag,data}` 密文。新成员加入时拿到的是密文，用本机密码派生的内容密钥解密后校验 `normalizeSnapshot` 再写入 `shared/`。
- **鉴权与限流**：latest/status/publish/heartbeat 都要求 token；`status` 不再接受匿名房间查询；每 IP 的 challenge/join 限流，连续错误密码会临时锁定（429）。
- **发现**：UDP 只用于找到房间地址，应答为 `{t,v:2,room,url}`，不含房间名；局域网内仍然可见“某个房间号的存在”。跨公网请用显式 `http://IP:端口` 地址。
- 同步：成员每 2.5 秒心跳一次；发现 rev 更新就下载密文、解密后覆盖 `shared/`；`baseRev` 不匹配时服务器返回 409 + 最新密文快照，上传方先同步再提示重试，避免静默覆盖。
- 快照限制：≤2000 个文件、≤32 MiB、单文件 ≤8 MiB；路径必须是相对 POSIX 路径（拒绝 `..`、绝对路径、反斜杠、Windows 保留名）。

## 安全与限制（v2）

- **非成员无法通过网络获得内容**：没有密码无法通过 join/latest/publish 获取任何文件内容；服务器房间里只有密文；抓包者只能看到密码学材料（随机盐/nonce/密文）与成员 ID/名等元数据，看不到密码、文件内容或更新说明（有自动化测试用“金丝雀”字符串证明）。
- **服务器也不能解密内容**：内容密钥由密码派生、从不上传；房主机器上的房间 JSON 即使泄露也读不到共享文件内容。但服务器持有 authKey，若房间服务器被攻破，攻击者可冒充成员加入（能看/写流量与密文，仍不能解密）。
- **认证**：密码最少 8 位；proof 基于服务端 nonce、单次有效（60s），不可重放；每 IP 有尝试限流与临时锁定。密码本身不写网络、不写房间文件。
- **本机密码**：`rememberPassword` 开启时密码以明文保存在**本工作区**的 `.dsh-group/member.json`（仅本机、仅磁盘），用于 DSH 重启自动重连；可 `/group set rememberPassword off` 关闭。共享内容解密后的 `shared/`、`backup/` 也是本机明文（不做磁盘加密）。
- **未做传输层 TLS**：内容已端到端加密，但流量元数据（房间号、成员名、消息大小、rev）在公网仍可被观察；公网部署仍建议 VPN/隧道，且需要端口映射/显式地址（UDP 发现跨不了公网）。
- **旧房间不兼容**：v1 房间文件（含明文快照/密码哈希）在升级启动时会被改名为 `<房间号>.json.legacy-v1` 并忽略，需要重新创建房间；旧客户端（v1 插件）无法连接 v2 房间。
- 房间服务器跟随房主进程：房主退出后房间不可用；其他成员保留本地 `shared/` 与 `backup/`，等房主重新上线后可继续。
- `shared/` 是最后写入者覆盖模型；上传前会检测服务器是否有更新，发现更新会先同步并拒绝本次上传，提示重试。
- 群组权限仍是“有密码即可写入共享”，没有成员级 ACL/踢人/审计；只邀请可信成员，`own/` 不应上传敏感内容。

## 验证

- 在 `group-collab` 目录下运行测试（Node ≥ 22；Node 24 需要 glob，不能直接传目录）：
  `node --test "tests/*.test.mjs"`
  覆盖协议校验、房间服务器/客户端、工作区读写、备份、readme、双成员端到端同步、独立攻击面测试与插件注册。
- 安装后在 Web UI 插件列表可见「群组协作」条目；`GET /group-collab/status`（仅允许 loopback 来源）返回当前进程内的成员与房间状态 JSON。
- 详细验证记录见仓库根目录的 `VERIFICATION.md`。
