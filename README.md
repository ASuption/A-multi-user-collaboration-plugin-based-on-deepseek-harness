#本插件由deepseek生成
# DSH Group Collaboration（DSH 群组协作插件）

一个 [DeepSeek Harness（DSH）](https://github.com/deepseek-ai/deepseek-harness) Host 插件：让多个工作区 / 多个 DSH 实例通过「房间号 + 密码」组成群组，在聊天框里加入房间、上传与同步共享文件夹、查看备份和 readme。

- 一个工作区 = 一个成员；工作区自动拥有 `shared/`（共享）、`own/`（私人）、`backup/`（版本记录）三个文件夹。
- `/group upload` 把 `own/` 上传到 `shared/`，生成 readme、追加 backup 版本并推送给房间内在线成员；其他成员自动覆盖同步。
- 新成员加入立即拉取最新共享快照；共享更新会向对话注入说明（必要时创建短目标让 Agent 解释）。
- **协议 v2 保密性**：密码不经过网络（挑战应答 + HMAC proof），共享内容 AES-256-GCM 端到端加密，房间服务器只存密文；无 token 无法获取任何内容；未鉴权状态接口已关闭；每 IP 有限流。
- 纯 Node 内置实现：房间 HTTP 服务器 + UDP 局域网发现，无外部服务、无 npm 依赖。

## 功能一览

| 能力 | 说明 |
|---|---|
| 房间 | `/group create <房间号> <密码≥8位> [房间名]`、`/group join <房间号> <密码> [地址]`、`/group leave` |
| 同步 | `/group upload [说明]`、`/group sync`、自动轮询覆盖 `shared/` |
| 备份 | `/group backup list`、`/group backup restore <版本>`；每次共享变更新增完整版本镜像（默认保留 50 版） |
| readme | `shared/readme/README.md`（项目总览/成员表/文件树）+ `shared/readme/members/<成员>.md` |
| 对话 | 共享更新时注入「[群组协作] 共享文件夹已更新」，可自动解释 |
| Agent 工具 | `group_room`、`group_share`（与命令同一套实现） |
| 安全 | 挑战应答认证、AES-256-GCM 内容加密、token 鉴权、限流锁定、反房间枚举、loopback-only 状态路由 |

## 快速开始

前置：已安装 DSH（Web/Desktop profile），Node.js ≥ 22。

```text
# 1) 获取本仓库（git clone 或下载 ZIP）
# 2) 让 DSH Agent 安装插件（target 必须是 group-collab 目录的绝对路径）：
plugin_manager install_bundle target = <仓库路径>/group-collab
```

安装后在 DSH Web UI 插件列表可见「群组协作 / Group Collaboration」。然后在任意会话的聊天框输入：

```text
/group help
/group create 123456 <你的强密码≥8位> 我的项目
/group upload 第一次上传
```

另一台机器/工作区加入：

```text
/group join 123456 <房间密码> http://<房主 IP>:45890
```

公网推荐经 VPN（Tailscale/WireGuard）或 SSH 隧道加入；插件已端到端加密内容，但不提供 TLS，元数据仍可能被观察。

> ⚠️ DSH 运行数据不要上传：工作区里的 `.dsh-group/`（含明文房间密码）、`own/`、`shared/`、`backup/`（共享内容与明文历史）已被 `.gitignore` 排除；若用 GitHub 网页上传，请上传 `github-upload/` 目录中的内容（见下）。

## 直接上传到 GitHub

本仓库根目录是可直接 `git init` / 上传的源码目录。为了让 GitHub 网页“拖拽上传”不会带上本地运行数据，提供了生成干净快照的脚本：

```bash
# 在仓库根目录运行（Node ≥ 22）
node scripts/export-github.mjs
# 生成的 github-upload/ 内容即可直接拖到 GitHub: Add file → Upload files
```

`github-upload/` 只包含：插件源码与测试、文档、LICENSE、`.gitignore`、`.github/workflows/tests.yml`；不包含任何 `.dsh-group`/own/shared/backup/房源数据。脚本会做敏感信息扫描，发现已知本地密码或运行态文件会中止。

使用 git 的方式（推荐，可保留 `.github/` 等隐藏文件）：

```bash
git init
git add .
git commit -m "feat: DSH group collaboration plugin v2"
git branch -M main
git remote add origin https://github.com/<你的账号>/<仓库名>.git
git push -u origin main
```

GitHub Actions 会按 `.github/workflows/tests.yml` 在 Ubuntu/Windows + Node 24 上运行全部测试。

## 测试

```bash
cd group-collab
node --test "tests/*.test.mjs"
```

- 57 个 `node:test` 用例：协议/加密/房间服务器、工作区/备份/readme、双成员端到端同步、真实插件注册、独立攻击面测试（金丝雀泄漏、篡改/重放、限流、旧房间、反枚举）。
- Windows 上若 `node` 不在 PATH，可先用 `where node` 找到 Node（DSH 桌面自带运行时位于 `<DSH_HOME>/dsh-runtimes/.../dependencies/node/bin/node.exe`）。

## 仓库结构

```text
group-collab/            # DSH 插件 bundle（Host-only，@local/dsh-group-collab）
  index.js               # /group 命令、group_room/group_share 工具、对话更新通知
  lib/crypto.js          # v2 密码学：scrypt KDF、HMAC proof、AES-256-GCM
  lib/room-server.js     # 盲中继房间服务器（挑战应答、token、限流、只存密文）
  lib/room-client.js     # 成员客户端（本地派生密钥、透明加解密）
  lib/member.js          # 成员运行时（加入/上传/同步/备份/readme/重连）
  lib/workspace.js       # own/shared/backup 读写与安全路径校验
  lib/backup.js          # 版本镜像、索引、回滚、保留
  lib/readme.js          # 项目/成员 readme 生成
  tests/                 # 57 个 node:test 用例（含 security.test.mjs）
DESIGN.md                # 模块契约与设计
SECURITY.md              # v2 威胁模型、密码学方案、Wire API、测试要求
VERIFICATION.md          # 交付记录、真实环境验证证据、残余风险
README.md                # 本文件
CHANGELOG.md             # 版本记录
scripts/export-github.mjs # 生成可直接上传的干净快照
```

## 安全说明

- 非成员无法通过网络获得共享内容；抓包者只能看到密文与盐/nonce/成员 id/名等元数据；房间服务器及其磁盘无法解密内容（内容密钥只由密码本地派生）。
- 已知边界：服务器持有 `authKey`，磁盘被读取者可冒充加入（拿密文、发垃圾流量）但不能解密；本机 `rememberPassword:true` 会明文保存密码（可关闭）；共享内容解密后在本机 `shared/`、`backup/` 为明文；无 TLS，公网建议 VPN；群组权限仍靠密码共享，无成员 ACL/踢人/审计。详见 [SECURITY.md](SECURITY.md) 与 [VERIFICATION.md](VERIFICATION.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。
