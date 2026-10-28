# DSH 群组协作插件 — 交付与验证记录（协议 v2 · 保密性加固）

日期：2026-10-28（v2 加固同日完成）· 工作区：本仓库根目录 · 插件：`@local/dsh-group-collab@2.0.0`（Host-only）

## 0. 结论

- 插件已升级到 **协议 v2** 并安装/激活在当前 DSH profile：**非成员、抓包者、房间服务器磁盘持有者都无法获得共享文件内容**；密码不再经过网络；未鉴权状态接口已关闭；每 IP 限流；旧 v1 房间不兼容并已清理。
- 自动化测试 **57/57 通过**；真实 Harness 端到端 **合法同步正常**，并实测 **20/20** 项攻击面检查通过。
- 仍存在的信任边界见 §5：服务器持有 `authKey` 可被冒充加入（但无法解密）；成员名/房间号/rev/流量大小等元数据在网络上可见；公网仍建议 VPN/隧道（未做 TLS）；磁盘被攻破 + 弱密码可被离线爆破。

## 1. 交付物

| 路径 | 说明 |
|---|---|
| [group-collab/](group-collab/) | 完整插件 bundle |
| [index.js](group-collab/index.js) | `/group` 命令、`group_room`/`group_share` 工具、更新通知、loopback-only 状态路由 |
| [lib/crypto.js](group-collab/lib/crypto.js) | v2 密码学：scrypt KDF、HMAC challenge proof、AES-256-GCM 快照加解密、密文格式/大小校验、密钥清零 |
| [lib/protocol.js](group-collab/lib/protocol.js) | v2 协议常量与校验（路径/快照/房间号/密码 ≥8 位） |
| [lib/room-server.js](group-collab/lib/room-server.js) | **盲中继**房间服务器：challenge/join proof、token 鉴权、限流锁定、只存密文、旧房间隔离、UDP v2（无房间名） |
| [lib/room-client.js](group-collab/lib/room-client.js) | 客户端：本地派生 authKey/contentKey、proof、透明加解密、冲突密文解密、密钥零化 |
| [lib/member.js](group-collab/lib/member.js) | 成员运行时（上传/同步/备份/readme/自动重连）——v2 下 API 无需改动 |
| [lib/workspace.js](group-collab/lib/workspace.js) · [lib/backup.js](group-collab/lib/backup.js) · [lib/readme.js](group-collab/lib/readme.js) | 工作区/备份/readme |
| [tests/](group-collab/tests/) | 57 个 `node:test` 用例（含 `security.test.mjs`） |
| [SECURITY.md](SECURITY.md) | 协议 v2 威胁模型、密码学方案、接口、测试要求的权威规格 |
| [DESIGN.md](DESIGN.md) | 原始模块契约（顶部注明 v2 以 SECURITY.md 为准） |
| [README.md](group-collab/README.md) | 安装、配置、命令、同步机制、v2 安全说明 |
| [VERIFICATION.md](VERIFICATION.md) | 本文件 |

安装状态：`plugin_manager install_bundle` → `application: applied`、`warnings: []`、`version: 2.0.0`；profile `package.json` bundles 含 `@local/dsh-group-collab`（Junction 链接到本工作区）；插件行 `include:group-collab` 激活；`cordis_inspect_query Tool/listTools` 可见 `group_room`/`group_share`；`GET /group-collab/status` 仅 loopback 可用（非 loopback 403，已有 fake-ctx 测试覆盖）。

## 2. 自动化测试（57/57）

命令（`<repo>/group-collab`，Node 22+；Node 24 需 glob 不能直接传目录）：

```powershell
node --test "tests/*.test.mjs"
```

| 文件 | 通过 | 覆盖 |
|---|---|---|
| `tests/net.test.mjs` | 17 | v2 challenge/proof、统一 401、限流锁定、密文篡改/AAD/重放、盲存储、旧房间、UDP v2、持久化、端口释放、金丝雀（HTTP body/房间 JSON 无明文） |
| `tests/security.test.mjs` | 10 | 非成员无内容、金丝雀（wire/磁盘/日志面）、反枚举、完整性、限流、旧房间、UDP、authKey 被盗残余风险、密码策略 |
| `tests/e2e.test.mjs` | 2 | 真实 RoomServer + CollabRuntime 双/三成员完整流程（上传→同步→冲突→readme→备份→回滚→通知） |
| `tests/workspace.test.mjs` | 11 | 目录/快照/clean/路径穿越/符号链接/状态 |
| `tests/backup.test.mjs` | 9 | 版本/回滚/保留/损坏索引 |
| `tests/readme.test.mjs` | 6 | 项目与成员 readme |
| `tests/fake-ctx.test.mjs` | 2 | 插件注册/卸载/命令/工具/loopback 状态路由 |

结果：**tests 57, pass 57, fail 0, exit 0（~3.6s）**。

## 3. 协议 v2 保密性实测（真实 Harness + 原始 HTTP 攻击面）

环境：真实安装的插件，房间 `864209`（强密码，本记录不保存密码）；共享文件含金丝雀 `CANARY-9f7c2d-DO-NOT-LEAK` 与说明 `NOTE-CANARY-4a91`；服务器房间文件 `$DSH_HOME/group-collab/rooms/864209.json`。

Lead 独立 live 脚本结果 **20/20 PASS**：

- 已知/未知房间 challenge 都返回 200 且 key 集合一致；未知房间盐连续探测保持稳定 → 不能通过盐变化区分房间存在性。
- 无密码 join（伪造 proof）→ `401 UNAUTHORIZED`；未知房间 join → **逐字节相同的 401**（不可枚举）。
- 无 token 的 `latest`/`status`/`publish` → 401；旧式 `status?room=` 不再泄露。
- challenge/401 响应中不含密码、文件内容、说明金丝雀。
- 服务器磁盘房间 JSON：键仅 `version,number,name,rev,snapshot,saltAuth,saltContent,authKey,createdAt,lastUpdate`；`snapshot` = `{rev,cipher,at}`；`cipher` = `{v,iv,tag,data}`；**不含 `password/passwordHash`、文件内容、说明、文件名、成员名金丝雀**。
- 合法客户端（密码）本地解密成功读到金丝雀；以另一成员身份 publish 加密更新后，本插件轮询**自动解密并同步**到 `shared/peer-canary.md`，而服务器房间 JSON 仍无任何明文/金丝雀。
- 安装（v2.0.0）后重新上传 rev4 成功，证明重装后合法链路正常。

QA 独立 `security.test.mjs` 额外实测证据：

- 抓包/记录 fetch：publish 请求体 key 恰为 `[baseRev,cipher,member,token,v]`；所有请求/响应体无内容/说明/路径金丝雀；**密码从不出现在任何线上请求**；成员名仅出现在协议允许的 `member`/`members` 元数据中。
- 篡改 `cipher.data/tag/iv` 或把旧 rev 密文重放 → 合法客户端 `PROTOCOL` 拒绝；`CollabRuntime.sync` 后 `shared/` 逐字节不变（不写坏数据）；恶意成员加密非法路径 `../escape.txt` → `BAD_PATH`，不落盘。
- 限流：第 31 次 challenge → 429 + `Retry-After`；5 次错误 join 后即使密码正确也 429；成功 join 清零计数。
- 旧 v1 房间：重命名为 `.json.legacy-v1` 且不提供；同号可用 v2 重建。
- 残余风险实测：仅拿房间 JSON 的 `authKey`（无密码）可以伪造 proof 加入并拿到密文，但**无法解密**（内容密钥由密码派生）。

## 4. 需求对照（原有功能 + 本次保密要求）

| 需求 | 实现 | 验证 |
|---|---|---|
| 创建插件接入 DSH | Host-only bundle v2.0.0，已安装激活 | 插件行/工具清单/HTTP 路由 |
| 聊天框输入房间号+密码加入群组 | `/group create|join`；v2 挑战应答，密码不过网；命令 `recordInput:false` | 命令/工具注册、fake-ctx、live create/join |
| 工作区三个文件夹（共享/自己/备份） | `shared/` `own/` `backup/`（+`.dsh-group/` 状态） | live 目录 |
| own/ 开发，聊天框上传到 shared/ | `/group upload`；服务端只收密文 | live rev2/rev4；e2e |
| 上传不破坏备份文件夹 | 备份只追加版本、不覆盖/不同步给他人 | live v1..v8；backup 单测 |
| 多成员在线时共享更新覆盖同步 | 服务器 rev + 成员轮询；密文解密后整体覆盖 shared/ | e2e 字节一致；live peer→本机同步 |
| 新成员上线拉取最新共享 | join 返回最新密文快照并立即解密覆盖；发布自己的成员 readme | e2e 后加入成员；live |
| 备份记录每次共享更改 | 上传/同步/恢复/初始化/成员 readme 都生成版本镜像 | live 8 个版本；单测 |
| shared/readme 总 readme + 每成员 readme | `shared/readme/README.md` + `members/<成员>.md` 自动生成/保留 | live 多成员 readme；单测 |
| 共享更新向对话注入目标/解释 | 更新通知注入（无 goal 时创建短目标解释，否则 followup/inject） | live 已收到更新/成员上线说明消息 |
| **非成员不能通过网络随意获得内容** | v2 端到端加密 + 挑战应答 + token 鉴权 + 限流 + 反枚举 + 盲服务器 + loopback 状态路由 | 57/57 测试 + live 20/20 攻击面检查 |

## 5. 安全模型、残余风险与限制

**达到的目标**：无密码者无法通过网络获得共享内容（直接接口全部 401，密文不可解）；抓包者拿不到密码/明文（只能看到密文、盐/nonce、成员 id/名、房间号、rev 等元数据）；房间服务器/其磁盘只能存密文；无 token 的状态/最新/发布接口不可用；房间枚举与密码爆破受到统一错误响应与限流阻挡。

**仍需注意**：

1. **服务器持有 authKey verifier**：能读房间 JSON 的攻击者可伪造 proof **加入**房间（拿到密文、可发布垃圾数据造成 DoS/覆盖），但没有密码就无法派生 contentKey，**仍不能读取内容**；v2 未做服务器身份/完整性签名，房间服务器是信任根。
2. **离线口令风险**：磁盘泄露 + 弱密码时，攻击者可离线 scrypt 猜密码（房间 JSON 含 `saltAuth/saltContent/authKey`），猜中即可解密历史密文。请用强密码；`rememberPassword` 会在本机 `.dsh-group/member.json` 明文保存密码（可 `/group set rememberPassword off`，代价是重启需重新加入）。
3. **元数据可见**：房间号/名、成员名/ID、rev、时间、流量大小/时序在网络与服务器上可见；内容与更新说明已加密。
4. **无 TLS**：内容端到端加密，但公网仍建议 VPN/隧道；跨公网需显式地址（UDP 发现跨不了公网），且建议只放行可信 IP。
5. **限流按来源 IP**：NAT/反向代理后所有成员共用一个桶，大群同时加入可能被 30 次/分钟的 challenge 限制短时影响。
6. **未知房间伪盐每进程稳定**：避免连续探测枚举；服务器重启后伪盐变化，跨重启时序对比仍有理论旁路（只泄露“某房间号是否存在”这类元数据，不泄露内容）。
7. **群组权限仍然扁平**：有密码即可读/覆盖全部 `shared/`，没有成员 ACL/踢人/审计；只邀请可信成员。
8. **旧数据**：v1 房间文件会被改名 `.legacy-v1` 且不再加载；旧工作区里 <8 位的密码无法自动重连（需重新创建/加入 v2 房间）。本次已删除旧 v1 演示房间 `731204`，当前演示房间为 `864209`。
9. **其他未覆盖**：真实跨主机 LAN 双机实测（本机 loopback + 地址推导单测）；浏览器 UI 图标最终渲染截图；公网反向代理 TLS 方案未实测；`/leave` 对未知格式 token 幂等返回 200（无泄露，保持 v1 语义）。

## 6. 使用与公网建议

```text
/group help
/group create 123456 <强密码≥8位> 我的项目
/group join   123456 <强密码≥8位> http://<房主地址>:45890
/group upload 完成登录模块
/group sync
/group status
/group backup list / restore <版本>
/group address
```

- 公网/跨机器：优先 VPN（Tailscale/WireGuard/ZeroTier）或 SSH 端口转发，只把 45890 暴露在加密覆盖网内；内容虽已 E2E 加密，VPN 仍能保护元数据并简化可达性。不建议直接把 45890 裸映射到公网。
- 端口：房间服务器跟随房主进程；不用时可用防火墙封禁 45890/45891，或卸载插件。
- 升级完成后建议刷新/重启 DSH，在插件列表确认「群组协作」为 v2.0.0，并输入 `/group help` 实际体验一次。
