# 群组协作插件 — 网络保密性加固设计（协议 v2）

目标（用户要求）：**非成员不能通过网络随意获得共享内容**。顺带修复：明文传密码、未鉴权状态接口、无登录限流、UDP 发现泄露房间名。

范围：`lib/protocol.js`、新增 `lib/crypto.js`、`lib/room-server.js`、`lib/room-client.js`、`tests/net.test.mjs`（net-dev 负责）；`index.js`（状态路由 loopback 限制，Lead）；`tests/security.test.mjs` 与 e2e 复核（qa-verifier）；文档/安装/实测（Lead）。

## 威胁模型与目标

| 攻击者能力 | 加固后应达到 |
|---|---|
| 能访问 TCP 45890 / UDP 45891，但没有密码 | 不能获得任何共享文件内容；不能确认某个房间是否存在；不能枚举成员/版本 |
| 能抓包/中间人（HTTP 明文） | 只能看到密文、随机盐/nonce、成员 id/名等元数据；**看不到密码、文件内容、更新说明** |
| 拿到房主磁盘上的房间 JSON | 只能看到 authKey（可冒充加入）与密文；**无法解密共享内容**（内容密钥由密码派生，服务器不保存密码） |
| 猜测密码 | 只能在线尝试，受每 IP 限流/锁定；4-8 位房间号无法枚举（unknown 房间与错误密码响应一致） |
| 恶意 UDP 发现应答（钓鱼） | 可把客户端引到假服务器，但客户端用密码本地派生内容密钥，假服务器无密码无法伪造可解密/可认证的快照；GCM 失败即拒绝 |

明确不在本轮范围：房间成员权限分级/踢人/审计（后续可做）；本机明文密码与磁盘加密（仍建议 rememberPassword off）；真正的公网中继/NAT 穿透（仍建议 VPN/隧道）。

## 密码学方案（Node 内置 `node:crypto`，无新依赖）

> 实现备注（已验证）：未知房间的 challenge 盐不是每次随机，而是由每进程随机 secret 经 HMAC 派生的**稳定**伪盐；这样连续探测两次也看不出“未知房间盐会变、真实房间盐稳定”的差异。代价是服务器进程重启后伪盐会变（真实房间盐持久化不变），跨重启时序对比仍有理论上的枚举旁路，属已记录残余风险。房间文件只保存 `saltAuth/saltContent/authKey(verifier)/密文`；持有房间文件者可离线猜测密码（scrypt 每次约几十毫秒）并伪造 proof 加入，但只有猜中密码才能派生 contentKey 解密内容。

- KDF：`scryptSync(password, salt, 32)`，salt 16B，参数沿用 Node 默认（N=16384, r=8, p=1）。
- 每房间两个固定随机盐：`saltAuth`（认证）、`saltContent`（内容加密）。
- `authKey = scrypt(password, saltAuth, 32)`；服务器存储 `authKey`（hex，称为 verifier），**不存密码**。
- `contentKey = scrypt(password, saltContent, 32)`；**只存在于成员进程内存**，服务器永远拿不到。
- 认证：客户端向服务器取 challenge（返回 `saltAuth/saltContent/nonce`），计算
  `proof = HMAC-SHA256(authKey, "dsh-group/v2:" + room + ":" + nonce + ":" + member.id)`，发送 proof（不是密码）。
  服务器用存储的 authKey 按同样公式校验（constant-time），nonce 单次有效、60s 过期。
- 内容加密：AES-256-GCM，随机 12B IV，AAD = `"dsh-group/v2:" + room + ":" + rev`（绑定版本，防重放/换 rev）。
  明文 payload = UTF-8 JSON：`{ by:{id,name}, note, at, files:[{path,size,sha256,data(base64)}], changes:{added,modified,deleted} }`。
  密文格式：`{ v:2, iv:base64, tag:base64, data:base64 }`。
- 服务器只保存密文；`rev` 由服务器分配，客户端加密时用 `rev = baseRev + 1` 作为 AAD，双方一致。
- 协议版本 `PROTOCOL_VERSION = 2`；v1 客户端/服务器互斥（旧房间不兼容，见下）。

## 接口变更（服务器 HTTP）

- `POST /group/v1/challenge` body `{ v:2, room }` →
  `{ ok:true, v:2, room, saltAuth, saltContent, nonce }`
  - 对任何合法格式的房间号都返回形状相同的随机 challenge（未知房间也生成随机值）→ 不能枚举房间存在性。
  - 每 IP 限流（如 30 次/分钟）。
- `POST /group/v1/join` body `{ v:2, room, member, nonce, proof }` →
  成功 `{ ok:true, token, server:{origin,hostName}, room:{number,name,rev,createdAt}, members, snapshot:{rev, cipher}|null, syncRequested }`
  - 未知房间 / 错误 proof / 过期 nonce 统一返回 401 `UNAUTHORIZED`（相同 message）。
  - 每 IP 失败 5 次/60s → 锁定 60s，返回 429 `TOO_MANY_REQUESTS`（带 `retryAfterSeconds`）。
  - 成功后清空失败计数。
- `POST /group/v1/heartbeat` `{ token, member, rev }`、`POST /leave` 不变（token 鉴权）。
- `GET /group/v1/latest?token=&rev=` 不变，但返回 `snapshot:{rev,cipher}`（密文）；客户端解密。
- `POST /group/v1/publish` body `{ token, member, baseRev, cipher }`：
  - 校验 token、baseRev；`cipher` 形状/大小校验；`rev = baseRev + 1`；服务器存 `{rev, cipher, at}`，不解析内容、不算 changes。
  - 409 冲突返回 `{ rev, lastUpdate, snapshot:{rev,cipher} }`（密文，客户端解密后放入 `CollabError('CONFLICT').details`）。
- `GET /group/v1/status?token=`：**必须带 token**（不再接受 room 参数）；无 token → 401。返回房间号/名/rev/成员；不再返回 snapshotDigest（无明文可算）。
- UDP 发现应答改为 `{ t:'dsh-group-room', v:2, room, url }`（**去掉房间名**）；客户端只接受 `v===2`。
- HTTP body 上限：发布请求可能因密文膨胀变大；`MAX_BODY_BYTES` 提高到 96 MiB，其余快照限制仍在客户端解密后校验（≤2000 文件/32 MiB/单文件 8 MiB）。
- 房间文件 v2 格式：`{ version:2, number, name, rev, snapshot:{rev, cipher, at}, saltAuth, saltContent, authKey, createdAt, lastUpdate }`，原子写、无明文。
- 旧 v1 房间文件（含 `passwordHash` 或 `version!==2`）：启动加载时改名为 `<room>.json.legacy-v1` 并忽略（日志 warn）；`createLocalRoom` 视其为不存在，可重建同名房间。旧演示房间由 Lead 清理。

## 客户端（RoomClient）行为

- `join()`：challenge → 本地派生 authKey/contentKey → proof → join → 用 contentKey 解密 snapshot → 返回 `{token, room, members, snapshot(明文), syncRequested, server}`。
- `latest(knownRev)`：服务器返回 cipher 则解密后返回明文 snapshot。
- `publish({baseRev, snapshot, note})`：内部用 contentKey 加密 `{by, note, at, files, changes}`（by 取 member），发送 cipher；保持现有函数签名，`member.js` 无需改动。
- 冲突错误：解密 409 的 cipher 后抛 `CollabError('CONFLICT', msg, { snapshot, lastUpdate, rev })`。
- `status()` 用 token 请求。
- `discoverRoom()` 只接受 v2 应答，返回 `{origin, room, via}`（name 不再提供）。
- `close()` 清空内存中的 authKey/contentKey（`buffer.fill(0)`）。
- 不在任何请求/URL/日志里发送密码。

## 客户端校验（解密后）

解密后必须 `normalizeSnapshot()`（路径安全、大小/数量/摘要校验），失败抛 `PROTOCOL`/`BAD_SNAPSHOT`；GCM tag/AAD 失败一律拒绝（不能把损坏/伪造数据写入 shared/）。

## index.js（Lead）

- `/group-collab/status` Web 路由：仅允许 loopback 来源（`127.0.0.1`、`::1`、`::ffff:127.*`），否则 403；响应不包含共享内容（仅目录统计/房间/成员），保持现状字段。
- 文档更新：README 安全章节改为“协议 v2 内容端到端加密 + 挑战应答”，公网仍建议 VPN/TLS 隧道（插件自身不做 TLS）。

## 测试要求（必须）

`tests/net.test.mjs` 重写/扩展覆盖：
1. 挑战应答：正确密码加入成功；错误密码 401；缺 proof/过期 nonce/重放 nonce 401；unknown 房间与错误密码响应形状一致。
2. 线上无明文：challenge/join/latest/publish 的请求/响应 JSON 中不出现密码或已知文件内容标记（用独特字符串做金丝雀）；publish 响应只有 cipher；服务器房间文件字符串中不出现金丝雀。
3. 密文可解/不可篡改：合法成员 join 后拿到明文快照；篡改 cipher.data/tag 或 AAD rev 后解密失败。
4. 鉴权：无 token 的 latest/publish/status 401；无 token 不能拿到房间信息。
5. 限流：连续错误 join 达到阈值后 429，且成功加入后失败计数清零。
6. 旧 v1 房间文件被安全忽略/改名，可重建同名 v2 房间。
7. 发现：UDP 应答 v2、不含房间名；客户端拒绝 v1 应答。
8. 既有能力不回归：并发发布冲突 409+密文最新快照、重启持久化、关端口释放。

qa-verifier：新增 `tests/security.test.mjs`（黑盒 HTTP 攻击面验证 + 金丝雀）并复核 `e2e.test.mjs` 全绿；不修改插件源码。

## 验收标准（Lead 实测）

- 全量测试通过（net + security + e2e + workspace/backup/readme + fake-ctx）。
- 重装插件后：合法 create/join/upload/sync/restore/readme 正常。
- 攻击面实测：
  - 无密码原始 HTTP：challenge 可行但 join 401、status/latest/publish 401、拿不到任何文件内容；
  - 枚举：对不存在房间的 challenge 与已存在房间不可区分；join 错误响应一致；
  - 抓包视角：内容/说明/密码均不出现在任何响应或服务器磁盘文件中（用金丝雀字符串 grep 房间 JSON、日志）；
  - 房间 JSON 只有 authKey/盐/密文；服务器进程不持有 contentKey。
- 更新 `README.md`、`VERIFICATION.md` 安全章节与协议版本说明。
