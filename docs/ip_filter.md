# pg_net IP 过滤（SSRF 防护）

本文介绍 pg_net 的 IP 过滤能力：通过 `pg_net.blocked_cidrs` 与 `pg_net.allowed_cidrs` 两个 GUC，限制后台 worker 可以把请求发往哪些地址。

相关代码：

- `src/ip_filter.c` / `src/ip_filter.h`：匹配逻辑与 libcurl 回调
- `src/core.c`：注册回调、生成错误信息
- `src/core.h`：`CurlHandle` 中的拦截状态
- `src/worker.c`：GUC 注册与 SIGHUP 重新加载
- `test/test_ip_filter.py`：集成测试

## 1. 它解决什么问题

任何能调用 `net.http_get()` / `net.http_post()` / `net.http_delete()` 的角色，都能让 pg_net 的后台 worker 向任意地址发起请求。在多租户、共享数据库或云环境中，这会形成 SSRF 攻击面：worker 可能被指向：

- 回环地址 `127.0.0.1` / `::1`（同机或同容器内的其他服务）
- 云元数据地址 `169.254.169.254`
- 内网网段（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 等）
- 链路本地地址 `fe80::/10`

IP 过滤在 **TCP 建连之前** 依据真实的目标 IP 做判定，被拒绝的地址不会建立任何连接。

## 2. 配置项

| GUC | 默认值 | 说明 |
|---|---|---|
| `pg_net.blocked_cidrs` | `''` | 逗号分隔的 CIDR 列表，命中即拒绝 |
| `pg_net.allowed_cidrs` | `''` | 逗号分隔的 CIDR 列表，命中即放行，优先于 blocked |

两个参数都是 `PGC_SIGHUP` 级别，定义在 `src/worker.c` 的 `_PG_init()` 中，并带有 check/assign 钩子。

### 2.1 语法

- 逗号分隔，例如 `'127.0.0.0/8,::1/128,10.0.0.0/8'`
- 支持 IPv4 与 IPv6
- 不带前缀的裸 IP 等价于 `/32`（IPv4）或 `/128`（IPv6）
- 条目两侧的空格和制表符会被忽略
- IPv4-mapped IPv6（`::ffff:a.b.c.d`）会归一化为 IPv4 后参与匹配，因此 `::ffff:127.0.0.1` 能命中 `127.0.0.0/8`
- 非法的 IP / 前缀会在配置被应用时拒绝（会话级 `SET` 立即报错；`postgresql.conf` / `ALTER SYSTEM` 的值在 reload 时校验，校验失败保留旧值并记录日志）
- 空字符串表示不配置任何规则

### 2.2 匹配优先级

对每一次连接尝试，按以下顺序判定：

1. 目标 IP 命中 `pg_net.allowed_cidrs` → **放行**（不再检查 blocked）
2. 否则命中 `pg_net.blocked_cidrs` → **拒绝**
3. 都不命中 → **放行**

这意味着：

- `allowed_cidrs` 只是 blocked 的例外清单，**不是“仅允许”白名单**。如果只配置 `allowed_cidrs` 而不配置 `blocked_cidrs`，所有地址仍然可以访问。
- 两个列表都为空是默认行为，与未引入 IP 过滤之前完全一致。
- 同一个 IP 同时命中两个列表时，allowlist 获胜。

### 2.3 生效方式

```sql
alter system set pg_net.blocked_cidrs to '127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10';
select pg_reload_conf();
```

worker 在 `SIGHUP` 时会执行 `ProcessConfigFile(PGC_SIGHUP)`，从而触发 assign 钩子重新解析列表。也可以直接重启 worker：

```sql
select net.worker_restart();
select net.wait_until_running();
```

> 普通会话中的 `SET pg_net.blocked_cidrs = ...` 只会影响当前会话加载的列表，不会改变后台 worker 的判定。持久化配置请使用 `ALTER SYSTEM` 或 `postgresql.conf` 并 reload。

## 3. 工作原理

pg_net 使用 libcurl 的 multi/easy 接口异步执行请求。过滤通过两个回调实现：一个在建连前拦截（主路径），一个在建连后、发请求前复核（兜底）。

### 3.1 主拦截：`CURLOPT_OPENSOCKETFUNCTION`（建连前）

`pg_net_opensocket_cb()` 在 libcurl 每次要为请求创建 socket 时被调用，参数中已经包含 **解析后的目标 `sockaddr`**：

- 命中 blocked → 返回 `CURL_SOCKET_BAD`，libcurl 不会调用 `connect()`，请求以连接失败结束
- 命中 allowed / 未命中任何规则 → 由回调自己调用 `socket()` 并把 fd 交还给 libcurl

因为判定依据是“准备连接的 IP”而不是用户写的 URL，以下路径都会被覆盖：

- 每一次新的连接尝试
- 每一次重定向跳转（`3xx` 的 `Location` 指向内网地址时，新连接同样被拦截）
- 每一次 DNS 重新解析（DNS rebinding 在建立新连接时会被重新检查）

### 3.2 兜底：`CURLOPT_PREREQFUNCTION`（建连后、发请求前）

`pg_net_prereq_cb()` 在连接已经建立、HTTP 请求尚未发出时执行，主要用于两类场景：

- **复用 keep-alive 连接**：没有新建 socket，不会经过 opensocket 回调，但仍然需要确认对端 IP 是否仍被允许
- **运行时收紧规则**：通过 SIGHUP 把某个网段加入 blocked 后，已经建立的连接在下一次发请求前会被复核并中止

命中 blocked 时返回 `CURL_PREREQFUNC_ABORT`，libcurl 以 `CURLE_ABORTED_BY_CALLBACK` 结束请求。

### 3.3 判定流程

```
                     ┌─────────────────────────────┐
                     │ 配置了 allowed / blocked ?  │
                     └──────────────┬──────────────┘
                          否 │              │ 是
                             ▼              ▼
                       放行（不过滤）  解析目标 IP
                                            │
                          ┌─────────────────┴─────────────────┐
                          │ 命中 allowed_cidrs ?              │
                          └───────┬───────────────────┬───────┘
                              是  │                   │ 否
                                  ▼                   ▼
                                放行        ┌─────────────────────┐
                                            │ 命中 blocked_cidrs ?│
                                            └──────┬──────┬───────┘
                                              是   │      │ 否
                                                   ▼      ▼
                                            拒绝，不建连   放行
```

当规则非空但目标地址无法解析成 IP（非 IP 地址族）时，采取 **fail closed**：拒绝该连接并记录 `pg_net.ip_filter_unparseable`。没有配置任何规则时则保持默认放行，不改变原有行为。

## 4. 错误上报

被拦截的请求不会产生 HTTP 响应，而是写入 `net._http_response`：

- `status_code` 为 `NULL`
- `timed_out` 为 `false`
- `error_msg` 以稳定的错误码开头

### 4.1 错误码

| `error_msg` 前缀 | 含义 |
|---|---|
| `pg_net.ip_filter_blocked` | 目标 IP 命中 `pg_net.blocked_cidrs`，消息中会带上具体 IP 和命中的 GUC |
| `pg_net.ip_filter_unparseable` | 已配置规则，但目标地址无法解析为 IP，按 fail closed 拒绝 |

错误码定义在 `src/ip_filter.h` 中，属于对外的稳定接口，客户端和测试可以按前缀匹配，不要在后续版本中随意修改。

### 4.2 三种归因

libcurl 在 opensocket 回调返回 `CURL_SOCKET_BAD` 后，统一上报 `CURLE_COULDNT_CONNECT`，这与真实的网络连接失败是同一个错误码。pg_net 通过每个 handle 上的状态进行区分：

| 场景 | `error_msg` 形态 |
|---|---|
| 所有候选地址都被拦截，没有任何 socket 创建成功（也从未 `connect()`） | `pg_net.ip_filter_blocked: destination 10.0.0.5 matched pg_net.blocked_cidrs (no connection attempted)` |
| 部分候选地址被拦截，剩余地址真实连接失败 | `pg_net.ip_filter_blocked: destination 10.0.0.5 matched pg_net.blocked_cidrs; connection failed: Couldn't connect to server` |
| 完全没有被过滤，纯粹的网络失败 | 不包含 `pg_net.ip_filter` 前缀，保持 curl 原始错误信息 |
| prereq 兜底中止 | 直接输出命中原因，例如 `pg_net.ip_filter_blocked: destination 10.0.0.5 matched pg_net.blocked_cidrs` |

其中 `(no connection attempted)` 是判断“请求根本没有触达目标”的关键标记。混合场景说明一个域名解析出了多个 IP：被拦的地址没有建连，剩下的地址确实尝试过但失败了。

### 4.3 查询示例

```sql
-- 查看最近的 IP 过滤拒绝
select id, status_code, timed_out, error_msg
from net._http_response
where error_msg like 'pg_net.ip_filter%'
order by id desc
limit 20;

-- 检查某个请求的结果
select status_code, timed_out, error_msg
from net._http_response
where id = <request_id>;
```

日志中也会记录拦截行为：

- 拦截：`WARNING: pg_net: aborting request to <ip> (matched pg_net.blocked_cidrs), no connection attempted`
- 放行：`DEBUG1: pg_net: <ip> allowed by pg_net.allowed_cidrs`

## 5. 覆盖场景与不覆盖场景

### 5.1 覆盖

- **直连**：检查 libcurl 从 URL 解析出的目标 IP
- **重定向**：`3xx` 指向内网地址时，新连接在建连前被拒绝
- **DNS rebinding**：每次重新解析 / 新建连接都会重新判定，域名在两次请求之间切换 A 记录无法绕过
- **keep-alive 复用连接**：通过 prereq 回调复核对端 IP
- **回环地址**：网络防火墙和云安全组通常无法限制同一主机/容器内的 loopback 流量，本过滤可以
- **运行时收紧**：SIGHUP 更新规则后，新建连接立即生效，复用连接在下一次发请求前生效

### 5.2 不覆盖 / 注意事项

- **HTTP/HTTPS/SOCKS 代理**：过滤检查的是 TCP 对端 IP。配置代理（包括 postmaster 继承的 `http_proxy`、`https_proxy`、`all_proxy` 环境变量）后，对端是代理而不是最终目标，此时本过滤只能算 best-effort，应在代理侧做目的地限制。
- **DNS 查询本身仍会发生**：域名解析在 opensocket 之前完成，被拦截只会阻止 TCP 连接，不会阻止 DNS 查询。
- **已在发送中的请求**：SIGHUP 收紧规则不能撤回已经发出的请求，只能阻止后续建连和复用连接上的下一次请求。
- **协议范围**：pg_net 只允许 `http` / `https`，其他协议不会进入该路径。
- **配置权限**：`pg_net.blocked_cidrs` / `allowed_cidrs` 不是 `GUC_SUPERUSER_ONLY`，但修改全局值仍需要 `ALTER SYSTEM` 权限（超级用户，或被 `GRANT ALTER SYSTEM ON PARAMETER` 授权的角色）。普通会话的 `SET` 不会影响 worker。

## 6. 配置示例

### 6.1 基线：屏蔽回环、链路本地和云元数据

```sql
alter system set pg_net.blocked_cidrs to
  '127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10';
select pg_reload_conf();
```

### 6.2 屏蔽所有私网，但保留一个内部 API

```sql
alter system set pg_net.blocked_cidrs to
  '127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10,'
  '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';
alter system set pg_net.allowed_cidrs to '10.0.5.100/32';
select pg_reload_conf();
```

### 6.3 只允许访问指定地址（实现“仅白名单”效果）

由于默认是放行，若要做到“只允许访问某几个地址”，需要把“其余所有地址”加入 blocked，再用 allowed 开例外：

```sql
-- 拒绝所有 IPv4 / IPv6，再放行指定地址
alter system set pg_net.blocked_cidrs to '0.0.0.0/0,::/0';
alter system set pg_net.allowed_cidrs to '203.0.113.10/32,2001:db8::10/128';
select pg_reload_conf();
```

## 7. 运维与排查

```sql
-- 查看当前配置
show pg_net.blocked_cidrs;
show pg_net.allowed_cidrs;

-- 修改并 reload
alter system set pg_net.blocked_cidrs to '127.0.0.0/8,::1/128';
select pg_reload_conf();

-- 确认 worker 状态
select net.worker_restart();
select net.wait_until_running();
```

排查步骤：

1. 确认 `show` 看到的值符合预期
2. 确认 worker 已加载新配置（`pg_reload_conf()` 后检查日志，或直接重启 worker）
3. 查询 `net._http_response.error_msg`，按错误码和 `(no connection attempted)` 判断是过滤拒绝还是真实网络失败
4. 如果配置了代理，确认 worker 进程环境中的 `*_proxy` 变量；有代理时过滤不再权威
5. 需要看放行日志时，将 `log_min_messages` 调到 `debug1`

## 8. 测试

`test/test_ip_filter.py` 覆盖以下行为：

- GUC 默认值为空
- 命中 blocked 时请求被拒绝，`status_code` 为空、`timed_out` 为 `false`，`error_msg` 以 `pg_net.ip_filter_blocked` 开头并包含 `(no connection attempted)`
- 命中 allowed 时即使同时命中 blocked 也会成功
- 两个列表都不命中时请求正常通过
- 重定向请求不会绕过过滤

测试通过 `alter system set` + `net.worker_restart()` 驱动配置加载，以保证时序确定；每个用例结束后恢复空配置。

## 9. 与上游合并的关系

IP 过滤是本地功能，主要落在一个独立文件里，尽量减少与 `supabase/pg_net` 上游合并时的冲突面：

- 新增：`src/ip_filter.c`、`src/ip_filter.h`
- 修改：`src/core.c`（注册两个回调、错误信息归因）、`src/core.h`（`CurlHandle` 状态字段）、`src/worker.c`（GUC 注册与 SIGHUP 重载）
- 上游代码中的请求执行主流程、响应写入表结构均未改变

`Makefile` 使用 `SOURCES = $(wildcard src/*.c)`，`ip_filter.c` 会被自动编译，无需修改构建文件。
