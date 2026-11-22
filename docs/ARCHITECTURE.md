# 架构

CulvertProxy 的核心是「一个引擎、两种入口、一套路由」。

- `LocalProxyServer`：SOCKS5 与 HTTP CONNECT 混合入口，给显式配置了代理的客户端用。
- `InterceptServer`：接收 `CulvertHook.dll` 重定向过来的连接，给桌面应用做透明接管。
- 两者最终都进入 `RuleEngine` → `OutboundConnector` → `TunnelFactory`，共用健康度、统计和连接表。

```text
LocalProxyServer ─┐
                  ├─▶ RuleEngine ─▶ OutboundConnector ─▶ TunnelFactory ─▶ 目标
InterceptServer ──┘         │                  │
                            │                  ├─ 直连（DoH/静态 hosts/系统解析）
                            │                  ├─ 阻断
                            │                  └─ 多跳 SOCKS5 / HTTP / TLS
                            ▼
                    ConnectionRegistry / TrafficStats
```

## 进程注入

`ProcessInjector` 只处理当前登录会话的 x64 进程。

1. `OpenProcess` 获取创建线程、读写虚拟内存与查询权限。
2. `IsWow64Process2` 排除 32 位进程；系统关键进程、杀毒软件、构建工具与用户排除项直接跳过。
3. `VirtualAllocEx` 写入 `CulvertHook.dll` 的 UTF-16 绝对路径。
4. `CreateRemoteThread` 调用 `LoadLibraryW`。
5. 远程线程退出码非零即视为模块加载成功；Hook 会保留一个命名就绪事件，注入器最多等 400 ms，用来缩短首次网络调用的竞态窗口。
6. 成功的 PID 记入内存表，之后每 1.2 秒扫描新进程；失败项冷却 30 秒再试。

注入不是继承的。新启动的子进程必须在下一轮扫描中被单独注入。系统服务、会话 0、高完整性进程（未以管理员运行 CulvertProxy 时）不会进入。

## Winsock Hook

Hook 用 MinHook 做函数内联挂钩，因此无论调用来自静态导入、延迟加载还是 `GetProcAddress`，都会经过我们。

| 函数 | 行为 |
| --- | --- |
| `getaddrinfo` / `GetAddrInfoW` | 公共域名返回 `198.19.0.0/16` 内的稳定 fake-IP，不发起真实 DNS 查询；`localhost`、单标签主机名、`.local`、`.lan`、`.home.arpa`、IP 字面量和 `AI_PASSIVE` 走原函数。`AF_INET6` 请求返回 `::ffff:198.19.x.y`，由 IPv6 接管入口还原。引擎本地 DNS 默认使用不相交的 `198.18.0.0/16` |
| `freeaddrinfo` | 识别并释放 Hook 自己分配的 fake 链表，其余交给原函数 |
| `connect` | 非回环 TCP 目标改为连接回环接管入口，先发送目标前导；fake-IP 会还原为域名 |
| `WSAConnect` | 同上，`lpCallerData` 在前导之后发送，`lpCalleeData` 置空 |
| `ConnectEx` / `WSAIoctl` | 覆盖 .NET 等异步 Socket。`WSAIoctl` 返回指向本 Hook 的扩展函数指针，内联 Hook 同时兜底已经缓存的指针。前导通过 ConnectEx 自带的发送缓冲发送，IOCP 与 overlapped 语义保持不变 |
| `sendto` / `WSASendTo` | 发往 fake-IP 的 UDP 数据报直接拒绝，促使 QUIC 回落 TCP |

IPv4 回环不接管；IPv6 回环与未指定地址不接管。UDP 目标不是 fake-IP 时保持原行为。原始套接字不接管。非阻塞套接字在重定向时用 `select` 等待可写，然后完成前导发送，不修改应用的阻塞模式。

`FreeAddrInfoW` 在 ws2_32 中与 `freeaddrinfo` 共用入口，因此只需挂钩 `freeaddrinfo`；释放时会同时检查窄字符与宽字符的 fake 分配链表。

套接字会先 `getsockname` 判断地址族：IPv4 套接字重定向到 `127.0.0.1:<port>`，IPv6 套接字重定向到 `[::1]:<port6>`。目标若是 IPv4-mapped IPv6 地址，会拆回 IPv4 处理，避免把 IPv4 sockaddr 塞给 IPv6 套接字。

ConnectEx 的合并缓冲存放在固定槽位池里。同步完成立即归还；返回 `WSA_IO_PENDING` 的槽位由内核持有，10 秒后由分配器回收。发送缓冲超过 1 KiB 的 ConnectEx 调用会被拒绝，因为主流运行时不会这样用，而扩大每个注入进程的常驻虚拟内存不值得。

### 前导协议 CPX1

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | ASCII `CPX1` |
| 4 | 1 | 版本，当前 1 |
| 5 | 1 | 标志位，保留 0 |
| 6 | 4 | 发起进程 PID，小端 |
| 10 | 16 | 每次引擎启动重新生成的随机令牌 |
| 26 | 1 | 地址类型：1 IPv4，2 域名，3 IPv6 |
| 27 | 2 | 端口，大端 |
| 29 | 变长 | IPv4 4 字节 / IPv6 16 字节 / 域名 1 字节长度 + ASCII |

入口在 5 秒内读不完前导就断开。令牌用固定时间比较。目标端口为 0、域名为空或含控制字符时拒绝。前导之后就是应用的原始字节流，不做二次封装。

PID 只作为兜底。正常情况下入口用 `GetExtendedTcpTable` 把客户端端口映射回真实进程，防止本机其他进程伪造 PID 套用规则。

## 接管失败时的行为

- 上游连接失败或规则阻断：入口对客户端发 RST，连接表记录错误与耗时。
- 引擎停止：写 `enabled=0`，Hook 在下一次配置检查（≤1 秒）后放行所有流量。
- 引擎崩溃：`hook.conf` 可能残留为启用状态。默认失败关闭，应用断网而不是直连。重新启动引擎会复用新端口和令牌，Hook 自动恢复。
- 开启「回退直连」：连接接管端口失败时，Hook 用真实 DNS/真实地址直连。这会泄漏真实地址，只适合排错。
- 主动关闭接管：Hook 配置变为 `enabled=0`。应用若还缓存着 fake-IP，连接时会把假地址还原成域名并用真实 DNS 直连，不需要重启应用。这是用户主动关闭接管的预期行为。

ConnectEx 的合并发送缓冲放在 4096 个固定槽位中。同步完成立即归还；`WSA_IO_PENDING` 的槽位在 3 分钟后才允许回收，覆盖系统 TCP 超时，避免内核仍引用旧缓冲。

## DNS 的三条路径

1. **Hook fake-IP**：覆盖使用 `getaddrinfo` / `GetAddrInfoW` 的应用。解析在本进程内完成，域名随前导送到引擎。
2. **引擎本地 DNS + fake-IP**：覆盖使用 `GetAddrInfoExW`、Go 解析器等绕过 `getaddrinfo` 的程序。把系统 DNS 指向 `127.0.0.1:5353`，应用拿到引擎 fake-IP，连接被 Hook 捕获后由 `FakeIpPool` 还原域名。只有透明接管真正运行时本地 DNS 才返回 fake-IP；接管关闭或注入失败时自动回退真实解析，避免应用拿到无法连接的地址。
3. **DoH / 系统解析**：引擎为直连或上游链路解析域名时使用。静态 hosts 在 `ResolveAsync` 与 `QueryAsync` 两个入口都会生效，避免系统解析模式绕过 hosts。

应用自己实现 DoH、直接连接 IP、或使用 UDP 明文 DNS 的场景不在前两条覆盖范围。前者是应用的选择，后两者需要用系统防火墙或本地 DNS 强制收口。

## 并发与性能

- 每条 TCP 连接两个方向各一个 64 KiB 池化缓冲区，`NetworkStream` 上直接泵数据。
- ConnectEx 使用 4096 个 1 KiB 的固定槽位，避免每条异步连接都分配堆内存；未完成的操作不会阻塞后续连接。
- 套接字统一 `NoDelay`、256 KiB 收发缓冲、KeepAlive；回环监听启用 Windows 回环快速路径。
- 进程归属用 TCP 表快照缓存 300 毫秒，进程路径缓存 2 分钟。
- 规则编译成不可变快照，命中缓存 8192 条，配置变更时版本号失效。
- 上游健康度按端点记录 EWMA 与连续失败，连续 3 次失败熔断 30 秒。
- WinUI 进程启用 Server GC、并发 GC 与 Tiered PGO。
- Hook 配置文件每秒最多检查一次，不随连接数线性增长。

透明度优先于极限吞吐：注入路径比内核驱动多一次本地回环跳转。超高连接速率场景建议使用本地 SOCKS5 入口，或把 CulvertProxy 作为分流层、把真正的隧道客户端放在它上游。

## 凭据与隐私

- 上游密码与本地入口密码以 DPAPI（当前用户）加密后写 JSON。
- 接管令牌每次启动重新生成，不落日志，只写入用户 ACL 保护的 `hook.conf`。
- 接管入口只绑定回环地址 `127.0.0.1` 与 `[::1]`，不监听局域网；显式的 SOCKS5/HTTP 局域网入口需要单独开启并强制用户名密码。
- 应用无遥测、无云端上报。日志只写本地。
- Hook 在目标进程内运行，能读取该进程的连接目标。这是接管能力的代价，部署前应告知设备使用者。

## 扩展点

- 新上游协议：在 `TunnelFactory` 增加握手实现，并在 `ProxyProtocol` 注册。
- 新传输伪装：扩展 `ProxyEndpoint` 与 `TlsStreamFactory`，或在 `TunnelFactory` 外包一层流。
- 新规则维度：扩展 `RouteRequest` 与 `RuleEngine.CompiledRule`，保持不可变快照模式。
- 更强的 UDP：需要 WFP 或 WinDivert 级别的重定向，现有用户态 Hook 做不到。
