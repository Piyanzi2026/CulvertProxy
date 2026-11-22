# 高审查网络部署指南

先明确边界：CulvertProxy 解决的是「应用怎么稳定、少泄漏地走到代理」，不是「流量长什么样才不像代理」。后者需要 uTLS、REALITY、ECH、QUIC 伪装、主动探测防护这类传输层能力，本工程没有实现。

所以推荐的分工是：

```text
应用 ── Winsock 接管 ── CulvertProxy ── 强伪装隧道（可选） ── 出口
                          │
                          ├─ 规则：进程 / 域名 / IP / 端口
                          ├─ DNS 收口：DoH / fake-IP
                          └─ 失败关闭
```

如果上游已经是 sing-box、Xray、Hysteria 等提供的本地 SOCKS5，把 CulvertProxy 的服务器指向 `127.0.0.1:<端口>` 即可。CulvertProxy 负责逐进程分流、DNS 防泄漏和连接可观测性，强伪装交给更擅长的组件。

---

## 威胁模型

| 威胁 | CulvertProxy 的应对 | 仍需注意 |
| --- | --- | --- |
| 本地 DNS 污染 | Hook fake-IP；DoH 走代理；本地 DNS + fake-IP | 应用自带 DoH/硬编码 IP 不受控 |
| SNI 阻断 | TLS 包装 + 独立 SNI | TLS 指纹仍是 .NET SslStream |
| 代理端口被识别 | TLS 包装、多跳、随机本地接管端口 | 没有流量填充与多路复用 |
| 证书中间人 | SHA-256 叶证书固定 | 换证书需同步更新指纹 |
| 代理不可达时泄漏 | 默认失败关闭 | 开启回退直连会暴露真实地址 |
| 单个出口被封 | 多链路延迟/故障转移、连续失败熔断 | 熔断期间会尝试下一条链路 |
| UDP/QUIC 泄漏 | 发往 fake-IP 的 UDP 被拒绝 | 直连真实 IP 的 UDP 仍会出去 |
| 本机其他进程滥用入口 | 回环绑定 + 每次启动随机令牌 | 同用户进程仍可读取用户目录 |

---

## 推荐拓扑

### A. TLS 包装的 SOCKS5

适合你有可控的 SOCKS5 服务端，并且能给它配置证书。

1. 服务端在 443 上终止 TLS，证书与伪装域名匹配。
2. TLS 之后直接讲 SOCKS5，不需要额外 ALPN。
3. 客户端端点填真实地址与端口，勾选 TLS，SNI 填伪装域名。连接主机可以直接填中转 IP，SNI 单独填证书域名；这样引导阶段不依赖被污染的 DNS。
4. 填叶证书 SHA-256 指纹。抓取指纹：

```powershell
$tcp = [System.Net.Sockets.TcpClient]::new('proxy.example.com', 443)
$ssl = [System.Net.Security.SslStream]::new($tcp.GetStream())
$ssl.AuthenticateAsClient('cdn.example.com')
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
[Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($cert.RawData))
$ssl.Dispose(); $tcp.Dispose()
```

5. 如果要穿 CDN，确认 CDN 允许你使用的协议与端口；CulvertProxy 只做 TCP 流，不做 WebSocket 封装。

### B. 本地强伪装隧道 + CulvertProxy 分流

适合需要对抗主动探测、流量指纹或 QUIC 干扰的环境。

1. 在本机运行 sing-box / Xray / Hysteria，暴露一个 SOCKS5 监听，例如 `127.0.0.1:2080`。
2. CulvertProxy 新增服务器：`SOCKS5 127.0.0.1:2080`。
3. 路由规则决定哪些进程走这个上游，哪些直连。
4. 本机隧道客户端只由 CulvertProxy 使用；不要让浏览器直接连它，否则又回到「谁都能用、没有分流」的状态。

多跳也可以在这个模型里做：CulvertProxy → 中转 TLS SOCKS5 → 出口。每跳独立超时与健康度。

---

## DNS 收口

DNS 是最容易漏的地方。按应用使用的 API 分三类：

| 应用行为 | 覆盖方式 |
| --- | --- |
| 调用 `getaddrinfo` / `GetAddrInfoW` | Hook 直接返回 fake-IP，域名随前导进入引擎，本地 DNS 零查询；`AF_INET6` 返回 v4-mapped 假地址 |
| 调用 `GetAddrInfoExW`、纯 Go 程序、自带解析器 | 启用本地 DNS + fake-IP，把系统 DNS 指向 `127.0.0.1:5353`；接管未运行时自动回退真实解析 |
| 应用内置 DoH/DoT 或硬编码 IP | CulvertProxy 无法改写。用防火墙阻断其解析出口，或接受该应用绕过策略 |

本地 DNS 的 DoH 建议：

- DoH 地址填 IP 形式，例如 `https://1.1.1.1/dns-query`。
- 开启「DoH 走代理」，避免引导请求暴露给本地网络。
- 指定一个可用的 DoH 策略，别让它跟随一条可能失败的分流。
- 静态 hosts 对所有解析入口生效，适合固定落地或内网服务。
- fake-IP 默认使用 `198.18.0.0/16`。`198.19.0.0/16` 被注入层占用，配置时不要重叠；引擎也会主动跳过该段。
- 系统 DNS 指向本地 fake-IP 服务后，**所有上游服务器与 DoH 端点的主机名都要改成 IP**，SNI 单独填域名。否则引擎在引导阶段也会拿到 fake-IP，代码会直接报错提示，而不是悄悄连错地址。

Windows 修改 DNS 后，如果网络使用 DHCP，记得恢复「自动获得 DNS 服务器地址」。

---

## 失败关闭与恢复

默认 `FailOpen=false`。引擎不可达时，注入进程的连接会立刻失败，而不是偷偷直连。

- 同一用户只运行一个启用接管的 CulvertProxy 实例；GUI 有单实例锁，引擎层还有接管占用锁。
- 正常停止引擎会写 `enabled=0`，已注入进程放行。
- 引擎崩溃时配置可能残留启用状态。应用网络会中断；重新启动 CulvertProxy 后 Hook 在 1 秒内切到新端口与令牌。
- 如果这期间你需要紧急恢复网络，关闭 CulvertProxy 后删除 `%LOCALAPPDATA%\Nexsteaduser\CulvertProxy\hook.conf`，或把其中 `enabled` 改为 `0`。
- 「回退直连」只用于排错。它会把真实源地址和真实 DNS 暴露给本地网络。

---

## 传输层取舍

本工程已经有的：

- TLS 1.2 / 1.3，SNI 可与连接地址分离。
- 叶证书 SHA-256 固定。
- SOCKS5 / HTTP CONNECT 多跳。
- 连接健康度与链路切换。

本工程没有的，别误以为有：

- 浏览器指纹级 ClientHello（uTLS）。
- Encrypted ClientHello。
- 流量填充、时序混淆、多路复用。
- QUIC 代理与 UDP 转发。
- 主动探测防护与回落站点。

在 DPI 会做主动探测的网络里，单靠「TLS + SOCKS5」不够。把 CulvertProxy 当作分流与 DNS 收口层，传输层交给专门实现，是更现实的组合。

---

## 部署检查表

- [ ] 上游链路至少两条，且属于不同网络路径。
- [ ] 所有公网上游启用 TLS；SNI 与证书一致；指纹已固定。
- [ ] DoH 地址使用 IP，且 DoH 走代理。
- [ ] 本地 DNS 与 fake-IP 已开启，系统 DNS 已指向本地端口。
- [ ] 失败关闭保持开启。
- [ ] 规则默认策略明确：未命中时是直连还是代理，符合你的使用场景。
- [ ] 排除项覆盖游戏反作弊、备份工具、内网管理工具等不希望被注入的进程。
- [ ] 以管理员身份运行（如果需要接管高完整性应用）。
- [ ] 记录恢复步骤：关闭引擎、禁用 hook.conf、恢复系统 DNS。
- [ ] 二进制已签名，避免 SmartScreen 与终端安全软件误报。

---

## 验证方法

- 打开「连接」页，确认目标、进程、命中规则、链路与字节数符合预期。
- 在受控环境用抓包或 `netstat` 检查是否仍有直连 53/443 的流量。
- 停掉上游，确认应用断网而不是直连。
- 停掉 CulvertProxy，确认 `hook.conf` 变为 `enabled=0`，应用恢复。
- 换证书后验证指纹不匹配时连接被拒绝，而不是静默放行。
