# Egress · IP 纯净度检测

**v2.0 · 2026-11-05**

打开即检测本机出口 IP：联合 20 多个 IP 数据库、16 个 DNS 黑名单、17 个威胁、代理与机房列表、同 /24 邻居和整个 ASN 的信誉，再用你当前的浏览器和网络实测 WebRTC、DNS、TCP 指纹、IPv6、Cloudflare Turnstile 与 Google reCAPTCHA，给出一个能说清每一分扣在哪里的质量分。

[打开网站](https://blackslience-reaper.github.io/egress-observatory/) · 评分规则见 [SCORING.md](SCORING.md) · 后端见 [api/README.md](api/README.md)

## 用法

- 打开页面自动识别本机出口并检测；**测本机出口** 按钮随时重新识别（切换代理节点后用它）。
- 输入任意公网 IPv4 / IPv6 查询别人的地址；此时只计算 IP 信誉，连接实测不适用。`?ip=1.2.3.4` 可直接分享。
- **隐藏 IP** 遮住页面上所有地址，方便截图；**导出报告** 生成本地 JSON，隐藏状态下 IP 一并打码。

## 检测内容

| 部分 | 内容 |
| --- | --- |
| IP 情报库 | IPinfo（权重最高）、Proxycheck、ip-api.com、IP2Location、DB-IP（经后端）；IPLocate、GeoIPLookup、TechnikNews IPgeo（主来源失败时补充）；可选 IPQualityScore、Scamalytics、IPRegistry、IPData、vpnapi.io、IPHub、GetIPIntel、AbuseIPDB（需各自 key）；IPQuery、ipapi.is、IPinfo、ipwho.is、IP.SB、ipleak（MaxMind）、GeoJS、ipapi.co、iplocation.net、FreeIPAPI、GeoLite2（RIPEstat）、Blackbox v3 beta、Cloudflare（仅本机） |
| 注册与路由 | RDAP（各 RIR）、ip.guide、Net Atlas（IPtoASN / DB-IP City Lite）、RIR 分配记录、RIPEstat 前缀 / 路由 / RPKI、PeeringDB、RDAP autnum |
| 威胁与扫描 | Shodan InternetDB（端口与代理标签）、StopForumSpam、Tor Project Onionoo、AlienVault OTX、PTR 反查；可选 GreyNoise、CrowdSec CTI、VirusTotal、AbuseIPDB |
| 黑名单 | SpamCop、Barracuda、PSBL、Mailspike、UCEPROTECT、GBUdb、NordSpam、JustSpam、SEM、SPFBL、0spam、InterServer、blocklist.de、S5H、DroneBL、dan.me.uk Tor（经 DNS-over-HTTPS） |
| 列表 | FireHOL Level 1/2/3、IPsum（≥3 个黑名单）、blocklist.de、GreenSnow、CyberCrime、ET 已入侵主机、CINS Army、BotScout、StopForumSpam 7 天、DShield 攻击网段、公开 SOCKS / HTTPS 代理、Tor 出口、X4BNet 机房段与 VPN 段（IPv4） |
| 邻居与 ASN 信誉 | 同 /24 其他地址的上榜数、整段是否被列入、同段 Tor 中继；整个 ASN 宣告空间的滥用密度与全网平均之比 |
| 多源 IP 类型 | 各库给出的使用类型（家宽 / 移动 / 商业 / 机房…）与公司类型，逐源对照 |
| ASN 画像 | 推断网络类型（运营商 / 移动 / 机房 / CDN / 骨干 / 企业 / 教育）、PeeringDB 自报、宣告规模、注册日期、RPKI、可选 Cloudflare Radar 机器流量占比、地址段租赁判断 |
| 连接实测 | 各网站看到的出口、WebRTC、DNS 解析器与 EDNS 子网、TCP/IP SYN 指纹、时区与语言、IPv6、Cloudflare WARP、Turnstile、reCAPTCHA v3 |

评分以安全为主：IP 自身记录、邻居和 ASN 信誉权重最高；基准 92 分，正面证据最多加 8 分。**ASN 交叉核对**作为低权重提示：IP 被数据库标成家宽，但宣告它的 ASN 被推断为机房、CDN 或骨干网，会单独扣分并在“ASN 一致性”里说明原因；子分配给其他公司、近期登记或由 IP 租赁平台管理的地址段标为“租赁 / 转售”。

## 配置

公开服务的间接补充见 [DATA-SOURCES.md](DATA-SOURCES.md)：TechnikNews IPgeo 只在本轮主 ip-api 查询失败后补充；Blackbox 使用公开 v3 beta 的分项分类，替换含义过宽的 Y/N 判断；Net Atlas 补充网络归属、前缀与 DB-IP City Lite 地理数据，同库按字段去重。

`config.js` 只放公开值：后端地址、Turnstile site key、reCAPTCHA site key。key 留空时对应实测显示“未配置”，不影响其他评分。两个 key 都要登记这些域名：`blackslience-reaper.github.io`、`127.0.0.1`、`localhost`。密钥只放在后端运行时 secret，见 [api/README.md](api/README.md)。

## 本地运行

```bash
python -m http.server 4187 --bind 127.0.0.1
```

打开 http://127.0.0.1:4187/ 。后端只允许 GitHub Pages 和本地 4187 端口跨域调用。加 `?captchaTest=1`（仅本地）会用 Cloudflare 的测试 key 跑一遍 Turnstile 流程，结果恒为通过。

双击“启动网站.cmd”也可以启动本地页面。

## 代码结构

- `src/main.js` 编排：识别出口、并发查询、结果到达即重新评分。
- `src/sources.js` 各数据源适配器，统一成同一结构；未返回的字段保持 `null`，不当作“否”。
- `src/blocklists.js` DNS 黑名单（DoH）与 CIDR 列表。
- `src/asn.js` ASN 档案、类型推断与租赁判断。
- `src/probes.js`、`src/captcha.js` 连接实测与人机验证。
- `src/score.js` 评分引擎，保留每项扣分的来源与解释。
- `src/render.js`、`styles.css` 页面呈现。
- `api/worker.js` 后端（Cloudflare Worker ESM，部署在 Sites）。

## 隐私

被检测的 IP 会发送给上面列出的数据服务；连接实测会让浏览器访问 STUN、bash.ws、ip-api EDNS、tcpip.incolumitas.com、Cloudflare 与 Google。页面没有账号、统计或追踪，导出报告在浏览器本地生成。分数是基于公开数据的估计，不代表任何网站的真实风控结论。
