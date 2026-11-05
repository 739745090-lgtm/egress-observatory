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

评分以安全为主：IP 自身记录、邻居和 ASN 信誉权重最高；基准 92 分，正面证据最多加 10 分。**ASN 交叉核对**作为低权重提示：IP 被数据库标成家宽，但宣告它的 ASN 被推断为机房或 CDN，会单独扣分并在“ASN 一致性”里说明原因；骨干网只提示、不扣分；子分配给其他公司、近期登记或由 IP 租赁平台管理的地址段标为“租赁 / 转售”。

## 配置

公开服务的间接补充见 [DATA-SOURCES.md](DATA-SOURCES.md)：TechnikNews IPgeo 只在本轮主 ip-api 查询失败后补充；Blackbox 使用公开 v3 beta 的分项分类，替换含义过宽的 Y/N 判断；Net Atlas 补充网络归属、前缀与 DB-IP City Lite 地理数据，同库按字段去重。

`config.js` 只放公开值：后端地址、Turnstile site key、reCAPTCHA site key。key 留空时对应实测显示“未配置”，不影响其他评分。两个 key 都要登记这些域名：`blackslience-reaper.github.io`、`127.0.0.1`、`localhost`。密钥只放在后端运行时 secret，见 [api/README.md](api/README.md)。

后端状态查询遇到连接失败会重试一次；“重新检测”和人机验证的“再测一次”会重新检查后端。状态查询失败时，Radar 和验证码仍会尝试各自接口，连接失败按实际错误显示。Google 脚本加载、初始化、执行和服务端校验均有超时，失败后保留重试按钮；只有后端明确返回缺少密钥时才显示“未配置”。

## 本地运行

```bash
python local_server.py
```

打开 http://127.0.0.1:4187/ 。后端只允许 GitHub Pages 和本地 4187 端口跨域调用。加 `?captchaTest=1`（仅本地）会用 Cloudflare 的测试 key 跑一遍 Turnstile 流程，结果恒为通过。

Windows 双击“启动网站.cmd”启动本机查询服务。点击“查询”后，服务并行读取该 IP 的 IPinfo 详情页与 IPSuper 多库表，各自校验目标地址并补充缺失字段。需要 Python、Playwright 和 Chromium（首次安装可运行 python -m pip install playwright 和 python -m playwright install chromium）。同一 IP 的页面结果在内存保留 10 分钟。GitHub Pages 自动使用线上 Chromium 服务；访客只需打开网站并查询。免费容器休眠后的首次请求可能需要等待唤醒。Linux 容器从 Dockerfile 启动，/health 提供健康状态。IPinfo 网页和官方接口合并为一条数据库记录。IPSuper 补充的类型按原库名标识。

来源字段不足时，`/lookup/sources` 进一步尝试 IPHub、IPQualityScore、IPData、IPRegistry、DB-IP、Scamalytics、ipapi.is、IPQuery 和 Blackbox 的固定查询入口。每页核对目标 IP，只补充缺失字段；网页与接口仍为同一条来源记录。受校验、额度或网络限制时逐源保留原因；已有接口结果继续展示。多源类型区的“从来源网页补全”提供书签与报告导入入口，支持在访客已打开的官方结果页读取字段。IPHub 的 block 0 显示“家宽或商业”，不增加家宽投票；网页未提供类型时保留未知。

网站默认在云端读取 IPSuper 的逐库类型、风险分和风险矩阵，供所有访客自动补全，访客无需安装插件。IPOK 与已有公开接口同时提供间接补充；第三方失败或额度不足时保留原因。

IPHub、IPQualityScore 与 IPSuper 另支持可选的 [Chrome 自动查询扩展](browser-helper/README.md)，使用访客当前浏览器会话增强本机结果。安装后，“查询”和“重新检测”会自动建立临时标签组，先读取 IPSuper 第三方逐库类型和风险矩阵，再读取两站的目标字段并关闭临时标签；不需要逐次导入，也不向服务器复制 Cookie。页面显示 Chrome 的逐源自动读取状态。查询取消会关闭该页发起的临时标签，其他标签保持原状。

[下载 Chrome 扩展 v1.1.0（ZIP）](https://blackslience-reaper.github.io/egress-observatory/downloads/egress-browser-helper-v1.1.0.zip)。网页“多源 IP 类型”区也提供下载和安装说明，访客可自行选择。安装包保存在仓库 `downloads/`，包含完整的 `browser-helper/` 文件夹；解压后按[安装说明](browser-helper/README.md)加载即可。

网页中的明确 VPN、代理、Tor、机房、中继、爬虫和滥用标记进入现有加权投票，明确的 0–100 风险分进入风险评分。IPSuper 的逐库风险矩阵也会自动补充这些字段；未支持和获取失败的格子不投票。IPQS、Scamalytics、AbuseIPDB 的具名风险分用于评分，其他条形百分比保留原意。官网、Chrome、IPSuper 和 IPOK 的同库结果合并，只保留一份来源权重，返回字段时立即重新计算总分和用途评分。

网页自动补全优先调用 Chromium 网页服务，连接失败时经现有 API 的 `/v1/page/ipinfo`、`/v1/page/ipsuper` 中转，随后再次尝试原入口。中转服务先唤醒容器，再读取报告；相同来源和 IP 的并发请求合并，成功报告在边缘缓存，原始观察时间起最多保留 10 分钟。前端在连接中断、临时服务错误和限流时有限重试，为备用连接保留时间；整轮最长 4 分钟，切换查询会取消旧请求。状态栏显示连接与重试进度，失败保留具体原因。本地页面优先使用 4188 服务，连接失败后使用同一线上恢复路径。

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
