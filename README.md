<div align="center">

# Egress · IP 纯净度检测

打开即检测本机出口 IP，给出一个能说清每一分扣在哪里的质量分。

[![在线使用](https://img.shields.io/badge/%E5%9C%A8%E7%BA%BF%E4%BD%BF%E7%94%A8-Egress-2563eb)](https://blackslience-reaper.github.io/egress-observatory/)
[![CI](https://github.com/BlackSlience-Reaper/egress-observatory/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/BlackSlience-Reaper/egress-observatory/actions/workflows/ci.yml)
[![Stars](https://img.shields.io/github/stars/BlackSlience-Reaper/egress-observatory?style=flat)](https://github.com/BlackSlience-Reaper/egress-observatory/stargazers)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![爱发电](https://img.shields.io/badge/%E7%88%B1%E5%8F%91%E7%94%B5-%E8%B5%9E%E5%8A%A9-946ce6)](https://ifdian.net/a/Harukili)

**v2.0 · 2026-11-05**

[**打开网站**](https://blackslience-reaper.github.io/egress-observatory/) · [评分规则](SCORING.md) · [数据来源](DATA-SOURCES.md) · [后端](api/README.md) · [Chrome 扩展](browser-helper/README.md) · [参与开发](CONTRIBUTING.md)

</div>

Egress 联合 20 多个 IP 数据库、16 个 DNS 黑名单、17 个威胁、代理与机房列表、同 /24 邻居和整个 ASN 的信誉，再用你当前的浏览器和网络实测 WebRTC、DNS、TCP 指纹、IPv6、Cloudflare Turnstile 与 Google reCAPTCHA。

- **多源交叉**：同一底层数据库只计一份权重，避免重复投票。
- **结果可解释**：每一项扣分都保留来源和原因。
- **边查边更新**：结果到达即重新评分，失败的来源逐个显示原因。
- **无需账号**：页面没有账号或第三方统计，导出报告在浏览器本地生成；共享人数估计只保存加盐哈希（见[隐私](#隐私)）。

> 分数是基于公开数据的估计，不代表任何网站的真实风控结论。

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

间接补充的来源和取舍依据见 [DATA-SOURCES.md](DATA-SOURCES.md)：TechnikNews IPgeo 只在本轮主 ip-api 查询失败后补充；Blackbox 使用公开 v3 beta 的分项分类，替换含义过宽的 Y/N 判断；Net Atlas 补充网络归属、前缀与 DB-IP City Lite 地理数据，同库按字段去重。

## 评分

评分以安全为主：IP 自身记录、邻居和 ASN 信誉权重最高；基准 92 分，正面证据最多加 10 分。完整规则见 [SCORING.md](SCORING.md)。

**ASN 交叉核对**作为低权重提示：IP 被数据库标成家宽，但宣告它的 ASN 被推断为机房或 CDN，会单独扣分并在“ASN 一致性”里说明原因；骨干网只提示、不扣分；子分配给其他公司、近期登记或由 IP 租赁平台管理的地址段标为“租赁 / 转售”。

网页中的明确 VPN、代理、Tor、机房、中继、爬虫和滥用标记进入现有加权投票，明确的 0–100 风险分进入风险评分。IPSuper 的逐库风险矩阵也会自动补充这些字段；未支持和获取失败的格子不投票。IPQS、Scamalytics、AbuseIPDB 的具名风险分用于评分，其他条形百分比保留原意。官网、Chrome、IPSuper 和 IPOK 的同库结果合并，只保留一份来源权重，返回字段时立即重新计算总分和用途评分。

## Chrome 扩展（可选）

不安装也能使用：网站默认在云端读取 IPSuper 的逐库类型、风险分和风险矩阵，供所有访客自动补全。

[**下载 Chrome 扩展 v1.3.1（ZIP）**](https://blackslience-reaper.github.io/egress-observatory/downloads/egress-browser-helper-v1.3.1.zip) · [安装说明](browser-helper/README.md)

扩展使用访客当前的浏览器会话增强本机结果，覆盖 18 个来源，补齐接口缺失的字段：

- 安装后，“查询”和“重新检测”会自动建立临时标签组，最多同时打开 3 个来源查询页，逐个读取目标字段后关闭标签；每读到一个就合并进结果，不需要逐次导入。
- 不向服务器复制 Cookie。页面显示 Chrome 的逐源自动读取状态，并逐源显示失败原因。
- 遇到人机验证时点“去验证”手动完成；插件持续等待，通过后自动补充并重新评分。
- 点“停止等待”、切换查询或关闭检测页会取消本轮并清理该页发起的临时标签，其他标签保持原状。

安装包保存在仓库 `downloads/`，包含完整的 `browser-helper/` 文件夹；网页“多源 IP 类型”区也提供下载和安装说明。

## 自动代码审查

[OpenAI PR Review](https://github.com/BlackSlience-Reaper/egress-observatory/actions/workflows/openai-review.yml) 在同仓库的非草稿 PR 新建、更新、重新打开或转为可审查时自动运行，固定使用 `gpt-6-astra`、High 推理强度，并以 `github-actions[bot]` 发布绑定实际 head commit 的 GitHub Review。新提交会取消旧运行，过期报告不发布；审查只发表意见，不批准或合并 PR。

仓库管理员在 [Actions Secrets](https://github.com/BlackSlience-Reaper/egress-observatory/settings/secrets/actions) 配置专用的 `OPENAI_API_KEY` 后生效，调用计入该 key 所属 OpenAI API 项目。缺少密钥时工作流摘要会明确显示待配置并跳过审查。维护者也可在工作流页面点击 **Run workflow**，输入 PR 编号手动运行；fork PR 使用这个维护者入口。

审查规则保存在 [`.github/codex/review.md`](.github/codex/review.md)，从默认分支读取。审查 job 对代码只读、禁止联网和执行项目代码，发布 job 独立运行且不接触 OpenAI 密钥；默认仅有仓库写权限的触发者可以调用模型。报告区分静态证据与实际运行，遵守不新增、不运行测试的项目规则。GitHub 自动审查与 OpenAI Platform 中保存的 Agent 定义分别配置。

## 本地运行

需要 Python 3；只有跑测试时才需要 Node.js。

macOS / Linux：

```bash
python3 local_server.py
```

Windows（也可以双击“启动网站.cmd”）：

```powershell
python local_server.py
```

打开 <http://127.0.0.1:4187/> 。页面在 4187 端口，本机查询服务在 4188 端口，都只监听 `127.0.0.1`。后端只允许 GitHub Pages 和本地 4187 端口跨域调用。加 `?captchaTest=1`（仅本地）会用 Cloudflare 的测试 key 跑一遍 Turnstile 流程，结果恒为通过。

本地的“查询”还需要 Playwright 和 Chromium，首次安装（macOS / Linux 上用 `python3`）：

```bash
python -m pip install playwright
python -m playwright install chromium
```

运行测试：

```bash
npm test
```

## 配置

`config.js` 只放公开值：后端地址、Turnstile site key、reCAPTCHA site key。key 留空时对应实测显示“未配置”，不影响其他评分。两个 key 都要登记这些域名：`blackslience-reaper.github.io`、`127.0.0.1`、`localhost`。密钥只放在后端运行时 secret，见 [api/README.md](api/README.md)。

后端状态查询遇到连接失败会重试一次；“重新检测”和人机验证的“再测一次”会重新检查后端。状态查询失败时，Radar 和验证码仍会尝试各自接口，连接失败按实际错误显示。Google 脚本加载、初始化、执行和服务端校验均有超时，失败后保留重试按钮；只有后端明确返回缺少密钥时才显示“未配置”。

网页自动补全统一调用主 API 的 `/v1/page/*`，由主 API 唤醒 Chromium 容器并读取报告；IPinfo、IPSuper、其他来源和 GetIPIntel 的云端入口共享每个出口 IP 每分钟 30 次的查询额度，D1 原子计数跨运行实例共享。Render 在访问缓存和浏览器前必须消费主 API 生成的短期一次性凭据，直接请求 Render 会被拒绝。相同来源和目标 IP 的并发请求合并，成功报告从原始观察时间起最多保留 10 分钟。连接中断和临时服务错误会有限重试，调用者超限则显示等待原因并停止重试；整轮最长 4 分钟，切换查询会取消旧请求。本地页面优先使用 4188 服务，连接失败后使用同一线上入口。

| 组件 | 位置 | 上线方式 |
| --- | --- | --- |
| 网站 | 仓库根目录，GitHub Pages | 合并到 `master` 后自动发布 |
| API | `api/worker.js`，部署在 Sites | 手动部署，见 [api/README.md](api/README.md#部署) |
| 网页查询服务 | `cloud_server.py`、`Dockerfile`、`render.yaml`，部署在 Render | Linux 容器从 Dockerfile 启动，`/health` 提供健康状态 |
| Chrome 扩展 | `browser-helper/`，打包到 `downloads/` | 访客自行下载安装 |

### 代码结构

| 路径 | 作用 |
| --- | --- |
| `src/main.js` | 编排：识别出口、并发查询、结果到达即重新评分 |
| `src/sources.js` | 各数据源适配器，统一成同一结构；未返回的字段保持 `null`，不当作“否” |
| `src/blocklists.js` | DNS 黑名单（DoH）与 CIDR 列表 |
| `src/asn.js` | ASN 档案、类型推断与租赁判断 |
| `src/probes.js`、`src/captcha.js` | 连接实测与人机验证 |
| `src/score.js` | 评分引擎，保留每项扣分的来源与解释 |
| `src/render.js`、`styles.css` | 页面呈现 |
| `src/page-lookups.js`、`src/provider-pages.js`、`src/page-extract.js`、`src/page-providers.js`、`src/ipinfo-page.js`、`src/ipsuper.js`、`src/supplements.js` | 来源网页读取与第三方补全 |
| `api/worker.js` | 后端（Cloudflare Worker ESM，部署在 Sites） |
| `local_server.py`、`cloud_server.py`、`provider_pages.py` | 本机启动器、线上查询 API 与来源网页读取 |
| `browser-helper/` | Chrome 扩展 |
| `tests/` | 单元测试 |

### 网页补全

接口字段不足时，Egress 从来源网页补齐。这些路径的结果都会逐源校验目标 IP，只补充缺失字段；同库结果合并为一条记录。

**查询路径**

- **IPinfo 与 IPSuper**：点击“查询”后，服务并行读取该 IP 的 IPinfo 详情页与 IPSuper 多库表，各自校验目标地址并补充缺失字段。同一 IP 的页面结果在内存保留 10 分钟。IPinfo 网页和官方接口合并为一条数据库记录；IPSuper 补充的类型按原库名标识。
- **其他来源**：字段不足时，`/lookup/sources` 进一步尝试 IPHub、IPQualityScore、IPData、IPRegistry、DB-IP、Scamalytics、ipapi.is、IPQuery 和 Blackbox 的固定查询入口。每页核对目标 IP；网页与接口仍为同一条来源记录。受校验、额度或网络限制时逐源保留原因，已有接口结果继续展示。
- **IPOK**：与已有公开接口同时提供间接补充；第三方失败或额度不足时保留原因。
- **手动导入**：多源类型区的“从来源网页补全”提供书签与报告导入入口，支持在访客已打开的官方结果页读取字段。
- **IPHub 的特殊处理**：block 0 显示“家宽或商业”，不增加家宽投票；网页未提供类型时保留未知。

**连接与恢复**

- GitHub Pages 自动使用线上 Chromium 服务，访客只需打开网站并查询。免费容器休眠后的首次请求可能需要等待唤醒。
- 自动补全优先调用 Chromium 网页服务，连接失败时经现有 API 的 `/v1/page/ipinfo`、`/v1/page/ipsuper` 中转，随后再次尝试原入口。
- 中转服务先唤醒容器，再读取报告；相同来源和 IP 的并发请求合并，成功报告在边缘缓存，原始观察时间起最多保留 10 分钟。
- 前端在连接中断、临时服务错误和限流时有限重试，为备用连接保留时间；整轮最长 4 分钟，切换查询会取消旧请求。状态栏显示连接与重试进度，失败保留具体原因。
- 本地页面优先使用 4188 服务，连接失败后使用同一线上恢复路径。

## 隐私

被检测的 IP 会发送给上面列出的数据服务；连接实测会让浏览器访问 STUN、bash.ws、ip-api EDNS、tcpip.incolumitas.com、Cloudflare 与 Google。页面没有账号或第三方统计，导出报告在浏览器本地生成。为了估计共享人数，本站 API 会记录每次检测的目标 IP 与查询方，查询方只以加盐哈希保存（盐值随机生成、只存在服务端数据库），不保存查询者 IP 或浏览器标识原文；超过 30 天的记录不再计入，并在之后任何一次检测时删除；浏览器里保存一个随机生成的匿名标识。

## 参与开发

任务统一放在 [Issues](https://github.com/BlackSlience-Reaper/egress-observatory/issues)，通过 PR 合入，`master` 受保护。反馈问题或提议新数据源时请[选择对应模板](https://github.com/BlackSlience-Reaper/egress-observatory/issues/new/choose)，并注意不要公开真实 IP。

环境配置（含 Windows）、分支约定和各模块的改动要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## Star 趋势

<a href="https://www.star-history.com/#BlackSlience-Reaper/egress-observatory&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=blackslience-reaper/egress-observatory&type=Date&theme=dark">
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=blackslience-reaper/egress-observatory&type=Date">
    <img alt="Egress 的 Star 增长趋势" src="https://api.star-history.com/svg?repos=blackslience-reaper/egress-observatory&type=Date" width="600">
  </picture>
</a>

## 联系与合作

广告投放、数据合作或其他合作，请在 X 上联系 [@BlackSlience](https://x.com/BlackSlience)。问题反馈和功能建议请走 [Issues](https://github.com/BlackSlience-Reaper/egress-observatory/issues)。

## 赞助

如果 Egress 帮到了你，可以在爱发电支持项目的开发：

[![在爱发电赞助](https://img.shields.io/badge/%E5%9C%A8%E7%88%B1%E5%8F%91%E7%94%B5%E8%B5%9E%E5%8A%A9-ifdian.net%2Fa%2FHarukili-946ce6?style=for-the-badge)](https://ifdian.net/a/Harukili)

点一个 Star、反馈问题或提交 PR，同样是很大的支持。

## 许可证

本项目按 [GNU General Public License v3.0](LICENSE) 授权。各数据源的服务条款和署名要求仍然适用，例如页面保留“IP Geolocation by DB-IP”署名。
