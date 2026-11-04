# EGRESS · 出口观测站

中文 IP 与 Claude 网络观测工作台，使用原生 HTML、CSS 和 JavaScript，在 GitHub Pages 运行。

网站：**https://blackslience-reaper.github.io/egress-observatory/**

## 功能入口

- **网络总览**：浏览器向 IPv4、IPv6、双栈、Cloudflare 和 IPPure 端点发起按需请求，对比同一地址族的出口，记录时间与请求耗时。
- **IP 数据对照**：指定公网 IP，查询 IPinfo、ipwho.is、FreeIPAPI 和 RIPEstat。逐来源显示返回数据、限流、跨域或连接失败；校验响应目标 IP。
- **综合评分**：以底层数据库为单位合并证据，默认 IPinfo 30%、MaxMind 25%、IP2Location 25%、DB-IP 20%。多个网站转引同一数据库只占一行；网站风险分单列为旁证。
- **Claude 观测**：官方状态、Claude trace 和 API 域名分开观察。Opaque 响应保留不可读语义；实际登录、对话和客户端路由需要在相应应用确认。
- **WebRTC**：用户点击后向 Google STUN 收集 ICE 候选；与已取得的同地址族 HTTP 出口对比。不访问摄像头或麦克风。
- **来源目录 / 观测笔记**：整理 Ping0、IPPure、Net.Coffee、ip.cx、ipinfo.cv、IPSUPER 及其相关数据库，区分历史观察、引用和本次新增接口。
- **报告导出**：浏览器生成 JSON，默认隐藏 IP。页面不保存账号、API key、历史个人地址或分析追踪数据。

## 评分规则

分数衡量录入数据与用户出口偏好的匹配程度。默认期望国家为 JP，可以修改或留空。规则与权重均在页面公开。

1. 国家匹配占 35%：与期望国家一致为 100，其他为 0；未设置期望国家时移除此维度。
2. 网络类型占 20%：住宅 / ISP 为 100，移动网络 80，企业网络 70，托管网络 30。
3. 隐私标记占 45%：VPN、Proxy、Tor、Relay 全部有明确值时计算 `100 - max(命中标签惩罚)`，惩罚分别为 40、45、70、30；未知字段保持缺失。

每个有效“数据库 × 维度”单元的权重为数据库权重乘维度权重。总分为有效单元的加权均值，覆盖率为有效单元权重除以预期总权重。覆盖率低于 60% 时明确标为暂定。底层库与维度可能相关，权重是可调整的个人偏好，未经过封禁概率校准。

IPinfo 的普通国家/ASN 查询不会补出付费隐私字段。尚无授权 API 的数据库支持按真实页面或授权数据人工录入；未提供的数据保持缺失。换目标 IP 或期望国家会清空旧证据，防止错配。所有数据库各占一行，来源不明的站方分数保留旁证。

## 运行与发布

本地无需安装依赖。在仓库目录运行：

```powershell
python -m http.server 4187 --bind 127.0.0.1
```

打开 `http://127.0.0.1:4187/`。GitHub 仓库的 Pages 发布源为 `main` 分支根目录；`.nojekyll` 保留原始静态文件。没有服务端进程、数据库下载或 API 密钥。

## 来源与接口约束

- [ipify](https://www.ipify.org/) 提供 IPv4 / IPv6 / 双栈调用者地址。
- [IPinfo 公共 API 说明](https://support.ipinfo.io/hc/en-us/articles/30792479436562-What-Is-the-Difference-Between-Using-the-Authenticated-Free-Plan-and-the-Public-API-With-No-Account) 支持免账户 Legacy API，额度按调用者出口共享。付费字段不在本站预设为可用。
- [ipwho.is](https://ipwhois.io/documentation) 的浏览器请求受来源域名共享额度影响。
- [FreeIPAPI](https://freeipapi.com/) 提供免费接口；[数据来源](https://freeipapi.com/data-sources) 包含 [DB-IP](https://db-ip.com/)（[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)）。FreeIPAPI 数据未经重新定位，展示字段经过格式化；没有完整逐字段来源映射，因此不自动把全部字段计入 DB-IP 的评分。
- [RIPEstat / RIS](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) 提供路由公告，属于独立观测维度。
- [IPPure MyIP Beta](https://ippure.com/MyIP-Info-API) 只查询调用者；跨域或网络失败时保留失败状态。
- [Cloudflare trace](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/) 的 `colo` 是 CDN 接入点。
- [Claude Status](https://status.claude.com/api) 反映服务方公告。

界面参考 [Cloudflare Radar](https://radar.cloudflare.com/) 的工作台结构、[Net.Coffee](https://ip.net.coffee/) 的逐目标出口对照与 [IPSUPER](https://ipsuper.com/) 的多库矩阵。本站界面与代码独立实现，未复制其品牌资源或绕过人工验证、配额与授权接口。

## 数据边界

静态网页无法强制 DIRECT、指定本机代理、读取代理客户端连接链，或单凭 HTTP 请求确认 DNS 解析器。DNS 泄漏检测保留专门站点入口。网络分流可能导致不同目标看到不同出口；服务端抓取结果不会作为访客出口。

所有第三方请求由点击触发，使用 `credentials: omit`，无后台轮询。GitHub Pages 与各数据服务有自己的访问日志；[GitHub Pages 文档](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) 说明其会记录访问者 IP。导出报告可包含用户主动填写的数据，请以隐藏 IP 开关状态为准。

来源与实现核对日期：2026-11-04。
