# EGRESS · 出口观测站

**v1.1 · 2026-11-05**

输入一个公网 IP，自动查询多个数据库接口，生成质量参考分、指标覆盖率、来源矩阵与分歧说明。原生 HTML、CSS 和 JavaScript 前端运行于 GitHub Pages，Proxycheck 授权查询由 Sites 托管的公开只读 API 提供。

[打开网站](https://blackslience-reaper.github.io/egress-observatory/) · [GitHub 仓库](https://github.com/BlackSlience-Reaper/egress-observatory)

## 使用入口

1. 在首页 **综合测评** 输入公网 IPv4 或 IPv6，或留空使用当前浏览器出口。期望国家可填写两位代码，如 `JP`；留空时比较多库国家共识。
2. 点击 **开始综合测评**。八个来源针对同一目标并行查询，结果返回后自动更新总分、覆盖率、主要发现和数据库字段矩阵。
3. 展开 **来源权重与计算设置** 调整可计分数据源的相对权重，页面使用本轮真实记录重新计算。进入 **评分依据** 查看维度、字段、底层来源和贡献。
4. 使用 **取消本轮** 停止待完成请求，或点击 **导出测评报告** 下载本地生成的 JSON。默认隐藏目标 IP；关闭隐藏开关会导出完整地址。

`dashboard.js` 管理查询与界面，`providers.js` 规范化提供方响应，`assessment.js` 自动融合实际字段；`api/worker.js` 在服务端执行 Proxycheck 授权查询。

其他入口：

- 首页折叠区 **当前浏览器出口观测**：逐个观察 ipify IPv4 / IPv6 / 双栈、Cloudflare 和 IPPure 所见出口，按地址族比较差异；其中可单独启动 Google STUN WebRTC 观察。
- **IP 数据对照**：保留 IPinfo、ipwho.is、FreeIPAPI 和 RIPEstat 的简洁并列查询入口。
- **Claude 观测**：分开显示官方服务公告、Claude trace 和 API 域名响应。Opaque 表示响应内容不可读；实际登录、模型调用与客户端路由各自需要真实运行证据。
- **来源目录 / 观测笔记**：包含历史使用的网站、底层数据来源和本次新增接口。目录收录范围大于当前八源自动流程，未配置授权的服务有明确说明。

## 自动查询的八个来源

- **[Proxycheck](https://proxycheck.io/api/)**：使用本方授权，通过 [Sites 查询入口](https://egress-observatory-api.reaper-f.chatgpt.site/v1/proxycheck) 的 `?ip={IP}` 参数取得精选字段。服务端真实查询已返回 HTTP 200 成功记录，密钥存放于 Sites 运行时 secret，未写入仓库或前端。成功记录缓存 600 秒；同一 Worker isolate 内按调用者每分钟限 10 次，限速不跨实例或重启持久化。
- **[IPinfo](https://support.ipinfo.io/hc/en-us/articles/34121895556242-Legacy-Free-API-vs-IPinfo-Lite)**：直接调用官方 Legacy Public API `https://ipinfo.io/{IP}/json`。免账户、免 token，同一调用出口共享每日 1,000 次。国家、城市和 ASN 来自实际响应；未返回的付费隐私字段保持 `null`。新 Lite API 需要 token，与这里的 Legacy 入口分别处理。
- **[IPQuery](https://ipquery.io/developers/api)**：调用 `https://api.ipquery.io/{IP}?format=json`，取得实际返回的 VPN、Proxy、Tor 和 Hosting 分类。[来源说明](https://ipquery.io/sources) 中未公布 Enterprise MMDB 的厂商品牌，因此地理字段作为旁证；明确归属于 IPQuery 的分类参与质量参考分。保留其关于 proxio.io、Proxmint 和 CC BY 4.0 的来源说明。
- **[ipapi.is](https://ipapi.is/free-tier.html)**：调用 `https://api.ipapi.is/?q={IP}`。当前匿名层提供位置、网络归属与 Bogon；完整代理、VPN 和滥用分类需要本方 API key。匿名额度为每个出口 IPv4 / IPv6 `/64` 每 UTC 日 30 次，遇到限流保留错误。
- **[ipwho.is](https://ipwhois.io/documentation)**：调用 `https://ipwho.is/{IP}`，提供位置与网络归属。当前免费层未包含 Security Data；浏览器 CORS 调用受整个来源域名共享的每日额度限制。
- **[DB-IP](https://db-ip.com/api/free)**：直接调用官方免费接口 `https://api.db-ip.com/v2/free/{IP}`，保留 `IP Geolocation by DB-IP` 署名。当前浏览器请求仅允许查询该服务看到的访问者 IP；其他目标可能返回 `RESTRICTED`，页面保留访问限制，不换用其他数据冒充 DB-IP。免费额度为每日 500 次。
- **[FreeIPAPI](https://freeipapi.com/)**：调用 `https://free.freeipapi.com/api/v1/json/{IP}`。免 key，每个访客出口每 10 秒 10 次、每分钟最多 60 次。[公开来源](https://freeipapi.com/data-sources) 包含 [DB-IP](https://db-ip.com/)（[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)），逐字段映射和其他上游未完全披露。地理与 `isProxy` 作为聚合旁证展示，不给 DB-IP 增加重复票，也不将代理标记归因于 DB-IP。
- **[RIPEstat / RIS](https://stat.ripe.net/docs/data-api/api-endpoints/network-info)**：取得公告前缀与 ASN，并校验目标属于返回前缀。路由信息单独展示，不参与风险或地理计分。

单个来源不可读、额度耗尽、目标不匹配或访问受限时，其字段保持缺失。浏览器跨域权限、扩展、网络路由和提供方策略均可能影响当轮返回；“已配置查询入口”不代表每次都会获得八份成功响应。

## 自动评分与可解释性

所有成功记录必须指向同一个规范化 IP。目标冲突时暂停综合评分；同一底层库经多个网站提供的同字段先去重，选取最新观测。同库最新记录互相冲突时，该字段保留未知。独立库的分歧继续显示。

默认来源权重是相对值：IPinfo `30`、ipapi.is `25`、Proxycheck `20`、IPQuery `20`、DB-IP `20`、ipwho.is `15`。IPinfo 的权重仅作用于实际返回的字段。FreeIPAPI 的目录权重为 `10`，其聚合记录只作旁证；RIPE 为 `0`，单独提供路由证据。后两项不计质量分，界面禁用其权重编辑。

维度权重与刻度由实现公开定义：

- **匿名与滥用风险 70%**：逐项使用明确的布尔值。VPN、Proxy、Tor、Relay、Abuser、Bogon 的内部权重分别为 `15 / 25 / 20 / 5 / 25 / 10`。明确阴性 `false` 对应 100；命中时的参考刻度分别为 `30 / 25 / 0 / 50 / 0 / 0`。各字段先按数据库权重融合，再将 VPN、Proxy、Tor、Relay 归为关联匿名信号组：取已观测字段中的最低分为组分数，以这些字段权重之和为组有效权重。Abuser、Bogon 分别计分，厂商未提供的标记保持 `null`，覆盖率仍按实际已知字段计算。
- **网络类型适配 20%**：类型占该维度 70%，Hosting 标记占 30%。住宅、ISP、移动、商业、托管类型对应 `100 / 90 / 85 / 70 / 35`；明确 Hosting 阴性为 100、阳性为 35。这是本项目公开的适配刻度：Hosting 说明基础设施类型，不等同滥用风险；未命中 Hosting 也不推断住宅。
- **地区一致性 10%**：指定期望国家时，按匹配来源的权重比例计算；未指定时，使用领先国家的加权支持比例，并展示其他国家与平票情况。国家一致只描述地理证据。

每个字段先按底层来源权重融合；匿名字段采用上述分组规则，其他字段按各维度的公开权重计算。总分显示为“综合参考分 · 含类型适配”，范围 `0–100`，由已覆盖维度权重归一化。分组减少同类标签的重复作用，也保留 Tor 等明确命中，避免被同组其他阴性字段冲淡。Tor、Abuser、Bogon 的重要阳性在主要发现中置顶提醒；Hosting 显示为琥珀色“机房”标签。

**覆盖率与交叉确认分别计算。** 覆盖率表示预设指标权重中已有实际数据的比例；同一字段是否有多个独立库支持，是另一项证据。来源数量多、同一网站返回字段多，均不能自动提高独立交叉确认程度。

有效覆盖低于 20%、无风险字段或目标冲突时显示“数据不足，暂不评分”。覆盖率低于 80%、风险指标覆盖不足 70%、风险来源不足两个、同一风险字段没有交叉确认，或存在分歧时，结果保持“暂定参考”。一个低覆盖的高分不能解读为全面检测通过；参考分也没有经过 Claude 可用性或账号封禁概率校准。

## 资料来源与未接入项目

界面参考 [Cloudflare Radar](https://radar.cloudflare.com/) 的工作台组织、[Net.Coffee](https://ip.net.coffee/) 的逐目标对照，以及 [IPSuper](https://ipsuper.com/) 的多库矩阵。品牌资源和代码独立实现。

MaxMind、IP2Location、IPQualityScore、Scamalytics、IPRegistry、AbuseIPDB 等列入来源目录，目前未配置其授权 API。AbuseIPDB 官方说明的地理、使用类型、ISP 和域名来自 IPinfo，相关字段应按 IPinfo 去重；其滥用举报属于单独的数据证据。IP-API 免费入口仅 HTTP，本站 HTTPS 页面没有直接调用该入口。

Proxycheck 已取得本方授权并加入第八个自动来源。公开只读服务部署于 Sites，GitHub Pages 前端仅保存服务地址；授权凭据由服务端运行时读取。接口、缓存、限速及精选字段见 [服务端说明](api/README.md)。

Ping0、IPPure、Net.Coffee、ip.cx、ipinfo.cv 的公开评分方向、阈值、算法披露范围及可迁移规则，见 [评分来源核对与实现建议](SCORING-SOURCES.md)。研究区分行为风险、网络类型适配、地区和浏览器环境，不把住宅或机房类型直接当成滥用结论。

补充观测入口包括 [ipify](https://www.ipify.org/)、[IPPure MyIP Beta](https://ippure.com/MyIP-Info-API)、[Cloudflare trace](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/) 和 [Claude Status](https://status.claude.com/api)。IPPure Beta 仅描述调用者出口，其站方分数独立展示。

## 本地运行与发布

在仓库目录运行静态文件服务，无需安装项目依赖：

```powershell
python -m http.server 4187 --bind 127.0.0.1
```

浏览器打开 [本地入口](http://127.0.0.1:4187/)。ES modules 通过 HTTP/HTTPS 加载，直接双击 `index.html` 无法替代静态服务入口。

GitHub Pages 使用 `main` 分支根目录发布，`.nojekyll` 保留原始静态文件。模块与资源使用相对路径，页面导航使用 hash，适用于仓库子路径部署。Proxycheck 源 API 单独部署于 Sites；前端没有密钥注入、数据库下载或后台轮询。

## 数据与网络边界

前端检测请求由用户操作触发，采用 `credentials: omit`；Proxycheck 请求再由服务端加入本方授权。目标 IP 会发送到所查询的服务，浏览器请求实际从哪个出口发出由当前网络和代理规则决定。静态网页无法强制 DIRECT、指定系统代理或读取客户端实际路由链。不同域名可看到不同出口；DB-IP 的访问者限制也可能受到这种分流影响。

报告在浏览器本地生成，默认隐藏 IP；来源记录、错误、时间和缺失状态会随报告保留。前端没有账号系统或分析追踪。Proxycheck 源 API 接收查询目标并使用短期缓存和调用频率计数；GitHub Pages、Sites 与上游数据服务分别处理各自的访问日志。

浏览器环境、WebRTC、DNS、Claude 网页和桌面/命令行客户端的结论各自限定在实际观察范围。DNS 泄漏检测保留专门站点入口，浏览器 HTTP 结果不能证明整机 DNS 或所有应用采用同一路径。
