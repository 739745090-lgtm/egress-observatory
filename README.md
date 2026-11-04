# Egress · IP 质量检测

**v1.3 · 2026-11-05**

一个深色 IP 检测页面：打开后自动填入当前公网出口，点击“查询”后联合九个数据源，展示质量参考、风险标记和地理分歧。

[打开网站](https://blackslience-reaper.github.io/egress-observatory/) · [GitHub 仓库](https://github.com/BlackSlience-Reaper/egress-observatory)

## 使用

1. 开页只请求一次 [ipify](https://www.ipify.org/) 获取公网出口并填入输入框。已经开始手动输入的地址会保留，完整检测由“查询”按钮启动。
2. 输入或确认一个公网 IPv4 / IPv6，点击 **查询**。九个来源针对同一目标并行返回结果，失败和未知字段单独保留。
3. 查看顶部 IP 概览与渐变质量指针、左侧环形分数和城市对照、右侧六项检测结论与 ASN，以及底部来源状态标签。
4. **原始数据**、**评分设置**、**检测方法** 默认折叠，展开后可查看逐库字段、调整来源权重与可选期望国家。**取消**终止本轮请求；**导出**生成本地 JSON 报告，默认隐藏 IP。

自动填入的地址是当前浏览器访问 ipify 时所见的公网出口，受代理和分流规则影响；局域网网卡地址不在本页采集范围。自动识别失败时可直接输入目标地址。

## 九个自动来源

- **[IPinfo](https://support.ipinfo.io/hc/en-us/articles/34121895556242-Legacy-Free-API-vs-IPinfo-Lite)**：官方 Legacy Public API，免 token，返回实际位置与 ASN。默认权重 30，未返回的隐私字段保持缺失。
- **[IP2Location.io](https://www.ip2location.io/ip2location-documentation)**：服务端调用官方 Keyless API，提供实际位置、ASN 与 `is_proxy`。默认权重 25，保留 IP Geolocation by IP2Location.io 署名。
- **[ipapi.is](https://ipapi.is/free-tier.html)**：匿名层的位置、网络归属与 Bogon。默认权重 25，完整安全字段需要提供方授权。
- **[Proxycheck](https://proxycheck.io/api/)**：服务端使用本方授权，返回明确的 VPN、Proxy、Tor、Hosting 等精选分类，默认权重 20。
- **[IPQuery](https://ipquery.io/sources)**：明确归属的分类参与评分，默认权重 20；未命名 Enterprise MMDB 的地理字段只作旁证。
- **[DB-IP](https://db-ip.com/api/free)**：服务端使用官方免费 API 查询目标国家与城市，默认权重 20，保留 IP Geolocation by DB-IP 署名。
- **[ipwho.is](https://ipwhois.io/documentation)**：位置与网络归属，默认权重 15；免费层未提供的 Security Data 保持未知。
- **[FreeIPAPI](https://freeipapi.com/data-sources)**：来源包含 DB-IP（CC BY 4.0），逐字段上游未完全披露。聚合结果单列旁证，不重复计入 DB-IP 或其他库。
- **[RIPEstat / RIS](https://stat.ripe.net/docs/data-api/api-endpoints/network-info)**：公告前缀与 ASN 路由证据，校验目标属于返回前缀，不计入风险分。

权重只作用于真实返回的字段。同一底层库的同字段去重后融合；目标不匹配、请求失败和未提供的字段保持 `null`，不会补成阴性 `false`。

## 评分与呈现

“综合参考分 · 含类型适配”由 **匿名与滥用风险 70% / 网络类型适配 20% / 地区一致性 10%** 构成。VPN、Proxy、Tor、Relay 先逐字段按数据库融合，再取已知字段中的最低分作为关联匿名组分数；组权重为这些字段的已知权重之和。Abuser 与 Bogon 分别计分。

Hosting 说明机房类型，属于本项目的网络适配刻度，不等同滥用证据。明确的 Tor、Abuser、Bogon 命中保留独立提醒。地区偏好未填写时展示多库国家共识，城市分歧继续按来源呈现。

覆盖率描述实际获得的指标权重，交叉确认描述同字段有多少独立来源。覆盖不足、分歧或独立风险证据不足时标为暂定；有效覆盖低于 20%、没有风险字段或目标冲突时暂不生成总分。高分不代表所有指标已检查，也不是账号或服务可用概率。

原站评分方向、公开阈值和披露边界见 [评分来源核对与实现建议](SCORING-SOURCES.md)。研究文档提及的其他服务不表示已接入自动查询。

## 托管与当前限制

前端位于 GitHub Pages；Proxycheck、DB-IP、IP2Location 的公开只读适配器位于 Sites。密钥仅存 Sites 运行时 secret，仓库和前端不包含其值。

成功的服务端结果缓存 **600 秒**；三条查询路由共享每调用者、每 Worker isolate **10 次/分钟**的内存限速，不能替代各上游日额度。详细路由、返回字段和额度见 [API 说明](api/README.md)。

2026-11-05 的正式托管调用中，Proxycheck 已返回成功记录；DB-IP 返回 `429 upstream-daily-quota`，IP2Location 返回 `429 upstream-rate-limit`。后两项受共享托管出口的免费额度或频率限制，保持缺失，不自动重试或更换出口。九源已集成，实际成功数量以本轮结果为准。

## 本地运行

```powershell
python -m http.server 4187 --bind 127.0.0.1
```

在仓库目录运行后打开 [本地入口](http://127.0.0.1:4187/)。ES modules 需要 HTTP/HTTPS 静态服务。生产前端从 `main` 分支根目录发布，使用相对资源路径与 `.nojekyll`。

`app.js` 负责公网地址填入与页面初始化；`dashboard.js` 编排查询；`visuals.js` 呈现深色结果布局；`providers.js` 规范化响应；`assessment.js` 计算参考分；`api/worker.js` 提供三个服务端适配器。

## 数据流

开页的自动地址识别与点击“查询”后的九源请求分别触发，前端请求使用 `credentials: omit`。目标 IP 会发送到对应数据服务；服务端查询描述明确指定的目标，浏览器请求出口由当前网络决定。

报告由浏览器本地生成，隐藏开关决定是否导出完整目标 IP。页面没有账号系统、分析追踪或后台轮询；GitHub Pages、Sites 和上游服务分别处理自己的访问日志。服务端仅保留短期查询缓存和频率计数。
