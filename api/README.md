# 三源服务端适配器

`worker.js` 是无依赖 Cloudflare Worker ESM，默认导出 `fetch(request, env, ctx)`。GitHub Pages 托管静态前端，Sites 托管三个公开只读查询入口；前端只保存服务地址。Proxycheck 的本方授权密钥由运行时 secret 提供，DB-IP 与 IP2Location 使用官方免费服务端 API。

[健康信息](https://egress-observatory-api.reaper-f.chatgpt.site/health) · [Proxycheck](https://egress-observatory-api.reaper-f.chatgpt.site/v1/proxycheck) · [DB-IP](https://egress-observatory-api.reaper-f.chatgpt.site/v1/dbip) · [IP2Location](https://egress-observatory-api.reaper-f.chatgpt.site/v1/ip2location)

## 部署与实际状态

截至 2026-11-05，三路由代码已部署到 Sites 保存版本 3，访问模式为 `public`。Sites 保存版本与 `/health` 的协议字段 `apiVersion` 分别管理，当前协议值为 2。

- **Proxycheck**：本方授权已配置，正式托管服务已观察到 HTTP 200 成功结果，GitHub origin 的 CORS 匹配。
- **DB-IP**：正式托管入口返回 HTTP 429、`upstream-daily-quota`；共享服务端出口的免费日额度已用尽，前端保持该来源缺失。
- **IP2Location**：正式托管入口返回 HTTP 429、`upstream-rate-limit`；当前托管出口受免费额度或频率限制，前端保留失败状态。

本机直接查询成功与托管出口额度分别记录。九源已经集成；当前成功来源数以当轮返回为准。遇到 429 后停止请求，不自动重试、切换出口或规避配额，等待提供方额度恢复。

## 运行时与发布

- `PROXYCHECK_API_KEY`：本方授权密钥，保存在 Sites 运行时 secret。仓库、前端文件、构建输出和响应均不包含其值。
- `ALLOWED_ORIGIN`：单个精确 HTTPS origin，默认为 `https://blackslience-reaper.github.io`。不接受路径、尾斜杠、通配符或多个 origin；生产默认不开放 localhost。

Sites Worker ESM 打包时，将 `worker.js` 作为 `worker/index.js`，构建为 `dist/server/index.js`；`.openai/hosting.json` 保留该 API Site 的 `project_id`，不配置 `static`。部署名称为 `egress-observatory-api`，不依赖 KV、D1、R2 或额外依赖包。

## 路由与来源

- `GET /health`：返回协议版本、来源列表、Proxycheck secret 是否配置的布尔值、缓存与限速参数。它不查询上游，也不返回 secret。
- `GET /v1/proxycheck?ip={IP}`：向官方 `https://proxycheck.io/v3/{IP}` 请求授权数据；服务端添加本方 key。
- `GET /v1/dbip?ip={IP}`：向官方 `https://api.db-ip.com/v2/free/{IP}` 查询指定地址，免费每日 500 次。这是 DB-IP 正式服务端 API 的使用方式。
- `GET /v1/ip2location?ip={IP}`：向官方 `https://api.ip2location.io/?ip={IP}` 查询 Keyless 数据，官方每日 1,000 次额度；不配置或模拟个人密钥。

查询必须提供一个明确公网 IPv4 或 IPv6。拒绝域名、URL、端口、重复参数、私有/回环/组播/文档地址、IPv4 映射 IPv6 和特殊用途范围；IPv6 规范化后再次校验上游响应目标。

`OPTIONS` 只允许指定 origin 对 GET 的预检，请求头为 `Accept`、`Content-Type`。其他 origin 返回 403；无 Origin 的服务端调用可以访问。允许来源得到精确 `Access-Control-Allow-Origin`、`Access-Control-Allow-Credentials: true`、`Vary: Origin`；GitHub 前端仍使用 `credentials: omit`。

## 精选返回字段

统一返回来源 ID、数据库、目标 IP、时间、耗时、国家、城市、ASN、组织、网络类型、`flags`、`fieldSources`、状态、错误代码、署名与 `cacheHit`。

- Proxycheck 仅映射明确的 `vpn`、`proxy`、`tor`、`hosting`；`relay`、`abuser`、`bogon` 保持 `null`，`compromised` 不转换为滥用记录。
- DB-IP 使用实际国家与城市；未提供的 ASN 和安全字段保持 `null`。
- IP2Location 使用实际位置、ASN、组织及布尔 `is_proxy`；其他风险字段不补值。保留 [IP Geolocation by IP2Location.io](https://www.ip2location.io) 署名。

每次成功结果必须包含匹配目标的 IP 记录。服务端不返回密钥、完整上游响应或请求 URL，不提供任意 URL 转发。前端将精选字段交给 `assessment.js`，数据源默认权重为 Proxycheck 20、DB-IP 20、IP2Location 25；IPinfo 30 仅作用于其实际字段。

## 缓存、频率与上游额度

- 仅访问三个固定官方上游地址，禁止重定向，不转发访客 cookie、Origin 或授权头。错误使用本方固定文案，不记录含密钥的上游 URL。
- 上游超时为 12 秒；429 返回额度或频率错误，并保留有界 `Retry-After`，不会自动重试。
- 成功的精选记录在 `caches.default` 中缓存 **600 秒**。缓存 key 区分提供方、规范化目标与缓存版本，不含密钥、访客请求头或 origin。返回浏览器使用 `private, no-store`，CORS 按本次请求生成。
- 缓存不可用或写入失败时不伪造命中；`cacheHit` 只在读到有效缓存时为真。错误结果不作为成功数据缓存。
- **每个调用者在单一 Worker isolate 内每分钟最多 10 次，三条查询路由共享此计数。** 只在 `request.cf` 存在时采用平台的 `CF-Connecting-IP`；缺少可信地址时使用共享桶。缓存命中也计数。
- 内存计数不跨 isolate、区域或重启持久化；各上游的日额度仍独立执行。服务端共享出口可能导致免费额度先于本站频率限制耗尽。

来源说明：[Proxycheck API](https://proxycheck.io/api/) · [Proxycheck 条款](https://proxycheck.io/terms/) · [DB-IP 免费 API](https://db-ip.com/api/free) · [IP2Location API 文档](https://www.ip2location.io/ip2location-documentation)。
