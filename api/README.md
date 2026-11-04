# Proxycheck 服务端适配器

`worker.js` 是无依赖 Cloudflare Worker ESM，默认导出 `fetch(request, env, ctx)`。GitHub Pages 继续托管静态前端，前端只调用此服务的公开地址。Proxycheck 私钥仅由运行时绑定读取。

截至 2026-11-05，本方 Proxycheck 授权已配置为 Sites 运行时 secret，服务端真实查询已返回 HTTP 200 成功记录。Sites 访问模式为 `public`，向 GitHub Pages 提供公开只读查询；前端已将其列为第八个自动来源。

[公开查询入口](https://egress-observatory-api.reaper-f.chatgpt.site/v1/proxycheck) · [服务健康信息](https://egress-observatory-api.reaper-f.chatgpt.site/health)

## 运行时绑定

- `PROXYCHECK_API_KEY`：用户本人 Proxycheck 账户的私钥，保存为 Sites 的受保护运行时 secret。禁止写入此仓库、构建输出、前端配置、命令行参数或日志。
- `ALLOWED_ORIGIN`：单个精确 HTTPS origin，默认 `https://blackslience-reaper.github.io`。不接受路径、尾斜杠、通配符或多个 origin；生产默认不开放 localhost。

Sites Worker ESM 打包时，将 `worker.js` 作为 `worker/index.js` 源码，构建输出为 `dist/server/index.js`；产物的 `.openai/hosting.json` 保留该 API Site 的 `project_id`，不配置 `static`。本适配器不需要依赖包、KV、D1 或 R2。

部署名称为 `egress-observatory-api`，使用 Worker ESM 入口。受保护 runtime secret 通过 Sites 环境变量绑定；源码和部署清单只出现绑定名称。

## 接口

`GET /health` 返回服务版本、secret 是否已配置的布尔值、缓存与限速参数。它不请求 Proxycheck，也不返回任何 secret。

`GET /v1/proxycheck?ip=1.1.1.1` 查询一个明确公网 IP。支持普通全球单播 IPv4、IPv6；拒绝域名、URL、端口、重复参数、私有地址、回环、组播、文档地址、IPv4 映射 IPv6 和特殊用途范围。输入的 IPv6 会规范化后再核对响应目标。

`OPTIONS` 只支持允许 origin 对 GET 的预检，允许请求头为 `Accept`、`Content-Type`。来自其他 origin 的请求返回 403。无 Origin 的服务端请求可以访问；平台入口已公开，查询不要求访客登录 Sites。

合法 origin 得到精确的 `Access-Control-Allow-Origin`、`Access-Control-Allow-Credentials: true` 和 `Vary: Origin`。CORS 控制浏览器读取能力；GitHub 前端仍使用 `credentials: omit`，不携带用户 cookie、Proxycheck 密钥或平台访问凭据。

## 返回字段

返回与前端数据适配器一致的精选结构：`providerId: proxycheck`、`database: Proxycheck`、`ip`、`observedAt`、`duration`、`country`、`city`、`asn`、`org`、`networkType`、`flags`、`fieldSources`、`status`、`error`、`errorCode`、来源署名与缓存命中状态。

质量字段仅从上游明确的布尔值转换：`vpn`、`proxy`、`tor`、`hosting`。`relay`、`abuser`、`bogon` 保持 `null`；`compromised` 不转换为 `abuser`。Hosting 为真时网络类型为 `hosting`，其他类型仅对明确的原始类型做映射，缺失保持 `null`。上游国家使用 `location.country_code`，组织优先使用 `network.organisation`。

每个成功结果必须恰好包含一个匹配目标的 IP 记录。上游整份响应、运营商细节、攻击历史、设备估算、综合风险分、私钥与请求 URL 均不返回。前端将这些精选字段与其他数据库共同评估，避免作为上游完整数据转发服务。数据使用范围参照 [Proxycheck 条款](https://proxycheck.io/terms/)。

## 请求、缓存与额度

- 上游仅可请求固定 `https://proxycheck.io/v3/{ip}`，私钥由服务端添加到 `key` 参数；禁止重定向，不转发客户端 cookie、Origin、授权或代理地址。错误只返回本方固定文案，不记录上游 URL 或错误对象。
- 上游请求最多 12 秒；429 返回 `upstream-rate-limit` 与有界 `Retry-After`，不自动重试。401/403 等错误保持不可用状态。
- 成功的精选记录在 `caches.default` 保留 10 分钟；缓存 key 为当前服务 host、固定版本和规范化目标 IP，不包含私钥、客户端头或 origin。缓存内容不含 CORS，命中后按本次请求重新生成 CORS；返回浏览器的响应使用 `private, no-store`。
- Cache API 是平台缓存，可能在预览或某些鉴权配置下不可用。缓存写入失败不会伪造命中，`cacheHit` 只在实际读到有效缓存时为真。密钥更换不会改变 IP 缓存 key，旧数据至多保留到 10 分钟有效期。
- 每个调用者每分钟最多 10 次，由 Worker isolate 内存计数。只在 `request.cf` 存在时采用平台提供的 `CF-Connecting-IP`；不使用 `X-Forwarded-For`、`X-Real-IP` 或请求参数。没有可信调用者地址时共享一个有界桶。
- 内存限速不跨 isolate、区域或重启持久化，无法代替账户日配额；上游账户额度仍由 Proxycheck 执行。缓存命中也计入本方请求频率。

## 前端接入

前端的 `proxycheck` 数据源向 `https://egress-observatory-api.reaper-f.chatgpt.site/v1/proxycheck?ip={encodedIP}` 发起请求，使用与其他来源相同的目标匹配、取消和错误显示流程。数据来源 ID 与 `fieldSources` 均为 `proxycheck`，默认权重 20；IPinfo 的默认权重为 30，仅作用于实际返回字段。

前端只保存公开 API base URL。授权密钥保留在 Sites 运行时，仓库、GitHub Pages 文件与查询响应均不包含其值。服务端只转发规范化精选记录，不提供任意 URL 请求或完整上游数据转发。

缓存 TTL 为 600 秒，限速为每个调用者每个 isolate 每分钟 10 次；跨 isolate、跨区域和重启后的全局额度仍由上游执行。`cacheHit` 以实际缓存读取结果为准，已经成功的服务端请求不替代每次前端调用和缓存命中的观察。
