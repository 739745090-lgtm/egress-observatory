# Egress API

`worker.js` 是无依赖的 Cloudflare Worker ESM，部署在 Sites（`egress-observatory-api`）。前端只调用它的公开地址；所有密钥都是运行时 secret，仓库与前端都不包含其值。

## 路由

| 路由 | 方法 | 需要 | 说明 |
| --- | --- | --- | --- |
| `/health` | GET | — | 返回 `apiVersion` 与已启用的 `routes`，前端据此决定调用哪些来源 |
| `/v1/page/ipinfo?ip=` | GET | — | 唤醒网页查询容器并读取目标 IP 的 IPinfo 摘要；按 IP 合并并发请求、缓存成功报告 |
| `/v1/page/ipsuper?ip=` | GET | — | 读取目标 IP 的 IPSuper 类型表、逐库风险百分比与明确匿名 / 滥用标记 `riskFlags`，保留原始观察时间 |
| `/v1/page/sources?ip=` | GET | — | 读取其他固定来源的网页字段，部分失败的报告仅缓存 60 秒 |
| `/v1/page/getipintel?ip=` | GET | — | 经 Render 调用 GetIPIntel，使用同一个调用者 IP 限额 |
| `/v1/proxycheck?ip=` | GET | `PROXYCHECK_API_KEY` | VPN、代理、Tor、机房、风险分、入侵 / 爬虫标记、设备估计 |
| `/v1/ipapi?ip=` | GET | — | ip-api.com（免费接口只有 HTTP，浏览器无法直连）：代理、机房、移动 |
| `/v1/ip2location?ip=` | GET | `IP2LOCATION_API_KEY`（建议） | IP2Location.io；免密钥额度按调用 IP 计算，托管出口共享会被用光，配置免费账号 key（每月 5 万次）后按账号计；套餐含 `usage_type` 时提供使用 / 公司类型 |
| `/v1/dbip?ip=` | GET | — | DB-IP 免费接口，每日 500 次 |
| `/v1/abuseipdb?ip=` | GET | `ABUSEIPDB_API_KEY`（可选） | 滥用置信度、举报数、用途类型；IPv4 另查同 /24 近 30 天被举报的邻居（check-block） |
| `/v1/ipqs?ip=` | GET | `IPQS_API_KEY`（可选） | IPQualityScore 欺诈分、VPN / 代理 / Tor（含活跃）、近期滥用、爬虫、连接类型；缓存 6 小时 |
| `/v1/ipinfo?ip=` | GET | `IPINFO_TOKEN`（可选） | 优先用 `api.ipinfo.io/lookup`（anonymous.is_vpn / is_proxy / is_tor / is_relay / is_res_proxy、is_hosting、is_mobile、as.type），套餐不含时退回旧接口 |
| `/v1/ipregistry?ip=` | GET | `IPREGISTRY_API_KEY`（可选） | 连接类型、公司类型、安全标记；缓存 6 小时 |
| `/v1/ipdata?ip=` | GET | `IPDATA_API_KEY`（可选） | 威胁标记与分数、机房、ASN 类型 |
| `/v1/ipapiis?ip=` | GET | `IPAPI_IS_KEY`（可选） | ipapi.is 完整版：VPN / 代理 / Tor / 机房 / 滥用 / 爬虫、公司与 ASN 类型、滥用分 |
| `/v1/scamalytics?ip=` | GET | `SCAMALYTICS_USER` + `SCAMALYTICS_KEY`（可选，可选 `SCAMALYTICS_HOST`） | Scamalytics 欺诈分、机房、VPN、iCloud 中继 |
| `/v1/vpnapi?ip=` | GET | `VPNAPI_KEY`（可选） | VPN / 代理 / Tor / 中继 |
| `/v1/iphub?ip=` | GET | `IPHUB_KEY`（可选） | block 0 家宽 / 1 非家宽（机房、代理）/ 2 混合 |
| `/v1/getipintel?ip=` | GET | `GETIPINTEL_CONTACT`（可选，填你的邮箱） | 代理 / VPN 概率 |
| `/v1/greynoise?ip=` | GET | `GREYNOISE_API_KEY`（可选） | 是否在全网扫描（noise）、恶意 / 良性分类、RIOT 已知良性服务 |
| `/v1/crowdsec?ip=` | GET | `CROWDSEC_CTI_KEY`（可选） | CrowdSec 信誉、行为、代理 / VPN / Tor 分类、风险分 |
| `/v1/virustotal?ip=` | GET | `VT_API_KEY`（可选） | 判定恶意 / 可疑的安全厂商数量 |
| `/v1/radar?asn=` | GET | `CF_RADAR_TOKEN`（可选） | Cloudflare Radar 近 28 天 ASN 人机流量占比，缓存 6 小时 |
| `/v1/turnstile/verify` | POST | `TURNSTILE_SECRET_KEY` | `{ "token": "…" }` → `{ success, hostname, challengeTs, errorCodes }` |
| `/v1/recaptcha/verify` | POST | `RECAPTCHA_SECRET_KEY` | `{ "token": "…" }` → `{ success, score, action, hostname, errorCodes }` |

未配置 secret 的路由不出现在 `/health.routes` 里，调用返回 503；前端显示“未配置”，不计分。

## 获取密钥

- **Turnstile**：Cloudflare 控制台 → Turnstile → Add widget，模式选 Managed，域名填 `blackslience-reaper.github.io`、`127.0.0.1`、`localhost`。site key 写进根目录 `config.js`，secret key 设为 `TURNSTILE_SECRET_KEY`。
- **reCAPTCHA v3**：https://www.google.com/recaptcha/admin 新建 v3（基于分数），同样三个域名。site key 写进 `config.js`，secret 设为 `RECAPTCHA_SECRET_KEY`。
- **IP2Location.io**（建议）：注册免费账号，key 设为 `IP2LOCATION_API_KEY`，解决共享出口被限流的问题。
- **IPQualityScore**（可选）：注册免费账号（每月少量额度），key 设为 `IPQS_API_KEY`。
- **IPinfo**（可选）：token 设为 `IPINFO_TOKEN`；匿名标记、is_hosting 等字段只有包含它们的套餐才返回，免费 Lite 只有国家与 ASN。
- **IPRegistry** / **IPData**（可选）：免费 key 分别设为 `IPREGISTRY_API_KEY`、`IPDATA_API_KEY`。
- **其他可选来源**：ipapi.is、Scamalytics、vpnapi.io、IPHub、GreyNoise、CrowdSec、VirusTotal 都有免费层，注册后把 key 设为上表对应的变量；GetIPIntel 只需要一个能收信的联系邮箱。
- **AbuseIPDB**（可选）：注册后在 API 页面创建 key，免费每日 1,000 次 check、100 次 check-block。
- **Cloudflare Radar**（可选）：Cloudflare 控制台 → My Profile → API Tokens，创建带 `Account · Radar · Read` 权限的 token。

## 安全与限额

- CORS 只允许 `ALLOWED_ORIGIN`（默认 `https://blackslience-reaper.github.io`）和本地 `http://127.0.0.1:4187`、`http://localhost:4187`；预检只接受 `Accept`、`Content-Type` 头。
- 查询只接受一个公网 IP 参数，拒绝域名、URL、私网、保留地址；上游响应的目标必须与查询一致。
- 只访问固定的上游地址，禁止重定向，不转发访客 cookie、Origin 或授权头；错误使用固定文案，不回显上游 URL 或密钥。
- 每个调用者出口 IP 每 60 秒最多 30 次查询，查询、网页补全、统计和验证码校验共享额度，缓存命中也计数。计数由 D1 单条 UPSERT 原子更新，跨 isolate、区域及 Worker 重启共享；超限返回 `429 caller-rate-limit`、`Retry-After` 和 `retryAfterSeconds`。`/health`、合法预检不占查询额度。
- 只接受 Cloudflare 提供的调用者地址；Sites 无 `request.cf` 时要求平台覆盖后的 `CF-Connecting-IP` 与 `X-Real-IP` 一致，忽略 `X-Forwarded-For`、请求体和目标 IP 中的身份声明。缺失可信地址或 D1 不可用时返回 503，暂停查询以保持额度保护。D1 的限流键使用服务端随机盐与调用者 IP 的 SHA-256，不存调用者 IP 原文；过期计数和凭据会被清理。
- Render 查询统一经 `/v1/page/*` 转发。主 API 通过额度检查后生成 120 秒有效的一次性随机凭据，并在 D1 绑定来源及目标 IP；Render 在访问缓存和 Chromium 前请求 `/internal/page-admission` 原子消费凭据。缺失、过期、重放或目标不符返回 403，额度校验异常返回 503；直接访问 Render 和伪造转发头无法绕过主 API。内部凭据接口独立限制每调用者 IP 每分钟 120 次，不占访客额度。Render 同时最多接纳 3 个未完成查询，给健康检查保留线程。
- 成功查询按“来源 + IP”缓存，普通 API 默认 1 小时，低额度来源更长，旧结果回退最多 24 小时；网页报告最多 10 分钟，部分失败的 sources 报告最多 60 秒。验证路由不缓存。上游 429 返回有界 `Retry-After`；调用者超限时前端停止本轮网页重试。
- Turnstile / reCAPTCHA 校验会附带平台提供的访客 IP（`remoteip`）。Turnstile token 上限 2,048 字符、请求体上限 4 KB；reCAPTCHA token 上限 8,192 字符、请求体上限 16 KB。请求体按流限长，HTTP 失败原因会回传给页面，避免被误显示为“无分数”。

## 部署

Sites 的构建目录是本仓库之外的 `.sites-api/`（已在 `.gitignore`）：

```bash
cp api/worker.js .sites-api/worker/index.js
cd .sites-api && npm run build
```

构建产物 `dist/server/index.js` 与 `dist/.openai/hosting.json`（保留 `project_id`）交给 Sites 部署，secret 在 Sites 的环境变量里设置。
