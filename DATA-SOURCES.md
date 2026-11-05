# 公开查询服务的间接补充

更新日期：2026-11-05。

本站只把实际返回、且与目标 IP 一致的字段纳入结果。间接来源保留服务名称、版本或缓存时间；没有证据的原始数据库名称继续保持未确认。

## TechnikNews IPgeo

[公开入口](https://api.techniknews.net/)提供 IPgeo 服务；接口为 `https://api.techniknews.net/ipgeo/{IP}`，本轮公共地址查询实际返回 HTTP 200 与 CORS `*`。

可补充国家、城市、ASN、组织、PTR、移动、代理和机房标记。响应采用 ip-api 兼容结构，本站不据此宣称其原始数据库归属已得到独立核实。

当前目标的主 ip-api 查询真实成功时跳过补充请求；主查询失败或服务端未启用时才调用这个独立公开接口。两条路径不会同时给同一轮增加定位票。返回的 `cacheTimestamp` 保留为来源时间；来源缓存不会伪装成实时检测。

## Blackbox v3 beta

[官方接口说明](https://blackbox.ipinfo.app/)明确公开 `GET /api/v3beta/{IP}`，Beta 阶段不要求 API key，未来可能变化。接口不稳定或要求授权时显示不可用。

替换原先的 v1 Y/N 读取方式。v1 的 Y 包含机房、云平台等不同列表命中，不能统一当成代理。v3 分别读取 `proxy`、`tor`、`hosting`、`vpnasn`、`goodvpn` 等实际信号，保留分类、规则依据和服务版本。

分类为 unknown 时，未命中信号不作为明确阴性票；分类置信度不换算成欺诈分。Spamhaus、SFS、IC3 的间接标记保留在报告中，避免同源情报重复扣分。该服务属于 ipinfo.app，不能归名为 IPinfo.io 数据库。

## Net Atlas

[官方接口说明](https://www.ipinfo.app/api/ip2country/)公开 `https://atlas.ipinfo.app/api/v2/ip/{IP}`，无需鉴权且支持 CORS，网络归属数据关联 IPtoASN/BGP。

补充 ASN、组织与前缀。接口顶层国家标签是宣告 AS 的注册国家，与 `location` 地理信息分开保留，也不自动推导“原生／广播”。

官方文档明确 `location.source = baseline` 来自 DB-IP City Lite（CC BY 4.0）。这条路径按 0.6 权重补充地理字段，并与 DB-IP、FreeIPAPI 按底层数据库去重；国家、城市和时区分别取同库已返回字段中权重最高的一票。其他定位路径（geofeed、registry、override 等）保留来源，只展示。页面保留“IP Geolocation by DB-IP”署名。

## AbuseIPDB 中的 IPinfo 字段（需要账号授权）

[官方 CHECK 文档](https://docs.abuseipdb.com/#check-endpoint)明确位置、使用类型、ISP 与域名来自 IPinfo。后端已有独立的密钥配置入口；未配置时显示“未配置密钥”，这些字段保持未知。AbuseIPDB 自身的举报分保留其独立来源。

## 来源网页补全

按 2026-11-05 的用户请求，对字段不足的来源增加单目标网页读取：IPHub、IPQualityScore、IPData、IPRegistry、DB-IP、Scamalytics、ipapi.is、IPQuery、Blackbox。固定目标地址、有限等待，成功和失败均逐源展示。遇到人机校验时停止读取并保留原因；网页未显示的字段保持未知，接口已提供的字段优先。

IPHub 的 `block=0` 覆盖家宽和商业，只展示“家宽或商业”；`block=1` 覆盖代理、VPN 和机房，只展示该组合标签。两者均不推导单独的使用类型。IPQualityScore 只使用目标表格中的明确 VPN、PROXY、TOR 字段及明确风险分。Scamalytics 风险与匿名标记保持同库合并，地理字段不重复投票。

用户可在多源类型区展开“从来源网页补全”，通过书签从自己的官方查询页回传当前目标字段，或粘贴报告 JSON；核对 IP 与 10 分钟有效期。IPPure 继续仅提供查询链接。

IPHub 与 IPQualityScore 的日常查询采用自动流程：可安装 `browser-helper` 一次，由 Egress 查询入口调用当前 Chrome 会话，临时结果页读取后关闭。独立 Chromium 会话受人机校验限制时保留失败原因，当前 Chrome 的成功报告仍能自动补齐字段。IPHub 除 block 组合标签外，按网页明确的 `proxyType.proxy`、`tor`、`hosting`、`relay` 等字段参与对应投票；组合 block 标签不拆成 VPN 或代理标记。

IPSuper 风险矩阵按其页面图例读取：`detected` 为明确阳性，普通指示格为明确阴性，`null`（不支持）和 `failed`（获取失败）均不参与。逐库的 VPN、Proxy、Tor、Server、Abuse、Bot 分别映射到已有评分字段。IPQualityScore、Scamalytics、AbuseIPDB 的具名风险分进入同库风险评分；其他百分比不自动当作欺诈分。Chrome、官网与间接网页的补充都保留来源和时间，同一数据库不增加重复票。

IPOK 补充覆盖其已返回的 IPHub、vpnapi.io、Scamalytics、IPQS、ip-api、ipapi.is、Proxycheck 和 AbuseIPDB 具名行。只有目标一致、行明确成功且观测时间在最近 72 小时的记录用于补缺；时间不明、超过时限和额度不足均保留原因。支持明确的使用 / 公司类型、风险分与匿名标记，已有同库字段优先。IPSuper Chrome 页面与云端页面同时返回时使用较新的观察，避免旧缓存覆盖新补全。

## Net.Coffee 的底层来源

目标查询响应（`https://ip.net.coffee/api/ip/lookup/<IP>`）的 `geo_sources` 为地理观察。抽样查询返回 g1、g2、g3、g7；[页面脚本](https://ip.net.coffee/ip/ip-page.js?v=20260910d)按 g1、g7、g3、g2 排序。公开响应和显示逻辑没有给出这些代码与具体厂商的对应关系。company_type、isResidential、is_datacenter 是顶层汇总字段，没有逐库标签。本站保留各来源代号，只在旁证区展示，不参与数据库类型或定位投票。[官方卡片说明](https://card.net.coffee/)披露的资料包括 BGP、反向 DNS、WHOIS 和历史滥用记录。

本机查询服务支持在授权范围内按单个目标读取 IPinfo 详情页。结果仅回到发起查询的页面，网页与接口按 IPinfo 同库合并。
