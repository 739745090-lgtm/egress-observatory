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

## 未自动抓取的页面

IPinfo、Scamalytics、IPPure 等网页可显示更多信息，但公开条款对自动抓取或数据再分发有明确限制。本站保留已有官方 API 或查询链接，未用网页抓取、借用他人密钥、轮换出口或绕过验证码来替代授权接口。

- [IPinfo 条款](https://ipinfo.io/terms-of-service)
- [Scamalytics 条款](https://scamalytics.com/terms-of-service/)
- [IPPure 条款](https://ippure.com/en/terms-privacy)
