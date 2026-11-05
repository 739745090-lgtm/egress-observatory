# Egress Chrome 插件 v1.3.1

[下载 ZIP](https://blackslience-reaper.github.io/egress-observatory/downloads/egress-browser-helper-v1.3.1.zip)

解压后，在 chrome://extensions 开启开发者模式，加载 browser-helper 文件夹。更新时替换原目录文件并点“重新加载”，再刷新 Egress 页面。点击“查询”或“重新检测”触发读取。

覆盖 18 个来源：IPSuper、IPinfo、IP2Location、IPRegistry、ip-api.com、IPData、AbuseIPDB、DB-IP、Proxycheck、IPQualityScore、ipapi.is、IPLocate、GeoIPLookup、IPHub、IPQuery、Blackbox、Scamalytics、GreyNoise。公开接口由插件直接请求，其余读取当前 Chrome 会话的结果页。ipapi.is 与 IPLocate 在网站接口成功或明确限流时跳过，避免重复消耗额度。

最多同时加载 3 个来源，临时标签归入“Egress 自动查询”。遇到人机验证时保留标签并释放并发名额，Egress 显示“去验证”。插件持续等待用户手动通过，然后自动读取、回传并重新评分。等待没有固定超时；“停止等待”、切换查询或关闭 Egress 页面会取消本轮并清理标签。扩展不操作验证码。

“查询详情”按来源区分插件、API 和服务器，记录 HTTP 状态、额度、连接超时、拒绝访问、目标不匹配或字段缺失以及耗时。验证通过仍缺少可识别字段时如实报告；网页可访问不等于取得类型。已读到的有效字段按数据库合并，未知字段不作为否定结论。

权限：tabs、tabGroups 创建和清理临时标签；scripting 读取这些标签内的公开结果。host_permissions 限于上述来源。ip-api.com 的免费接口使用 HTTP。登录 Cookie 留在浏览器内，插件不向 Egress 服务复制 Cookie、账号或 API key。

结果按来源与 IP 缓存 10 分钟。page-extract.js、page-providers.js 与站点 src/ 对应文件同步，IP 校验复用 util.js。安装包包含完整 browser-helper/ 文件夹。

v1.3.1 修复 IPData 的卡片布局，读取 ASN、公司、信任分与风险徽记；信任分保留原意。IPQS 从目标结果区读取风险分、VPN、代理与 Tor，缺失字段逐项说明。插件直接返回解析异常，页面仍在加载外部资源时也会尝试读取。查询时可复用已打开的相同 IP 结果页，用户原有标签始终保留。
