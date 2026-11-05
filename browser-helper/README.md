# Egress 自动网页查询

[下载 v1.2.1 ZIP 安装包](https://blackslience-reaper.github.io/egress-observatory/downloads/egress-browser-helper-v1.2.1.zip)，解压后选择其中的 `browser-helper` 文件夹进行安装。网站“多源 IP 类型”区也提供同一下载入口。

安装一次后，Egress 的“查询”和“重新检测”会自动使用当前 Chrome 会话读取以下来源的公开查询页，补齐接口没有返回的字段：

| 来源 | 读取的字段 |
|---|---|
| IPSuper | 各库的使用类型、公司类型与风险矩阵 |
| IPHub | block 分类、代理 / Tor / 机房 / 住宅代理标记 |
| IPQualityScore | VPN、代理、Tor、近期滥用、机器人、机房、欺诈分、连接类型 |
| Scamalytics | 欺诈分、VPN / 代理 / Tor / 机房 / 爬虫 / 住宅代理，以及它核对的 Spamhaus、FireHOL、IPsum、X4Bnet 黑名单 |
| IP2Location | 使用类型（ISP / MOB / DCH …）、代理与代理类型、威胁类别、欺诈分、坐标 |
| GreyNoise | 是否被观测到扫描、良性 / 恶意分类、扫描方、最近出现、VPN / Tor |
| DB-IP、IPRegistry | 使用类型、公司类型、匿名与威胁标记（页面通过浏览器校验后） |
| Blackbox、IPQuery | 分类与匿名标记（JSON 页面） |

ipapi.is 不在其中：它的网页与 Egress 直接调用的接口共用每个 IP 每天 30 次的额度，超额会被封禁 24 小时。IPData 也不在其中：它的网页要先通过 Turnstile 才显示完整记录，完整记录的版面还没有可用的读取规则。

扩展最多同时打开 3 个临时标签，放进“Egress 自动查询”标签组，读完即关闭；每个来源一读到就回传，页面边收边合并。网页要求人机验证时，扩展不会点击或完成验证码：该标签保留最多 150 秒并让出并发名额，Egress 页面显示「去验证」按钮，点击后切到该标签由你自己完成，扩展随后自动读取并切回 Egress。超时未完成的来源记为“人机验证未完成”。

扩展不修改已有标签，也不把登录 Cookie、账号或 API key 发送给 Egress 服务。权限范围：上表各来源与 Egress 网站和本地 4187 页面。`tabs` 用于创建、切换和关闭临时标签，`tabGroups` 用于分组，`scripting` 只在扩展创建的来源结果页读取公开字段。

在 `chrome://extensions` 打开开发者模式，选择“加载已解压的扩展程序”，选择本目录；然后刷新 Egress 页面。全部读取由查询入口触发。

入口文件为 `manifest.json`；结果提取复用站点的 `src/page-extract.js`，IP 校验复用 `src/util.js`。后台只接受 Egress 页面发来的公网 IP 查询，成功结果按来源和 IP 缓存 10 分钟，切换查询会取消本页的旧任务。

仓库中的发行包位于 `downloads/egress-browser-helper-v1.2.1.zip`。更新扩展版本时，同步 `manifest.json`、安装包文件名和网页下载链接。
