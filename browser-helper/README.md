# Egress 自动网页查询

安装一次后，Egress 的“查询”和“重新检测”会自动使用当前 Chrome 会话读取 IPHub、IPQualityScore 与 IPSuper。IPSuper 的具名数据库类型和风险矩阵用于补齐官网未返回的字段。扩展创建独立临时标签组，读取目标结果后关闭，不修改已有标签，也不把登录 Cookie、账号或 API key 发送给 Egress 服务。

权限范围：IPHub、IPQualityScore、IPSuper 三个来源，以及 Egress 网站和本地 4187 页面。`tabs` 用于创建和关闭临时标签，`tabGroups` 用于分组，`scripting` 只在扩展创建的来源结果页读取公开字段。

在 `chrome://extensions` 打开开发者模式，选择“加载已解压的扩展程序”，选择本目录；然后刷新 Egress 页面。全部读取由查询入口触发。网页需要人机校验时保留原因，扩展不点击或完成验证码。

入口文件为 `manifest.json`；结果提取复用站点的 `src/page-extract.js`，IP 校验复用 `src/util.js`。后台只接受 Egress 页面发来的公网 IP 查询，成功结果按来源和 IP 缓存 10 分钟，切换查询会取消本页的旧任务。
