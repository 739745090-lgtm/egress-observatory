## 关联 Issue

Closes #

## 改了什么

<!-- 说明结果和原因，不用逐行复述代码。 -->

## 怎么验证的

- [ ] `npm test` 通过
- [ ] 在本地或线上页面实际验证过（写明步骤和结果）

验证平台：<!-- Windows / macOS / 只跑了 CI -->

## 按改动范围核对

只勾选涉及的项，其余可以删除。

- [ ] **页面资源**：改过的文件已更新 `index.html` 或 import 里的 `?v=` 版本号
- [ ] **评分**：`SCORING.md` 和 `tests/score.test.mjs` 已同步
- [ ] **数据源**：`README.md` 的检测内容、`DATA-SOURCES.md` 已同步
- [ ] **后端**：`api/README.md` 已同步，合并后需要手动部署 `api/worker.js`
- [ ] **查询服务**：`local_server.py`、`cloud_server.py`、`provider_pages.py` 或 `Dockerfile` 有变化，合并后确认 Render 已更新
- [ ] **Chrome 扩展**：已升版本、重新打包到 `downloads/` 并更新所有版本引用（见 [贡献指南](https://github.com/BlackSlience-Reaper/egress-observatory/blob/master/CONTRIBUTING.md#chrome-扩展)）

## 提交前确认

- [ ] 代码、文档、测试和截图里没有真实 IP，也没有密钥
- [ ] PR 标题是一句英文祈使句，合并后它就是 `master` 上的提交信息
