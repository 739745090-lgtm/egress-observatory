# 参与开发

任务统一放在 [Issues](https://github.com/BlackSlience-Reaper/egress-observatory/issues)，通过 PR 完成。`master` 受保护，任何人（包括仓库管理员）都不能直接推送。

**合并到 `master` 就等于发布**：GitHub Pages 从 `master` 根目录直接提供网站。

## 工作流

1. **建 issue**：在 [新建页面](https://github.com/BlackSlience-Reaper/egress-observatory/issues/new/choose) 选一个模板，自己要做的工作选“开发任务”。
2. **开分支**：从最新的 `master` 拉出，分支名用 `<issue 编号>-<简短描述>`。
3. **提 PR**：按模板填写，正文写 `Closes #编号`，合并时 issue 会自动关闭。
4. **合并**：CI 通过后 squash 合并，远程分支会自动删除。

常用命令（把 `12` 换成你的 issue 编号）：

```bash
gh issue develop 12 --base master --name 12-short-description --checkout
```

```bash
git push -u origin HEAD
```

```bash
gh pr create
```

```bash
gh pr merge --squash
```

合并后回到 `master` 并清理：

```bash
git switch master
git pull --prune
git branch -d 12-short-description
```

`git branch -d` 可能因为 squash 合并提示分支未合并；确认 PR 已合并后，可以换成 `git branch -D`。

### 多端开发

离开前把分支推上去，到另一台电脑继续：

```bash
git fetch
git switch 12-short-description
```

进度和没做完的部分记在 issue 评论里。别在两台电脑上同时改同一个分支；回来继续前先 `git pull`。

## 环境配置

需要 Git、[GitHub CLI](https://cli.github.com/)、Python 3.12 和 Node.js 24（CI 使用的版本）。Node 只用来跑测试，项目没有 npm 依赖。

### Windows

在 PowerShell 里安装工具：

```powershell
winget install Git.Git
winget install GitHub.cli
winget install OpenJS.NodeJS.LTS
winget install Python.Python.3.12
```

重新打开终端后克隆并设置提交身份：

```powershell
gh auth login
gh repo clone BlackSlience-Reaper/egress-observatory
cd egress-observatory
git config user.name "你的名字"
git config user.email "<ID>+<用户名>@users.noreply.github.com"
```

运行测试和本地站点（也可以双击 `启动网站.cmd`）：

```powershell
npm test
python local_server.py
```

邮箱建议用 GitHub 的 noreply 地址，可以在 [邮箱设置](https://github.com/settings/emails) 查到，这样提交记录既能关联账号，又不会暴露真实邮箱。

### macOS / Linux

```bash
npm test
python3 local_server.py
```

### 网页查询功能

本地的“查询”和网页补全还需要 Playwright 和 Chromium。Windows 上用 `python`，macOS / Linux 上用 `python3`：

```bash
python -m pip install playwright
python -m playwright install chromium
```

### 换行符

`.gitattributes` 已经统一了换行符：仓库内都是 LF，`.cmd`、`.bat`、`.ps1` 在工作区是 CRLF。不需要改 `core.autocrlf`。如果 PR 的 diff 显示整个文件都变了，通常是编辑器改了换行符，改回 LF 即可。

## 提交与 PR

- **一个 PR 解决一个 issue**，无关改动另开。
- **PR 标题就是 `master` 上的提交信息**（squash 合并，正文不进入提交信息）。用一句英文祈使句说明结果，例如 `Raise the bonus cap from 8 to 10`。
- **CI 必须通过**：Ubuntu 和 Windows 上都会运行单元测试、Python 语法检查，并核对扩展与网站的共用文件是否一致。
- **PR 上的讨论要全部解决**才能合并。目前不要求审批，因为项目由一人维护，而 GitHub 不允许作者批准自己的 PR。

## 按改动范围的约定

### 页面与缓存

浏览器模块通过 `?v=` 版本号刷新缓存。改了哪个文件，就更新引用它的地方：`index.html` 里的 `styles.css` 和 `src/main.js`，以及其他模块 `import` 语句里的版本号。

### 评分

`src/score.js` 是纯函数：输入证据，输出分数和解释。改规则时同步 [SCORING.md](SCORING.md) 和 `tests/score.test.mjs`。

### 数据源

- 适配器统一放在 `src/sources.js`。未返回的字段保持 `null`，不能当作“否”。
- 只采用实际返回、且与目标 IP 一致的字段。同一底层数据库合并计票。
- 同步 [README.md](README.md) 的检测内容；间接来源的依据写进 [DATA-SOURCES.md](DATA-SOURCES.md)。

### 后端

`api/worker.js` **不会**随合并自动上线，需要按 [api/README.md](api/README.md#部署) 手动部署。新增路由或 secret 时同步更新路由表。

### 查询服务

`local_server.py`、`cloud_server.py`、`provider_pages.py` 和 `Dockerfile` 组成 Render 上的容器（定义在 `render.yaml`）。合并后到 Render 确认部署状态，线上 `/health` 提供健康检查。

### Chrome 扩展

`browser-helper/` 里的 `page-extract.js`、`page-providers.js` 和 `util.js` 必须与 `src/` 下的同名文件一致，CI 会检查。发新版本时：

1. 升级 `browser-helper/manifest.json` 的 `version`。
2. 在仓库根目录重新打包：

   ```bash
   zip -r downloads/egress-browser-helper-vX.Y.Z.zip browser-helper -x '*.DS_Store'
   ```

   Windows PowerShell：

   ```powershell
   Compress-Archive -Path browser-helper -DestinationPath downloads\egress-browser-helper-vX.Y.Z.zip
   ```

3. 更新版本引用：`README.md`、`browser-helper/README.md`、`index.html` 的下载链接，以及 `src/render.js` 里提示用户更新的版本判断。

## 隐私与密钥

- **不要提交真实 IP**。代码、测试、文档和截图里统一使用文档保留地址：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`。
- **密钥只放在后端运行时 secret**。`config.js` 只放公开值。

## Labels

| Label | 含义 |
| --- | --- |
| `task`、`bug`、`enhancement`、`data-source`、`documentation` | 类型 |
| `area:frontend`、`area:scoring`、`area:sources`、`area:api`、`area:lookup`、`area:extension`、`area:repo` | 涉及范围 |
| `platform:windows`、`platform:macos` | 只在该平台出现，或需要在该平台验证 |
| `P0`、`P1`、`P2` | 优先级：立刻处理、下一步处理、排期处理 |

## 许可

提交贡献即表示你同意按 [GPL-3.0](LICENSE) 授权你的代码。
