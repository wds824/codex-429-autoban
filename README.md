# codex-429-autoban

一个 CPA（CLIProxyAPI）插件：**Codex 凭证收到 429（限流）后自动禁用，并在对应限额窗口刷新后自动解禁。**

## 它做什么

1. **检测 429**：每次请求完成后，插件观察用量记录。如果某个 **codex** 凭证收到了 429，就触发禁用逻辑。
2. **判断禁多久**：读上游 OpenAI 返回的 `x-codex-*` 响应头，判断是 **5 小时窗口**被打满，还是 **周限额**被打满，并取对应窗口的刷新时间作为解禁时间。
   - 5 小时窗口满了 → 5 小时刷新后解禁
   - 周窗口满了 → 下周刷新时才解禁
   - 月窗口（通常只有一个窗口）满了 → 按该窗口返回的 `reset-at` 解禁
   - 两个都满 → 按较晚的（周）解禁
3. **自动解禁**：之后每次 CPA 选凭证时，插件把"还没到解禁时间"的凭证从候选里剔除；一旦过了刷新时间，自动放回候选。
4. **手动加回号池**：如果你在 Codex 侧手动重置额度或使用了重置卡，可以通过插件的 Management API / 资源页立即解除插件内存里的 ban，不必等原来的 `reset-at`。
5. **读取 CPA 实际冷却**：管理页通过 CPA 的 `host.auth.list` 读取账号当前 `next_retry_after`，同时显示插件解除时间、CPA 下次重试时间，并按两者较晚值给出预计实际回池时间。
6. **Discord 通知**：配置 Discord Incoming Webhook 后，新账号因 429 被排除时会发送账号、窗口、解除时间和 Codex 号池可用/总数。
7. **只管 codex**：非 codex 凭证一律不干预，交给 CPA 原有逻辑。

## 怎么判断 5 小时还是周限额

OpenAI 的 ChatGPT/Codex 后端在 429 时会返回一组自定义头（不是标准的 `x-ratelimit-*`）：

| 响应头 | 含义 |
|---|---|
| `x-codex-primary-window-minutes` | `300` = 5 小时；约 `43200` = 30 天月窗口 |
| `x-codex-primary-reset-at` | 主窗口刷新时间（Unix 秒） |
| `x-codex-primary-used-percent` | 5 小时窗口使用率（打满时 = 100） |
| `x-codex-secondary-window-minutes` | `10080` = 7 天（周）窗口 |
| `x-codex-secondary-reset-at` | 周窗口刷新时间（Unix 秒） |
| `x-codex-secondary-used-percent` | 周窗口使用率 |

**判断逻辑**：哪个窗口的 `used-percent` 到了 100，就用那个窗口的 `reset-at` 作为解禁时间。月重置账号如果只返回一个主窗口，则直接使用该窗口的 `reset-at`，不再强制按 5 小时处理。

> 如果 429 响应里没有这些头（少数情况，比如来自中间代理的伪 429），插件保守地按 5 小时禁用（这是更常见的情形）。

## CPA 实际回池时间从哪里读取

状态页请求 `/v0/management/plugins/codex-429-autoban/bans` 时，插件调用 CPA 的 `host.auth.list` 回调。CPA 会从运行中的 `AuthManager` 构造每个账号的状态，其中：

- `next_retry_after` 是 CPA 当前记录的下次重试时间；
- `unavailable`、`status`、`status_message` 用来说明账号当前是否仍被 CPA 冷却；
- 如果 CPA 没有返回明确时间，页面会显示“CPA 当前无明确回池时间”，不会把插件的时间冒充成 CPA 的精确时间。

“预计实际回池时间”取插件 `reset-at` 与 CPA `next_retry_after` 中较晚的一个。因为两边是独立状态，只有两者都到期后账号才适合再次使用。

## 为什么解禁不需要定时器

CPA 插件机制是**事件驱动**的，没有后台定时器。所以解禁用"惰性"方式实现：每次有新请求来、CPA 要选凭证时，插件顺手检查"现在过了解禁时间没"——过了就放回候选。效果等同于定时解禁，且不需要额外的唤醒机制。

## Management Panel / Plugin Store install

This repo ships a `registry.json`. After a GitHub release is published, it can be used as a custom CPA plugin-store source. Add this URL to `plugins.store-sources`, then restart or refresh the management panel and search for the plugin in the store:

```yaml
plugins:
  enabled: true
  store-sources:
    - https://raw.githubusercontent.com/wds824/codex-429-autoban/main/registry.json
```

If you want every CPA user to see it without adding a custom source, submit the same registry entry to the official `router-for-me/CLIProxyAPI-Plugins-Store` repository.

## 安装

### 1. 准备 C 编译器（CGO 必需）

CPA 插件是原生动态库，必须用 CGO 编译，所以需要 C 编译器。Windows 上装 MinGW-w64：

```powershell
winget install -e --id MartinStorsjo.LLVM-MinGW.UCRT
```

装完确认 `gcc --version` 能输出版本。

### 2. 编译

```powershell
cd codex-429-autoban
.\build.ps1            # Windows
# 或
bash build.sh          # 任意平台
```

成功后会生成 `codex-429-autoban.dll`（Windows）。

> 本插件把 CPA 的 `sdk/pluginabi`、`sdk/pluginapi` 两个包**本地化**到 `cpasdk/` 目录，因此**不需要** Go 1.26（CPA 主程序才需要），Go 1.21+ 即可编译。

### 3. 放到 CPA 插件目录

CPA 在 Windows amd64 上按顺序查找：
```
plugins/windows/amd64-<variant>/
plugins/windows/amd64/
plugins/
```

把 dll 放进去即可（推荐 `plugins/windows/amd64/codex-429-autoban.dll`）。

**插件 ID = 文件名去掉扩展名**，即 `codex-429-autoban`。

### 4. 在 config.yaml 启用

```yaml
plugins:
  enabled: true
  configs:
    codex-429-autoban:
      enabled: true
      priority: 100   # 数字越大越先执行；建议设高一点，让禁用判断先于其他调度插件
      discord_webhook_url: "https://discord.com/api/webhooks/<id>/<token>"
      discord_notify_429: true
      discord_notify_pool: true
```

配置说明：

- `discord_webhook_url`：Discord 频道的 Incoming Webhook URL；留空则关闭通知。
- `discord_notify_429`：是否发送新 429 排除通知，默认 `true`。同一个账号在同一段 ban 期间重复 429 不会重复刷屏。
- `discord_notify_pool`：是否在通知中附带“可用 / 总数”号池统计，默认 `true`。

Discord 统计优先读取 CPA 当前 Codex auth 列表，并排除 CPA 已禁用、不可用以及本插件 ban 中的账号；如果主机不支持 auth 列表回调，则使用最近一次调度候选统计。

> 如果你的 CPA 二进制不支持插件，响应头里不会有 `httpX-CPA-SUPPORT-PLUGIN: 1`。需要用 CGO 编译版的 CPA。

## 手动加回号池（Codex 重置额度/重置卡后）

CPA 插件没有“Codex 已手动重置额度”的事件回调，所以插件无法可靠自动感知你在 Codex 侧用了重置卡。为了解决这个问题，插件提供了 Management API 和一个资源页来**手动解除 ban**。

资源页（在 CPA 管理界面的插件菜单里也会出现）：

```text
/v0/resource/plugins/codex-429-autoban/status
```

资源页中的“测试 Discord Webhook”按钮会立即发送一条测试消息，并显示当前 Codex 号池可用/总数。

API（需要 CPA 管理密钥，支持 `Authorization: Bearer <key>` 或 `X-Management-Key`）：

```bash
# 查看当前被插件排除的账号
curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-429-autoban/bans

# 将单个账号加回号池
curl -X POST -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"auth_id":"<AUTH_ID>"}' \
  http://localhost:8317/v0/management/plugins/codex-429-autoban/unban

# 清空全部插件 ban 状态
curl -X POST -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-429-autoban/unban-all

# 测试 Discord Webhook
curl -X POST -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-429-autoban/test-webhook
```

注意：这里清除的是本插件的**内存 ban 状态**。请只在你确认 Codex 侧额度已经恢复（例如手动重置额度/使用重置卡）后使用，否则账号可能马上再次 429 并被重新 ban。

## 工作流程图

```
请求完成 → usage.handle（插件观察）
  │
  ├─ 不是 codex / 不是 429 → 跳过
  └─ 是 codex 且 429
        ├─ 读 x-codex-* 头，判断 5h、周限额还是月限额
        └─ 记录：该凭证"到 X 时间才能再用"

429 处理完成 → Discord Webhook
  └─ 账号 + 窗口 + reset-at + Codex 可用/总数

下次有请求来选凭证 → scheduler.pick（插件介入）
  ├─ 剔除"还没到解禁时间"的 codex 凭证
  ├─ 已过解禁时间的 → 放回候选（自动解禁）
  └─ 全部凭证都可用 → 交给 CPA 原本的轮询选；有凭证被禁 → 插件从可用凭证里按优先级挑一个
```

## 状态说明

- 禁用状态保存在**插件进程内存**里。CPA 重启后会清空（重启同时也清了 CPA 自己的冷却状态，所以一致）。
- 如果你通过 Management API 手动加回号池，清除的也是这份插件内存状态；不会修改 Codex 侧额度，也不会修改 CPA 凭证文件。
- 日志：禁用/解禁都会通过 CPA 的日志输出（`slog`），关键字 `codex-429-autoban:`。

## 文件说明

| 文件 | 作用 |
|---|---|
| `main.go` | 插件主代码（429 检测、窗口解禁、调度过滤、Discord 通知、Management API） |
| `cpasdk/pluginabi/` | CPA 插件 ABI 常量（本地化，免 Go 1.26） |
| `cpasdk/pluginapi/` | CPA 插件类型定义（本地化） |
| `build.ps1` / `build.sh` | 编译脚本 |
