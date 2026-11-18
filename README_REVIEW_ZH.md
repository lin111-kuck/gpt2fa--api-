# Sub2API 登录代码审查包

> 2026-11-17 更新：此目录已经加入本地协议登录和邮箱 API 自动取码。当前使用说明见 `LOCAL_LOGIN_ZH.md`，GUI 默认选择本地协议。下面保留的是原审查快照的历史说明和运行证据，不能作为新协议版本的实测结果。原快照哈希保留在 `SOURCE_MANIFEST.json`，新代码哈希另列于 `LOCAL_LOGIN_MANIFEST.json`。

这是 2026-11-16 修改后实际运行的源码快照。Python 源文件与工作目录中的文件逐字节一致。

## 本次需要检查的问题

目标是减少正常登录过程中触发真人安全验证。当前修改未解决这一问题，不能将本地测试通过视为避免认证成功。

最新正式批次已由用户要求停止：输入 31 个账号，6 个记录了最终结果（3 个真人验证跳过、2 个要求手机号、1 个运行错误），第 7 个途中停止，24 个未尝试，新增导入 0 个。包括途中停止账号在内，共 4 个观察到 Cloudflare challenge。

新诊断确认部分账号的 `/api/accounts/password/verify` 和 `/api/accounts/mfa/verify` 返回 HTTP 200，随后浏览器以 GET document 请求访问 `/api/accounts/email-otp/send`，出现 307 后返回 403，响应带 `cf-mitigated: challenge`。这些记录定位了触发阶段，尚不足以确定服务端触发原因。

## 主要文件

- `oauth_mail_login.py`：当前 Chrome OAuth 登录、TOTP、邮件验证码、真实回调、凭据交换与导入入口。
- `oauth_proxy_transport.py`：本地 HTTP CONNECT 与上游代理桥接。
- `batch_login.py`、`proxy_report.py`：后台 API、代理容量、导入与凭据校验。
- `test_oauth_mail_login.py`、`test_oauth_proxy_transport.py`、`test_batch_login.py`：本轮使用的回归测试。
- `batch_login_gui.py`、`batch_gui_service.py`、`test_batch_gui.py`、`start_gui.cmd`：现有 GUI 相关代码，随源码一并提供。
- `changes/`：本轮修改前后的差异；不包含原始备份文件。
- `evidence/sanitized_run.json`：经过匿名化和字段筛选的正式运行证据。
- `SOURCE_MANIFEST.json`：随包文件的 SHA-256。

## 本轮修改

1. 移除自动模式的 Playwright 请求拦截，改为本地 HTTP 服务接收 OAuth 回调。Playwright 开启请求路由会禁用 HTTP 缓存。
2. 为 localhost / 127.0.0.1 / ::1 配置代理例外，使本地回调直连。
3. 填写前检查文档、输入框及表单忙碌状态；填写后检查值是否被初始化重置；没有明确提交按钮时停止，不再回退按 Enter。
4. 增加不含查询参数、请求正文和 Cookie 的响应、重定向、资源失败诊断。

仍保留可见 Chrome 无痕默认值、出口一致性检查、同出口最多 5 个账号、分组 6/15/23、已有账号跳过、遇安全验证跳过。没有实现自动解验证码。

## 环境与本地测试

已验证环境：Windows、Python 3.12、安装版 Google Chrome、Playwright 1.62.0。GUI 使用 Python 自带 Tkinter。

```powershell
python -m pip install -r requirements.txt
python -B -m unittest test_oauth_mail_login test_oauth_proxy_transport test_batch_login
```

启用 Chrome 离线页面测试：

```powershell
$env:OAUTH_BROWSER_SMOKE='1'
python -B -m unittest test_oauth_mail_login test_oauth_proxy_transport test_batch_login
Remove-Item Env:OAUTH_BROWSER_SMOKE
```

本轮最终结果：90 项全部通过，包含 3 项安装版 Chrome 离线流程测试。测试使用模拟页面及真实本地 HTTP 回调，不会登录真实账号或导入后台。这不证明真人验证触发率下降。

## 真实运行配置

查看 `python -B oauth_mail_login.py --help`。需要另外提供自己的账号文件、后台地址、后台管理员凭据和可用代理。源码保留当时的默认后台地址；审查或使用其他后台时请通过 `--base-url` 和 `--email` 显式指定。

`accounts.example.txt` 只有虚构的格式示例，不能用于真实登录。输入格式为 `邮箱----密码----TOTP密钥[----收件URL]`。管理员密码可由程序隐藏提示读取，或通过 `SUB2API_PASSWORD` / `SUB2API_TOKEN` 提供。

包内不包含真实账号输入、管理员密码、真实 TOTP 密钥、Token、代理认证信息、原始日志、导出凭据或交接原文。GuJumpgate、gptregister 和 sentinel 参考工程未包含在此包中。
