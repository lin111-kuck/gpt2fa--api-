# 服务器批量登录和固定出口

`server_batch_login.py` 在 Linux 服务器上读取 JSON 标准输入，执行本地协议登录、验证身份，再导入 Sub2API，并把密码和 TOTP 保存到站点的加密凭证运营配置。账号密码、TOTP 和 OAuth token 不写进本工具的日志。

运行前需安装现有登录服务，并能通过服务器本机的 `http://127.0.0.1:8080` 访问 Sub2API。脚本先以 root 读取现有 Docker 管理员配置、备份并更新受限路由配置，随后降为 `sub2api-login` 用户执行登录。

## 分配与并发

- `--ports` 按顺序优先选取 Sub2API 中 `172.19.0.1` 对应的节点端口。
- 每个实际出口 IP 最多 5 个账号；同 IP 的其他节点账号数合并计算。尚未导入但已有固定路由的账号也预留名额。
- 优先节点容量不足时，补选活跃、延迟低于 300ms、节点账号数为 0 的 Dasho 美国节点，并实测出口。
- 最多 4 个登录任务并发，同一个 IP 最多 2 个同时登录；导入串行复查 IP 容量。
- 已有账号跳过；不自动覆盖已有账号。导入状态不明时停止后续任务，先核对站点再重试。
- 所有登录连接使用 IPv4 CONNECT 通道，TLS 仍由原会话建立；登录前后检查同一出口 IP、国家和时区。

示例调用：

```bash
/opt/sub2api-login/current/.venv/bin/python -u -B \
  /opt/sub2api-login/current/server_batch_login.py \
  --ports 20202 19506 --group-ids 6 15 23 --workers 4
```

输入是一个 JSON 数组，每个对象使用 `email`、`password`、`mfa_secret`，可以另外提供 `mail_url`。未提供 `mail_url` 时读取 `/etc/sub2api-login/relogin.json` 中该邮箱的配置。不要把真实凭据放到命令参数或终端历史中。

没有邮箱 API 时也可尝试密码和 TOTP 登录；只有上游实际要求邮箱验证码时才返回 `mailbox_required`，不会把空 URL 写入服务配置。

## 后续重登

服务配置新增 `ipv4_only: true` 和 `account_proxies`。`account_proxies` 按登录邮箱保存 `proxy_url`、`expected_exit_ip`、`country_code`，优先于默认代理。服务仍兼容原来的 `/api/v1/relogin` 请求格式。

只有预先记录在 `/etc/sub2api-login/portal-rebind-state.json`、且换绑服务明确返回 `remote_outcome: changed` 的账号，才在下一次批量登录时切换为记录的新邮箱和接码 URL。原密码和 TOTP 沿用输入值，新邮箱必须通过真实 OAuth 身份验证才会导入。该脚本不会自行向换绑站点提交操作。

受限结果保存在 `/var/lib/sub2api-login/batch-*.json`。这些结果不含密码、TOTP、接码 URL token 或 OAuth token。

邮箱 API 的连接中断会在原有请求时间预算内最多重试 3 次 GET；HTTP 错误、认证 POST 不自动重放。手机号验证需要账号持有人完成，邮箱取码无法替代。
