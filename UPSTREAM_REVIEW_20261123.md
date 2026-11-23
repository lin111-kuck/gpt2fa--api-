# sentinel-rs 更新评估与本项目适配

评估日期：2026-11-23。时间为北京时间。检查的上游为 [wangshen233/sentinel-rs](https://github.com/wangshen233/sentinel-rs)，最新提交为 `f222371c7960be490baf4ab1a2873da900506f2a`；本项目修改基线为 `c99a37ce8454cac957d9dcc731420927613e20d3`。

## 最近更新

| 时间 | 提交 | 内容 |
| --- | --- | --- |
| 2026-11-18 22:43 | [f222371](https://github.com/wangshen233/sentinel-rs/commit/f222371c7960be490baf4ab1a2873da900506f2a) | 清理个人路径、真实邮箱端点和供应商示例；本地 WebUI 配置移出版本控制；补充运行产物的忽略规则。 |
| 2026-11-18 22:02 | [3a8f3b2](https://github.com/wangshen233/sentinel-rs/commit/3a8f3b229648b2c32ef5c01311232cb5ce0c9aaa) | 设备与传输配置调整、静态邮箱清单、JSON 取码与 `no_code` 待机语义，以及本地 WebUI。 |

查询时没有比 11 月 18 日更新的提交。此次评估关注 `src/flow/email.rs`、`src/flow/otp.rs` 的邮箱接口约定，以及最新提交的配置清理。

上游是 Rust 项目，使用 Cargo 的 `wreq=0.16.1`、`wreq-util=0.2.0`；本项目是 Python 服务，依赖 Python `wreq==0.13.0` 和原有 Node 适配器。它们不是同一个包的可直接替换版本。此提交没有引入 Rust VM，也没有修改 Sentinel token 生成、TLS 模拟或设备指纹实现。

## 实际修改

1. 邮箱接口待机响应优先于验证码正文。原实现会跳过 `code=no_code` 字段，却仍从附带正文中抽取旧的六位数字；现在待机响应整体进入等待状态，包括 `code=null`、空字符串和上游定义的暂无验证码占位值，以及嵌套的 `data` / `result`。
2. 补充上游使用的验证码、时间戳字段别名，保留收件人、发件人、新鲜度、快照和已使用验证码检查。字段大小写不同但值冲突时拒绝选码。
3. 区分 HTTP 200 内的邮箱 API 失败与正常待机。明确的授权失效、邮箱过期或不可重试失败会立即结束本次邮箱读取，不再持续等到取码超时。诊断只返回固定说明，不回显邮箱 API 正文或链接。
4. 读取响应时检查停止信号与剩余预算；预算已耗尽时不再发起 GET，检测到过期或取消时不使用部分响应。该检查发生在响应块交付时；requests 的底层读取仍受其 socket timeout 约束。
5. GUI 与两个命令行入口去掉预填的个人站点和管理员邮箱，改由 `SUB2API_BASE_URL` / `SUB2API_EMAIL` 或显式参数提供。批处理 JSON 导出目录、`.used` 和 `.bak` 加入忽略规则。

没有复制上游注册流程的通用 POST 重试策略；本项目原有的认证请求处理及登录结果校验保持现有实现。

## 兼容示例

待机：

```json
{"success":false,"code":"no_code","retryable":true}
```

收到新邮件：

```json
{"ok":true,"data":{"verificationCode":"123456","receivedAt":1794929150000,"recipient":"person@example.com"}}
```

`retryable=true` 不会屏蔽明确的 `invalid_token` 等授权错误；未知的普通 JSON 状态页没有可用码时仍继续等待。原有六位文本、常见 JSON 和 WDMail HTML 返回形式继续支持。

## 验证

新增离线邮箱契约测试覆盖待机响应夹带旧码、字段别名、授权错误脱敏、快照失败、过期与已用验证码、响应中断和读取超时。验证仅使用模拟响应与本地测试服务；未登录真实账号、调用真实邮箱或部署服务器。

在 Windows 的 Python 环境中运行 `python -B -m unittest discover -q`：共 193 项，190 项通过，3 项按原有 opt-in 开关跳过（旧版浏览器流程的离线冒烟测试），无失败。GUI 测试与 Node 离线运行时测试包含在本次回归中。该结果不代表 Linux 实机或真实账号登录已验证。源码 SHA-256 清单同步更新。
