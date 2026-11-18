# Sub2API 本地登录服务

本仓库保存 `Sub2API本地登录Linux源码(1).tar.gz` 中提供的源码快照。首次提交保留压缩包内全部 40 个文件的原始内容，并补充本说明和 `.gitignore`。

## 文档

- [使用、安装和接口说明](LOCAL_LOGIN_ZH.md)
- [Linux 批处理与固定出口说明](SERVER_BATCH_ZH.md)
- [原代码审查说明](README_REVIEW_ZH.md)
- [源码 SHA-256 清单](LOCAL_LOGIN_MANIFEST.json)

`README_REVIEW_ZH.md` 保留了较早审查快照的历史说明，其中提到的部分辅助文件不在本源码包内。当前使用方式以 `LOCAL_LOGIN_ZH.md` 为准。

## Linux 安装

需要 Python 3.11+ 和 Node.js。

```bash
bash install_local_login.sh
.venv/bin/python -B batch_login.py --help
.venv/bin/python -B relogin_service.py --help
```

Linux 依赖见 `requirements-local.txt`。旧版浏览器流程的额外依赖见 `requirements.txt`。Windows 图形界面可通过 `start_gui.cmd` 启动。

实际运行所需的账号、后台凭据、代理和邮箱配置由使用者单独提供；`relogin.example.json` 仅提供配置格式。

## 来源与许可

保留的组件来源、改动和许可说明见 [login_vendor/SOURCE.md](login_vendor/SOURCE.md)。协议组件及注明 SPDX 标识的新模块使用 AGPL-3.0-only，完整许可见 [login_vendor/LICENSE](login_vendor/LICENSE)；相关 MIT 声明保留在 [login_vendor/TURB_LICENSE](login_vendor/TURB_LICENSE)。
