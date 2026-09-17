---
name: ios-dependency-security
description: "检查 iOS 工程的 CocoaPods/SwiftPM 来源、锁定提交、本地 Pod、安装脚本、远程二进制和制品完整性；用户要求 iOS 依赖安全或供应链检查时使用。"
---

# iOS dependency security

使用当前工具仓库的 `flutter-supply-guard` 对纯 iOS 或 Flutter 工程的 iOS 依赖做只读供应链检查。重点是 CocoaPods Spec repo、SwiftPM revision、本地 Podspec、prepare command、Framework 下载来源和制品完整性。

工具命令：

```bash
cd <security-check-repo>
.venv/bin/flutter-supply-guard /path/to/ios-project \
  --scope ios --source-dir /path/to/ios-project/Pods \
  --json /tmp/ios-dependency-security.json
```

`--scope ios` 允许没有 `pubspec.yaml` 的原生 iOS 工程。在线模式查询可识别的 OSV 坐标；CocoaPods 普通包没有通用 OSV 生态时必须报告覆盖缺口。网络不可用时使用 `--offline`，并保留缺口。工具只读取 `Podfile.lock`、`Package.resolved`、Podfile/Podspec 和显式 `--source-dir`，不执行 `pod install`、Podfile、Podspec 或下载脚本。

特别关注非官方 Spec repo、Gitee/私有仓库、未固定 Git revision、`EXTERNAL SOURCES` 的本地插件、`prepare_command` 中的 curl/wget、解压后直接使用的 Framework，以及只依赖 `SPEC CHECKSUMS` 的完整性假设。

`SOURCE_UNTRUSTED` 是白名单策略结果，不是已确认恶意；`POD_ARTIFACT_UNVERIFIED` 说明 Podspec checksum 不能覆盖二进制。对私有 Pod、广告/音视频 SDK 和自建镜像使用组织情报、审核基线以及独立 SHA-256/签名清单。
