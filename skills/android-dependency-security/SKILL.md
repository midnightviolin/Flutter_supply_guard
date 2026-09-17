---
name: android-dependency-security
description: "检查 Android 工程的 Gradle/Maven 依赖、仓库来源、锁文件、制品校验和远程构建脚本；用户要求 Android 依赖安全或供应链检查时使用。"
---

# Android dependency security

使用当前工具仓库的 `flutter-supply-guard` 对纯 Android 或 Flutter 工程的 Android 目录做只读依赖供应链检查。重点是 Gradle/Maven 依赖是否可复现、来源是否经过组织审核、下载制品是否有校验，以及构建阶段是否执行远程脚本。

工具命令：

```bash
cd <security-check-repo>
.venv/bin/flutter-supply-guard /path/to/android-project \
  --scope android --json /tmp/android-dependency-security.json
```

`--scope android` 允许没有 `pubspec.yaml` 的原生 Android 工程。在线模式查询 OSV；网络不可用时使用 `--offline`，并明确报告漏洞情报覆盖不足。工具只读 `gradle.lockfile`、`dependency-locks/*.lockfile`、Gradle 配置和 verification metadata，不运行 Gradle、插件或构建脚本。

至少检查 Gradle lockfile、所有 release variant、buildscript/插件 repositories、动态版本、JitPack/内网镜像、`verification-metadata.xml`、本地 AAR/JAR 和远程 `apply from`。缺少锁文件或校验元数据是阻断性覆盖缺口，不可解释成“无漏洞”。

报告 `SOURCE_UNTRUSTED` 时先与组织批准的仓库白名单核对；不要直接把业务需要的镜像标记为恶意，也不要为消除告警盲目扩大白名单。报告 `ARTIFACT_TAMPERED`、动态版本、远程脚本或校验关闭时，优先要求隔离构建、固定版本和独立制品哈希/签名审核。
