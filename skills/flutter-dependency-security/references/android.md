# Android 依赖检查规则

读取 `gradle.lockfile` 和 `dependency-locks/*.lockfile`。锁文件应覆盖实际 release/debug variant 和全部 configuration；只有一个 variant 的锁文件不足以证明构建完整性。

检查 Gradle 配置中的：

- `buildscript`、插件管理和项目 repositories。
- `mavenCentral()`、`google()` 之外的镜像、JitPack、内网仓库及其 HTTPS 配置。
- 动态版本、`SNAPSHOT`、`+`、`latest` 和远程 `apply from`。
- 依赖校验是否存在 `gradle/verification-metadata.xml`，是否有有效 SHA-256，是否存在关闭校验或过宽 trust 规则。

没有 Gradle lockfile 时报告无法确认传递 Maven 依赖；没有 verification metadata 时报告制品替换风险。不要仅凭仓库白名单或 Gradle metadata 存在就判定安全。构建插件、`flatDir` 本地 AAR/JAR 和自定义 variant 需要单独纳入审核。

对于纯 Android 工程调用：

```bash
.venv/bin/flutter-supply-guard /path/to/android-project \
  --scope android --json /tmp/android-dependency-security.json
```

工具不会运行 Gradle。建议用户在无发布凭据的可信环境生成锁文件和 verification metadata，审核 SHA-256/签名后再提交。
