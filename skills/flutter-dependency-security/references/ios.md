# iOS 依赖检查规则

读取 `Podfile.lock` 的 `PODS`、`SPEC REPOS`、`EXTERNAL SOURCES`、`CHECKOUT OPTIONS` 和 `SPEC CHECKSUMS`；读取 `Package.resolved` v1/v2/v3 的 pins 和 revision。

重点检查：

- Podfile 的 Spec repo 来源，特别是非 CocoaPods 官方仓库、Gitee/私有 Spec repo 和未固定仓库 revision。
- Git Pod/SwiftPM 是否固定完整 commit。
- `EXTERNAL SOURCES` 中的本地 Pod、`.symlinks/plugins` 和本地 Podspec。
- Podspec 的 `prepare_command`、脚本 phase、远程下载、解压、动态执行和未校验的二进制 Framework。
- `SPEC CHECKSUMS` 只代表 Podspec 指纹，不等于源码、Framework 或 XCFramework 的完整性证明。

OSV 没有通用 CocoaPods 包名生态。普通 CocoaPods 包没有可用公开坐标时要报告覆盖缺口；有 Git commit 的依赖可查询 commit 情报。使用 `--advisories` 加载组织维护的精确版本情报，并使用 `--source-dir ios/Pods` 检查已下载源码：

```bash
.venv/bin/flutter-supply-guard /path/to/ios-project \
  --scope ios --source-dir /path/to/ios-project/Pods \
  --json /tmp/ios-dependency-security.json
```

纯 iOS 工程没有 `pubspec.yaml` 也可以检查。工具不执行 `pod install`、Podfile 或 Podspec。对于远程下载的 Framework、AAR 类似制品和私有二进制，要求提供独立审核的 SHA-256/签名清单。
