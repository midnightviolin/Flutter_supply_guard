# Flutter Supply Guard

Flutter 工程依赖供应链检查工具，支持 Flutter/Dart Pub、Android Maven/Gradle、iOS CocoaPods 和 SwiftPM。Python 3.10+，适合本地检查和 CI 门禁。

扫描只读取工程文件，不运行 `pub get`、Gradle、CocoaPods、Podfile 或依赖安装脚本。默认联网查询 OSV 与 pub.dev；只发送包坐标或 Git commit，不上传源码。私有工程可先使用 `--offline`。

## 快速使用

在本工具目录运行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .

# 在线扫描真实 Flutter 工程，输出路径应为新文件
.venv/bin/flutter-supply-guard /path/to/flutter_project --json reports/scan-001.json

# 离线检查来源、版本、脚本和锁文件
.venv/bin/python -m supply_guard /path/to/flutter_project --offline

# 使用组织来源策略、禁用清单和 iOS 等生态的精确版本情报
.venv/bin/python -m supply_guard /path/to/flutter_project \
  --policy examples/policy.json --advisories examples/advisories.json
```

示例清单中的包名和情报是**虚构测试数据**，没有预装真实的恶意库黑名单。请替换为组织审核过的情报；实时公开情报由 OSV 提供。

## 检查范围

| 生态 | 依赖清单 | 检查内容 |
| --- | --- | --- |
| Flutter / Dart | 各层级 `pubspec.lock` | 包括锁文件内传递依赖；Hosted 来源、SHA-256 格式及官方元数据对照、Git 提交固定、路径依赖、覆盖声明、OSV |
| Android | `gradle.lockfile`、旧式 `dependency-locks/*.lockfile` | Maven 精确版本、OSV、动态版本、仓库 URL、远程脚本、校验元数据结构及弱化配置 |
| iOS CocoaPods | `Podfile.lock` | 包括传递 Pod；合并 subspec、来源仓库、Git commit、本地 Pod、安装脚本、组织情报 |
| iOS SwiftPM | `Package.resolved` v1/v2/v3 | 依赖来源、固定 commit、OSV commit 查询、组织情报 |
| 已下载源码 | 显式 `--source-dir` | 下载执行、动态执行和安装脚本的启发式检查，记录所检查文件 SHA-256 供基线比较 |
| 本地制品 | 显式 `--artifacts` | 实际读取 AAR/JAR/ZIP/Framework 等文件并对照审核过的 SHA-256 |

Gradle/Ruby 是可执行语言，静态解析不能保证得到所有依赖；本工具以**实际锁文件**为依赖清单，不把 `build.gradle` 中声明的直接依赖当作完整依赖树。Flutter SDK 依赖不按 Pub 包查询。私有 Pub 包不以同名公有包冒充查询结果。

OSV 当前 schema 包含 Pub/Maven，但没有标准 CocoaPods 生态。普通 Pod 使用组织精确版本情报；有完整 Git commit 的 Pod 和 SwiftPM 包可查询 OSV commit。无可查询坐标时会显示覆盖缺口。加载组织情报不会自动消除这一公开情报缺口；清单未命中也不能证明无漏洞。

## 让三端依赖清单完整

先在可信隔离环境准备工程解析结果，再扫描。首次解析可能运行插件或下载第三方内容，建议使用无发布凭据、无签名密钥的隔离构建环境。

Flutter 应将 `pubspec.lock` 纳入版本管理；CI 可在审核后使用 `flutter pub get --enforce-lockfile`。此工具会检查锁文件，但不证明它与当前 `pubspec.yaml` 完全一致。

Android 需要开启 Gradle dependency locking，并为实际构建的所有 configuration / variant 写入锁文件。示意配置（按项目 Gradle DSL 调整）：

```groovy
allprojects {
    dependencyLocking {
        lockAllConfigurations()
    }
}
```

在可信环境对实际构建任务使用 `--write-locks`，再审核锁文件。构建插件和 `buildscript` 可能需要额外锁定；工具不会自动修改或运行 Gradle。所有需要发布的 variant 都应覆盖，单一 debug 配置不足以代表 release。

Gradle 的 `gradle/verification-metadata.xml` 应在可信环境生成并独立审核 SHA-256/签名，CI 强制使用 strict verification。工具检查 XML 结构与部分弱化设置，但不验证 Gradle 缓存，也不证明所有制品都被元数据覆盖或构建时已启用校验。不要把从未知来源首次下载得到的哈希直接批准为可信。

iOS 应保留审核过的 `Podfile.lock` / `Package.resolved`。`SPEC CHECKSUMS` 是 Podspec 指纹，**不是下载制品的哈希**。原生库的二进制需另外提供制品清单。

## 防止同版本被替换

先对可信版本生成候选基线，审核后提交到版本管理：

```bash
.venv/bin/python -m supply_guard /path/to/flutter_project \
  --save-baseline baseline.candidate.json

# 后续检查对照审核通过的基线
.venv/bin/python -m supply_guard /path/to/flutter_project \
  --baseline baseline.approved.json --json reports/scan-002.json
```

新增或升级依赖为 medium；同版本来源、commit 或指纹变化为 high。基线生成只是记录现状，即使扫描失败也可以输出候选文件，绝不表示已审核通过。保护基线/策略文件的修改权限，避免与投毒依赖一起被自动批准。

可以显式扫描已下载依赖目录（本工具不自动读取用户的全部缓存）：

```bash
.venv/bin/python -m supply_guard /path/to/flutter_project \
  --source-dir /path/to/downloaded/flutter_plugin \
  --source-dir /path/to/downloaded/native_library \
  --baseline baseline.approved.json
```

建立基线和后续扫描要使用相同的 `--source-dir` 顺序及范围。所检查的源码文件增加、改变或消失会阻断。符号链接文件会报告跳过；不遍历符号链接目录；默认排除 `.git`、`.venv`、`build`、`node_modules`、`.gradle`、`Pods`、`.symlinks`、`.dart_tool` 子目录。可把具体包目录作为 `--source-dir` 根目录。源码检查只涵盖代码中列出的文本扩展名，其他资源或二进制使用制品清单。

制品清单格式为项目内相对路径到 SHA-256 的 JSON 映射，例如：

```json
{
  "vendor/library.aar": "替换成从可信来源独立核实的64位十六进制SHA256"
}
```

```bash
.venv/bin/python -m supply_guard /path/to/flutter_project --artifacts approved-artifacts.json
```

哈希不符返回 critical；缺失制品返回 high；路径越界拒绝。只校验清单中列出的文件，不自动发现未列出的二进制。Pub 官方对照仅比较锁文件与发布元数据，不下载归档、不证明本地缓存未被篡改；缓存源码可用基线检查。

## CI 门禁与报告

退出码：

- `0`：未命中阈值，且没有未允许的覆盖缺口；不表示绝对安全。
- `1`：存在达到 `--fail-on` 阈值的问题，默认 `high`。
- `2`：解析/配置/网络错误或覆盖不足，且没有优先返回的阻断风险。

`--fail-on medium` 可将新增依赖、版本升级、安装脚本入口等纳入审核门禁。`--allow-incomplete` 显式允许情报覆盖不足、离线等缺口通过，报告仍保留 `incomplete`；不要在严格 CI 中默认打开。API 失败会报告错误，不会变成“零漏洞”。未知文本严重性按 high 处理，原始 CVSS 信息保留在 JSON 中；不自行猜算 CVSS 分数。

通用 CI 步骤（工程解析结果必须预先生成）：

```bash
python -m pip install /path/to/security-check
flutter-supply-guard "$PROJECT_DIR" \
  --policy /path/to/approved-policy.json \
  --baseline /path/to/approved-baseline.json \
  --fail-on medium \
  --json "$RUN_REPORT_DIR/dependency-security.json"
```

CI 请在失败时仍归档 JSON 报告，并避免用 `|| true` 吞掉退出码。输出文件必须不存在，防止覆盖锁文件、策略或已有证据。报告含依赖来源 URL 和文件名，应按内部数据管理；来源 URL 不应嵌入凭据。

## 能力边界

此工具提供可运行的静态供应链检查和 CI 门禁，不能保证识别所有未知投毒。仓库主机在白名单中不代表仓库作者可信；没有已知漏洞不代表没有恶意逻辑。脚本规则是人工复核线索，注释、文档 URL 等也可能误报。未进行动态沙箱执行、二进制逆向、签名信任链验证、维护者身份分析或完整行为分析。

检测结果应结合依赖升级审核、可信镜像、隔离构建、凭据最小化、制品签名和锁文件保护使用。

## 开发验证

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q supply_guard
```

测试使用临时工程和模拟情报，不下载或执行恶意样本。

接口与格式依据：[OSV Query API](https://google.github.io/osv.dev/post-v1-query/)、[OSV schema 生态定义](https://ossf.github.io/osv-schema/)、[Dart 锁文件与内容哈希](https://dart.dev/tools/pub/packages)、[pub.dev API](https://pub.dev/help/api)、[Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)、[CocoaPods Podfile](https://guides.cocoapods.org/using/the-podfile.html)。
