---
name: flutter-dependency-security
description: "检查 Flutter 工程及其 Android、iOS 依赖的已知漏洞、来源、锁定、完整性和安装脚本风险；用户要求依赖安全、供应链检查或投毒排查时使用。"
---

# Flutter dependency security

使用本 skill 对 Flutter 工程做只读的依赖供应链检查。目标是发现已知漏洞、依赖来源不可信或未审核、版本/提交未锁定、下载内容被替换，以及安装阶段下载或执行外部内容的风险。扫描结果不能证明依赖绝对安全；没有命中公开漏洞也不等于没有投毒。

## 检查范围

先识别用户给出的工程根目录和实际存在的锁文件，再选择范围：

- Flutter 全量检查：`--scope flutter --scope android --scope ios`，适用于同时包含三端目录的 Flutter app。
- 只检查 Flutter/Dart：`--scope flutter`。
- Android 原生依赖：使用 `$android-dependency-security`。
- iOS 原生依赖：使用 `$ios-dependency-security`。

如果用户没有指定范围，Flutter 工程默认扫描 Flutter 锁文件，并根据 `android/`、`ios/` 目录补充原生检查。不要因为缺少某平台锁文件而跳过；将其报告为覆盖缺口。

## 执行方式

当前工具仓库含有 `supply_guard` 包。优先使用 PATH 中已安装的 `flutter-supply-guard`；若不存在，在包含 `pyproject.toml` 的工具仓库目录创建虚拟环境并调用同名入口：

```bash
cd <security-check-repo>
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/flutter-supply-guard /path/to/flutter-project \
  --scope flutter --scope android --scope ios \
  --json /tmp/flutter-dependency-security.json
```

报告路径应放在 `/tmp` 或其他临时目录，且必须是不存在的新文件。不要把报告写入被检查工程，不要覆盖已有策略、锁文件、基线或安全证据。

在线扫描是默认选择，因为它会查询 OSV 已知漏洞和 pub.dev 发布哈希。网络不可用或用户要求离线时使用 `--offline`，但必须把 OSV、官方哈希和私有仓库覆盖不足写入结论；不要把离线结果描述成“无漏洞”。OSV 查询只发送包坐标、版本或 Git commit，不上传工程源码。

扫描只读取文件，不执行 `flutter pub get`、Gradle、CocoaPods、Podfile、Podspec 或依赖安装脚本。不要为了生成锁文件或构建结果而自动运行工程命令。若锁文件不存在，报告缺口并建议用户在隔离构建环境生成后重新扫描。

## 结果判断

优先解释 `KNOWN_VULNERABILITY`、`ARTIFACT_TAMPERED`、`PUB_HASH_MISMATCH`、`GIT_UNPINNED`、`SOURCE_TRANSPORT`、`SOURCE_CREDENTIALS`、`GRADLE_VERIFICATION_MISSING` 和安装阶段远程下载等高风险结果。

`SOURCE_UNTRUSTED` 表示来源主机不在当前白名单，不表示已经确认恶意。结合项目组织批准的镜像清单判断是否应加入策略；不要为了让结果通过而盲目扩大白名单。`LOCAL_DEPENDENCY`、`GIT_REVIEW`、`POD_ARTIFACT_UNVERIFIED` 通常需要人工审核和制品哈希。

报告中同时存在风险和覆盖缺口时，分别说明：风险是已经观察到的问题，缺口是工具没有足够证据完成检查。没有组织情报或基线时，不要声称已检测所有投毒；建议后续加入精确版本恶意库清单、来源策略、审核基线和二进制 SHA-256/签名清单。

需要进一步解释平台规则时，按需读取：

- [Flutter/Dart 规则](references/flutter.md)
- [Android 规则](references/android.md)
- [iOS 规则](references/ios.md)

## 常用参数

使用 `--policy` 加载组织允许主机、禁用依赖和必检平台；使用 `--advisories` 加载组织维护的精确版本漏洞/恶意库情报；使用 `--baseline` 对照已审核依赖和源码文件指纹；使用 `--artifacts` 对照项目内 AAR、JAR、Framework、ZIP 等制品的 SHA-256；使用重复的 `--source-dir` 检查已下载依赖源码。

`--save-baseline` 只生成候选基线，必须人工审核后才可纳入版本管理。不要把候选基线当成安全结论。CI 默认使用 `--fail-on high`；若使用 `--fail-on medium`，需准备处理新增依赖和安装脚本等审核项。不要使用 `--allow-incomplete` 吞掉覆盖缺口，除非用户明确要求并在最终报告中保留缺口。
