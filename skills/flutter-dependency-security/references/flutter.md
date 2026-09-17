# Flutter / Dart 检查规则

读取所有工程层级可见的 `pubspec.lock`，以锁文件中的传递依赖为实际清单。读取 `pubspec.yaml` 和 `pubspec_overrides.yaml` 只用于核对声明、依赖覆盖和来源，不以注释中的 URL 作为依赖来源。

对 hosted 包检查：

- 包名、解析版本和来源主机是否符合组织策略。
- 锁文件中的 SHA-256 是否存在且格式正确。
- 公有 `pub.dev` 包能否与 pub.dev 的 `archive_sha256` 对照；私有 registry 不要冒充公有包查询，报告为覆盖缺口。
- OSV 的 Pub 坐标是否有已知漏洞。

对 Git 包检查 HTTPS/SSH、仓库主机和完整 40/64 位 commit。分支名、tag 或短提交不能作为完整供应链锁定。Git commit 查询可用于 OSV，但没有公开漏洞也不代表仓库内容可信。

对 path、SDK 和 `dependency_overrides` 分别报告。path 包要通过 `--source-dir` 检查实际源码；覆盖依赖可能改变最终解析来源，必须人工确认。

工程声明的直接依赖没有出现在同目录锁文件时，报告解析覆盖缺口，不自动运行 Pub 求解器。CI 可在隔离环境生成锁文件并使用 `dart pub get --enforce-lockfile` 或对应 Flutter 命令后再检查。
