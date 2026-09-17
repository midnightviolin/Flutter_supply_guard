# Flutter Supply Guard

[中文文档](README_CN.md)

Flutter Supply Guard is a read-only dependency supply-chain checker for Flutter/Dart Pub, Android Maven/Gradle, iOS CocoaPods, and Swift Package Manager projects. It is designed for local reviews and CI gates.

The scanner reads project files and does not run `flutter pub get`, Gradle, CocoaPods, Podfiles, Podspecs, or dependency installation scripts. Online scans query OSV and pub.dev using package coordinates, versions, or Git commits; project source code is not uploaded. Use `--offline` for private or disconnected environments, and keep the resulting coverage gaps visible.

## Installation

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Run the CLI with either the installed entry point or the Python module:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project
.venv/bin/python -m supply_guard /path/to/flutter_project
```

## Quick start

Scan a Flutter app and its native platforms:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --scope flutter --scope android --scope ios \
  --json /tmp/flutter-dependency-security.json
```

Run an offline scan of lockfiles, sources, and configuration:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --offline --json /tmp/flutter-dependency-security-offline.json
```

Use organization policy and exact-version advisory data:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --policy examples/policy.json \
  --advisories examples/advisories.json
```

The advisory and deny-list files under `examples/` contain fictional demonstration data. Replace them with reviewed organization intelligence before using them as a security control.

## Scope modes

The same checker can inspect a complete Flutter app or a native project independently:

| Scope | Main inputs | What it checks |
| --- | --- | --- |
| `flutter` | `pubspec.lock`, `pubspec.yaml` | Transitive Pub dependencies, hosted hashes, registry sources, Git commits, path dependencies, overrides, and OSV |
| `android` | Gradle lockfiles, Gradle configuration, verification metadata | Maven versions, repositories, dynamic versions, remote scripts, Gradle verification, and OSV |
| `ios` | `Podfile.lock`, `Podfile`, `Package.resolved`, Podspecs | CocoaPods and SwiftPM sources, revisions, local Pods, install hooks, remote binary downloads, and organization advisories |

Use the focused skills when the project is native-only:

- `$flutter-dependency-security` for Flutter apps and combined Flutter/Android/iOS checks.
- `$android-dependency-security` for standalone Android projects.
- `$ios-dependency-security` for standalone iOS projects.

The skill definitions are in `skills/`. The platform-specific guidance is in `skills/flutter-dependency-security/references/`.

## Additional source and artifact checks

The scanner does not automatically inspect every package cache. Pass downloaded dependency directories explicitly:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --source-dir /path/to/downloaded/flutter_plugin \
  --source-dir /path/to/ios/Pods \
  --json /tmp/dependency-security.json
```

Source scanning uses static heuristics for direct download-and-execute patterns, dynamic execution, install hooks, remote Gradle scripts, insecure repositories, and dependency overrides. It does not execute scripts or prove that a binary is safe.

For AAR, JAR, Framework, XCFramework, ZIP, or other local artifacts, provide an independently reviewed SHA-256 manifest. Paths must be relative to the project root:

```json
{
  "vendor/library.aar": "64 hexadecimal SHA-256 characters"
}
```

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --artifacts approved-artifacts.json
```

Only listed files are checked. A missing artifact is high severity; a digest mismatch is critical severity. An approved hash must come from an independently trusted source; do not approve a hash generated from an untrusted first download.

## Baselines and same-version replacement

Generate a candidate baseline from a trusted checkout, review it, and commit only the approved result:

```bash
.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --save-baseline baseline.candidate.json

.venv/bin/flutter-supply-guard /path/to/flutter_project \
  --baseline baseline.approved.json \
  --json /tmp/dependency-security-follow-up.json
```

New or upgraded dependencies are reported for review. A change to the source, commit, package fingerprint, or checked source file is higher risk. A candidate baseline records state; it does not certify that state as safe. Protect baselines, policies, advisory data, and artifact manifests from changes made by dependency updates.

## Lockfile expectations

Flutter applications should commit `pubspec.lock` and use an enforce-lockfile workflow in CI after reviewing the resolved dependencies. The scanner does not run Pub's solver and reports when declared dependencies are absent from the local lockfile.

Android projects should enable Gradle dependency locking for every release/debug configuration and variant that is built. They should also commit reviewed `gradle/verification-metadata.xml` containing SHA-256 and/or signature verification rules, with strict verification enabled in CI. The scanner does not run Gradle and cannot prove that every build configuration is covered when lockfiles or verification metadata are missing.

iOS projects should commit reviewed `Podfile.lock` and `Package.resolved`. CocoaPods `SPEC CHECKSUMS` identify Podspec contents; they do not prove the integrity of downloaded source code, Frameworks, or XCFrameworks. Remote binary downloads and local Podspec `prepare_command` hooks need independent artifact hashes or signatures.

## CI behavior

Exit codes are:

- `0`: no finding reaches `--fail-on`, and no disallowed coverage gap remains.
- `1`: a finding reaches the selected threshold; the default threshold is `high`.
- `2`: parsing, configuration, network, or coverage errors remain without a higher-priority blocking finding.

Use `--fail-on medium` to require review of new dependencies, upgrades, and install hooks. `--allow-incomplete` explicitly permits incomplete intelligence or offline coverage, but the report remains marked `incomplete`; do not enable it by default in strict CI.

Example CI invocation:

```bash
python -m pip install /path/to/flutter-supply-guard
flutter-supply-guard "$PROJECT_DIR" \
  --policy /path/to/approved-policy.json \
  --baseline /path/to/approved-baseline.json \
  --fail-on medium \
  --json "$RUN_REPORT_DIR/dependency-security.json"
```

Archive the JSON report when CI fails. Do not use `|| true` to discard the exit code. Output files must be new files so a scan cannot overwrite a lockfile, policy, baseline, or existing evidence.

## Interpretation and limitations

`SOURCE_UNTRUSTED` means that a source host is outside the configured allow-list; it is not proof that the host or package is malicious. Review private registries, mirrors, Gitee repositories, JitPack, and internal Maven/CocoaPods sources against organization policy.

Known-vulnerability results come from the available advisory data. CocoaPods package names generally do not have a standard OSV ecosystem, so ordinary Pods may produce coverage gaps. Private Pub registries cannot be validated against public pub.dev metadata. A clean result does not rule out unknown malicious behavior, compromised maintainers, or a replaced binary when no baseline or artifact manifest is available.

The tool does not perform dynamic sandbox execution, binary reverse engineering, maintainer identity analysis, signature trust-chain validation, or complete behavioral analysis. Combine it with isolated dependency resolution, least-privilege build credentials, reviewed mirrors, artifact signing, protected lockfiles, and human review of high-risk install scripts.

## Development checks

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q supply_guard
```

The test suite uses temporary projects and mocked intelligence. It does not download or execute malicious samples.

The implementation follows the public formats and APIs documented by [OSV Query API](https://google.github.io/osv.dev/post-v1-query/), [OSV schema](https://ossf.github.io/osv-schema/), [Dart Pub packages](https://dart.dev/tools/pub/packages), [pub.dev API](https://pub.dev/help/api), [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html), and [CocoaPods Podfiles](https://guides.cocoapods.org/using/the-podfile.html).
