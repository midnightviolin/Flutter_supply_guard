"""Read-only inventory and heuristic checks. Never runs project code."""
from __future__ import annotations

import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP = {".git", ".venv", "build", "node_modules", ".gradle", "Pods", ".symlinks", ".dart_tool"}
DEFAULT_HOSTS = {"pub.dev", "pub.dartlang.org", "repo.maven.apache.org", "repo1.maven.org",
                 "dl.google.com", "maven.google.com", "plugins.gradle.org", "cdn.cocoapods.org",
                 "github.com"}


class StrictLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently dropping inventory entries."""


def strict_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"YAML 重复键: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, strict_mapping)


def load_yaml(path):
    return yaml.load(read_text(path), Loader=StrictLoader)


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    source: str
    file: str
    checksum: str = ""
    commit: str = ""

    @property
    def key(self):
        return f"{self.ecosystem}:{self.name}@{self.version}"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("文件超过 8 MiB 限制")
    return path.read_text(encoding="utf-8")


def mapping(value):
    if not isinstance(value, dict):
        raise ValueError("预期为对象/map")
    return value


class Scan:
    def __init__(self, root, policy=None):
        self.root = Path(root).resolve()
        self.policy = policy or {}
        unknown = set(self.policy) - {"allowed_hosts", "deny", "required_platforms"}
        if unknown:
            raise ValueError(f"未知策略字段: {sorted(unknown)}")
        for key in ("allowed_hosts", "required_platforms"):
            if key in self.policy and (not isinstance(self.policy[key], list) or
                                      not all(isinstance(x, str) for x in self.policy[key])):
                raise ValueError(f"{key} 必须为字符串数组")
        if set(self.policy.get("required_platforms", [])) - {"flutter", "android", "ios"}:
            raise ValueError("required_platforms 仅支持 flutter/android/ios")
        if not isinstance(self.policy.get("deny", []), list):
            raise ValueError("deny 必须为数组")
        for item in self.policy.get("deny", []):
            mapping(item)
            if not {"ecosystem", "name"} <= item.keys() or set(item) - {"ecosystem", "name", "version", "reason"}:
                raise ValueError("deny 项必须包含 ecosystem/name，可选 version/reason")
        self.hosts = set(self.policy.get("allowed_hosts", DEFAULT_HOSTS))
        self.dependencies = []
        self.findings = []
        self.errors = []
        self.files = {}
        self.coverage = {}

    def add(self, rule, severity, message, file="", dependency="", **details):
        self.findings.append(dict(rule=rule, severity=severity, message=message,
                                  file=file, dependency=dependency, **details))

    def gap(self, message, file=""):
        self.errors.append({"message": message, "file": file})

    def source(self, source, file, dependency=""):
        if source.startswith(("path:", "sdk:")):
            return
        parsed = urlsplit(source)
        if parsed.scheme not in {"https", "ssh"}:
            self.add("SOURCE_TRANSPORT", "high", "依赖来源未使用 HTTPS/SSH", file, dependency)
        if parsed.hostname not in self.hosts:
            self.add("SOURCE_UNTRUSTED", "high", "依赖来源主机不在允许列表", file, dependency,
                     host=parsed.hostname or "unknown")
        if parsed.username and parsed.scheme != "ssh":
            self.add("SOURCE_CREDENTIALS", "high", "来源 URL 含凭据，请改用凭据管理", file, dependency)

    def dep(self, dep):
        self.dependencies.append(dep)
        for denied in self.policy.get("deny", []):
            if (denied["ecosystem"] == dep.ecosystem and denied["name"] == dep.name
                    and denied.get("version", dep.version) == dep.version):
                self.add("DENIED_PACKAGE", "critical", denied.get("reason", "命中组织禁用依赖"),
                         dep.file, dep.key)

    def pub(self, path, file):
        doc = mapping(load_yaml(path))
        packages = mapping(doc.get("packages"))
        for name, raw in packages.items():
            data = mapping(raw)
            version = str(data["version"])
            kind = data["source"]
            desc = data.get("description")
            sha = commit = ""
            if kind == "hosted":
                if isinstance(desc, dict):
                    source = str(desc.get("url", "https://pub.dev"))
                    sha = str(desc.get("sha256", ""))
                    if desc.get("name", name) != name:
                        self.add("PUB_NAME_MISMATCH", "high", "锁文件名称与 hosted 名称不同", file, name)
                else:
                    source = "https://pub.dev"
                if not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                    self.add("PUB_HASH_MISSING", "high", "Hosted 依赖缺少有效 SHA-256", file, name)
                self.source(source, file, name)
            elif kind == "git":
                desc = mapping(desc)
                source = str(desc["url"])
                commit = str(desc.get("resolved-ref", ""))
                self.source(source, file, name)
                if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
                    self.add("GIT_UNPINNED", "high", "Git 依赖未锁定完整 commit", file, name)
                self.add("GIT_REVIEW", "medium", "Git 依赖需审核仓库及锁定提交", file, name)
            elif kind in {"path", "sdk"}:
                source = f"{kind}:{desc.get('path', '') if isinstance(desc, dict) else desc}"
                if kind == "path":
                    self.add("LOCAL_DEPENDENCY", "medium", "本地依赖需单独审核源码", file, name)
            else:
                raise ValueError(f"未知 Pub source: {kind}")
            self.dep(Dependency("Pub", str(name), version, source, file, sha, commit))

    def pods(self, path, file):
        doc = mapping(load_yaml(path))
        entries = doc.get("PODS")
        if not isinstance(entries, list):
            raise ValueError("Podfile.lock 缺少 PODS 数组")
        origins = {}
        for repo, names in mapping(doc.get("SPEC REPOS", {})).items():
            for name in names:
                origins[name] = "https://cdn.cocoapods.org" if repo == "trunk" else repo
        external = mapping(doc.get("EXTERNAL SOURCES", {}))
        checkouts = mapping(doc.get("CHECKOUT OPTIONS", {}))
        hashes = mapping(doc.get("SPEC CHECKSUMS", {}))
        seen = set()
        for entry in entries:
            label = next(iter(entry)) if isinstance(entry, dict) else entry
            match = re.fullmatch(r"([^ ]+) \(([^()]+)\)", str(label))
            if not match:
                raise ValueError(f"无法识别 Pod 条目: {label}")
            name, version = match.groups()
            name = name.split("/")[0]
            if (name, version) in seen:
                continue
            seen.add((name, version))
            ext = mapping(external.get(name, {}))
            checkout = mapping(checkouts.get(name, {}))
            commit = str(checkout.get(":commit", ext.get(":commit", "")))
            source = str(ext.get(":git", origins.get(name, "unknown")))
            if ":path" in ext or ":podspec" in ext:
                source = "path:" + str(ext.get(":path", ext.get(":podspec")))
                self.add("LOCAL_DEPENDENCY", "medium", "本地 Pod/Podspec 需审核原生源码及安装脚本", file, name)
            elif source == "unknown":
                self.add("POD_SOURCE_UNKNOWN", "high", "Pod 来源信息缺失", file, name)
            else:
                self.source(source, file, name)
            if ":git" in ext and not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
                self.add("GIT_UNPINNED", "high", "Pod Git 来源未固定完整 commit", file, name)
            self.dep(Dependency("CocoaPods", name, version, source, file, str(hashes.get(name, "")), commit))
        self.add("POD_ARTIFACT_UNVERIFIED", "medium", "SPEC CHECKSUMS 校验 Podspec，不代表下载源码或二进制完整性", file)

    def gradle(self, path, file):
        count = 0
        for line in read_text(path).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            match = re.fullmatch(r"([^:\s=]+):([^:\s=]+):([^=\s]+)(?:=.*)?", line)
            if not match:
                raise ValueError(f"无法识别 Gradle lock 条目: {line}")
            group, name, version = match.groups()
            self.dep(Dependency("Maven", f"{group}:{name}", version, "gradle-resolved", file))
            count += 1
            if re.search(r"[+\[\](),]|latest\.|SNAPSHOT", version, re.I):
                self.add("DYNAMIC_VERSION", "high", "Maven 版本不稳定或为动态版本", file, f"{group}:{name}")
        return count

    def swift(self, path, file):
        doc = mapping(json.loads(read_text(path)))
        pins = doc.get("pins", doc.get("object", {}).get("pins"))
        if not isinstance(pins, list):
            raise ValueError("Package.resolved 缺少 pins 数组")
        for pin in pins:
            state = mapping(pin["state"])
            source = str(pin.get("location", pin.get("repositoryURL", "")))
            name = str(pin.get("identity", pin.get("package", source)))
            commit = str(state.get("revision", ""))
            self.source(source, file, name)
            if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
                self.add("GIT_UNPINNED", "high", "SwiftPM 未固定完整 commit", file, name)
            self.dep(Dependency("SwiftURL", name, str(state.get("version") or commit), source, file, commit=commit))

    def scripts(self, path, file):
        content = read_text(path)
        # Source URLs in comments and documentation are not dependency sources.
        suffix = path.suffix.lower()
        if suffix in {".gradle", ".kts"}:
            code = re.sub(r"(?m)^\s*//.*$", "", content)
        elif suffix in {".rb", ".podspec", ".sh", ".yaml", ".yml"} or path.name in {"Podfile", "pubspec.yaml", "pubspec_overrides.yaml"}:
            code = re.sub(r"(?m)#.*$", "", content)
        else:
            code = content
        patterns = [
            ("REMOTE_EXEC", "high", r"(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash|zsh)\b", "发现下载后直接执行命令"),
            ("ENCODED_EXEC", "high", r"(?:base64\s+(?:-d|--decode)|eval\s*\()", "发现解码或动态执行模式，需人工核查"),
            ("INSTALL_SCRIPT", "medium", r"\b(?:prepare_command|script_phases?|post_install|pre_install)\b", "发现安装或构建脚本入口"),
            ("REMOTE_GRADLE", "high", r"apply\s*(?:\(|\s)\s*from\s*[:=]\s*[\"']https?://", "发现远程 Gradle 脚本"),
            ("DYNAMIC_VERSION", "high", r"[\"'][^\"'\s]+:[^\"'\s]+:[^\"'\s]*(?:\+|SNAPSHOT|latest\.[^\"']*)[\"']", "发现动态 Maven 依赖"),
            ("DEPENDENCY_OVERRIDE", "medium", r"^\s*dependency_overrides\s*:", "依赖覆盖可能改变实际依赖来源"),
            ("INSECURE_REPOSITORY", "high", r"allowInsecureProtocol\s*=\s*true|isAllowInsecureProtocol\s*=\s*true", "仓库允许明文传输"),
        ]
        for rule, level, pattern, message in patterns:
            for match in re.finditer(pattern, code, re.M):
                self.add(rule, level, message, file, line=code.count("\n", 0, match.start()) + 1)
        # Only dependency/source declarations are repository inputs. URLs in library
        # code are runtime endpoints and must not become source allow-list findings.
        if path.name == "Podfile":
            source_text = "\n".join(line for line in code.splitlines()
                                      if re.search(r"^\s*source\s+['\"]https?://", line))
        elif suffix in {".gradle", ".kts"}:
            source_text = "\n".join(line for line in code.splitlines()
                                      if re.search(r"\b(?:url|maven|repositories|apply\s+from)\b", line))
        elif suffix == ".podspec" or path.name.endswith(".podspec.json"):
            source_text = "\n".join(line for line in code.splitlines()
                                      if re.search(r"(?:s\.source|\"source\"\s*:|:source)", line))
        else:
            source_text = ""
        for source in set(re.findall(r"https?://[^\s\"'<>)}\]]+", source_text)):
            self.source(source, file)

    def verification(self, path, file):
        text = read_text(path)
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise ValueError("XML 不允许 DTD/实体声明")
        root = ET.fromstring(text)
        if root.tag.split("}")[-1] != "verification-metadata":
            raise ValueError("无效 Gradle verification-metadata 根元素")
        values = [e.attrib.get("value", "") for e in root.iter() if e.tag.split("}")[-1] == "sha256"]
        if not values or any(not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in values):
            self.add("GRADLE_HASH_MISSING", "high", "Gradle 校验元数据缺少有效 SHA-256", file)
        for e in root.iter():
            tag = e.tag.split("}")[-1]
            if tag == "verify-metadata" and (e.text or "").strip() == "false":
                self.add("GRADLE_METADATA_DISABLED", "high", "Gradle 元数据校验被关闭", file)
            if tag == "trust":
                self.add("GRADLE_TRUST_BYPASS", "medium", "存在跳过制品校验的 trust 规则，请审核范围", file)

    def inventory(self):
        scope = set(self.policy["required_platforms"]) if "required_platforms" in self.policy else None
        if not (self.root / "pubspec.yaml").is_file():
            if scope is None or "flutter" in scope:
                self.gap("目标根目录缺少 pubspec.yaml")
        found = {"flutter": 0, "android": 0, "ios": 0}
        for directory, dirs, names in os.walk(self.root, followlinks=False,
                                              onerror=lambda e: self.gap(f"目录读取失败: {e.filename}")):
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(directory) / d).is_symlink())
            for name in sorted(names):
                path = Path(directory) / name
                file = path.relative_to(self.root).as_posix()
                parser = None
                platform = None
                script_platform = None
                if name == "pubspec.lock":
                    parser, platform = self.pub, "flutter"
                    script_platform = "flutter"
                elif name == "Podfile.lock":
                    parser, platform = self.pods, "ios"
                    script_platform = "ios"
                elif name == "gradle.lockfile" or name.endswith(".lockfile") and "dependency-locks" in path.parts:
                    parser, platform = self.gradle, "android"
                elif name == "Package.resolved":
                    parser, platform = self.swift, "ios"
                    script_platform = "ios"
                elif name == "verification-metadata.xml":
                    script_platform = "android"
                script = (name in {"pubspec.yaml", "pubspec_overrides.yaml", "Podfile", "gradle.properties"}
                          or name.endswith((".gradle", ".gradle.kts", ".podspec", ".podspec.json")))
                if name in {"pubspec.yaml", "pubspec_overrides.yaml"}:
                    script_platform = "flutter"
                elif name == "Podfile" or name.endswith((".podspec", ".podspec.json")):
                    script_platform = "ios"
                elif name == "gradle.properties" or name.endswith((".gradle", ".gradle.kts")):
                    script_platform = "android"
                if scope and platform not in scope:
                    parser = None
                if scope and script_platform not in scope:
                    script = False
                if not parser and not script and name != "verification-metadata.xml":
                    continue
                if scope and script_platform not in scope and name == "verification-metadata.xml":
                    continue
                if path.is_symlink():
                    self.gap("跳过符号链接文件", file)
                    continue
                try:
                    self.files[file] = digest(path)
                    if parser:
                        parser(path, file)
                        found[platform] += 1
                    if script:
                        if name in {"pubspec.yaml", "pubspec_overrides.yaml"}:
                            mapping(load_yaml(path))
                        if name not in {"pubspec.yaml", "pubspec_overrides.yaml"}:
                            self.scripts(path, file)
                    if name == "verification-metadata.xml":
                        self.verification(path, file)
                except (OSError, ValueError, TypeError, KeyError, StopIteration, ET.ParseError, yaml.YAMLError) as exc:
                    self.gap(f"文件解析失败: {type(exc).__name__}: {exc}", file)
        if "required_platforms" in self.policy:
            required = set(self.policy["required_platforms"])
        else:
            required = {"flutter"}
            required.update(p for p in ("android", "ios") if (self.root / p).exists())
        for platform, count in found.items():
            self.coverage[platform] = {"lockfiles": count, "required": platform in required}
            if platform in required and not count:
                self.gap(f"{platform} 缺少可解析锁文件；无法确认传递依赖")
        # Catch obvious stale lockfiles without attempting Pub's version solver.
        for file in self.files:
            if not file.endswith("pubspec.yaml"):
                continue
            try:
                manifest = mapping(load_yaml(self.root / file))
                lockfile = str(Path(file).with_name("pubspec.lock"))
                names = {d.name for d in self.dependencies if d.file == lockfile and d.ecosystem == "Pub"}
                for section in ("dependencies", "dev_dependencies"):
                    declared = mapping(manifest.get(section) or {})
                    for name in declared:
                        if name not in names:
                            self.gap(f"声明依赖 {name} 未出现在同目录锁文件；请确认解析结果或 workspace 根锁文件", file)
            except (OSError, ValueError, TypeError, yaml.YAMLError):
                # The primary parse already records malformed manifests.
                self.gap("无法核对声明依赖与锁文件", file)
        if "android" in required:
            if not any(p.endswith("verification-metadata.xml") for p in self.files):
                self.add("GRADLE_VERIFICATION_MISSING", "high", "缺少 Gradle 依赖校验元数据", "android")
            self.add("GRADLE_COVERAGE_REVIEW", "medium", "需确认锁文件覆盖全部 variant/configuration 及构建插件；元数据存在不代表构建时已强制校验", "android")
        return self

    def artifacts(self, manifest):
        doc = mapping(json.loads(read_text(manifest)))
        for relative, expected in doc.items():
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                raise ValueError(f"无效 SHA-256: {relative}")
            path = (self.root / relative).resolve()
            if not path.is_relative_to(self.root) or Path(relative).is_absolute():
                raise ValueError("制品清单路径必须在项目目录内")
            if not path.is_file():
                self.add("ARTIFACT_MISSING", "high", "清单中的制品不存在", relative)
            elif digest(path) != expected.lower():
                self.add("ARTIFACT_TAMPERED", "critical", "制品 SHA-256 与审核值不一致", relative)

    def snapshot(self):
        return {"schema": 1, "dependencies": [asdict(d) for d in sorted(self.dependencies, key=lambda d: (d.file, d.key))],
                "files": dict(sorted(self.files.items()))}

    def baseline(self, path):
        previous = mapping(json.loads(read_text(path)))
        if previous.get("schema") != 1 or not isinstance(previous.get("dependencies"), list):
            raise ValueError("不支持的基线格式")
        old = {(d["file"], d["ecosystem"], d["name"]): d for d in previous["dependencies"]}
        new = {(d.file, d.ecosystem, d.name): asdict(d) for d in self.dependencies}
        for key, item in new.items():
            prior = old.get(key)
            if not prior:
                self.add("DEPENDENCY_ADDED", "medium", "新增依赖，请审核后更新基线", item["file"], item["name"])
            elif item != prior:
                same_version = item["version"] == prior["version"]
                self.add("DEPENDENCY_CHANGED", "high" if same_version else "medium",
                         "依赖版本、来源或指纹发生变化", item["file"], item["name"])
        for key in old.keys() - new.keys():
            self.add("DEPENDENCY_REMOVED", "info", "依赖已移除", key[0], key[2])
        for file, sha in self.files.items():
            if file in previous.get("files", {}) and previous["files"][file] != sha:
                self.add("INPUT_CHANGED", "high" if file.startswith("source[") else "medium", "依赖配置/源码/锁文件内容较基线变化", file)
            elif file.startswith("source[") and file not in previous.get("files", {}):
                self.add("SOURCE_ADDED", "high", "依赖源码新增文件，请审核", file)
        for file in previous.get("files", {}).keys() - self.files.keys():
            self.add("INPUT_REMOVED", "high", "基线文件被删除或此次扫描未覆盖", file)

    def report(self):
        return {**self.snapshot(), "coverage": self.coverage, "errors": self.errors,
                "findings": sorted(self.findings, key=lambda f: (-LEVELS[f["severity"]], f["file"], f["rule"]))}
