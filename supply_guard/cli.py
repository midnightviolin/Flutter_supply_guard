import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .core import LEVELS, Scan, mapping, read_text
from .intelligence import local_advisories, online, pub_hashes


def safe_text(value):
    return "".join(c if c.isprintable() else " " for c in str(value))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Flutter / Android / iOS 依赖供应链检查（只读扫描）")
    parser.add_argument("project", type=Path, help="Flutter 工程根目录")
    parser.add_argument("--offline", action="store_true", help="不联网；报告漏洞情报覆盖不足")
    parser.add_argument("--policy", type=Path, help="组织 JSON 策略")
    parser.add_argument("--advisories", type=Path, help="组织精确版本漏洞/恶意库 JSON 情报")
    parser.add_argument("--baseline", type=Path, help="对照已审核依赖基线")
    parser.add_argument("--save-baseline", type=Path, help="保存候选基线（仅新文件；使用前必须审核）")
    parser.add_argument("--artifacts", type=Path, help="对照项目内制品 SHA-256 清单")
    parser.add_argument("--source-dir", action="append", type=Path, default=[], help="额外扫描已下载的依赖源码目录，可重复")
    parser.add_argument("--json", type=Path, dest="output", help="写入 JSON 报告（仅新文件）")
    parser.add_argument("--fail-on", choices=LEVELS, default="high")
    parser.add_argument("--allow-incomplete", action="store_true", help="显式允许覆盖不足通过；高风险仍阻断")
    args = parser.parse_args(argv)
    try:
        if not args.project.is_dir():
            raise ValueError("项目目录不存在")
        outputs = [p.resolve() for p in (args.output, args.save_baseline) if p]
        if len(outputs) != len(set(outputs)) or any(p.exists() for p in outputs):
            raise ValueError("输出路径必须互不相同且不存在，以保护已有文件")
        policy = mapping(json.loads(read_text(args.policy))) if args.policy else {}
        scan = Scan(args.project, policy).inventory()
        if args.source_dir:
            scan_sources(scan, args.source_dir)
        if args.artifacts:
            scan.artifacts(args.artifacts)
        if args.baseline:
            scan.baseline(args.baseline)
        if args.advisories:
            local_advisories(scan, args.advisories)
        if args.offline:
            scan.gap("离线模式：未查询实时已知漏洞及官方 Pub 哈希")
            scan.coverage["osv"] = {"status": "skipped"}
        else:
            print("查询 OSV（发送依赖名称/版本或 commit）及 pub.dev 哈希…", file=sys.stderr)
            online(scan)
            pub_hashes(scan)
        blocked = any(LEVELS[f["severity"]] >= LEVELS[args.fail_on] for f in scan.findings)
        exit_code = 1 if blocked else 2 if scan.errors and not args.allow_incomplete else 0
        report = scan.report()
        report.update(timestamp=datetime.now(timezone.utc).isoformat(), exit_code=exit_code,
                      status="blocked" if blocked else "incomplete" if scan.errors else "no_findings_above_threshold")
        for path, doc in ((args.output, report), (args.save_baseline, scan.snapshot())):
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("x", encoding="utf-8") as stream:
                    json.dump(doc, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
        print(f"依赖 {len(scan.dependencies)} 个 | 风险 {len(scan.findings)} 项 | 覆盖缺口 {len(scan.errors)} 项 | {report['status']}")
        for f in report["findings"]:
            print(safe_text(f"[{f['severity'].upper()}] {f['rule']} {f['dependency']} {f['file']}: {f['message']}"))
        for error in scan.errors:
            print(safe_text(f"[INCOMPLETE] {error['file']}: {error['message']}"))
        if args.save_baseline:
            print("已生成候选基线：请审核后纳入版本管理，生成基线不代表通过安全检查。")
        return exit_code
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc:
        print(safe_text(f"检查失败: {type(exc).__name__}: {exc}"), file=sys.stderr)
        return 2


def scan_sources(scan, paths):
    import os
    from .core import SKIP, digest

    suffixes = {".dart", ".java", ".kt", ".swift", ".m", ".mm", ".c", ".cpp", ".sh", ".rb", ".podspec"}
    for index, root in enumerate(paths):
        root = root.resolve()
        if not root.is_dir():
            raise ValueError(f"额外源码目录不存在: {root}")
        count = 0
        for directory, dirs, files in os.walk(root, followlinks=False,
                                              onerror=lambda e: scan.gap(f"源码目录读取失败: {e.filename}")):
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(directory) / d).is_symlink())
            for name in sorted(files):
                path = Path(directory) / name
                if path.suffix not in suffixes and not name.endswith((".gradle", ".gradle.kts", ".podspec.json")):
                    continue
                label = f"source[{index}]/" + path.relative_to(root).as_posix()
                if path.is_symlink():
                    scan.gap("跳过符号链接源码", label)
                    continue
                try:
                    scan.scripts(path, label)
                    scan.files[label] = digest(path)
                    count += 1
                except (OSError, ValueError) as exc:
                    scan.gap(f"源码检查失败: {type(exc).__name__}", label)
        scan.coverage[f"source[{index}]"] = {"files": count, "scope": "heuristic patterns only"}
