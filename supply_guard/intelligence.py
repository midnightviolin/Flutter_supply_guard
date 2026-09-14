"""Public advisory lookups plus organization-provided exact-version intelligence."""
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .core import LEVELS, mapping, read_text


def request_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "flutter-supply-guard/0.1"})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=25) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
                if len(raw) > 32 * 1024 * 1024:
                    raise ValueError("API 响应超出大小限制")
                return mapping(json.loads(raw))
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(0.5 * 2 ** attempt)


def osv_query(payload, fetch=request_json):
    records, tokens = {}, set()
    payload = dict(payload)
    for _ in range(100):
        result = fetch("https://api.osv.dev/v1/query", payload)
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise ValueError("OSV vulns 格式错误")
        for vuln in vulns:
            mapping(vuln)
            if not isinstance(vuln.get("id"), str):
                raise ValueError("OSV 缺少漏洞 ID")
            if not vuln.get("withdrawn"):
                records[vuln["id"]] = vuln
        token = result.get("next_page_token")
        if not token:
            return list(records.values())
        if not isinstance(token, str) or token in tokens:
            raise ValueError("OSV 分页 token 无效或重复")
        tokens.add(token)
        payload["page_token"] = token
    raise ValueError("OSV 分页超限，查询不完整")


def query_for(dep):
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", dep.commit):
        return {"commit": dep.commit}
    if dep.ecosystem == "Maven":
        return {"package": {"ecosystem": "Maven", "name": dep.name}, "version": dep.version}
    if (dep.ecosystem == "Pub" and not dep.source.startswith(("path:", "sdk:"))
            and urlsplit(dep.source).hostname in {"pub.dev", "pub.dartlang.org"}):
        return {"package": {"ecosystem": "Pub", "name": dep.name}, "version": dep.version}
    return None


def severity(record):
    if record["id"].startswith("MAL-"):
        return "critical"
    value = str(record.get("database_specific", {}).get("severity", "")).lower()
    value = {"moderate": "medium"}.get(value, value)
    # Unknown CVSS vector is preserved in evidence, conservatively blocks at high.
    return value if value in LEVELS else "high"


def online(scan, fetch=request_json):
    queries = {}
    for dep in scan.dependencies:
        if dep.source.startswith("sdk:"):
            continue
        query = query_for(dep)
        if query is None:
            scan.gap(f"无 OSV 可用坐标/commit：{dep.key}；请使用组织情报并人工审核", dep.file)
            continue
        queries.setdefault(json.dumps(query, sort_keys=True), []).append(dep)
    checked = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(osv_query, json.loads(q), fetch): deps for q, deps in queries.items()}
        for future in as_completed(futures):
            deps = futures[future]
            try:
                records = future.result()
                checked += len(deps)
                for dep in deps:
                    for record in records:
                        scan.add("KNOWN_VULNERABILITY", severity(record), record.get("summary", record["id"]),
                                 dep.file, dep.key, advisory=record["id"],
                                 url="https://osv.dev/vulnerability/" + quote(record["id"], safe=""),
                                 severity_evidence=record.get("severity", []),
                                 severity_policy="缺少可识别文本级别时按 high 阻断",
                                 affected=record.get("affected", []))
            except (OSError, ValueError, TypeError, KeyError) as exc:
                for dep in deps:
                    scan.gap(f"OSV 查询失败 {dep.key}: {type(exc).__name__}", dep.file)
    scan.coverage["osv"] = {"status": "queried", "checked_dependencies": checked,
                            "unique_queries": len(queries)}


def pub_hashes(scan, fetch=request_json):
    # Query only the fixed official host; never request a URL supplied by a lockfile.
    for dep in scan.dependencies:
        if dep.ecosystem != "Pub" or not dep.checksum:
            continue
        if urlsplit(dep.source).hostname not in {"pub.dev", "pub.dartlang.org"}:
            scan.gap(f"私有 Pub 来源未进行官方哈希对照: {dep.key}", dep.file)
            continue
        try:
            doc = fetch(f"https://pub.dev/api/packages/{quote(dep.name, safe='')}/versions/{quote(dep.version, safe='')}")
            actual = doc.get("archive_sha256", "")
            if not isinstance(actual, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", actual):
                raise ValueError("API 未返回有效 archive_sha256")
            if actual.lower() != dep.checksum.lower():
                scan.add("PUB_HASH_MISMATCH", "critical", "锁文件 SHA-256 与 pub.dev 元数据不一致", dep.file, dep.key)
        except (OSError, ValueError, TypeError) as exc:
            scan.gap(f"Pub 官方哈希对照失败 {dep.key}: {type(exc).__name__}", dep.file)


def local_advisories(scan, path):
    doc = mapping(json.loads(read_text(path)))
    if doc.get("schema") != 1 or not isinstance(doc.get("advisories"), list):
        raise ValueError("情报文件必须包含 schema: 1 和 advisories 数组")
    for entry in doc["advisories"]:
        mapping(entry)
        if not all(isinstance(entry.get(k), str) for k in ("id", "ecosystem", "name", "reason")):
            raise ValueError("情报项缺少 id/ecosystem/name/reason")
        if not isinstance(entry.get("versions"), list) or not all(isinstance(v, str) for v in entry["versions"]):
            raise ValueError("情报项 versions 必须为精确版本字符串数组")
        if entry.get("severity") not in LEVELS:
            raise ValueError("情报项 severity 无效")
        for dep in scan.dependencies:
            if dep.ecosystem == entry["ecosystem"] and dep.name == entry["name"] and dep.version in entry["versions"]:
                scan.add("LOCAL_ADVISORY", entry["severity"], entry["reason"], dep.file, dep.key,
                         advisory=entry["id"])
    scan.coverage["local_advisories"] = {"records": len(doc["advisories"]), "scope": "exact versions only"}
