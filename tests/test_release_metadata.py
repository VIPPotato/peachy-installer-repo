"""Metadata-only checks with synthetic ZIPs; no game, network or executed DLLs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from tools.release_metadata import ReleaseError, check_archive, check_document, encode_document, generate, inspect_archive
from tools.validate_catalog import CatalogError, check_schema, validators

SOURCE = Path(__file__).resolve().parents[1]

class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")
        if not scratch:
            raise RuntimeError("Set owned scratch for metadata tests")
        self.temp = tempfile.TemporaryDirectory(prefix="peachy-release-test-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / "Fixture.zip"
        self.write_zip([("Mods/Fixture.dll", b"synthetic data, not a DLL"), ("UserData/Loader.cfg", b"fixture defaults")])
        self.release = {"id": 17, "tag_name": "v1.4", "draft": False, "prerelease": False,
                        "html_url": "https://github.com/example/fixture/releases/tag/v1.4", "assets": []}
        self.refresh_asset()

    def write_zip(self, members):
        with zipfile.ZipFile(self.archive, "w") as archive:
            for name, value in members:
                archive.writestr(name, value)

    def refresh_asset(self):
        raw = self.archive.read_bytes()
        self.release["assets"] = [{"id": 23, "name": "Fixture.zip", "size": len(raw),
                                  "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                                  "browser_download_url": "https://github.com/example/fixture/releases/download/v1.4/Fixture.zip"}]

    def manifest(self):
        return generate(self.release, "example/fixture", "a" * 40, "fixture", 23, self.archive)

    def test_generate_and_check_exact_archive_members(self):
        document = self.manifest()
        check_schema(validators(SOURCE)["version"], document, "version.json")
        self.assertEqual(len(check_archive(document, self.archive)["files"]), 2)
        self.assertEqual(document["artifacts"][0]["requirements"]["loader"]["qualification"], "pending")

    def test_wrong_provider_digest_refuses_generation(self):
        self.release["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ReleaseError, "identity"):
            self.manifest()

    def test_asset_url_cannot_switch_repository(self):
        self.release["assets"][0]["browser_download_url"] = "https://github.com/other/repository/releases/download/v1.4/Fixture.zip"
        with self.assertRaisesRegex(ReleaseError, "URL"):
            self.manifest()

    def test_release_source_cannot_switch_repository(self):
        self.release["html_url"] = "https://github.com/other/repository/releases/tag/v1.4"
        with self.assertRaisesRegex(ReleaseError, "selected repository"):
            self.manifest()

    def test_draft_release_is_not_stable(self):
        self.release["draft"] = True
        with self.assertRaisesRegex(ReleaseError, "published stable"):
            self.manifest()

    def test_traversal_member_refused_before_member_reads(self):
        self.write_zip([("../escape.dll", b"no")])
        with self.assertRaisesRegex(ReleaseError, "path"):
            inspect_archive(self.archive)

    def test_case_colliding_members_refused(self):
        self.write_zip([("Mods/Fixture.dll", b"one"), ("mods/fixture.dll", b"two")])
        with self.assertRaisesRegex(ReleaseError, "Duplicate"):
            inspect_archive(self.archive)

    def test_symlink_member_refused(self):
        member = zipfile.ZipInfo("Mods/Fixture.dll")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_zip([(member, b"elsewhere")])
        with self.assertRaisesRegex(ReleaseError, "redirected"):
            inspect_archive(self.archive)

    def test_file_directory_collision_refused(self):
        self.write_zip([("Mods", b"file"), ("Mods/Fixture.dll", b"nested")])
        with self.assertRaisesRegex(ReleaseError, "collision"):
            inspect_archive(self.archive)

    def test_changed_archive_member_hash_is_not_accepted(self):
        document = self.manifest()
        document["artifacts"][0]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReleaseError, "members"):
            check_archive(document, self.archive)

    def test_duplicate_manifest_members_refused(self):
        document = self.manifest()
        document["artifacts"][0]["files"].append(copy.deepcopy(document["artifacts"][0]["files"][0]))
        with self.assertRaisesRegex(ReleaseError, "Duplicate"):
            check_document(document)

    def test_tag_and_version_are_bound(self):
        document = self.manifest()
        document["version"] = "1.5"
        with self.assertRaisesRegex(ReleaseError, "tag and version"):
            check_document(document)

    def test_unqualified_loader_cannot_be_claimed_verified(self):
        document = self.manifest()
        document["artifacts"][0]["requirements"]["loader"]["qualification"] = "verified"
        with self.assertRaises(CatalogError):
            check_schema(validators(SOURCE)["version"], document, "version.json")

    def test_metadata_cannot_contain_commands(self):
        document = self.manifest()
        document["command"] = "must not execute"
        with self.assertRaises(CatalogError):
            check_schema(validators(SOURCE)["version"], document, "version.json")

    def test_member_crc_failure_is_reported(self):
        raw = self.archive.read_bytes().replace(b"synthetic data, not a DLL", b"damaged__ data, not a DLL")
        self.archive.write_bytes(raw)
        with self.assertRaisesRegex(ReleaseError, "Unreadable archive"):
            inspect_archive(self.archive)

    def test_generated_json_cannot_exceed_its_reader_limit(self):
        with self.assertRaisesRegex(ReleaseError, "reader.*size limit"):
            encode_document(self.manifest(), 64)

if __name__ == "__main__":
    unittest.main()
