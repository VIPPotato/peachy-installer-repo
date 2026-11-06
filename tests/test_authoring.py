"""Single-file authoring and generated snapshots, using owned metadata copies only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.validate_catalog import CatalogError, validate

SOURCE = Path(__file__).resolve().parents[1]


class AuthoringTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")
        if not scratch:
            raise RuntimeError("Set TMPDIR or RUNNER_TEMP to owned scratch")
        self.temp = tempfile.TemporaryDirectory(prefix="peachy-authoring-test-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        shutil.copyfile(SOURCE / "catalogue.json", self.root / "catalogue.json")
        shutil.copytree(SOURCE / "mods", self.root / "mods")
        shutil.copytree(SOURCE / "tools/schemas", self.root / "tools/schemas")
        self.output = Path(self.temp.name) / "output"

    def read(self, relative):
        return json.loads((self.root / relative).read_text(encoding="utf-8"))

    def write(self, relative, document):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")

    def build(self, output=None):
        from tools.build_catalog import build
        return build(self.root, output or self.output)

    def files(self):
        return {str(path.relative_to(self.output)): path.read_bytes()
                for path in self.output.rglob("*") if path.is_file()}

    def add_declared_test_entry(self):
        document = self.read("mods/frozen-cookies/mod.json")
        document["name"] = "Synthetic authoring test copy, not a published mod"
        document["workshop"]["itemId"] = "123"
        self.write("mods/declared-test-copy/mod.json", document)

    def test_source_checkout_validates_without_prebuilt_snapshot(self):
        result = subprocess.run([sys.executable, str(SOURCE / "tools/validate_catalog.py"),
                                 "--root", str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["entries"], 4)
        self.assertFalse((self.root / "catalog.json").exists())
        self.assertFalse(self.output.exists())

    def test_build_preserves_client_contract_and_exact_melatonin_recipe(self):
        result = self.build()
        self.assertEqual(result["entries"], 4)
        self.assertEqual(result["workshopEntries"], 3)
        self.assertEqual(result["releaseManifests"], 1)
        self.assertEqual(result["installable"], 0)
        self.assertFalse(result["signatureVerified"])
        self.assertEqual(validate(self.output), result)
        recipe = self.output / "recipes/melatonin-access/windows-steam.json"
        self.assertEqual(hashlib.sha256(recipe.read_bytes()).hexdigest(),
                         "99f2c5b323a050ce968e7738c6b4c78fa7be495ed731ecde71028fd63921dd69")
        entry = json.loads((self.output / "entries/cookie-clicker-access.json").read_text())
        self.assertEqual([(a["id"], a["role"]) for a in entry["authors"]],
                         [("vip-potato", "maintainer"), ("amsel", "upstream-author"),
                          ("fiora-xena", "original-author")])
        self.assertEqual([r["entryId"] for r in entry["recommendations"]],
                         ["frozen-cookies", "grandpas-greenhouse"])
        self.assertTrue(all(r["optional"] for r in entry["recommendations"]))
        self.assertIsNone(entry["releaseSource"]["version"])

    def test_source_validation_api_accepts_authoring_format(self):
        self.assertEqual(validate(self.root)["entries"], 4)
        self.assertFalse(self.output.exists())

    def test_release_cli_accepts_generated_schema_root(self):
        self.build()
        result = subprocess.run([sys.executable, "-m", "tools.release_metadata", "--schema-root", str(self.output),
                                 "validate", "--manifest", str(self.root / "mods/melatonin-access/version.json")],
                                cwd=SOURCE, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["installationQualified"])

    def test_publisher_manifest_is_copied_as_exact_bytes(self):
        self.build()
        source = (self.root / "mods/melatonin-access/version.json").read_bytes()
        target = (self.output / "releases/melatonin-access/v1.4/version.json").read_bytes()
        self.assertEqual(source, target)
        self.assertEqual(hashlib.sha256(target).hexdigest(),
                         "e5c80a96bc48919c6380156a558b26d0dd52585f026a7ae4ab35e1929ecfc7c6")

    def test_identical_sources_produce_identical_bytes(self):
        self.build()
        first = self.files()
        self.build()
        self.assertEqual(first, self.files())

    def test_new_entry_needs_no_index_recipe_or_hash_edits(self):
        self.add_declared_test_entry()
        self.assertEqual(self.build()["entries"], 5)
        entry = json.loads((self.output / "entries/declared-test-copy.json").read_text())
        self.assertEqual(entry["releaseSource"]["url"],
                         "https://steamcommunity.com/sharedfiles/filedetails/?id=123")
        self.assertEqual(entry["recipe"]["id"], "declared-test-copy-steam-workshop")

    def test_rebuild_removes_stale_generated_entries(self):
        self.add_declared_test_entry()
        self.build()
        shutil.rmtree(self.root / "mods/declared-test-copy")
        self.assertEqual(self.build()["entries"], 4)
        self.assertFalse((self.output / "entries/declared-test-copy.json").exists())
        self.assertFalse((self.output / "recipes/declared-test-copy").exists())

    def test_failed_validation_preserves_previous_output(self):
        self.build()
        before = self.files()
        document = self.read("mods/frozen-cookies/mod.json")
        document["workshop"]["itemId"] = "3807399658"
        self.write("mods/frozen-cookies/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "Duplicate Workshop"):
            self.build()
        self.assertEqual(before, self.files())

    def test_missing_recommendation_target_is_refused(self):
        document = self.read("mods/cookie-clicker-access/mod.json")
        document["recommendations"][0]["entryId"] = "missing-entry"
        self.write("mods/cookie-clicker-access/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "recommendation"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_unknown_source_fields_are_not_silently_discarded(self):
        document = self.read("mods/frozen-cookies/mod.json")
        document["command"] = "must not execute"
        self.write("mods/frozen-cookies/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "command"):
            self.build()

    def test_unknown_workshop_fields_are_refused(self):
        document = self.read("mods/frozen-cookies/mod.json")
        document["workshop"]["version"] = "15.0"
        self.write("mods/frozen-cookies/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "version"):
            self.build()

    def test_route_must_be_unambiguous(self):
        document = self.read("mods/frozen-cookies/mod.json")
        document["archive"] = self.read("mods/melatonin-access/mod.json")["archive"]
        self.write("mods/frozen-cookies/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "exactly one"):
            self.build()

    def test_archive_repository_must_match_publisher_manifest(self):
        document = self.read("mods/melatonin-access/mod.json")
        document["repository"] = "other/repository"
        self.write("mods/melatonin-access/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "repository"):
            self.build()

    def test_unsupported_archive_profile_is_refused(self):
        document = self.read("mods/melatonin-access/mod.json")
        document["archive"]["profile"] = "windows-x64-melonloader"
        self.write("mods/melatonin-access/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "profile"):
            self.build()

    def test_traversing_probe_path_is_refused(self):
        document = self.read("mods/melatonin-access/mod.json")
        document["archive"]["probe"]["path"] = "../unrelated.dll"
        self.write("mods/melatonin-access/mod.json", document)
        with self.assertRaisesRegex(CatalogError, "path"):
            self.build()

    def test_publisher_manifest_does_not_claim_fresh_archive_check(self):
        document = self.read("mods/melatonin-access/mod.json")
        document["archive"]["verification"] = "provider-metadata-only"
        self.write("mods/melatonin-access/mod.json", document)
        self.assertFalse(self.build()["packageBytesVerified"])
        recipe = json.loads((self.output / "recipes/melatonin-access/windows-steam.json").read_text())
        self.assertEqual(recipe["packageLayout"]["verification"], "upstream-declarations-only")

    def test_hard_linked_source_is_refused(self):
        source = self.root / "mods/frozen-cookies/mod.json"
        link = self.root / "linked-source.json"
        os.link(source, link)
        with self.assertRaisesRegex(CatalogError, "Hard-linked"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_duplicate_json_keys_are_refused(self):
        path = self.root / "mods/frozen-cookies/mod.json"
        path.write_text(path.read_text().replace('"name":', '"name": "duplicate", "name":', 1),
                        encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "Duplicate JSON"):
            self.build()

    def test_expired_source_metadata_is_not_refreshed_implicitly(self):
        document = self.read("catalogue.json")
        document.update(generatedAt="2020-01-01T00:00:00Z", expiresAt="2020-02-01T00:00:00Z")
        self.write("catalogue.json", document)
        with self.assertRaisesRegex(CatalogError, "expired"):
            self.build()

    def test_malformed_mod_folder_is_not_silently_ignored(self):
        (self.root / "mods/Unexpected Folder").mkdir()
        with self.assertRaisesRegex(CatalogError, "folder"):
            self.build()

    def test_catalogue_typo_is_refused(self):
        document = self.read("catalogue.json")
        document["entrys"] = []
        self.write("catalogue.json", document)
        with self.assertRaisesRegex(CatalogError, "entrys"):
            self.build()

    def test_edited_generated_file_is_not_overwritten(self):
        self.build()
        path = self.output / "entries/frozen-cookies.json"
        path.write_bytes(path.read_bytes() + b" ")
        before = self.files()
        with self.assertRaisesRegex(CatalogError, "changed|edited"):
            self.build()
        self.assertEqual(before, self.files())

    def test_unexpected_output_file_is_not_deleted(self):
        self.build()
        path = self.output / "keep.txt"
        path.write_bytes(b"not generated by Peachy")
        before = self.files()
        with self.assertRaisesRegex(CatalogError, "unexpected|unowned"):
            self.build()
        self.assertEqual(before, self.files())

    def test_output_cannot_replace_source_or_its_descendants(self):
        with self.assertRaisesRegex(CatalogError, "output|Output"):
            self.build(self.root / "mods/new-output")
        self.assertTrue((self.root / "mods/frozen-cookies/mod.json").is_file())

    def test_existing_unmarked_output_is_not_claimed(self):
        self.output.mkdir()
        (self.output / "notes.txt").write_text("not generated")
        with self.assertRaisesRegex(CatalogError, "unowned|generated"):
            self.build()
        self.assertEqual((self.output / "notes.txt").read_text(), "not generated")

    def test_withdrawn_entry_stays_unavailable(self):
        document = self.read("mods/frozen-cookies/mod.json")
        document["withdrawn"] = True
        document["blockers"] = ["Withdrawn authoring test."]
        self.write("mods/frozen-cookies/mod.json", document)
        self.build()
        entry = json.loads((self.output / "entries/frozen-cookies.json").read_text())
        self.assertEqual(entry["eligibility"]["state"], "withdrawn")
        self.assertIn("Withdrawn authoring test.", entry["eligibility"]["blockers"])
        self.assertEqual(entry["actions"], [])


if __name__ == "__main__":
    unittest.main()
