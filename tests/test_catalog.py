"""Offline catalogue validation with owned temporary metadata copies."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from tools.validate_catalog import CatalogError, validate

SOURCE = Path(__file__).resolve().parents[1]
INPUTS = (
    "catalog.json", "entries/melatonin-access.json",
    "recipes/melatonin-access/windows-steam.json",
    "schemas/catalog.schema.json", "schemas/entry.schema.json", "schemas/recipe.schema.json",
)

class CatalogueTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")
        if not scratch:
            raise RuntimeError("Set TMPDIR or RUNNER_TEMP to an owned scratch directory")
        self.temporary = tempfile.TemporaryDirectory(prefix="peachy-catalog-test-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in INPUTS:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, target)

    def read(self, name):
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")

    def bind_entry(self):
        catalog = self.read("catalog.json")
        catalog["entries"][0]["sha256"] = hashlib.sha256((self.root / catalog["entries"][0]["path"]).read_bytes()).hexdigest()
        self.write("catalog.json", catalog)

    def bind_recipe(self):
        entry = self.read("entries/melatonin-access.json")
        entry["recipe"]["sha256"] = hashlib.sha256((self.root / entry["recipe"]["path"]).read_bytes()).hexdigest()
        self.write("entries/melatonin-access.json", entry)
        self.bind_entry()

    def test_current_real_entry_is_valid_but_not_installable(self):
        result = validate(self.root)
        self.assertEqual(result["entries"], 1)

    def test_changed_entry_bytes_refuse_stale_hash(self):
        path = self.root / "entries/melatonin-access.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(CatalogError, "hash"):
            validate(self.root)

    def test_parent_traversal_is_refused(self):
        data = self.read("catalog.json")
        data["entries"][0]["path"] = "entries/../entries/melatonin-access.json"
        self.write("catalog.json", data)
        with self.assertRaisesRegex(CatalogError, "path"):
            validate(self.root)

    def test_duplicate_entry_ids_are_refused(self):
        data = self.read("catalog.json")
        data["entries"].append(data["entries"][0].copy())
        self.write("catalog.json", data)
        with self.assertRaisesRegex(CatalogError, "Duplicate"):
            validate(self.root)

    def test_unknown_schema_version_is_refused(self):
        data = self.read("catalog.json")
        data["schemaVersion"] = 2
        self.write("catalog.json", data)
        with self.assertRaises(CatalogError):
            validate(self.root)

    def test_recipe_identity_must_match_entry(self):
        name = "recipes/melatonin-access/windows-steam.json"
        data = self.read(name)
        data["gameId"] = "another-game"
        self.write(name, data)
        self.bind_recipe()
        with self.assertRaisesRegex(CatalogError, "identity"):
            validate(self.root)

    def test_download_url_cannot_select_another_repository(self):
        name = "entries/melatonin-access.json"
        data = self.read(name)
        data["releaseSource"]["legacyRelease"]["downloadUrl"] = "https://github.com/other/repository/releases/download/v1.4/MelatoninAccess-v1.4.zip"
        self.write(name, data)
        self.bind_entry()
        with self.assertRaisesRegex(CatalogError, "URL"):
            validate(self.root)

    def test_duplicate_json_keys_are_refused(self):
        path = self.root / "catalog.json"
        value = path.read_text(encoding="utf-8").replace('"revision": 1', '"revision": 2, "revision": 1')
        path.write_text(value, encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(CatalogError, "Duplicate JSON"):
            validate(self.root)

    def test_pending_entry_cannot_advertise_install(self):
        name = "entries/melatonin-access.json"
        data = self.read(name)
        data["actions"].append({"type": "install"})
        self.write(name, data)
        self.bind_entry()
        with self.assertRaisesRegex(CatalogError, "unverified"):
            validate(self.root)

    def test_unknown_command_field_is_refused(self):
        name = "entries/melatonin-access.json"
        data = self.read(name)
        data["command"] = "untrusted-command"
        self.write(name, data)
        self.bind_entry()
        with self.assertRaises(CatalogError):
            validate(self.root)

    def test_expired_snapshot_is_refused(self):
        data = self.read("catalog.json")
        data["generatedAt"] = "2020-01-01T00:00:00Z"
        data["expiresAt"] = "2020-02-01T00:00:00Z"
        self.write("catalog.json", data)
        with self.assertRaisesRegex(CatalogError, "expired"):
            validate(self.root)

    def test_target_file_paths_cannot_traverse(self):
        name = "recipes/melatonin-access/windows-steam.json"
        data = self.read(name)
        data["installedProbe"]["path"] = "../unrelated.dll"
        self.write(name, data)
        self.bind_recipe()
        with self.assertRaisesRegex(CatalogError, "path"):
            validate(self.root)

    def test_external_dynamic_schema_reference_is_refused_offline(self):
        name = "schemas/entry.schema.json"
        data = self.read(name)
        data["$dynamicRef"] = "https://example.invalid/remote-schema.json"
        self.write(name, data)
        with self.assertRaisesRegex(CatalogError, "external"):
            validate(self.root)

    def test_invalid_schema_has_a_readable_validation_error(self):
        name = "schemas/entry.schema.json"
        data = self.read(name)
        data["type"] = "not-a-json-type"
        self.write(name, data)
        with self.assertRaisesRegex(CatalogError, "Invalid schema"):
            validate(self.root)

if __name__ == "__main__":
    unittest.main()
