"""Offline catalogue validation with owned temporary metadata copies."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from tools.build_catalog import build
from tools.validate_catalog import CatalogError, validate

SOURCE = Path(__file__).resolve().parents[1]

class CatalogueTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")
        if not scratch:
            raise RuntimeError("Set TMPDIR or RUNNER_TEMP to an owned scratch directory")
        self.temporary = tempfile.TemporaryDirectory(prefix="peachy-catalog-test-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "snapshot"
        build(SOURCE, self.root)

    def read(self, name):
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")

    def bind_entry(self, entry_id="melatonin-access"):
        catalog = self.read("catalog.json")
        reference = next(item for item in catalog["entries"] if item["id"] == entry_id)
        reference["sha256"] = hashlib.sha256((self.root / reference["path"]).read_bytes()).hexdigest()
        self.write("catalog.json", catalog)

    def bind_recipe(self):
        entry = self.read("entries/melatonin-access.json")
        entry["recipe"]["sha256"] = hashlib.sha256((self.root / entry["recipe"]["path"]).read_bytes()).hexdigest()
        self.write("entries/melatonin-access.json", entry)
        self.bind_entry()

    def test_current_real_entry_is_valid_but_not_installable(self):
        result = validate(self.root)
        self.assertEqual(result["entries"], len(self.read("catalog.json")["entries"]))
        self.assertEqual(result["installable"], 0)
        self.assertFalse(result["signatureVerified"])

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
        revision = self.read("catalog.json")["revision"]
        value = path.read_text(encoding="utf-8").replace(f'"revision": {revision}', f'"revision": {revision}, "revision": {revision}')
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

    def add_workshop(self, entry_id="frozen-cookies", item_id="2816199538"):
        """Declared metadata copies, not fabricated live/provider observations."""
        catalog = self.read("catalog.json")
        if not getattr(self, "workshop_fixture_started", False):
            catalog["entries"] = [item for item in catalog["entries"] if item["id"] == "melatonin-access"]
            self.workshop_fixture_started = True
        url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={item_id}"
        recipe_name = f"recipes/{entry_id}/steam-workshop.json"
        recipe = {"schemaVersion": 1, "id": entry_id + "-steam-workshop", "modId": entry_id,
                  "gameId": "cookie-clicker", "deliveryRoute": "steam-workshop",
                  "workshop": {"appId": "1454400", "itemId": item_id, "url": url},
                  "installedProbe": {"type": "not-implemented"}, "ownership": "external-steam",
                  "capabilities": {"install": False, "update": False, "uninstall": False, "adoption": False}}
        (self.root / recipe_name).parent.mkdir(parents=True, exist_ok=True)
        self.write(recipe_name, recipe)
        entry = {"schemaVersion": 1, "id": entry_id, "gameId": "cookie-clicker", "name": entry_id,
                 "category": "mods", "authors": [{"id": "erbkaiser", "name": "Erbkaiser"}],
                 "description": "Declared Workshop metadata validation fixture.", "upstream": url,
                 "releaseSource": {"provider": "steam-workshop", "appId": "1454400", "itemId": item_id,
                                   "url": url, "version": None},
                 "recipe": {"id": recipe["id"], "path": recipe_name,
                            "sha256": hashlib.sha256((self.root / recipe_name).read_bytes()).hexdigest()},
                 "eligibility": {"state": "pending-verification", "blockers": ["Unsigned snapshot."]},
                 "actions": [{"type": "open-steam-workshop"}]}
        name = f"entries/{entry_id}.json"
        self.write(name, entry)
        catalog["entries"].append({"id": entry_id, "path": name,
                                   "sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest()})
        self.write("catalog.json", catalog)
        return name

    def test_workshop_route_is_valid_without_a_github_zip_or_loader(self):
        self.add_workshop()
        result = validate(self.root)
        self.assertEqual(result["workshopEntries"], 1)
        self.assertEqual(result["installable"], 0)

    def test_workshop_url_must_match_its_item(self):
        name = self.add_workshop()
        entry = self.read(name)
        entry["releaseSource"]["url"] += "&id=3792850996"
        self.write(name, entry)
        self.bind_entry("frozen-cookies")
        with self.assertRaisesRegex(CatalogError, "Workshop URL"):
            validate(self.root)

    def test_github_version_cannot_be_assigned_to_workshop(self):
        name = self.add_workshop()
        entry = self.read(name)
        entry["releaseSource"]["version"] = "15.0"
        self.write(name, entry)
        self.bind_entry("frozen-cookies")
        with self.assertRaises(CatalogError):
            validate(self.root)

    def test_workshop_cannot_advertise_managed_update(self):
        name = self.add_workshop()
        entry = self.read(name)
        entry["actions"].append({"type": "update"})
        self.write(name, entry)
        self.bind_entry("frozen-cookies")
        with self.assertRaisesRegex(CatalogError, "unverified"):
            validate(self.root)

    def test_workshop_recipe_must_match_source_identity(self):
        name = self.add_workshop()
        entry = self.read(name)
        recipe_name = entry["recipe"]["path"]
        recipe = self.read(recipe_name)
        recipe["workshop"]["itemId"] = "3792850996"
        self.write(recipe_name, recipe)
        entry["recipe"]["sha256"] = hashlib.sha256((self.root / recipe_name).read_bytes()).hexdigest()
        self.write(name, entry)
        self.bind_entry("frozen-cookies")
        with self.assertRaisesRegex(CatalogError, "Workshop.*identity"):
            validate(self.root)

    def test_duplicate_workshop_items_are_refused(self):
        self.add_workshop()
        self.add_workshop("other-frozen-cookies", "2816199538")
        with self.assertRaisesRegex(CatalogError, "Duplicate Workshop"):
            validate(self.root)

    def test_optional_recommendations_can_reference_same_game_entries(self):
        first = self.add_workshop()
        self.add_workshop("grandpas-greenhouse", "3792850996")
        entry = self.read(first)
        entry["recommendations"] = [{"entryId": "grandpas-greenhouse", "optional": True,
                                      "reason": "Optional companion."}]
        self.write(first, entry)
        self.bind_entry("frozen-cookies")
        self.assertEqual(validate(self.root)["workshopEntries"], 2)

    def test_missing_recommendation_target_is_refused(self):
        name = self.add_workshop()
        entry = self.read(name)
        entry["recommendations"] = [{"entryId": "missing-entry", "optional": True, "reason": "Optional."}]
        self.write(name, entry)
        self.bind_entry("frozen-cookies")
        with self.assertRaisesRegex(CatalogError, "recommendation"):
            validate(self.root)

    def test_cross_game_recommendation_is_refused(self):
        self.add_workshop()
        entry = self.read("entries/melatonin-access.json")
        entry["recommendations"] = [{"entryId": "frozen-cookies", "optional": True, "reason": "Optional."}]
        self.write("entries/melatonin-access.json", entry)
        self.bind_entry()
        with self.assertRaisesRegex(CatalogError, "recommendation"):
            validate(self.root)

    def bind_manifest(self):
        entry = self.read("entries/melatonin-access.json")
        manifest = entry["releaseSource"]["manifest"]
        manifest["sha256"] = hashlib.sha256((self.root / manifest["path"]).read_bytes()).hexdigest()
        self.write("entries/melatonin-access.json", entry)
        self.bind_entry()

    def test_release_manifest_stale_hash_is_refused(self):
        entry = self.read("entries/melatonin-access.json")
        path = self.root / entry["releaseSource"]["manifest"]["path"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(CatalogError, "manifest hash"):
            validate(self.root)

    def test_release_manifest_cannot_select_another_mod(self):
        entry = self.read("entries/melatonin-access.json")
        name = entry["releaseSource"]["manifest"]["path"]
        manifest = self.read(name)
        manifest["modId"] = "another-mod"
        self.write(name, manifest)
        self.bind_manifest()
        with self.assertRaisesRegex(CatalogError, "manifest identity"):
            validate(self.root)

    def test_release_manifest_cannot_select_another_asset(self):
        entry = self.read("entries/melatonin-access.json")
        name = entry["releaseSource"]["manifest"]["path"]
        manifest = self.read(name)
        manifest["artifacts"][0]["asset"]["id"] += 1
        self.write(name, manifest)
        self.bind_manifest()
        with self.assertRaisesRegex(CatalogError, "manifest asset"):
            validate(self.root)

    def test_release_manifest_must_contain_required_recipe_paths(self):
        name = "recipes/melatonin-access/windows-steam.json"
        recipe = self.read(name)
        recipe["packageLayout"]["requiredPaths"].append("Mods/absent.dll")
        self.write(name, recipe)
        self.bind_recipe()
        with self.assertRaisesRegex(CatalogError, "required recipe path"):
            validate(self.root)

    def test_archive_verification_claim_requires_bound_manifest(self):
        name = "entries/melatonin-access.json"
        entry = self.read(name)
        del entry["releaseSource"]["manifest"]
        self.write(name, entry)
        self.bind_entry()
        with self.assertRaisesRegex(CatalogError, "require a bound release manifest"):
            validate(self.root)

if __name__ == "__main__":
    unittest.main()
