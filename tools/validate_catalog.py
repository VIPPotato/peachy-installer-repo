"""Check catalogue structure and references offline, without installing payloads."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

MAX_JSON_BYTES = 262144
MUTATING_ACTIONS = {"install", "update", "uninstall"}
RESERVED = {"con", "prn", "aux", "nul", "clock$"}
RESERVED.update(f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10))


class CatalogError(ValueError):
    pass


def safe_parts(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
        raise CatalogError(f"Unsupported relative path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") or part.endswith(".") or part.split(".")[0].lower() in RESERVED for part in parts):
        raise CatalogError(f"Unsafe relative path: {value!r}")
    return parts


def reject_redirect(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise CatalogError(f"Redirected catalogue path: {path}")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise CatalogError(f"Hard-linked catalogue path: {path}")
    return info


def read_bytes(root, relative):
    path = root
    for part in safe_parts(relative):
        path = path / part
        reject_redirect(path)
    before = reject_redirect(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_JSON_BYTES:
        raise CatalogError(f"Catalogue JSON is not a bounded regular file: {relative}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    after = reject_redirect(path)
    if len(raw) > MAX_JSON_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise CatalogError(f"Catalogue file changed or exceeded its limit: {relative}")
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise CatalogError(f"Unsupported JSON constant: {value}")


def parse(raw, label):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CatalogError(f"Invalid JSON in {label}: {error}") from error


def reject_external_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ("$ref", "$dynamicRef", "$recursiveRef") and (not isinstance(child, str) or not child.startswith("#/")):
                raise CatalogError("Schemas must not resolve external references")
            reject_external_refs(child)
    elif isinstance(value, list):
        for child in value:
            reject_external_refs(child)


def validators(root, directory=None):
    if directory is None:
        directory = "tools/schemas" if (root / "tools/schemas").is_dir() else "schemas"
    result = {}
    for name in ("catalog", "entry", "recipe", "workshop-recipe", "version"):
        relative = f"{directory}/{name}.schema.json"
        schema = parse(read_bytes(root, relative), relative)
        reject_external_refs(schema)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            raise CatalogError(f"Invalid schema in {relative}: {error.message}") from error
        result[name] = Draft202012Validator(schema, format_checker=FormatChecker())
    return result


def check_schema(validator, data, label):
    errors = list(validator.iter_errors(data))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "root"
        raise CatalogError(f"{label}/{location}: {first.message}")


def bound_document(root, reference, directory, validator):
    if not reference["path"].startswith(directory + "/"):
        raise CatalogError(f"Reference path must be inside {directory}/")
    raw = read_bytes(root, reference["path"])
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise CatalogError(f"Reference hash mismatch: {reference['path']}")
    data = parse(raw, reference["path"])
    check_schema(validator, data, reference["path"])
    if data["id"] != reference["id"]:
        raise CatalogError(f"Reference identity mismatch: {reference['path']}")
    return data


def release_document(root, entry, recipe, checks):
    source = entry["releaseSource"]
    reference = source.get("manifest")
    if not reference:
        if source["legacyRelease"]["verification"] != "provider-metadata-only":
            raise CatalogError("Verified archive records require a bound release manifest")
        return False
    if not reference["path"].startswith("releases/"):
        raise CatalogError("Release manifest path must be inside releases/")
    raw = read_bytes(root, reference["path"])
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise CatalogError("Release manifest hash mismatch")
    document = parse(raw, reference["path"])
    check_schema(checks["version"], document, reference["path"])
    if __package__:
        from .release_metadata import ReleaseError, check_document
    else:
        from release_metadata import ReleaseError, check_document
    try:
        check_document(document)
    except ReleaseError as error:
        raise CatalogError(str(error)) from error
    release, legacy = document["release"], source["legacyRelease"]
    if (document["modId"] != entry["id"] or release["repository"] != source["repository"]
            or release["id"] != legacy["releaseId"] or release["tag"] != legacy["releaseTag"]):
        raise CatalogError("Release manifest identity does not match the catalogue entry")
    expected_url = f"https://github.com/{source['repository']}/releases/download/{release['tag']}/version.json"
    if reference["downloadUrl"] != expected_url:
        raise CatalogError("Release manifest URL does not match the selected release")
    artifact = document["artifacts"][0]
    asset = artifact["asset"]
    if any(asset[left] != legacy[right] for left, right in
           (("id", "assetId"), ("name", "assetName"), ("size", "size"), ("sha256", "sha256"), ("url", "downloadUrl"))):
        raise CatalogError("Release manifest asset does not match the selected ZIP")
    if (artifact["os"] != recipe["platform"]["os"]
            or artifact["gameArchitecture"] != recipe["platform"]["gameArchitecture"]):
        raise CatalogError("Release manifest platform does not match the recipe")
    files = {item["path"] for item in artifact["files"]}
    if any(path not in files for path in recipe["packageLayout"]["requiredPaths"]):
        raise CatalogError("Release manifest is missing a required recipe path")
    return True


def validate(root):
    root = Path(root).absolute()
    for ancestor in reversed((root, *root.parents)):
        reject_redirect(ancestor)
    if (root / "catalogue.json").exists():
        if __package__:
            from .build_catalog import build
        else:
            from build_catalog import build
        return build(root)
    checks = validators(root, "schemas")
    data = parse(read_bytes(root, "catalog.json"), "catalog.json")
    check_schema(checks["catalog"], data, "catalog.json")
    generated = datetime.fromisoformat(data["generatedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
    if generated >= expires:
        raise CatalogError("Catalogue expiry must follow generation")
    if expires <= datetime.now(timezone.utc):
        raise CatalogError("Catalogue snapshot expired")
    ids, paths, recipes = set(), set(), set()
    entries, workshop_items, game_apps = {}, set(), {}
    workshop_count = manifest_count = 0
    for reference in data["entries"]:
        if reference["id"] in ids or reference["path"].casefold() in paths:
            raise CatalogError("Duplicate catalogue entry identity or path")
        ids.add(reference["id"])
        paths.add(reference["path"].casefold())
        entry = bound_document(root, reference, "entries", checks["entry"])
        entries[entry["id"]] = entry
        source = entry["releaseSource"]
        workshop = source["provider"] == "steam-workshop"
        if any(action["type"] in MUTATING_ACTIONS for action in entry["actions"]):
            raise CatalogError("An unverified or withdrawn entry cannot advertise installation, update or uninstall")
        allowed_actions = {"open-steam-workshop", "open-repository"} if workshop else {"review-installation", "open-repository"}
        if any(action["type"] not in allowed_actions for action in entry["actions"]):
            raise CatalogError("Action is not supported by the declared delivery route")
        github_upstream = re.fullmatch(r"https://github[.]com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", entry["upstream"])
        if any(action["type"] == "open-repository" for action in entry["actions"]) and not github_upstream:
            raise CatalogError("Open repository requires a reviewed GitHub project URL")
        if workshop:
            expected = f"https://steamcommunity.com/sharedfiles/filedetails/?id={source['itemId']}"
            if source["url"] != expected:
                raise CatalogError("Workshop URL does not match its item identity")
            if entry["upstream"] != expected and not github_upstream:
                raise CatalogError("Unsupported Workshop upstream URL")
            if source["itemId"] in workshop_items:
                raise CatalogError("Duplicate Workshop item identity")
            workshop_items.add(source["itemId"])
            workshop_count += 1
        else:
            if entry["upstream"] != f"https://github.com/{source['repository']}":
                raise CatalogError("Upstream URL does not match the release repository")
            release = source["legacyRelease"]
            if len(safe_parts(release["assetName"])) != 1 or not release["assetName"].endswith(".zip"):
                raise CatalogError("Legacy asset name must identify one ZIP file")
            expected = f"https://github.com/{source['repository']}/releases/download/{release['releaseTag']}/{release['assetName']}"
            if release["downloadUrl"] != expected:
                raise CatalogError("Legacy asset URL does not match its repository, tag and filename")
        author_ids = [author["id"] for author in entry["authors"]]
        if len(set(author_ids)) != len(author_ids):
            raise CatalogError("Duplicate author identity")
        recipe_ref = entry["recipe"]
        if recipe_ref["id"] in recipes or recipe_ref["path"].casefold() in paths:
            raise CatalogError("Duplicate recipe identity or path")
        recipes.add(recipe_ref["id"])
        paths.add(recipe_ref["path"].casefold())
        recipe = bound_document(root, recipe_ref, "recipes", checks["workshop-recipe" if workshop else "recipe"])
        if recipe["modId"] != entry["id"] or recipe["gameId"] != entry["gameId"]:
            raise CatalogError("Recipe mod/game identity does not match the entry")
        app_id = source["appId"] if workshop else recipe["discovery"]["appId"]
        if game_apps.setdefault(entry["gameId"], app_id) != app_id:
            raise CatalogError("Conflicting game/Steam identity")
        if workshop:
            if any(recipe["workshop"][key] != source[key] for key in ("appId", "itemId", "url")):
                raise CatalogError("Workshop recipe/source identity mismatch")
            continue
        manifest_count += int(release_document(root, entry, recipe, checks))
        declared = [recipe["discovery"]["executable"], recipe["installedProbe"]["path"], recipe["filePolicy"]["configurationPath"]]
        declared.extend(probe["path"] for probe in recipe["installedProbe"]["support"])
        declared.extend(recipe["packageLayout"]["requiredPaths"])
        for relative in declared:
            safe_parts(relative)
        required_paths = recipe["packageLayout"]["requiredPaths"]
        if len({path.casefold() for path in required_paths}) != len(required_paths):
            raise CatalogError("Duplicate package destination path")
    for entry in entries.values():
        recommended = set()
        for recommendation in entry.get("recommendations", []):
            target = recommendation["entryId"]
            if target == entry["id"] or target in recommended or target not in entries:
                raise CatalogError("Invalid, duplicate or missing recommendation target")
            if entries[target]["gameId"] != entry["gameId"]:
                raise CatalogError("A mod recommendation must refer to the same game")
            recommended.add(target)
    return {"entries": len(ids), "recipes": len(recipes), "installable": 0,
            "workshopEntries": workshop_count, "releaseManifests": manifest_count,
            "signatureVerified": False, "packageBytesVerified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    options = parser.parse_args()
    try:
        print(json.dumps(validate(options.root), sort_keys=True))
    except (CatalogError, OSError, ValueError) as error:
        print(f"Catalogue validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
