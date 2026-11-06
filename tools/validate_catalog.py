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


def validators(root):
    result = {}
    for name in ("catalog", "entry", "recipe"):
        relative = f"schemas/{name}.schema.json"
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


def validate(root):
    root = Path(root).absolute()
    for ancestor in reversed((root, *root.parents)):
        reject_redirect(ancestor)
    checks = validators(root)
    data = parse(read_bytes(root, "catalog.json"), "catalog.json")
    check_schema(checks["catalog"], data, "catalog.json")
    generated = datetime.fromisoformat(data["generatedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
    if generated >= expires:
        raise CatalogError("Catalogue expiry must follow generation")
    if expires <= datetime.now(timezone.utc):
        raise CatalogError("Catalogue snapshot expired")
    ids, paths, recipes = set(), set(), set()
    for reference in data["entries"]:
        if reference["id"] in ids or reference["path"].casefold() in paths:
            raise CatalogError("Duplicate catalogue entry identity or path")
        ids.add(reference["id"])
        paths.add(reference["path"].casefold())
        entry = bound_document(root, reference, "entries", checks["entry"])
        source = entry["releaseSource"]
        if entry["upstream"] != f"https://github.com/{source['repository']}":
            raise CatalogError("Upstream URL does not match the release repository")
        release = source["legacyRelease"]
        if len(safe_parts(release["assetName"])) != 1 or not release["assetName"].endswith(".zip"):
            raise CatalogError("Legacy asset name must identify one ZIP file")
        expected = f"https://github.com/{source['repository']}/releases/download/{release['releaseTag']}/{release['assetName']}"
        if release["downloadUrl"] != expected:
            raise CatalogError("Legacy asset URL does not match its repository, tag and filename")
        if any(action["type"] in MUTATING_ACTIONS for action in entry["actions"]):
            raise CatalogError("An unverified or withdrawn entry cannot advertise installation, update or uninstall")
        author_ids = [author["id"] for author in entry["authors"]]
        if len(set(author_ids)) != len(author_ids):
            raise CatalogError("Duplicate author identity")
        recipe_ref = entry["recipe"]
        if recipe_ref["id"] in recipes or recipe_ref["path"].casefold() in paths:
            raise CatalogError("Duplicate recipe identity or path")
        recipes.add(recipe_ref["id"])
        paths.add(recipe_ref["path"].casefold())
        recipe = bound_document(root, recipe_ref, "recipes", checks["recipe"])
        if recipe["modId"] != entry["id"] or recipe["gameId"] != entry["gameId"]:
            raise CatalogError("Recipe mod/game identity does not match the entry")
        declared = [recipe["discovery"]["executable"], recipe["installedProbe"]["path"], recipe["filePolicy"]["configurationPath"]]
        declared.extend(probe["path"] for probe in recipe["installedProbe"]["support"])
        declared.extend(recipe["packageLayout"]["requiredPaths"])
        for relative in declared:
            safe_parts(relative)
        required_paths = recipe["packageLayout"]["requiredPaths"]
        if len({path.casefold() for path in required_paths}) != len(required_paths):
            raise CatalogError("Duplicate package destination path")
    return {"entries": len(ids), "recipes": len(recipes), "installable": 0,
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
