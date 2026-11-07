"""Build a client catalogue from one mod.json per mod, without network or payload I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

if __package__:
    from .validate_catalog import MAX_JSON_BYTES, CatalogError, check_schema, parse, read_bytes, reject_redirect, safe_parts, validate, validators
else:
    from validate_catalog import MAX_JSON_BYTES, CatalogError, check_schema, parse, read_bytes, reject_redirect, safe_parts, validate, validators

SCHEMAS = ("catalog", "entry", "recipe", "workshop-recipe", "version")
MARKER = ".peachy-generated.json"
MANAGEMENT = {"install": False, "update": False, "uninstall": False, "adoption": False}
UNSIGNED = "Catalogue authentication does not grant installation, ownership or external-action capability."
WORKSHOP_BLOCKERS = [
    UNSIGNED,
    "Trusted external-action dispatch and Workshop local-installation observation are not implemented. "
    "Subscription, in-game activation and Workshop payload version remain unobserved.",
]
ARCHIVE_BLOCKERS = [
    UNSIGNED,
    "Compatible loader/runtime artifacts and hashes remain unqualified.",
    "Game compatibility and bundled dependency redistribution requirements remain unqualified.",
    "Differing existing-file and configuration policies require a selected production implementation.",
    "Production installation transactions and generic live recipe execution are not implemented.",
]


def fields(document, required, optional, label):
    if not isinstance(document, dict):
        raise CatalogError(f"{label}: expected an object")
    missing = set(required) - document.keys()
    unknown = document.keys() - set(required) - set(optional)
    if missing or unknown:
        raise CatalogError(f"{label}: missing fields {sorted(missing)}, unknown fields {sorted(unknown)}")


def checked_path(path, allow_missing=False):
    path = Path(path).absolute()
    if ".." in path.parts:
        raise CatalogError(f"Parent traversal is not allowed: {path}")
    for ancestor in reversed((path, *path.parents)):
        try:
            reject_redirect(ancestor)
        except FileNotFoundError:
            if not allow_missing:
                raise
    return path


def encode(document):
    raw = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(raw) > MAX_JSON_BYTES:
        raise CatalogError("Generated JSON exceeds the client's size limit")
    return raw


def archive_route(root, mod_id, mod, archive, checks, documents):
    label = f"mods/{mod_id}/mod.json/archive"
    fields(archive, ("profile", "appId", "executable", "probe", "requiredPaths", "configurationPath",
                     "observedAt", "verification"), (), label)
    if archive["profile"] != "windows-x86-melonloader":
        raise CatalogError(f"{label}: unsupported archive profile")
    probe = archive["probe"]
    fields(probe, ("path", "assemblyName", "modName", "gameDeveloper", "gameName"), ("support",), label + "/probe")
    raw = read_bytes(root, f"mods/{mod_id}/version.json")
    manifest = parse(raw, f"mods/{mod_id}/version.json")
    check_schema(checks["version"], manifest, f"mods/{mod_id}/version.json")
    release = manifest["release"]
    if manifest["modId"] != mod_id or release["repository"] != mod.get("repository"):
        raise CatalogError(f"{label}: publisher mod identity or repository does not match")
    asset = manifest["artifacts"][0]["asset"]
    manifest_path = f"releases/{mod_id}/{release['tag']}/version.json"
    safe_parts(manifest_path)
    documents[manifest_path] = raw
    source = {
        "provider": "github", "repository": mod["repository"], "channel": "stable", "metadataAsset": "version.json",
        "legacyRelease": {
            "releaseTag": release["tag"], "releaseId": release["id"], "assetId": asset["id"],
            "assetName": asset["name"], "size": asset["size"], "sha256": asset["sha256"],
            "downloadUrl": asset["url"], "observedAt": archive["observedAt"], "verification": archive["verification"],
        },
        "manifest": {
            "path": manifest_path, "sha256": hashlib.sha256(raw).hexdigest(),
            "downloadUrl": f"https://github.com/{mod['repository']}/releases/download/{release['tag']}/version.json",
        },
    }
    recipe = {
        "schemaVersion": 1, "id": mod_id + "-windows-steam", "modId": mod_id, "gameId": mod["game"],
        "platform": {"os": "windows", "gameArchitecture": "x86", "runtime": "unqualified"},
        "discovery": {
            "provider": "steam", "appId": archive["appId"], "executable": archive["executable"],
            "registeredIdentity": "selected-app-manifest-and-contained-x86-executable",
            "unregisteredIdentity": "identifying-product-metadata-required",
        },
        "installedProbe": {
            "type": "pe-cli-meloninfo", "path": probe["path"], "assemblyName": probe["assemblyName"],
            "modName": probe["modName"], "gameDeveloper": probe["gameDeveloper"], "gameName": probe["gameName"],
            "versionScheme": "numeric-dotted", "support": probe.get("support", []),
        },
        "packageLayout": {
            "verification": "archive-members-verified" if archive["verification"] == "archive-bytes-verified"
                            else "upstream-declarations-only",
            "requiredPaths": archive["requiredPaths"],
        },
        "loader": {"family": "melonloader", "qualification": "pending", "version": None, "artifact": None},
        "filePolicy": {
            "differentExistingFiles": "require-review", "configurationPath": archive["configurationPath"],
            "configurationPolicy": "require-review", "ownership": "receipt-owned-files-only", "unmanagedFiles": "preserve",
        },
        "capabilities": dict(MANAGEMENT),
    }
    return source, recipe, "windows-steam", ARCHIVE_BLOCKERS


def workshop_route(mod_id, mod):
    workshop = mod["workshop"]
    fields(workshop, ("appId", "itemId"), (), f"mods/{mod_id}/mod.json/workshop")
    url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={workshop['itemId']}"
    source = {"provider": "steam-workshop", **workshop, "url": url, "version": None}
    recipe = {
        "schemaVersion": 1, "id": mod_id + "-steam-workshop", "modId": mod_id, "gameId": mod["game"],
        "deliveryRoute": "steam-workshop", "workshop": {**workshop, "url": url},
        "installedProbe": {"type": "not-implemented"}, "ownership": "external-steam", "capabilities": dict(MANAGEMENT),
    }
    return source, recipe, "steam-workshop", WORKSHOP_BLOCKERS


def compile_sources(root):
    root = checked_path(root)
    config = parse(read_bytes(root, "catalogue.json"), "catalogue.json")
    fields(config, ("repository", "revision", "generatedAt", "expiresAt"), (), "catalogue.json")
    checks = validators(root, "tools/schemas")
    documents = {f"schemas/{name}.schema.json": read_bytes(root, f"tools/schemas/{name}.schema.json") for name in SCHEMAS}
    mods = root / "mods"
    reject_redirect(mods)
    folders = []
    with os.scandir(mods) as entries:
        for item in entries:
            info = reject_redirect(Path(item.path))
            if (not stat.S_ISDIR(info.st_mode) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item.name)
                    or len(item.name) > 80):
                raise CatalogError(f"Invalid mod folder: {item.name!r}; expected mods/<slug>/mod.json")
            safe_parts(item.name)
            folders.append(item.name)
            if len(folders) > 128:
                raise CatalogError("Too many mod folders")
    references = []
    for mod_id in sorted(folders):
        label = f"mods/{mod_id}/mod.json"
        mod = parse(read_bytes(root, label), label)
        fields(mod, ("name", "game", "authors", "description"),
               ("repository", "category", "workshop", "archive", "recommendations", "withdrawn", "blockers"), label)
        if ("workshop" in mod) == ("archive" in mod):
            raise CatalogError(f"{label}: specify exactly one of workshop or archive")
        if type(mod.get("withdrawn", False)) is not bool:
            raise CatalogError(f"{label}/withdrawn: expected a boolean")
        if not isinstance(mod.get("blockers", []), list):
            raise CatalogError(f"{label}/blockers: expected an array")
        if "workshop" in mod:
            source, recipe, route, blockers = workshop_route(mod_id, mod)
        else:
            source, recipe, route, blockers = archive_route(root, mod_id, mod, mod["archive"], checks, documents)
        recipe_path = f"recipes/{mod_id}/{route}.json"
        documents[recipe_path] = encode(recipe)
        if "repository" in mod:
            if not isinstance(mod["repository"], str):
                raise CatalogError(f"{label}/repository: expected owner/repo")
            upstream = "https://github.com/" + mod["repository"]
        else:
            upstream = source["url"]
        actions = [] if mod.get("withdrawn", False) else [
            {"type": "open-steam-workshop" if route == "steam-workshop" else "review-installation"}
        ]
        if actions and "repository" in mod:
            actions.append({"type": "open-repository"})
        entry = {
            "schemaVersion": 1, "id": mod_id, "gameId": mod["game"], "name": mod["name"],
            "category": mod.get("category", "mods"), "authors": mod["authors"], "description": mod["description"],
            "upstream": upstream, "releaseSource": source,
            "recipe": {"id": recipe["id"], "path": recipe_path, "sha256": hashlib.sha256(documents[recipe_path]).hexdigest()},
            "eligibility": {"state": "withdrawn" if mod.get("withdrawn", False) else "pending-verification",
                            "blockers": blockers + mod.get("blockers", [])},
            "actions": actions,
        }
        if "recommendations" in mod:
            if not isinstance(mod["recommendations"], list):
                raise CatalogError(f"{label}/recommendations: expected an array")
            entry["recommendations"] = []
            for recommendation in mod["recommendations"]:
                fields(recommendation, ("entryId", "reason"), (), label + "/recommendations")
                entry["recommendations"].append({"entryId": recommendation["entryId"], "optional": True,
                                                 "reason": recommendation["reason"]})
        path = f"entries/{mod_id}.json"
        documents[path] = encode(entry)
        references.append({"id": mod_id, "path": path, "sha256": hashlib.sha256(documents[path]).hexdigest()})
    documents["catalog.json"] = encode({
        "schemaVersion": 1, "id": "peachy-installer", "revision": config["revision"],
        "generatedAt": config["generatedAt"], "expiresAt": config["expiresAt"],
        "origin": {"provider": "github", "repository": config["repository"], "branch": "main"},
        "trust": {"state": "unsigned", "signature": None}, "entries": references,
    })
    return documents


def output_members(root):
    files, directories = set(), []
    pending = [root]
    while pending:
        directory = pending.pop()
        reject_redirect(directory)
        with os.scandir(directory) as entries:
            for item in entries:
                path = Path(item.path)
                info = reject_redirect(path)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(path)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    files.add(path.relative_to(root).as_posix())
                else:
                    raise CatalogError(f"Unowned output member: {path}")
    return files, directories


def clear_generated_output(output):
    if not output.exists():
        return
    if not output.is_dir() or not (output / MARKER).is_file():
        raise CatalogError(f"Refusing unowned output; expected a generated catalogue: {output}")
    marker = parse(read_bytes(output, MARKER), MARKER)
    fields(marker, ("generator", "files"), (), MARKER)
    if marker["generator"] != "peachy-catalogue-builder" or not isinstance(marker["files"], dict):
        raise CatalogError("Invalid generated-output marker")
    expected = marker["files"]
    if not expected or len(expected) > 1024 or MARKER in expected:
        raise CatalogError("Invalid generated-output membership")
    allowed_directories = set()
    for name, digest in expected.items():
        parts = safe_parts(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise CatalogError("Invalid generated-output hash")
        allowed_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    actual, directories = output_members(output)
    if actual != set(expected) | {MARKER} or {p.relative_to(output).as_posix() for p in directories} != allowed_directories:
        raise CatalogError("Refusing unexpected or missing files/directories in generated output")
    for name, digest in expected.items():
        if hashlib.sha256(read_bytes(output, name)).hexdigest() != digest:
            raise CatalogError(f"Generated output was changed or edited: {name}")
    # Delete only enumerated, unchanged generated files; never recursively erase the destination.
    for name, digest in expected.items():
        if hashlib.sha256(read_bytes(output, name)).hexdigest() != digest:
            raise CatalogError(f"Generated output changed before replacement: {name}")
        (output / name).unlink()
    reject_redirect(output / MARKER)
    (output / MARKER).unlink()
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        reject_redirect(directory)
        directory.rmdir()


def write_documents(root, documents):
    root.mkdir(parents=True, exist_ok=True)
    for relative, raw in documents.items():
        path = root.joinpath(*safe_parts(relative))
        path.parent.mkdir(parents=True, exist_ok=True)
        checked_path(path.parent)
        with path.open("xb") as stream:
            stream.write(raw)


def build(root, output=None):
    root = checked_path(root)
    if output is not None:
        output = checked_path(output, allow_missing=True)
        if (root == output or root.is_relative_to(output)
                or output.is_relative_to(root) and output.relative_to(root).parts[:1] != ("dist",)):
            raise CatalogError("Output must be under dist/ or outside the source checkout, never over source files")
    documents = compile_sources(root)
    scratch = os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")
    scratch = checked_path(scratch or root / ".build", allow_missing=True)
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="peachy-catalogue-build-", dir=scratch) as temporary:
        stage = Path(temporary)
        write_documents(stage, documents)
        result = validate(stage)
    if output is not None:
        checked_path(output, allow_missing=True)
        clear_generated_output(output)
        write_documents(output, documents)
        marker = {"generator": "peachy-catalogue-builder",
                  "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(documents.items())}}
        with (output / MARKER).open("xb") as stream:
            stream.write(encode(marker))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parents[1])
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--check", action="store_true", help="Validate source without retaining generated files")
    commands.add_argument("--output", type=Path, help="Generated snapshot directory (default: dist/catalogue)")
    options = parser.parse_args()
    try:
        output = None if options.check else options.output or options.root / "dist/catalogue"
        result = build(options.root, output)
        if output is not None:
            result = {**result, "output": str(output.absolute())}
        print(json.dumps(result, sort_keys=True))
    except (CatalogError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Catalogue build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
