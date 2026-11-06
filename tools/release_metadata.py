"""Generate and validate version.json from a pinned published ZIP, without executing it."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 4096
RESERVED = {"con", "prn", "aux", "nul", "clock$"}
RESERVED.update(f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10))


class ReleaseError(ValueError):
    pass


def member_parts(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", name):
        raise ReleaseError(f"Unsupported archive path: {name!r}")
    parts = name.split("/")
    if any(part in ("", ".", "..") or part.endswith(".") or part.split(".")[0].lower() in RESERVED for part in parts):
        raise ReleaseError(f"Unsafe archive path: {name!r}")
    return parts


def inspect_archive(path):
    path = Path(path).absolute()
    for ancestor in reversed((path, *path.parents)):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ReleaseError("Redirected archive path")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ARCHIVE_BYTES:
        raise ReleaseError("Archive is not a bounded, unlinked regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_ARCHIVE_BYTES + 1)
    after = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if len(raw) > MAX_ARCHIVE_BYTES or identity(before) != identity(after):
        raise ReleaseError("Archive changed or exceeded its size limit")
    files = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_MEMBERS or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
                raise ReleaseError("Archive exceeds member/decompression bounds")
            kinds = {}
            for item in members:
                name = item.filename[:-1] if item.is_dir() else item.filename
                member_parts(name)
                key = name.casefold()
                mode = stat.S_IFMT(item.external_attr >> 16)
                if (item.filename != item.orig_filename or key in kinds or item.flag_bits & 1
                        or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                        or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or item.file_size > MAX_MEMBER_BYTES):
                    raise ReleaseError("Duplicate, redirected, encrypted or oversized archive member")
                kinds[key] = "directory" if item.is_dir() else "file"
            for key in kinds:
                parts = key.split("/")
                if any(kinds.get("/".join(parts[:index])) == "file" for index in range(1, len(parts))):
                    raise ReleaseError("Archive file/directory path collision")
            for item in members:
                if item.is_dir():
                    continue
                with archive.open(item) as stream:
                    data = stream.read(item.file_size + 1)
                if len(data) != item.file_size:
                    raise ReleaseError("Archive member size mismatch")
                files.append({"path": item.filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as error:
        raise ReleaseError(f"Unreadable archive: {error}") from error
    if not files:
        raise ReleaseError("Archive has no file members")
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "files": sorted(files, key=lambda item: item["path"])}


def check_document(document):
    release = document["release"]
    if release["tag"] != "v" + document["version"]:
        raise ReleaseError("Release tag and version do not match")
    targets, assets = set(), set()
    for artifact in document["artifacts"]:
        target = (artifact["os"], artifact["gameArchitecture"])
        asset = artifact["asset"]
        if target in targets or asset["id"] in assets:
            raise ReleaseError("Duplicate release target or asset identity")
        targets.add(target)
        assets.add(asset["id"])
        if len(member_parts(asset["name"])) != 1 or not asset["name"].endswith(".zip"):
            raise ReleaseError("Release asset name must identify one ZIP file")
        expected = f"https://github.com/{release['repository']}/releases/download/{release['tag']}/{asset['name']}"
        if asset["url"] != expected:
            raise ReleaseError("Release asset URL does not match repository, tag and name")
        paths = set()
        for item in artifact["files"]:
            member_parts(item["path"])
            key = item["path"].casefold()
            if key in paths:
                raise ReleaseError("Duplicate release member path")
            paths.add(key)
        for key in paths:
            parts = key.split("/")
            if any("/".join(parts[:index]) in paths for index in range(1, len(parts))):
                raise ReleaseError("Release member file/directory collision")
        if sum(item["size"] for item in artifact["files"]) > MAX_EXPANDED_BYTES:
            raise ReleaseError("Release members exceed decompression bounds")


def check_archive(document, path):
    if len(document["artifacts"]) != 1:
        raise ReleaseError("Select one artifact before checking an archive")
    observed = inspect_archive(path)
    artifact = document["artifacts"][0]
    asset = artifact["asset"]
    if observed["size"] != asset["size"] or observed["sha256"] != asset["sha256"]:
        raise ReleaseError("Archive size or SHA-256 does not match version.json")
    if observed["files"] != sorted(artifact["files"], key=lambda item: item["path"]):
        raise ReleaseError("Archive members do not match version.json")
    return observed


def generate(release, repository, commit, mod_id, asset_id, archive_path):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ReleaseError("Invalid release repository")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", mod_id):
        raise ReleaseError("Invalid commit or mod identity")
    tag = release.get("tag_name", "")
    if (not re.fullmatch(r"v[0-9]+(?:[.][0-9]+){0,3}", tag)
            or release.get("draft") is not False or release.get("prerelease") is not False
            or type(release.get("id")) is not int or release["id"] < 1
            or release.get("html_url") != f"https://github.com/{repository}/releases/tag/{tag}"):
        raise ReleaseError("Expected a published stable release from the selected repository")
    assets = [asset for asset in release.get("assets", []) if asset.get("id") == asset_id]
    if len(assets) != 1:
        raise ReleaseError("Release asset is missing or ambiguous")
    asset = assets[0]
    observed = inspect_archive(archive_path)
    if (type(asset.get("size")) is not int or observed["size"] != asset["size"]
            or asset.get("digest") != "sha256:" + observed["sha256"]):
        raise ReleaseError("Archive identity differs from the published asset")
    document = {"schemaVersion": 1, "modId": mod_id, "version": tag[1:],
                "release": {"provider": "github", "repository": repository, "id": release["id"],
                            "tag": tag, "commit": commit, "channel": "stable"},
                "artifacts": [{"os": "windows", "gameArchitecture": "x86", "layout": "game-root-overlay",
                               "asset": {"id": asset["id"], "name": asset["name"], "size": observed["size"],
                                         "sha256": observed["sha256"], "url": asset["browser_download_url"]},
                               "files": observed["files"],
                               "requirements": {"loader": {"family": "melonloader", "qualification": "pending",
                                                            "version": None, "artifact": None},
                                                "runtime": "unqualified"}}]}
    check_document(document)
    return document


def encode_document(document, limit):
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if len(text.encode("utf-8")) > limit:
        raise ReleaseError("Generated metadata exceeds the reader's JSON size limit")
    return text


def main():
    # Module invocation keeps this metadata tool and the catalogue CLI on the same schema/parser implementation.
    from tools.validate_catalog import MAX_JSON_BYTES, CatalogError, check_schema, parse, read_bytes, validators
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-root", type=Path, default=Path(__file__).resolve().parents[1])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("generate")
    build.add_argument("--release-json", type=Path, required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--mod-id", required=True)
    build.add_argument("--asset-id", type=int, required=True)
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("validate")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--archive", type=Path)
    options = parser.parse_args()
    try:
        if options.command == "generate":
            release = parse(read_bytes(options.release_json.absolute().parent, options.release_json.name), "release JSON")
            document = generate(release, options.repository, options.commit, options.mod_id, options.asset_id, options.archive)
        else:
            document = parse(read_bytes(options.manifest.absolute().parent, options.manifest.name), "version.json")
        check_schema(validators(options.schema_root)["version"], document, "version.json")
        check_document(document)
        if options.command == "validate" and options.archive:
            check_archive(document, options.archive)
        if options.command == "generate":
            text = encode_document(document, MAX_JSON_BYTES)
            options.output.parent.mkdir(parents=True, exist_ok=True)
            with options.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        print(json.dumps({"modId": document["modId"], "version": document["version"],
                          "files": sum(len(artifact["files"]) for artifact in document["artifacts"]),
                          "archiveBytesVerified": bool(options.archive), "signatureVerified": False,
                          "installationQualified": False}, sort_keys=True))
    except (CatalogError, ReleaseError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Release metadata validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
