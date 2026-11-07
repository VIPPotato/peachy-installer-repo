"""Validate, prepare and publish the signed catalogue feed (not application releases).

The public CLI has one fixed HTTPS destination. The private local-bare-repository
seam is used only by offline tests. Signing keys never enter this Python process.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__:
    from .build_catalog import MARKER, SCHEMAS, build, checked_path, compile_sources, encode, fields, output_members, write_documents
    from .validate_catalog import MAX_JSON_BYTES, CatalogError, parse, read_bytes, safe_parts
else:
    from build_catalog import MARKER, SCHEMAS, build, checked_path, compile_sources, encode, fields, output_members, write_documents
    from validate_catalog import MAX_JSON_BYTES, CatalogError, parse, read_bytes, safe_parts

REPOSITORY = "VIPPotato/peachy-installer-repo"
REMOTE = "https://github.com/" + REPOSITORY + ".git"
FEED_REF = "refs/heads/catalogue"
SOURCE_REF = "refs/heads/main"
ALGORITHM = "ecdsa-p256-sha256-p1363"
SIGNATURE = "catalog.signature.json"
DOMAIN = b"PeachyInstaller.Catalogue.v1\0" + ALGORITHM.encode("ascii") + b"\0"
TOOLS = Path(__file__).absolute().parent
MAX_MEMBERS = 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")


def directory(path, *, missing=False):
    value = os.fspath(path)
    if value.startswith(("\\\\", "//")) or "\x00" in value:
        raise CatalogError("UNC/device paths are not permitted")
    result = checked_path(path, allow_missing=missing)
    if result.exists() and not result.is_dir():
        raise CatalogError("Expected a regular directory")
    return result


@contextmanager
def signature_directory_guard(root):
    """Pin Windows ancestors against replacement during exclusive creation.

    OPEN_REPARSE_POINT inspects each directory itself. Omitting SHARE_DELETE
    prevents replacement with a junction between checking and signature creation.
    This is process-local, not a privilege/ACL or system configuration change.
    """
    if os.name != "nt":
        raise CatalogError("Signature creation requires guarded Windows/CNG tooling")
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = (wintypes.HANDLE, wintypes.LPVOID)
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL

    class Information(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                    ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]

    handles = []
    try:
        for ancestor in reversed((root, *root.parents)):
            # LIST_DIRECTORY participates in Windows share-access checks;
            # READ_ATTRIBUTES alone is metadata-only and does not pin renames.
            handle = kernel.CreateFileW(str(ancestor), 0x81, 0x3, None, 3, 0x02200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise CatalogError("Cannot lock signature directory ancestry")
            handles.append(handle)
            info = Information()
            if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
                    or info.attributes & 0x400 or not info.attributes & 0x10):
                raise CatalogError("Unsafe signature directory ancestry")
        directory(root)
        yield
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def scratch_directory():
    value = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
    if not value or not Path(value).is_absolute():
        raise CatalogError("Set RUNNER_TEMP or TMPDIR to an absolute owned scratch directory")
    result = directory(value)
    return result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc(value, label):
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise CatalogError(f"{label}: expected a bounded UTC timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CatalogError(f"{label}: invalid UTC timestamp") from error


def integer(value, label, *, minimum=1):
    if type(value) is not int or not minimum <= value <= 0xffffffffffffffff:
        raise CatalogError(f"{label}: invalid bounded integer")
    return value


def envelope(document):
    fields(document, ("schemaVersion", "algorithm", "keyId", "signature"), (), SIGNATURE)
    if (type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1
            or document["algorithm"] != ALGORITHM
            or not isinstance(document["keyId"], str) or not HEX64.fullmatch(document["keyId"])
            or not isinstance(document["signature"], str)
            or not re.fullmatch(r"[0-9a-f]{128}", document["signature"])):
        raise CatalogError("Invalid detached signature envelope")
    return document


def bundle_hash(documents):
    digest = hashlib.sha256()
    for name, raw in sorted(documents.items()):
        if name == SIGNATURE:
            continue
        digest.update(name.encode("ascii") + b"\0" + bytes.fromhex(sha(raw)))
    return digest.hexdigest()


def check_members(documents):
    """The marker is an ownership receipt, not an allowlist or trust anchor."""
    if len(documents) > MAX_MEMBERS or sum(map(len, documents.values())) > MAX_BUNDLE_BYTES:
        raise CatalogError("Catalogue membership/size limit exceeded")
    if MARKER not in documents or "catalog.json" not in documents:
        raise CatalogError("Missing generated catalogue membership marker/index")
    marker = parse(documents[MARKER], MARKER)
    fields(marker, ("generator", "files"), (), MARKER)
    if marker["generator"] != "peachy-catalogue-builder" or not isinstance(marker["files"], dict):
        raise CatalogError("Invalid generated catalogue marker")
    known = {"catalog.json"} | {f"schemas/{name}.schema.json" for name in SCHEMAS}
    index = parse(documents["catalog.json"], "catalog.json")
    if not isinstance(index, dict) or not isinstance(index.get("entries"), list) or not 1 <= len(index["entries"]) <= 128:
        raise CatalogError("Invalid catalogue index membership")
    for reference in index["entries"]:
        fields(reference, ("id", "path", "sha256"), (), "entry reference")
        relative = reference["path"]
        safe_parts(relative)
        if not relative.startswith("entries/") or relative not in documents or relative in known:
            raise CatalogError("Invalid/duplicate entry membership")
        known.add(relative)
        entry = parse(documents[relative], relative)
        if not isinstance(entry, dict):
            raise CatalogError("Invalid entry")
        recipe = entry.get("recipe")
        fields(recipe, ("id", "path", "sha256"), (), "recipe reference")
        name = recipe["path"]
        safe_parts(name)
        if not name.startswith("recipes/") or name not in documents or name in known:
            raise CatalogError("Invalid/duplicate recipe membership")
        known.add(name)
        source = entry.get("releaseSource")
        if not isinstance(source, dict):
            raise CatalogError("Invalid release source")
        if "manifest" in source:
            manifest = source["manifest"]
            fields(manifest, ("path", "sha256", "downloadUrl"), (), "manifest reference")
            name = manifest["path"]
            safe_parts(name)
            if not name.startswith("releases/") or name not in documents or name in known:
                raise CatalogError("Invalid/duplicate manifest membership")
            known.add(name)
    if set(marker["files"]) != known or set(documents) - {SIGNATURE, MARKER} != known:
        raise CatalogError("Unexpected/missing snapshot membership")
    for name in known:
        expected = marker["files"][name]
        if not isinstance(expected, str) or not HEX64.fullmatch(expected) or sha(documents[name]) != expected:
            raise CatalogError(f"Generated member edited/hash mismatch: {name}")
    for name in SCHEMAS:
        relative = f"schemas/{name}.schema.json"
        if documents[relative] != read_bytes(TOOLS, relative):
            raise CatalogError(f"Unknown/edited snapshot schema: {relative}")
    if SIGNATURE in documents:
        envelope(parse(documents[SIGNATURE], SIGNATURE))
    return index


def read_snapshot(root):
    root = directory(root)
    names, directories = output_members(root)
    if len(names) > MAX_MEMBERS or len(directories) > MAX_MEMBERS:
        raise CatalogError("Catalogue membership limit exceeded")
    expected_dirs = set()
    folded = set()
    for name in names:
        parts = safe_parts(name)
        if len(name) > 240 or name != name.lower() or name.casefold() in folded:
            raise CatalogError("Unsafe/colliding snapshot path")
        folded.add(name.casefold())
        expected_dirs.update("/".join(parts[:n]) for n in range(1, len(parts)))
    if {p.relative_to(root).as_posix() for p in directories} != expected_dirs:
        raise CatalogError("Unexpected snapshot directories/membership")
    documents = {}
    total = 0
    for name in sorted(names):
        raw = read_bytes(root, name)
        total += len(raw)
        if total > MAX_BUNDLE_BYTES:
            raise CatalogError("Catalogue bundle size exceeded")
        documents[name] = raw
    check_members(documents)
    return documents


def policy_for(path, index, *, historical=False):
    path = checked_path(path)
    raw = read_bytes(path.parent, path.name)
    policy = parse(raw, "signing policy")
    fields(policy, ("schemaVersion", "algorithm", "minimumRevision", "minimumGeneratedAt", "keys"), (), "signing policy")
    if type(policy["schemaVersion"]) is not int or policy["schemaVersion"] != 1 or policy["algorithm"] != ALGORITHM:
        raise CatalogError("Unsupported signing policy")
    floor = integer(policy["minimumRevision"], "minimumRevision", minimum=4)
    floor_time = utc(policy["minimumGeneratedAt"], "minimumGeneratedAt")
    revision = integer(index.get("revision"), "revision")
    generated = utc(index.get("generatedAt"), "generatedAt")
    expires = utc(index.get("expiresAt"), "expiresAt")
    now = datetime.now(timezone.utc)
    if generated > now:
        raise CatalogError("Catalogue generation is in the future")
    if expires <= generated or expires - generated > timedelta(days=31):
        raise CatalogError("Catalogue signed lifetime must be positive and at most 31 days")
    if not historical:
        if revision < floor or generated < floor_time:
            raise CatalogError("Catalogue revision/generation floor not met")
        if now >= expires:
            raise CatalogError("Catalogue snapshot expired")
    if index.get("origin") != {"provider": "github", "repository": REPOSITORY, "branch": "main"}:
        raise CatalogError("Catalogue source identity does not match the fixed publisher")
    keys = policy["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        raise CatalogError("Invalid signing policy key count")
    seen, eligible = set(), []
    for key in keys:
        fields(key, ("keyId", "publicPoint", "validFrom", "validUntil", "revoked"), (), "policy key")
        key_id, point = key["keyId"], key["publicPoint"]
        if (not isinstance(key_id, str) or not HEX64.fullmatch(key_id)
                or not isinstance(point, str) or not re.fullmatch(r"[0-9a-f]{128}", point)
                or sha(bytes.fromhex(point)) != key_id or type(key["revoked"]) is not bool):
            raise CatalogError("Invalid signing key identity/encoding")
        if key_id in seen:
            raise CatalogError("Duplicate signing key")
        seen.add(key_id)
        start, end = utc(key["validFrom"], "validFrom"), utc(key["validUntil"], "validUntil")
        if start >= end:
            raise CatalogError("Invalid signing key validity window")
        if (not key["revoked"] and start <= generated and expires <= end
                and (historical or start <= now < end)):
            eligible.append(key)
    if not eligible:
        raise CatalogError("No non-revoked signing key covers snapshot/current validity windows")
    return sha(raw), eligible


def validation_process(root, index, *, historical=False):
    env = os.environ.copy()
    env.pop("PEACHY_CATALOGUE_SIGNING_KEY", None)
    if historical:
        # Only a previous remote feed uses a historical reference clock. This
        # runs the unchanged validator/member checks on the ORIGINAL signed bytes
        # in an isolated interpreter; it never makes an expired candidate current.
        code = ("import sys; from datetime import datetime,timedelta; from pathlib import Path; "
                "import tools.validate_catalog as v; "
                "clock=datetime.fromisoformat(sys.argv[2].replace('Z','+00:00'))-timedelta(microseconds=1); "
                "v.datetime=type('ReferenceClock',(datetime,),{'now':classmethod(lambda cls,tz=None: clock)}); "
                "v.validate(Path(sys.argv[1]))")
        command = [sys.executable, "-c", code, str(root), index["expiresAt"]]
        cwd = TOOLS.parent
    else:
        command = [sys.executable, str(TOOLS / "validate_catalog.py"), "--root", str(root)]
        cwd = None
    result = subprocess.run(command, capture_output=True, env=env, cwd=cwd, timeout=90)
    if result.returncode:
        raise CatalogError("Full catalogue validator refused the bundle")


def inspect_snapshot(root, policy, *, historical=False, cli_validation=True):
    root = directory(root)
    before = read_snapshot(root)
    index = parse(before["catalog.json"], "catalog.json")
    policy_hash, keys = policy_for(policy, index, historical=historical)
    if cli_validation:
        validation_process(root, index, historical=historical)
    if read_snapshot(root) != before:
        raise CatalogError("Snapshot changed during validation")
    # The signature is intentionally not included in bundleSha256 (P1363 ECDSA is randomized).
    result = {"indexBase64": base64.b64encode(before["catalog.json"]).decode("ascii"),
              "indexSha256": sha(before["catalog.json"]), "bundleSha256": bundle_hash(before),
              "policySha256": policy_hash, "keys": keys}
    if SIGNATURE in before:
        result["envelope"] = envelope(parse(before[SIGNATURE], SIGNATURE))
        result["signatureSha256"] = sha(before[SIGNATURE])
    return result


def store_signature(root, policy, document, expected_bundle, expected_policy):
    root = directory(root)
    with signature_directory_guard(root):
        return _store_signature_locked(root, policy, document, expected_bundle, expected_policy)


def _store_signature_locked(root, policy, document, expected_bundle, expected_policy):
    current = inspect_snapshot(root, policy)
    if "envelope" in current:
        raise CatalogError("Refusing to replace an existing signature")
    if current["bundleSha256"] != expected_bundle or current["policySha256"] != expected_policy:
        raise CatalogError("Snapshot/policy changed before signature publication")
    envelope(document)
    if document["keyId"] not in {key["keyId"] for key in current["keys"]}:
        raise CatalogError("Signature does not select an eligible policy key")
    raw = encode(document)
    target = root / SIGNATURE
    # Exclusive creation cannot overwrite a link, hardlink or edited pre-existing signature.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    after = inspect_snapshot(root, policy)
    if (read_bytes(root, SIGNATURE) != raw or after["bundleSha256"] != expected_bundle
            or after["policySha256"] != expected_policy):
        raise CatalogError("Signed snapshot failed exact readback")
    return {"signatureStored": True}


def verify_signature(root, policy, expected, *, historical=False):
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(TOOLS / "sign_catalogue.ps1"), "-Action", "Verify",
               "-Root", str(root), "-Policy", str(policy)]
    if historical:
        command.append("-Historical")
    env = os.environ.copy()
    env.pop("PEACHY_CATALOGUE_SIGNING_KEY", None)
    result = subprocess.run(command, env=env, capture_output=True, timeout=120)
    if result.returncode:
        raise CatalogError("Detached public-key signature verification failed")
    proof = parse(result.stdout, "public verification result")
    policy_path = checked_path(policy)
    if (proof.get("signatureVerified") is not True or proof.get("algorithm") != ALGORITHM
            or proof.get("bundleSha256") != bundle_hash(expected)
            or proof.get("indexSha256") != sha(expected["catalog.json"])
            or proof.get("signatureSha256") != sha(expected[SIGNATURE])
            or proof.get("policySha256") != sha(read_bytes(policy_path.parent, policy_path.name))):
        raise CatalogError("Public verification proof does not bind the captured candidate/policy")


def git_environment():
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.pop("PEACHY_CATALOGUE_SIGNING_KEY", None)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GCM_INTERACTIVE="Never", GH_PROMPT_DISABLED="1", GIT_LFS_SKIP_SMUDGE="1",
               GIT_AUTHOR_NAME="github-actions[bot]", GIT_COMMITTER_NAME="github-actions[bot]",
               GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
               GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com")
    return env


class Git:
    def __init__(self, root, remote, *, local=False):
        self.root, self.remote, self.local = root, remote, local
        self.env = git_environment()
        self.options = ["-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
                        "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false",
                        "-c", "core.hooksPath=" + str(root / "no-hooks"),
                        "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                        "-c", "protocol.file.allow=" + ("always" if local else "never"),
                        "-c", "http.followRedirects=false", "-c", "remote.origin.url=" + str(remote)]

    def run(self, *arguments, data=None):
        result = subprocess.run(["git", *self.options, *arguments], cwd=self.root,
                                env=self.env, input=data, capture_output=True, timeout=120)
        if result.returncode:
            # Never forward Git/credential-helper output; URLs/tokens are not diagnostics.
            raise CatalogError("Git operation failed (refused, drifted, or unavailable)")
        if len(result.stdout) > MAX_BUNDLE_BYTES * 2:
            raise CatalogError("Git output exceeded catalogue bounds")
        return result.stdout

    def text(self, *arguments, data=None):
        return self.run(*arguments, data=data).decode("utf-8").strip()


def source_identity(root, source_sha):
    root = directory(root)
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise CatalogError("Expected an exact source commit SHA")
    git = Git(root, REMOTE)
    if (git.text("rev-parse", "HEAD") != source_sha
            or git.text("status", "--porcelain=v1", "--untracked-files=all")):
        raise CatalogError("Source checkout drifted or is not clean at the requested SHA")


def prepare(root, output, source_sha):
    source_identity(root, source_sha)
    output = directory(output, missing=True)
    scratch = scratch_directory()
    if not output.is_relative_to(scratch) or output == scratch or output.exists():
        raise CatalogError("Fresh publication output must be absent and below owned runner scratch")
    previous = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = str(scratch)
    try:
        result = build(root, output)
    finally:
        if previous is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = previous
    source_identity(root, source_sha)
    return {**result, "sourceSha": source_sha, "output": str(output)}


def remote_refs(git):
    raw = git.text("ls-remote", "--refs", "origin", SOURCE_REF, FEED_REF)
    result = {}
    for line in raw.splitlines():
        value, name = line.split("\t")
        if name in result or name not in (SOURCE_REF, FEED_REF) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise CatalogError("Unexpected remote ref identity")
        result[name] = value
    return result


def check_remote_refs(git, expected_source, expected_feed):
    refs = remote_refs(git)
    if refs.get(SOURCE_REF) != expected_source:
        raise CatalogError("Remote source main drifted from the bound checkout")
    if refs.get(FEED_REF) != expected_feed:
        raise CatalogError("Remote catalogue branch drifted")


def tree_documents(git, commit):
    rows = git.run("ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    if len(rows) - 1 > MAX_MEMBERS:
        raise CatalogError("Remote catalogue membership limit exceeded")
    result, folded, total = {}, set(), 0
    for row in rows:
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split(" ")
        relative = name.decode("ascii")
        safe_parts(relative)
        if (mode != "100644" or kind != "blob" or len(relative) > 240 or relative != relative.lower()
                or relative.casefold() in folded or not re.fullmatch(r"[0-9a-f]{40}", object_id)):
            raise CatalogError("Unsafe remote catalogue member")
        folded.add(relative.casefold())
        size = int(git.text("cat-file", "-s", object_id))
        total += size
        if size > MAX_JSON_BYTES or total > MAX_BUNDLE_BYTES:
            raise CatalogError("Remote catalogue member/bundle size exceeded")
        result[relative] = git.run("cat-file", "blob", object_id)
    check_members(result)
    return result


def expected_source_documents(root):
    documents = compile_sources(root)
    return {**documents, MARKER: encode({"generator": "peachy-catalogue-builder",
                                        "files": {name: sha(raw) for name, raw in sorted(documents.items())}})}


def readback(git, commit, expected, source_sha):
    check_remote_refs(git, source_sha, commit)
    git.run("fetch", "--no-tags", "origin", FEED_REF + ":refs/peachy/readback")
    if git.text("rev-parse", "refs/peachy/readback") != commit or tree_documents(git, commit) != expected:
        raise CatalogError("Remote branch/member readback mismatch")
    check_remote_refs(git, source_sha, commit)


def publish(root, snapshot, policy, source_sha, *, _local_remote=None):
    if os.environ.get("PEACHY_CATALOGUE_SIGNING_KEY"):
        raise CatalogError("Signing secret must not be available to the publishing step")
    root, snapshot = directory(root), directory(snapshot)
    policy = checked_path(policy)
    source_identity(root, source_sha)
    candidate = read_snapshot(snapshot)
    if SIGNATURE not in candidate:
        raise CatalogError("Candidate detached signature is required")
    unsigned = {name: raw for name, raw in candidate.items() if name != SIGNATURE}
    if expected_source_documents(root) != unsigned:
        raise CatalogError("Candidate is not the exact generated source snapshot")
    inspect_snapshot(snapshot, policy)  # Candidate verification is ALWAYS current, never historical.
    verify_signature(snapshot, policy, candidate)
    scratch = scratch_directory()
    remote, local = REMOTE, False
    if _local_remote is not None:
        remote = directory(_local_remote)
        if not remote.is_relative_to(scratch):
            raise CatalogError("Local test remote must be below owned scratch")
        local = True
    with tempfile.TemporaryDirectory(prefix="peachy-feed-publish-", dir=scratch) as temporary:
        work = Path(temporary)
        repository = work / "git"
        repository.mkdir()
        git = Git(repository, remote, local=local)
        git.run("init", "--quiet")
        refs = remote_refs(git)
        previous_tip = refs.get(FEED_REF)
        check_remote_refs(git, source_sha, previous_tip)
        previous = None
        if previous_tip:
            git.run("fetch", "--no-tags", "origin", FEED_REF + ":refs/peachy/previous")
            if git.text("rev-parse", "refs/peachy/previous") != previous_tip:
                raise CatalogError("Remote catalogue branch drifted during fetch")
            previous = tree_documents(git, previous_tip)
            if SIGNATURE not in previous:
                raise CatalogError("Previous feed detached signature is missing")
            prior_root = work / "previous"
            write_documents(prior_root, previous)
            inspect_snapshot(prior_root, policy, historical=True)
            verify_signature(prior_root, policy, previous, historical=True)
            old_index = parse(previous["catalog.json"], "previous catalog.json")
            index = parse(candidate["catalog.json"], "catalog.json")
            if index["revision"] < old_index["revision"]:
                raise CatalogError("Catalogue revision rollback refused")
            if index["revision"] == old_index["revision"] and unsigned != {
                    name: raw for name, raw in previous.items() if name != SIGNATURE}:
                raise CatalogError("Catalogue same-revision equivocation refused")
            if utc(index["generatedAt"], "generatedAt") < utc(old_index["generatedAt"], "generatedAt"):
                raise CatalogError("Catalogue generation rollback refused")
        source_identity(root, source_sha)
        if expected_source_documents(root) != unsigned or read_snapshot(snapshot) != candidate:
            raise CatalogError("Source/candidate changed before publication")
        inspect_snapshot(snapshot, policy)
        check_remote_refs(git, source_sha, previous_tip)
        if previous is not None and unsigned == {name: raw for name, raw in previous.items() if name != SIGNATURE}:
            # A no-op retains the already published randomized signature, but it
            # must still be valid NOW under the independent current policy.
            inspect_snapshot(prior_root, policy)
            verify_signature(prior_root, policy, previous)
            readback(git, previous_tip, previous, source_sha)
            inspect_snapshot(prior_root, policy)
            if read_snapshot(prior_root) != previous or read_snapshot(snapshot) != candidate:
                raise CatalogError("Catalogue changed during publication readback")
            source_identity(root, source_sha)
            return {"status": "unchanged", "commit": previous_tip, "members": len(previous)}
        for name, raw in sorted(candidate.items()):
            object_id = git.text("hash-object", "-w", "--stdin", data=raw)
            git.run("update-index", "--add", "--cacheinfo", "100644," + object_id + "," + name)
        tree = git.text("write-tree")
        args = ["commit-tree", tree]
        if previous_tip:
            args.extend(("-p", previous_tip))  # Preserve all history; never an orphan replacement/force push.
        revision = parse(candidate["catalog.json"], "catalog.json")["revision"]
        commit = git.text(*args, data=f"Catalogue revision {revision} from {source_sha}\n".encode("ascii"))
        git.run("update-ref", "--no-deref", "HEAD", commit)
        # A concurrent append is also refused by normal Git fast-forward rules.
        git.run("push", "--porcelain", "origin", "HEAD:" + FEED_REF)
        readback(git, commit, candidate, source_sha)
        inspect_snapshot(snapshot, policy)
        if read_snapshot(snapshot) != candidate:
            raise CatalogError("Candidate changed during publication readback")
        source_identity(root, source_sha)
        return {"status": "published", "commit": commit, "members": len(candidate)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "store-signature", "prepare", "publish"):
        command = sub.add_parser(name)
        if name in ("inspect", "store-signature", "publish"):
            command.add_argument("--snapshot", type=Path, required=True)
            command.add_argument("--policy", type=Path, required=True)
        if name in ("prepare", "publish"):
            command.add_argument("--root", type=Path, default=TOOLS.parent)
            command.add_argument("--source-sha", required=True)
        if name == "inspect":
            command.add_argument("--historical", action="store_true", help="Previous remote feed verification only")
        if name == "prepare":
            command.add_argument("--output", type=Path, required=True)
        if name == "store-signature":
            command.add_argument("--expected-bundle", required=True)
            command.add_argument("--expected-policy", required=True)
    args = parser.parse_args()
    try:
        if os.environ.get("PEACHY_CATALOGUE_SIGNING_KEY"):
            raise CatalogError("Python tooling must not inherit the private signing secret")
        if args.command == "inspect":
            result = inspect_snapshot(args.snapshot, args.policy, historical=args.historical)
        elif args.command == "store-signature":
            raw = sys.stdin.buffer.read(4097)
            if len(raw) > 4096:
                raise CatalogError("Signature envelope exceeded size limit")
            # Windows PowerShell 5.1 may prefix native-pipeline stdin with a
            # UTF-8 BOM. This is only the PUBLIC IPC envelope, never index/member
            # input; stored JSON is always freshly encoded BOM-free below.
            result = store_signature(args.snapshot, args.policy, parse(raw.removeprefix(b"\xef\xbb\xbf"), SIGNATURE),
                                     args.expected_bundle, args.expected_policy)
        elif args.command == "prepare":
            result = prepare(args.root, args.output, args.source_sha)
        else:
            result = publish(args.root, args.snapshot, args.policy, args.source_sha)
        print(json.dumps(result, sort_keys=True))
    except (CatalogError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Catalogue producer refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
