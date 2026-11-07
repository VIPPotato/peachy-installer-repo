"""Producer policy and real local Git publication; no public network or private keys."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import publish_catalogue as producer
from tools.build_catalog import build, encode, MARKER
from tools.validate_catalog import CatalogError

SOURCE = Path(__file__).absolute().parents[1]


class ProducerTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        if not scratch:
            raise RuntimeError("Set RUNNER_TEMP or TMPDIR to owned scratch")
        self.temp = tempfile.TemporaryDirectory(prefix="peachy-producer-test-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / "source"
        self.root.mkdir()
        shutil.copytree(SOURCE / "mods", self.root / "mods")
        shutil.copytree(SOURCE / "tools/schemas", self.root / "tools/schemas")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.config = {"repository": producer.REPOSITORY, "revision": 4,
                       "generatedAt": self.utc(self.now - timedelta(minutes=1)),
                       "expiresAt": self.utc(self.now + timedelta(days=7))}
        self.write(self.root / "catalogue.json", self.config)
        # A public-only point is sufficient for policy checks; signature checks use real CNG separately.
        point = "01" * 64
        self.policy_data = {"schemaVersion": 1, "algorithm": producer.ALGORITHM,
                            "minimumRevision": 4, "minimumGeneratedAt": self.utc(self.now - timedelta(days=2)),
                            "keys": [{"keyId": hashlib.sha256(bytes.fromhex(point)).hexdigest(),
                                      "publicPoint": point, "validFrom": self.utc(self.now - timedelta(days=3)),
                                      "validUntil": self.utc(self.now + timedelta(days=40)), "revoked": False}]}
        self.policy = self.work / "policy.json"
        self.write(self.policy, self.policy_data)
        self.snapshot = self.work / "snapshot"
        build(self.root, self.snapshot)

    @staticmethod
    def utc(value):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def write(path, value):
        path.write_bytes(encode(value))

    def rebind_marker(self):
        files = {p.relative_to(self.snapshot).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.snapshot.rglob("*") if p.is_file() and p.name not in (MARKER, producer.SIGNATURE)}
        self.write(self.snapshot / MARKER, {"generator": "peachy-catalogue-builder", "files": files})

    def index(self):
        return json.loads((self.snapshot / "catalog.json").read_bytes())

    def inspect(self, historical=False):
        return producer.inspect_snapshot(self.snapshot, self.policy, historical=historical, cli_validation=False)

    def test_current_bundle_accepts_exact_generated_members(self):
        result = self.inspect()
        self.assertEqual(result["indexSha256"], hashlib.sha256((self.snapshot / "catalog.json").read_bytes()).hexdigest())
        self.assertEqual(result["keys"], self.policy_data["keys"])
        self.assertEqual(len(producer.read_snapshot(self.snapshot)), 16)

    def test_temporal_and_revision_refusals(self):
        for change, cause in [({"revision": 3}, "floor"),
                              ({"generatedAt": self.utc(self.now + timedelta(minutes=1))}, "future"),
                              ({"generatedAt": self.utc(self.now - timedelta(days=4))}, "floor"),
                              ({"expiresAt": self.utc(self.now + timedelta(days=32))}, "lifetime"),
                              ({"expiresAt": self.utc(self.now - timedelta(seconds=1))}, "expired")]:
            with self.subTest(change=change):
                index = {**self.config, **change}
                actual = self.index()
                actual.update({k: index[k] for k in ("revision", "generatedAt", "expiresAt")})
                self.write(self.snapshot / "catalog.json", actual)
                self.rebind_marker()
                with self.assertRaisesRegex(CatalogError, cause):
                    self.inspect()

    def test_policy_rejects_unknown_duplicate_invalid_or_revoked_keys(self):
        for change in ({"revoked": True}, {"validUntil": self.utc(self.now + timedelta(days=1))},
                       {"validFrom": self.utc(self.now)}, {"keyId": "00" * 32},
                       {"publicPoint": "AA" * 64}, {"unexpected": True}):
            with self.subTest(change=change):
                data = {**self.policy_data, "keys": [{**self.policy_data["keys"][0], **change}]}
                self.write(self.policy, data)
                with self.assertRaises(CatalogError):
                    self.inspect()
        data = {**self.policy_data, "keys": self.policy_data["keys"] * 2}
        self.write(self.policy, data)
        with self.assertRaisesRegex(CatalogError, "Duplicate"):
            self.inspect()

    def test_marker_is_not_authority_for_extra_or_weakened_schema_files(self):
        extra = self.snapshot / "secret.json"
        extra.write_bytes(b'{}')
        self.rebind_marker()
        with self.assertRaisesRegex(CatalogError, "membership"):
            self.inspect()
        extra.unlink()
        (self.snapshot / "schemas/entry.schema.json").write_bytes(b'{}')
        self.rebind_marker()
        with self.assertRaisesRegex(CatalogError, "schema"):
            self.inspect()

    def test_edited_missing_hardlinked_or_redirected_members_are_refused(self):
        path = self.snapshot / "catalog.json"
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        with self.assertRaisesRegex(CatalogError, "edited|hash"):
            self.inspect()
        path.write_bytes(original)
        link = self.work / "hardlink.json"
        os.link(path, link)
        with self.assertRaisesRegex(CatalogError, "Hard-linked"):
            self.inspect()
        link.unlink()
        (self.snapshot / "unexpected-empty-directory").mkdir()
        with self.assertRaisesRegex(CatalogError, "directories|membership"):
            self.inspect()

    def test_historical_mode_does_not_authorize_an_expired_candidate(self):
        index = self.index()
        index.update(revision=2, generatedAt=self.utc(self.now - timedelta(days=20)),
                     expiresAt=self.utc(self.now - timedelta(days=10)))
        self.write(self.snapshot / "catalog.json", index)
        self.rebind_marker()
        data = {**self.policy_data, "keys": [{**self.policy_data["keys"][0],
                                              "validFrom": self.utc(self.now - timedelta(days=30))}]}
        self.write(self.policy, data)
        self.assertEqual(len(self.inspect(historical=True)["keys"]), 1)
        with self.assertRaisesRegex(CatalogError, "floor|expired"):
            self.inspect()

    def test_noncanonical_duplicate_or_extra_envelope_fields_are_refused(self):
        envelope = {"schemaVersion": 1, "algorithm": producer.ALGORITHM,
                    "keyId": self.policy_data["keys"][0]["keyId"], "signature": "01" * 64}
        for change in ({"signature": "AA" * 64}, {"schemaVersion": True}, {"extra": 1}):
            with self.subTest(change=change):
                self.write(self.snapshot / producer.SIGNATURE, {**envelope, **change})
                with self.assertRaises(CatalogError):
                    self.inspect()
        (self.snapshot / producer.SIGNATURE).write_bytes(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(CatalogError, "Duplicate"):
            self.inspect()

    def test_current_full_validator_cli_runs_before_signing(self):
        result = producer.inspect_snapshot(self.snapshot, self.policy)
        self.assertEqual(result["indexSha256"], self.inspect()["indexSha256"])

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing guard required")
    def test_signature_creation_pins_directory_ancestry_against_replacement(self):
        replacement = self.work / "moved-snapshot"
        with producer.signature_directory_guard(self.snapshot):
            with self.assertRaises(OSError):
                self.snapshot.rename(replacement)
            self.assertTrue(self.snapshot.is_dir())
        self.snapshot.rename(replacement)
        replacement.rename(self.snapshot)

    def test_public_verification_proof_must_bind_captured_bytes(self):
        key_id = self.policy_data["keys"][0]["keyId"]
        self.write(self.snapshot / producer.SIGNATURE,
                   {"schemaVersion": 1, "algorithm": producer.ALGORITHM, "keyId": key_id, "signature": "01" * 64})
        documents = producer.read_snapshot(self.snapshot)
        proof = {"signatureVerified": True, "algorithm": producer.ALGORITHM,
                 "bundleSha256": producer.bundle_hash(documents), "indexSha256": producer.sha(documents["catalog.json"]),
                 "signatureSha256": producer.sha(documents[producer.SIGNATURE]),
                 "policySha256": producer.sha(self.policy.read_bytes())}
        result = subprocess.CompletedProcess([], 0, json.dumps(proof).encode(), b"")
        with patch("tools.publish_catalogue.subprocess.run", return_value=result):
            producer.verify_signature(self.snapshot, self.policy, documents)
            for name in ("bundleSha256", "indexSha256", "signatureSha256", "policySha256"):
                with self.subTest(field=name):
                    result.stdout = json.dumps({**proof, name: "00" * 32}).encode()
                    with self.assertRaisesRegex(CatalogError, "proof"):
                        producer.verify_signature(self.snapshot, self.policy, documents)

    def git(self, *args, cwd=None, data=None):
        env = producer.git_environment()
        result = subprocess.run(["git", *args], cwd=cwd or self.root, input=data,
                                capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout.decode().strip()

    def setup_git(self):
        # All refs and commits are confined to a disposable fixture, never this checkout or GitHub.
        self.git("init", "--initial-branch=main")
        self.git("add", "--", "catalogue.json", "mods", "tools")
        self.git("commit", "-m", "Owned metadata fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.remote = self.work / "feed.git"
        self.git("init", "--bare", str(self.remote))
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        self.addCleanup(patch.stopall)
        # Git tests isolate only the native crypto boundary; the separate CNG harness signs/verifies real bytes.
        patch("tools.publish_catalogue.verify_signature", side_effect=lambda *a, **kw: None).start()
        envelope = {"schemaVersion": 1, "algorithm": producer.ALGORITHM,
                    "keyId": self.policy_data["keys"][0]["keyId"], "signature": "01" * 64}
        self.write(self.snapshot / producer.SIGNATURE, envelope)

    def publish(self):
        return producer.publish(self.root, self.snapshot, self.policy, self.sha, _local_remote=self.remote)

    def test_real_git_first_publish_noop_history_and_exact_readback(self):
        self.setup_git()
        first = self.publish()
        self.assertEqual(first["status"], "published")
        first_tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        self.assertEqual(first["commit"], first_tip)
        self.assertEqual(self.git("show", "refs/heads/catalogue:catalog.json", cwd=self.remote),
                         (self.snapshot / "catalog.json").read_text().strip())
        envelope = json.loads((self.snapshot / producer.SIGNATURE).read_bytes())
        envelope["signature"] = "02" * 64  # randomized signatures must not cause redundant publication
        self.write(self.snapshot / producer.SIGNATURE, envelope)
        self.assertEqual(self.publish()["status"], "unchanged")
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote), first_tip)
        self.config["revision"] += 1
        self.write(self.root / "catalogue.json", self.config)
        self.git("add", "catalogue.json")
        self.git("commit", "-m", "Next owned revision")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        (self.snapshot / producer.SIGNATURE).unlink()
        build(self.root, self.snapshot)
        self.write(self.snapshot / producer.SIGNATURE, envelope)
        second = self.publish()
        self.assertEqual(second["status"], "published")
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue^", cwd=self.remote), first_tip)
        self.assertEqual(self.git("rev-list", "--count", "refs/heads/catalogue", cwd=self.remote), "2")

    def test_real_git_refuses_source_drift_unsigned_and_same_revision_edits(self):
        self.setup_git()
        self.publish()
        original_tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        self.config["expiresAt"] = self.utc(self.now + timedelta(days=8))
        self.write(self.root / "catalogue.json", self.config)
        with self.assertRaisesRegex(CatalogError, "source|Source"):
            self.publish()
        self.git("add", "catalogue.json")
        self.git("commit", "-m", "Same revision changed index fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        envelope = (self.snapshot / producer.SIGNATURE).read_bytes()
        (self.snapshot / producer.SIGNATURE).unlink()
        build(self.root, self.snapshot)
        (self.snapshot / producer.SIGNATURE).write_bytes(envelope)
        with self.assertRaisesRegex(CatalogError, "same.revision|equivocation"):
            self.publish()
        (self.snapshot / producer.SIGNATURE).unlink()
        with self.assertRaisesRegex(CatalogError, "signature"):
            self.publish()
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote), original_tip)

    def test_real_git_refuses_branch_race_and_remote_source_drift(self):
        self.setup_git()
        self.publish()
        tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        original = producer.check_remote_refs
        calls = []

        def race(git, expected_source, expected_feed):
            calls.append(1)
            if len(calls) == 2:
                # Another writer appends to the feed immediately before the publisher's final guard.
                tree = self.git("rev-parse", tip + "^{tree}", cwd=self.remote)
                other = self.git("commit-tree", tree, "-p", tip, data=b"Concurrent fixture writer\n", cwd=self.remote)
                self.git("update-ref", "refs/heads/catalogue", other, cwd=self.remote)
            return original(git, expected_source, expected_feed)

        with patch("tools.publish_catalogue.check_remote_refs", side_effect=race):
            with self.assertRaisesRegex(CatalogError, "drift"):
                self.publish()
        self.assertEqual(len(calls), 2)
        # Rewind only the owned remote main to make its identity disagree, without touching source.
        self.git("update-ref", "-d", "refs/heads/main", cwd=self.remote)
        with self.assertRaisesRegex(CatalogError, "source|Source"):
            self.publish()

    def test_real_git_refuses_revision_rollback(self):
        self.setup_git()
        self.config["revision"] = 6
        self.write(self.root / "catalogue.json", self.config)
        self.git("add", "catalogue.json")
        self.git("commit", "-m", "Higher revision fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        envelope = (self.snapshot / producer.SIGNATURE).read_bytes()
        (self.snapshot / producer.SIGNATURE).unlink()
        build(self.root, self.snapshot)
        (self.snapshot / producer.SIGNATURE).write_bytes(envelope)
        self.publish()
        tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        self.config["revision"] = 5
        self.write(self.root / "catalogue.json", self.config)
        self.git("add", "catalogue.json")
        self.git("commit", "-m", "Rollback fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        (self.snapshot / producer.SIGNATURE).unlink()
        build(self.root, self.snapshot)
        (self.snapshot / producer.SIGNATURE).write_bytes(envelope)
        with self.assertRaisesRegex(CatalogError, "rollback"):
            self.publish()
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote), tip)

    def test_real_git_refuses_unexpected_previous_members(self):
        self.setup_git()
        self.publish()
        tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        blob = self.git("hash-object", "-w", "--stdin", data=b"not catalogue data", cwd=self.remote)
        rows = self.git("ls-tree", tip, cwd=self.remote)
        tree = self.git("mktree", data=(rows + "\n100644 blob " + blob + "\tprivate-source.json\n").encode(), cwd=self.remote)
        bad = self.git("commit-tree", tree, "-p", tip, data=b"Unexpected member fixture\n", cwd=self.remote)
        self.git("update-ref", "refs/heads/catalogue", bad, cwd=self.remote)
        with self.assertRaisesRegex(CatalogError, "membership"):
            self.publish()
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote), bad)

    def test_real_git_normal_push_refuses_a_late_concurrent_append(self):
        self.setup_git()
        self.publish()
        tip = self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote)
        self.config["revision"] = 5
        self.write(self.root / "catalogue.json", self.config)
        self.git("add", "catalogue.json")
        self.git("commit", "-m", "Next revision for late race fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.git("push", str(self.remote), "HEAD:refs/heads/main")
        signature = (self.snapshot / producer.SIGNATURE).read_bytes()
        (self.snapshot / producer.SIGNATURE).unlink()
        build(self.root, self.snapshot)
        (self.snapshot / producer.SIGNATURE).write_bytes(signature)
        original = producer.Git.run
        concurrent = []

        def intercept(instance, *arguments, **kwargs):
            if arguments[0] == "push":
                tree = self.git("rev-parse", tip + "^{tree}", cwd=self.remote)
                other = self.git("commit-tree", tree, "-p", tip, data=b"Late concurrent append\n", cwd=self.remote)
                self.git("update-ref", "refs/heads/catalogue", other, cwd=self.remote)
                concurrent.append(other)
            return original(instance, *arguments, **kwargs)

        with patch.object(producer.Git, "run", intercept):
            with self.assertRaisesRegex(CatalogError, "Git operation failed"):
                self.publish()
        self.assertEqual(len(concurrent), 1)
        self.assertEqual(self.git("rev-parse", "refs/heads/catalogue", cwd=self.remote), concurrent[0])


if __name__ == "__main__":
    unittest.main()
