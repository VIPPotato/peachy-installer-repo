"""Real Windows CNG producer checks; ephemeral private keys never leave memory."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.build_catalog import encode
from tools import publish_catalogue as producer

SOURCE = Path(__file__).absolute().parents[1]


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "Windows built-in CNG required")
class SigningTests(unittest.TestCase):
    def test_actual_cng_signing_verification_and_refusals(self):
        scratch = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        if not scratch:
            raise RuntimeError("Set RUNNER_TEMP or TMPDIR to owned scratch")
        with tempfile.TemporaryDirectory(prefix="peachy-cng-producer-test-", dir=scratch) as temporary:
            work = Path(temporary)
            root = work / "source"
            root.mkdir()
            shutil.copytree(SOURCE / "mods", root / "mods")
            shutil.copytree(SOURCE / "tools/schemas", root / "tools/schemas")
            now = datetime.now(timezone.utc).replace(microsecond=0)
            config = {"repository": "VIPPotato/peachy-installer-repo", "revision": 4,
                      "generatedAt": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "expiresAt": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            (root / "catalogue.json").write_bytes(encode(config))
            snapshot = work / "snapshot"
            def git(*arguments, cwd=root):
                run = subprocess.run(["git", *arguments], cwd=cwd, env=producer.git_environment(),
                                     capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, "Owned Git fixture operation failed")
                return run.stdout.strip()

            git("init", "--initial-branch=main")
            git("add", "--", "catalogue.json", "mods", "tools")
            git("commit", "-m", "Owned CNG integration fixture")
            source_sha = git("rev-parse", "HEAD")
            remote = work / "feed.git"
            git("init", "--bare", str(remote))
            git("push", str(remote), "HEAD:refs/heads/main")
            producer.prepare(root, snapshot, source_sha)
            env = os.environ.copy()
            env.pop("PEACHY_CATALOGUE_SIGNING_KEY", None)
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                                     str(SOURCE / "tests/sign_catalogue_checks.ps1"),
                                     "-TestRoot", str(work), "-Signer", str(SOURCE / "tools/sign_catalogue.ps1")],
                                    capture_output=True, text=True, env=env, timeout=240)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(len(report["passed"]), 22)
            self.assertIn("stdin-bom-and-line-ending-accepted", report["passed"])
            self.assertIn("repeated-terminal-bom-refusal", report["passed"])
            self.assertIn("stdin-terminal-line-ending-accepted", report["passed"])
            self.assertIn("repeated-terminal-line-ending-refusal", report["passed"])
            self.assertTrue(report["privateKeyStayedInMemory"])
            self.assertEqual(report["algorithm"], "ecdsa-p256-sha256-p1363")
            # Complete prepare -> real CNG sign -> real Git publication/readback.
            # No mocks, public requests, retained keys or application operations.
            published = producer.publish(root, snapshot, work / "policy.json", source_sha, _local_remote=remote)
            self.assertEqual(published["status"], "published")
            self.assertEqual(published["commit"], git("rev-parse", "refs/heads/catalogue", cwd=remote))
            rerandomized = (work / "resigned-public-envelope.json").read_bytes()
            self.assertNotEqual((snapshot / producer.SIGNATURE).read_bytes(), rerandomized)
            (snapshot / producer.SIGNATURE).write_bytes(rerandomized)
            unchanged = producer.publish(root, snapshot, work / "policy.json", source_sha, _local_remote=remote)
            self.assertEqual(unchanged["status"], "unchanged")
            self.assertEqual(unchanged["commit"], published["commit"])


if __name__ == "__main__":
    unittest.main()
