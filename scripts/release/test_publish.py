"""Release publication checks without writing to GitHub."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import publish


class GitHub:
    def __init__(self, mutate=None, fail_upload=False, prior=None):
        self.release = None
        self.commands = []
        self.mutate = mutate
        self.fail_upload = fail_upload
        self.prior = prior
        self.tag_exists = False

    def output(self, command):
        endpoint = command[2]
        if endpoint.endswith("/releases?per_page=100"):
            assert command[3:] == ["--paginate", "--slurp"]
            return json.dumps([[{"id": 1, "tag_name": "unrelated"}], self.prior or []]).encode()
        if "/releases/tags/" in endpoint and self.release and not self.release["draft"]:
            return json.dumps(self.release).encode()
        raise subprocess.CalledProcessError(1, command, stderr=b"gh: Not Found (HTTP 404)")

    def run(self, command, **kwargs):
        if command[1] == "api" and "/git/ref/tags/" in command[2]:
            if self.release is None and not self.tag_exists:
                return subprocess.CompletedProcess(command, 1, "", "gh: Not Found (HTTP 404)")
            return subprocess.CompletedProcess(command, 0, json.dumps({"object": {
                "type": "commit", "sha": "a" * 40,
            }}), "")
        if command[1:3] != ["release", "create"]:
            raise AssertionError(f"unexpected GitHub write: {command}")
        self.commands.append(command)
        if self.fail_upload:
            raise subprocess.CalledProcessError(1, command)
        files = [Path(name) for name in command[4:command.index("--repo")]]
        self.release = {
            "id": 42, "tag_name": command[3], "draft": "--draft" in command,
            "prerelease": "--prerelease" in command,
            "target_commitish": command[command.index("--target") + 1],
            "assets": [{"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()} for path in files],
        }
        if self.mutate:
            self.mutate(self.release)
        return subprocess.CompletedProcess(command, 0)


class PublishTests(unittest.TestCase):
    def invoke(self, github, *, image=False, beta=True):
        github.tag_exists = not image and not beta
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            version = "1.0.1-44.1-dev" if beta else "1.0.0"
            tag = ("nginx-v" if image else "v") + version
            manifest = {"repository": "validation/panel", "version": version,
                        "channel": "beta" if beta else "stable", "notes": "发布说明\n",
                        "assets": [] if image else [{"id": "panel-linux-amd64"}],
                        "images": [{"id": "nginx"}] if image else []}
            (directory / "release-manifest.json").write_text(json.dumps(manifest))
            (directory / "checksums.txt").write_text("")
            args = ["publish.py", "--repository", "validation/panel", "--tag", tag,
                    "--commit", "a" * 40, "--directory", str(directory)]
            if beta or image:
                args.append("--create-tag")
            with patch.object(sys, "argv", args), \
                    patch.object(publish.subprocess, "run", side_effect=github.run), \
                    patch.object(publish.subprocess, "check_output", side_effect=github.output), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                publish.main()
            self.assertIn("Published validation/panel", output.getvalue())

    def test_direct_stable_and_beta_publication_for_core_and_independent_nginx(self):
        for image in (False, True):
            for beta in (False, True):
                with self.subTest(image=image, beta=beta):
                    github = GitHub()
                    self.invoke(github, image=image, beta=beta)
                    self.assertFalse(github.release["draft"])
                    self.assertEqual(github.release["prerelease"], beta)
                    command, = github.commands
                    self.assertIn("--latest=false" if beta or image else "--latest=true", command)
                    self.assertEqual("--verify-tag" in command, not beta and not image)
                    self.assertEqual("setup.sh" in {item["name"] for item in github.release["assets"]}, not image)

    def test_existing_published_release_and_recovery_draft_on_later_page_are_not_overwritten(self):
        for draft in (False, True):
            with self.subTest(draft=draft):
                github = GitHub(prior=[{"id": 99, "tag_name": "v1.0.1-44.1-dev", "draft": draft}])
                with self.assertRaisesRegex(ValueError, "id=99.*refusing overwrite"):
                    self.invoke(github)
                self.assertEqual(github.commands, [])

    def test_upload_failure_is_not_reported_as_success_or_followed_by_another_write(self):
        github = GitHub(fail_upload=True)
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(github)
        self.assertIsNone(github.release)
        self.assertEqual(len(github.commands), 1)

    def test_published_identity_channel_and_assets_are_still_checked(self):
        changes = [
            lambda release: release.update(draft=True),
            lambda release: release.update(prerelease=False),
            lambda release: release.update(target_commitish="b" * 40),
            lambda release: release["assets"].pop(),
            lambda release: release["assets"][0].update(digest="sha256:" + "0" * 64),
            lambda release: release["assets"][0].update(size=0),
        ]
        for index, change in enumerate(changes):
            with self.subTest(change=index), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.invoke(GitHub(mutate=change))

    def test_release_listing_errors_are_not_treated_as_absence(self):
        with patch.object(publish.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, ["gh", "api"])):
            with self.assertRaises(subprocess.CalledProcessError):
                publish.require_new_release("repos/validation/panel", "v1.0.0")


if __name__ == "__main__":
    unittest.main()
