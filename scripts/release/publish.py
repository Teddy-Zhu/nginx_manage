#!/usr/bin/env python3
"""Publish a complete signed directory through a new GitHub draft release."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def api(endpoint, body=None):
    command = ["gh", "api", endpoint]
    data = None
    if body is not None:
        command += ["--method", "PATCH", "--input", "-"]
        data = json.dumps(body).encode()
    return json.loads(subprocess.check_output(command, input=data))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repository", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--directory", required=True, type=Path)
    args = p.parse_args()
    manifest = json.loads((args.directory / "release-manifest.json").read_bytes())
    if manifest["repository"] != args.repository or "v" + manifest["version"] != args.tag:
        raise ValueError("release identity does not match signed directory")
    base = "repos/" + args.repository
    target = api(base + "/git/ref/tags/" + args.tag)["object"]
    for _ in range(4):
        if target["type"] == "commit":
            break
        if target["type"] != "tag":
            raise ValueError("release tag does not refer to a commit")
        target = api(base + "/git/tags/" + target["sha"])["object"]
    if target["type"] != "commit" or target["sha"] != args.commit:
        raise ValueError("release tag moved away from approved source commit")
    endpoint = base + "/releases/tags/" + args.tag
    prior = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if prior.returncode == 0:
        raise ValueError("release or recovery draft already exists; refusing overwrite")
    if "(HTTP 404)" not in prior.stderr:
        raise RuntimeError("cannot determine whether release already exists: " + prior.stderr)
    files = sorted(args.directory.iterdir())
    if not files or len(files) > 64 or any(not f.is_file() or f.is_symlink() or f.stat().st_size > 128 << 20 for f in files):
        raise ValueError("invalid signed release directory")
    expected = {}
    for path in files:
        digest = hashlib.sha256()
        with path.open("rb") as reader:
            for block in iter(lambda: reader.read(1 << 20), b""):
                digest.update(block)
        expected[path.name] = (path.stat().st_size, "sha256:" + digest.hexdigest())
    # Upload failure retains the draft for inspection. No clobber, deletion or
    # automatic reuse of a partial prior publication is performed.
    # Use the same approved notes as the signed manifest. GitHub's editable
    # release body is never an authority for receiver-side compatibility.
    with tempfile.TemporaryDirectory(prefix="nginxpanel-notes-") as temporary:
        notes = Path(temporary) / "notes.txt"
        notes.write_text(manifest["notes"], encoding="utf-8")
        subprocess.run(["gh", "release", "create", args.tag, *map(str, files), "--repo", args.repository,
                        "--draft", "--verify-tag", "--target", args.commit, "--title", args.tag, "--notes-file", str(notes)], check=True)
    release = api(endpoint)
    if release["tag_name"] != args.tag or not release["draft"] or release["target_commitish"] != args.commit:
        raise ValueError("created draft release identity changed")
    remote = release["assets"]
    if len(remote) != len(expected):
        raise ValueError("draft release asset count does not match signed directory")
    seen = set()
    for item in remote:
        name = item["name"]
        if name in seen or name not in expected or item["state"] != "uploaded" or item["size"] != expected[name][0] or item.get("digest") not in (None, "", expected[name][1]):
            raise ValueError("draft release contains missing or mismatched asset")
        seen.add(name)
    prerelease = manifest["channel"] == "prerelease"
    published = api(base + "/releases/" + str(release["id"]), {
        "draft": False, "prerelease": prerelease,
        "make_latest": "false" if prerelease else "legacy",
    })
    if published["id"] != release["id"] or published["draft"] or published["prerelease"] != prerelease:
        raise ValueError("release publication was not confirmed")
    print(f"Published {args.repository} {args.tag} ({release['id']})")


if __name__ == "__main__":
    main()
