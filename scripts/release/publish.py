#!/usr/bin/env python3
"""Publish a complete signed directory through a new GitHub draft release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def api(endpoint, body=None):
    command = ["gh", "api", endpoint]
    data = None
    if body is not None:
        command += ["--method", "PATCH", "--input", "-"]
        data = json.dumps(body).encode()
    return json.loads(subprocess.check_output(command, input=data))


def stage_bootstrap(directory, repository, tag):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValueError("invalid bootstrap repository")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", tag):
        raise ValueError("invalid bootstrap release tag")
    source = Path("setup.sh").read_text(encoding="utf-8")
    if source.count('default_repository="Teddy-Zhu/nginx_manage"') != 1 or source.count('default_version="latest"') != 1:
        raise ValueError("bootstrap identity placeholders are missing or duplicated")
    source = source.replace('default_repository="Teddy-Zhu/nginx_manage"', f'default_repository="{repository}"')
    source = source.replace('default_version="latest"', f'default_version="{tag}"')
    with (directory / "setup.sh").open("x", encoding="utf-8") as output:
        output.write(source)
    # 首次安装脚本通过 GitHub HTTPS 获取；面板归档仍由原签名清单绑定。
    checksums = directory / "checksums.txt"
    lines = checksums.read_text(encoding="utf-8").splitlines()
    if any(line.endswith("  setup.sh") for line in lines):
        raise ValueError("bootstrap checksum already exists")
    lines.append(hashlib.sha256(source.encode()).hexdigest() + "  setup.sh")
    checksums.write_text("\n".join(sorted(lines, key=lambda line: line.split("  ", 1)[1])) + "\n", encoding="utf-8")


def verify_tag(base, tag, commit, allow_missing=False):
    result = subprocess.run(["gh", "api", base + "/git/ref/tags/" + tag], capture_output=True, text=True)
    if result.returncode:
        if allow_missing and "(HTTP 404)" in result.stderr:
            return
        raise RuntimeError("cannot verify source tag: " + result.stderr)
    target = json.loads(result.stdout)["object"]
    for _ in range(4):
        if target["type"] == "commit":
            break
        if target["type"] != "tag":
            raise ValueError("release tag does not refer to a commit")
        target = api(base + "/git/tags/" + target["sha"])["object"]
    if target["type"] != "commit" or target["sha"] != commit:
        raise ValueError("release tag moved away from approved source commit")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repository", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--directory", required=True, type=Path)
    p.add_argument("--create-tag", action="store_true", help="create a missing tag for a -dev Beta build")
    args = p.parse_args()
    manifest = json.loads((args.directory / "release-manifest.json").read_bytes())
    image_only = not manifest["assets"] and len(manifest["images"]) == 1 and manifest["images"][0]["id"] == "nginx"
    prefix = "nginx-v" if image_only else "v"
    if manifest["repository"] != args.repository or prefix + manifest["version"] != args.tag:
        raise ValueError("release identity does not match signed directory")
    if manifest["channel"] not in ("stable", "beta"):
        raise ValueError("unsupported release channel")
    if args.create_tag and (manifest["channel"] != "beta" or not manifest["version"].endswith("-dev")):
        raise ValueError("automatic source tags are only allowed for -dev Beta releases")
    base = "repos/" + args.repository
    verify_tag(base, args.tag, args.commit, allow_missing=args.create_tag)
    endpoint = base + "/releases/tags/" + args.tag
    prior = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if prior.returncode == 0:
        raise ValueError("release or recovery draft already exists; refusing overwrite")
    if "(HTTP 404)" not in prior.stderr:
        raise RuntimeError("cannot determine whether release already exists: " + prior.stderr)
    if not image_only:
        stage_bootstrap(args.directory, args.repository, args.tag)
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
        command = ["gh", "release", "create", args.tag, *map(str, files), "--repo", args.repository,
                   "--draft", "--target", args.commit, "--title", args.tag, "--notes-file", str(notes)]
        if not args.create_tag:
            command.append("--verify-tag")
        subprocess.run(command, check=True)
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
    verify_tag(base, args.tag, args.commit, allow_missing=args.create_tag)
    prerelease = manifest["channel"] == "beta"
    published = api(base + "/releases/" + str(release["id"]), {
        "draft": False, "prerelease": prerelease,
        "make_latest": "false" if prerelease or image_only else "true",
    })
    if published["id"] != release["id"] or published["draft"] or published["prerelease"] != prerelease:
        raise ValueError("release publication was not confirmed")
    verify_tag(base, args.tag, args.commit)
    print(f"Published {args.repository} {args.tag} ({release['id']})")


if __name__ == "__main__":
    main()
