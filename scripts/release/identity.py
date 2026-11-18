#!/usr/bin/env python3
"""Pin release versions to source, with independent tag-free Nginx versions."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def identity(component, tag, version, run, attempt, reuse_version=False, channel=""):
    prefix = "nginx-v" if component == "nginx" else "v"
    if channel and (component != "nginx" or tag or channel not in ("stable", "dev")):
        raise ValueError("independent release channels require an untagged Nginx build")
    create_tag = not tag
    if tag and reuse_version:
        raise ValueError("a tagged release cannot reuse a generated version")
    if tag:
        if not tag.startswith(prefix):
            raise ValueError("release tag has the wrong component prefix")
        version = tag[len(prefix):]
    else:
        if channel == "stable":
            if "-" in version.split("+", 1)[0]:
                raise ValueError("stable component versions cannot contain a prerelease suffix")
        elif channel == "dev" and not version.endswith("-dev"):
            version += "-dev"
        if channel != "stable" and (not version.endswith("-dev") or "+" in version):
            raise ValueError("tag-free builds require a base version ending in -dev, without build metadata")
        if channel != "stable" and not reuse_version:
            if not re.fullmatch(r"[1-9][0-9]*", run) or not re.fullmatch(r"[1-9][0-9]*", attempt):
                raise ValueError("development builds require the GitHub run ID and attempt")
            version = version[:-4] + f"-{run}.{attempt}-dev"
        tag = prefix + version
    # The Go publication tool performs the complete SemVer validation before
    # signing. This bound also keeps paths, workflow outputs and OCI tags safe.
    if len(version) > 96 or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid release version")
    base, _, metadata = version.partition("+")
    _, has_pre, pre = base.partition("-")
    if has_pre and any(not part or part.isdigit() and len(part) > 1 and part.startswith("0") for part in pre.split(".")) or "+" in version and any(not part for part in metadata.split(".")):
        raise ValueError("invalid SemVer identifiers")
    return version, tag, create_tag


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--component", choices=["panel", "nginx"], required=True)
    p.add_argument("--tag", default="")
    p.add_argument("--version", default="")
    p.add_argument("--channel", choices=("stable", "dev"), default="", help="independent Nginx release channel")
    p.add_argument("--reuse-version", action="store_true", help="reuse a pinned development build version during publication")
    args = p.parse_args()
    version, tag, create_tag = identity(args.component, args.tag, args.version,
                                        os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", ""), args.reuse_version, args.channel)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if not create_tag:
        target = subprocess.check_output(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], text=True).strip()
        if target != commit:
            raise ValueError("release tag differs from checked-out source")
        folder = "/nginx" if args.component == "nginx" else ""
        notes = Path(f"deploy/release/notes{folder}/{version}.md")
        policy = Path(f"deploy/release/policies{folder}/{version}.json")
        if not notes.is_file() or not policy.is_file():
            raise ValueError("tagged releases require committed notes and policy")
    else:
        # Keep generated approval inputs outside the source and package tree.
        # Independent component builds do not need committed version-tag files.
        root = Path(os.environ["RUNNER_TEMP"]) / f"release-{args.component}"
        root.mkdir(exist_ok=True)
        notes, policy = root / "notes.md", root / "policy.json"
        description = "Nginx 组件稳定版" if args.channel == "stable" else "Beta 开发预览版本"
        lines = [f"{description} {version}"]
        if args.component == "nginx":
            capabilities = json.loads(Path("deploy/docker/nginx-capabilities.json").read_text(encoding="utf-8"))
            engine = capabilities["nginx_version"]
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", engine):
                raise ValueError("invalid Nginx engine version in image capabilities")
            lines += ["", f"Nginx 版本：{engine}"]
        notes.write_text("\n".join([*lines, "", f"源码提交：{commit}", ""]), encoding="utf-8")
        policy.write_text(json.dumps({"version": version, "automatic_rollback": False}) + "\n", encoding="utf-8")
    values = {"version": version, "commit": commit, "tag": tag,
              "create_tag": str(create_tag).lower(), "notes": str(notes), "policy": str(policy)}
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
