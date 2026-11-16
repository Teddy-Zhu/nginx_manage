#!/usr/bin/env python3
"""Stage built files, actual dependency notices and source evidence for signing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def read(path, limit):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > limit:
        raise ValueError(f"invalid release input: {path}")
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError(f"oversized release input: {path}")
    return raw


def json_stream(path):
    raw = read(path, 64 << 20).decode("utf-8")
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            return
        value, offset = decoder.raw_decode(raw, offset)
        yield value


def notices(records):
    output = bytearray()
    pattern = re.compile(r"^(licen[cs]e|copying|notice|copyright|patents)([._-].*)?$", re.I)
    for name, version, directory in sorted(records):
        root = Path(directory).resolve(strict=True)
        found = [p for p in sorted(root.iterdir()) if pattern.fullmatch(p.name) and p.is_file()]
        if not found or len(found) > 32:
            raise ValueError(f"dependency license files missing or excessive: {name}@{version}")
        for path in found:
            if not path.resolve().is_relative_to(root):
                raise ValueError(f"dependency license escapes package: {name}@{version}")
            raw = read(path, 1 << 20)
            if not raw:
                raise ValueError(f"empty dependency license: {name}@{version}")
            output.extend(f"\n===== {name}@{version} / {path.name} =====\n".encode())
            output.extend(raw)
            output.extend(b"\n")
            if len(output) > 16 << 20:
                raise ValueError("dependency notices exceed 16 MiB")
    return bytes(output)


def node_records(value, records):
    if isinstance(value, list):
        for child in value:
            node_records(child, records)
        return
    if not isinstance(value, dict):
        raise ValueError("invalid pnpm dependency report")
    for section in ("dependencies", "optionalDependencies"):
        for name, child in value.get(section, {}).items():
            if not isinstance(child, dict) or not child.get("version") or not child.get("path"):
                raise ValueError(f"incomplete pnpm dependency: {name}")
            path = Path(child["path"]).resolve(strict=True)
            if not path.is_relative_to(Path("web/node_modules").resolve()):
                raise ValueError(f"production dependency outside installed tree: {name}")
            records.add((name, child["version"], str(path)))
            node_records(child, records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--source-sbom", required=True, type=Path)
    parser.add_argument("--go-packages", required=True, type=Path)
    parser.add_argument("--node-dependencies", required=True, type=Path)
    parser.add_argument("--binaries", required=True, type=Path)
    args = parser.parse_args()
    spec = json.loads(read(args.input_root / "publication.json", 4 << 20))
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude)internal/webui/dist"])
    if commit != spec["commit"] or status:
        raise ValueError("publication must use the approved clean source commit")
    embedded_dist = Path("internal/webui/dist")
    if embedded_dist.is_symlink() or not embedded_dist.is_dir() or not (embedded_dist / "index.html").is_file() or (embedded_dist / "index.html").is_symlink():
        raise ValueError("frontend must be built into the core embed directory before release compilation")
    project_license = read("LICENSE", 256 << 10)
    if not project_license:
        raise ValueError("project LICENSE must be supplied before publishing")
    go_records = set()
    for package in json_stream(args.go_packages):
        module = package.get("Module")
        if not module or module.get("Main"):
            continue
        if module.get("Replace") or not module.get("Dir") or not module.get("Version"):
            raise ValueError("Go publication dependency is replaced or unresolved")
        go_records.add((module["Path"], module["Version"], module["Dir"]))
    if not go_records:
        raise ValueError("Go production dependency report is empty")
    go_root = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    go_notice = b"===== Go standard library =====\n" + read(go_root / "LICENSE", 256 << 10) + notices(go_records)
    npm_records = set()
    node_records(json.loads(read(args.node_dependencies, 32 << 20)), npm_records)
    if not npm_records:
        raise ValueError("frontend production dependency report is empty")
    node_notice = notices(npm_records)
    sbom = read(args.source_sbom, 16 << 20)
    shared = {
        "schema": 1, "repository": spec["manifest"]["repository"],
        "version": spec["manifest"]["version"], "commit": commit,
        "scope": "source-and-build-dependencies",
        "go_version": subprocess.check_output(["go", "env", "GOVERSION"], text=True).strip(),
        "node_version": subprocess.check_output(["node", "--version"], text=True).strip(),
        "pnpm_version": subprocess.check_output(["pnpm", "--version"], text=True).strip(),
        "go_sum_sha256": hashlib.sha256(read("go.sum", 8 << 20)).hexdigest(),
        "web_lock_sha256": hashlib.sha256(read("web/pnpm-lock.yaml", 8 << 20)).hexdigest(),
        "workflow_run": f"{os.environ['GITHUB_RUN_ID']}/{os.environ['GITHUB_RUN_ATTEMPT']}",
    }
    for package in spec["packages"]:
        asset = package["asset"]
        if asset["component"] != "panel":
            raise ValueError("default staging only accepts the core package")
        destination = args.input_root / package["directory"]
        destination.mkdir()
        provenance = dict(shared, asset=asset["id"])
        if asset["component"] == "panel":
            binary = args.binaries / ("nginxpanel-" + asset["architecture"])
            shutil.copyfile(binary, destination / "nginxpanel")
            provenance["binary_sha256"] = hashlib.sha256(read(binary, 192 << 20)).hexdigest()
            # 安装入口随面板进入同一签名文件清单，不另造一份二进制安装包。
            for name in ("install.sh", "manage.sh", "deploy/native/install.sh", "deploy/native/lifecycle.sh"):
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(read(name, 256 << 10))
            license_notices = go_notice + node_notice
        else:
            raise ValueError("default staging only accepts the core package")
        if len(license_notices) > 16 << 20:
            raise ValueError("combined dependency notices exceed 16 MiB")
        (destination / "LICENSE").write_bytes(project_license)
        (destination / "THIRD_PARTY_NOTICES.txt").write_bytes(license_notices)
        (destination / (asset["id"] + ".spdx.json")).write_bytes(sbom)
        (destination / (asset["id"] + ".provenance.json")).write_text(json.dumps(provenance, indent=2) + "\n")
        for root, directories, files in os.walk(destination):
            Path(root).chmod(0o755)
            for name in files:
                Path(root, name).chmod(0o644)


if __name__ == "__main__":
    main()
