#!/usr/bin/env python3
"""Assemble official code without setuptools, pip or a bundled interpreter."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from nginx import digest, download, output, unpack, write_json
from stage import read


LOCK = Path("internal/releases/fail2ban-source-lock.json")
ENTRIES = ("bin/fail2ban-server", "bin/fail2ban-client", "bin/fail2ban-regex")


def source_path(name):
    if name in ("COPYING", "README.md", "ChangeLog", *ENTRIES):
        return True
    if name.startswith("config/"):
        return name.endswith(".conf")
    return (name.startswith("fail2ban/") and name.endswith(".py")
            and not name.startswith("fail2ban/tests/") and name != "fail2ban/setup.py")


def assemble(args):
    spec = json.loads(read(args.input_root / "publication.json", 4 << 20))
    raw = read(LOCK, 64 << 10)
    lock = json.loads(raw)
    commit = output(["git", "rev-parse", "HEAD"])
    if commit != spec["commit"] or output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise ValueError("Fail2ban assembly must use the approved clean source commit")
    if lock["schema"] != 1 or platform.python_implementation() != "CPython" or sys.version_info.major != 3 or not lock["python"]["minimum_minor"] <= sys.version_info.minor <= lock["python"]["maximum_minor"]:
        raise ValueError("assembly Python does not meet the locked component range")
    packages = [p for p in spec["packages"] if p["asset"]["id"] == "fail2ban"]
    if len(packages) != 1:
        raise ValueError("publication must include exactly one official Fail2ban code asset")
    package = packages[0]
    asset = package["asset"]
    if package["directory"] != "fail2ban" or package["executable_files"] != list(ENTRIES) or asset["component"] != "fail2ban" or asset["version"] != lock["version"] or asset["python"] != lock["python"] or asset["abi"] != "system-python" or asset["architecture"] != "any" or asset["license"] != lock["license"]:
        raise ValueError("Fail2ban publication differs from the locked code recipe")
    workflow = f"{os.environ['GITHUB_RUN_ID']}/{os.environ['GITHUB_RUN_ATTEMPT']}"
    if not re.fullmatch(r"[0-9]+/[0-9]+", workflow):
        raise ValueError("assembly must identify its workflow run")
    epoch = output(["git", "show", "-s", "--format=%ct", "HEAD"])
    destination = args.input_root / "fail2ban"
    destination.mkdir()
    try:
        (destination / "build").mkdir()
        inventory = []
        total = 0
        with tempfile.TemporaryDirectory(prefix="nginxpanel-fail2ban-") as temp:
            archive = Path(temp) / "source.tar.gz"
            download(dict(lock, id="fail2ban"), archive)
            source = unpack(archive, Path(temp), lock["root"])
            for path in sorted(source.rglob("*")):
                if path.is_symlink():
                    raise ValueError("official source contains a link")
                if not path.is_file():
                    continue
                name = path.relative_to(source).as_posix()
                if not source_path(name):
                    continue
                if len(name) > 256 or not re.fullmatch(r"[a-zA-Z0-9_./+\-]+", name):
                    raise ValueError("official file is not a valid signed asset path")
                data = read(path, 2 << 20)
                total += len(data)
                if total > 32 << 20 or len(inventory) >= 1024:
                    raise ValueError("official code assembly exceeded its budget")
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                mode = 0o755 if name in ENTRIES else 0o644
                target.chmod(mode)
                inventory.append({"path": name, "sha256": digest(data), "size": len(data), "mode": mode})
        inventory.sort(key=lambda item: item["path"])
        copied = {f["path"]: f["sha256"] for f in inventory}
        if any(copied.get(name) != sha for name, sha in lock["required_files"].items()):
            raise ValueError("official entry or compatibility code differs from the source lock")
        if any(not read(destination / name, 64 << 10) for name in lock["license_files"]):
            raise ValueError("official component license text is missing")
        write_json(destination / "build/source-files.json", inventory)
        (destination / "build/fail2ban-source-lock.json").write_bytes(raw)
        versions = {}
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}
        for name in ENTRIES:
            tool = name.removeprefix("bin/")
            module = tool.replace("-", "")
            call = "exec_command_line()" if tool == "fail2ban-regex" else "exec_command_line(sys.argv)"
            bootstrap = ("import sys;sys.path.insert(0,sys.argv.pop(1));"
                         f"from fail2ban.client.{module} import exec_command_line;"
                         f"sys.argv[0]='{tool}';{call}")
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", bootstrap, str(destination.resolve()), "--version"],
                                    cwd="/", env=env, check=True, capture_output=True, timeout=15)
            version = (result.stdout + result.stderr).decode("utf-8")
            expected = f"{tool} {lock['version']}" if tool == "fail2ban-regex" else "Fail2Ban v" + lock["version"]
            if len(version) > 4096 or version.strip() != expected:
                raise ValueError("official entry returned a different version")
            versions[name] = version
        write_json(destination / "build/entry-versions.json", versions)
        provenance = {"schema": 1, "repository": spec["manifest"]["repository"],
                      "version": spec["manifest"]["version"], "commit": commit, "asset": "fail2ban",
                      "scope": "fail2ban-official-code", "workflow_run": workflow,
                      "fail2ban": {"lock_sha256": digest(raw),
                                   "inventory_sha256": digest(read(destination / "build/source-files.json", 1 << 20)),
                                   "versions_sha256": digest(read(destination / "build/entry-versions.json", 16 << 10)),
                                   "assembly_python_version": platform.python_version()}}
        write_json(destination / "fail2ban.provenance.json", provenance)
        compatibility = b"".join(read(destination / name, 64 << 10) for name in lock["license_files"] if name.startswith("fail2ban/compat/"))
        sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "fail2ban", "documentNamespace": f"https://github.com/{spec['manifest']['repository']}/component-sbom/{commit}/fail2ban/{lock['sha256']}",
                "creationInfo": {"created": datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: nginxpanel-fail2ban-assembler-1"]},
                "packages": [{"SPDXID": "SPDXRef-fail2ban-source", "name": "fail2ban", "versionInfo": lock["version"],
                              "downloadLocation": lock["url"], "filesAnalyzed": False,
                              "checksums": [{"algorithm": "SHA256", "checksumValue": lock["sha256"]}],
                              "licenseDeclared": lock["license"], "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"}],
                "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-fail2ban-source"}],
                "hasExtractedLicensingInfos": [{"licenseId": "LicenseRef-Async-Compat", "extractedText": compatibility.decode("utf-8"), "name": "Official async compatibility source notices"}]}
        write_json(destination / "fail2ban.spdx.json", sbom)
        for root, directories, files in os.walk(destination):
            Path(root).chmod(0o755)
            for name in files:
                path = Path(root, name)
                path.chmod(0o755 if path.relative_to(destination).as_posix() in ENTRIES else 0o644)
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", required=True, type=Path)
    assemble(parser.parse_args())


if __name__ == "__main__":
    main()
