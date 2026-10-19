#!/usr/bin/env python3
"""Build precompiled static Nginx on native Linux release runners, never hosts."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
from stage import read


LOCK = Path("internal/releases/nginx-source-lock.json")
RUNTIMES = ("libc.a", "libgcc.a", "libgcc_eh.a")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def output(command, limit=1 << 20):
    raw = subprocess.check_output(command, timeout=30)
    if len(raw) > limit:
        raise ValueError(f"excessive tool output: {command[0]}")
    return raw.decode("utf-8").strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


class SourceRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        target = urllib.parse.urlsplit(newurl)
        if self.count > 3 or target.scheme != "https" or target.hostname not in self.hosts or target.username or target.password or target.port not in (None, 443):
            raise ValueError("source redirect outside approved HTTPS hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(source, archive):
    origin = urllib.parse.urlsplit(source["url"])
    if origin.scheme != "https" or origin.hostname not in ("nginx.org", "github.com", "codeload.github.com", "zlib.net") or origin.username or origin.password or origin.query or origin.fragment or origin.port not in (None, 443):
        raise ValueError("source URL outside approved upstreams")
    hosts = {origin.hostname}
    if origin.hostname == "github.com":
        hosts.update(("release-assets.githubusercontent.com", "objects.githubusercontent.com"))
    opener = urllib.request.build_opener(SourceRedirect(hosts))
    start, size, sha = time.monotonic(), 0, hashlib.sha256()
    request = urllib.request.Request(source["url"], headers={"User-Agent": "nginxpanel-release/1", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=60) as response, archive.open("xb") as target:
        if response.status != 200:
            raise ValueError("upstream source download was not complete")
        while chunk := response.read(1 << 20):
            size += len(chunk)
            if size > source["size"] or size > 64 << 20 or time.monotonic() - start > 300:
                raise ValueError("upstream source download exceeded its budget")
            sha.update(chunk)
            target.write(chunk)
    if size != source["size"] or sha.hexdigest() != source["sha256"]:
        raise ValueError(f"upstream source does not match lock: {source['id']}")


def unpack(archive, parent, expected_root):
    # Pinned upstream archives may contain PAX metadata. Only regular files and
    # directories are materialized; no upstream link or special file is followed.
    seen, total, count = set(), 0, 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            count += 1
            total += member.size
            if count > 20000 or total > 400 << 20 or member.size > 64 << 20 or member.size < 0:
                raise ValueError("source extraction exceeded its budget")
            if not name or name != path.as_posix() or path.is_absolute() or path.parts[0] != expected_root or ".." in path.parts or "\\" in name or any(ord(c) < 32 for c in name) or name in seen:
                raise ValueError("unsafe or repeated upstream source path")
            seen.add(name)
            target = parent / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, length=1 << 20)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise ValueError("upstream source contains a link or special file")
    return parent / expected_root


def linux_headers(parent, architecture):
    # musl-gcc excludes glibc's headers; OpenSSL still needs Linux UAPI.
    multiarch = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[architecture]
    include = Path("/usr/include")
    for name, source in (("linux", include / "linux"), ("asm-generic", include / "asm-generic"), ("asm", include / multiarch / "asm")):
        shutil.copytree(source, parent / "linux-uapi" / name)


def runtime_archives(destination):
    musl = [Path(p) for p in output(["dpkg-query", "-L", "musl-dev"]).splitlines() if p.endswith("/libc.a")]
    if len(musl) != 1:
        raise ValueError("musl-dev must supply exactly one static libc archive")
    paths = [musl[0]] + [Path(output(["musl-gcc", "-print-file-name=" + n])) for n in RUNTIMES[1:]]
    result = []
    for name, path in zip(RUNTIMES, paths):
        path = path.resolve(strict=True)
        if not path.is_relative_to("/usr/lib") or path.name != name:
            raise ValueError("static runtime archive is outside the system toolchain")
        owners = output(["dpkg-query", "-S", str(path)]).splitlines()
        if len(owners) != 1 or ": " not in owners[0]:
            raise ValueError("static runtime archive has no unique package owner")
        package, owned_path = owners[0].split(": ", 1)
        if owned_path != str(path):
            raise ValueError("static runtime package ownership differs")
        version = output(["dpkg-query", "-W", "-f=${Version}", package])
        copyright_file = (Path("/usr/share/doc") / package.split(":")[0] / "copyright").resolve(strict=True)
        if not copyright_file.is_relative_to("/usr/share/doc"):
            raise ValueError("toolchain copyright outside system documentation")
        license_file = "licenses/toolchain/" + name + ".txt"
        license_text = read(copyright_file, 2 << 20)
        if not license_text:
            raise ValueError("empty runtime copyright")
        if name != "libc.a" and b"GCC RUNTIME LIBRARY EXCEPTION" not in license_text.upper():
            raise ValueError("GCC runtime copyright lacks its library exception")
        (destination / license_file).write_bytes(license_text)
        result.append({"name": name, "path": str(path), "package": package, "version": version,
                       "sha256": digest(read(path, 32 << 20)), "license_file": license_file})
    (destination / "licenses/toolchain/GPL-3.txt").write_bytes(read("/usr/share/common-licenses/GPL-3", 256 << 10))
    return result


def sbom_package(identifier, name, version, location, sha, license_id):
    return {"SPDXID": identifier, "name": name, "versionInfo": version,
            "downloadLocation": location, "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha}],
            "licenseConcluded": "NOASSERTION", "licenseDeclared": license_id,
            "copyrightText": "NOASSERTION"}


def build(args):
    spec = json.loads(read(args.spec, 4 << 20))
    lock_raw = read(LOCK, 64 << 10)
    lock = json.loads(lock_raw)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or architecture != args.architecture:
        raise ValueError("native release runner architecture differs from requested asset")
    commit = output(["git", "rev-parse", "HEAD"])
    if commit != spec["commit"] or output(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise ValueError("Nginx build must use the approved clean source commit")
    if lock["schema"] != 1 or [s["id"] for s in lock["sources"]] != ["nginx", "openssl", "pcre2", "zlib"]:
        raise ValueError("unsupported native source lock")
    identifier = "nginx-linux-" + architecture
    packages = [p for p in spec["packages"] if p["asset"]["id"] == identifier]
    if len(packages) != 1:
        raise ValueError("publication must include exactly one matching Nginx asset")
    package = packages[0]
    asset = package["asset"]
    if package["directory"] != identifier or package["executable_files"] != ["bin/nginx"] or asset["component"] != "nginx" or asset["version"] != lock["version"] or asset["architecture"] != architecture or asset["abi"] != "static" or asset["features"] != lock["features"]:
        raise ValueError("Nginx publication and source recipe differ")
    workflow = f"{os.environ['GITHUB_RUN_ID']}/{os.environ['GITHUB_RUN_ATTEMPT']}"
    if not re.fullmatch(r"[0-9]+/[0-9]+", workflow):
        raise ValueError("native build must identify its workflow run")
    runner = f"{os.environ['ImageOS']}/{os.environ['ImageVersion']}"
    epoch = output(["git", "show", "-s", "--format=%ct", "HEAD"])
    env = dict(os.environ, CC="musl-gcc", SOURCE_DATE_EPOCH=epoch, LC_ALL="C", TZ="UTC")
    # An ephemeral runner's ambient flags must not override the locked recipe.
    for name in ("CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "LIBRARY_PATH", "CPATH", "OPENSSL_CONF", "OPENSSL_MODULES"):
        env.pop(name, None)
    args.output.mkdir(parents=True, exist_ok=False)
    destination = args.output / identifier
    try:
        for name in ("bin", "build", "licenses/toolchain"):
            (destination / name).mkdir(parents=True)
        compiler = output(["musl-gcc", "--version"]).splitlines()[0]
        runtime = runtime_archives(destination)
        toolchain = (output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"]) + "\n").encode()
        (destination / "build/toolchain-packages.txt").write_bytes(toolchain)
        (destination / "build/nginx-source-lock.json").write_bytes(lock_raw)
        with tempfile.TemporaryDirectory(prefix="nginxpanel-native-") as temp:
            linux_headers(Path(temp), architecture)
            roots = {}
            for source in lock["sources"]:
                archive = Path(temp) / (source["id"] + ".tar.gz")
                download(source, archive)
                roots[source["id"]] = unpack(archive, Path(temp), source["root"])
                for name in source["license_files"]:
                    target = destination / "licenses" / source["id"] / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    raw = read(roots[source["id"]] / name, 2 << 20)
                    if not raw:
                        raise ValueError("upstream license text is empty")
                    target.write_bytes(raw)
            subprocess.run(["./configure", *lock["configure_args"]], cwd=roots["nginx"], env=env, check=True, timeout=180)
            subprocess.run(["make", "-j", str(min(os.cpu_count() or 1, 8))], cwd=roots["nginx"], env=env, check=True, timeout=1500)
            binary = roots["nginx"] / "objs/nginx"
            shutil.copyfile(binary, destination / "bin/nginx")
            # Only the native build job runs its own output; the signer reads ELF.
            version = subprocess.run([str(binary), "-V"], env=env, check=True, capture_output=True, timeout=15)
            build_info = version.stdout + version.stderr
            if len(build_info) > 64 << 10 or f"nginx version: nginx/{lock['version']}\n".encode() not in build_info or f"built with OpenSSL {lock['sources'][1]['version']} ".encode() not in build_info:
                raise ValueError("built Nginx/OpenSSL versions do not match source lock")
        binary_hash = digest(read(destination / "bin/nginx", 128 << 20))
        (destination / "build/nginx-V.txt").write_bytes(build_info)
        provenance = {"schema": 1, "repository": spec["manifest"]["repository"],
                      "version": spec["manifest"]["version"], "commit": commit, "asset": identifier,
                      "scope": "native-nginx-source-and-static-runtime", "binary_sha256": binary_hash,
                      "workflow_run": workflow, "native_nginx": {
                          "lock_sha256": digest(lock_raw), "configure_args": lock["configure_args"],
                          "compiler": "musl-gcc", "compiler_version": compiler,
                          "build_info_sha256": digest(build_info), "toolchain_sha256": digest(toolchain),
                          "runtime_archives": runtime, "runner_image": runner}}
        write_json(destination / (identifier + ".provenance.json"), provenance)
        packages = [sbom_package("SPDXRef-nginx-binary", identifier, lock["version"], "NOASSERTION", binary_hash, asset["license"])]
        for source in lock["sources"]:
            packages.append(sbom_package("SPDXRef-" + source["id"] + "-source", source["id"], source["version"], source["url"], source["sha256"], source["license"]))
        extracted_licenses = []
        for archive in runtime:
            suffix = archive["name"].replace(".", "-").replace("_", "-")
            license_id = "LicenseRef-Runtime-" + suffix
            license_text = read(destination / archive["license_file"], 2 << 20)
            if archive["name"] != "libc.a":
                license_text += b"\n" + read(destination / "licenses/toolchain/GPL-3.txt", 256 << 10)
            extracted_licenses.append({"licenseId": license_id, "extractedText": license_text.decode("utf-8"), "name": archive["package"] + " copyright and runtime terms"})
            packages.append(sbom_package("SPDXRef-runtime-" + suffix, archive["package"] + "/" + archive["name"], archive["version"], "NOASSERTION", archive["sha256"], license_id))
        relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-nginx-binary"}]
        relationships.extend({"spdxElementId": "SPDXRef-nginx-binary", "relationshipType": "GENERATED_FROM" if p["SPDXID"].endswith("-source") else "STATIC_LINK", "relatedSpdxElement": p["SPDXID"]} for p in packages[1:])
        sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": identifier, "documentNamespace": f"https://github.com/{spec['manifest']['repository']}/native-sbom/{commit}/{identifier}/{binary_hash}",
                "creationInfo": {"created": datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: nginxpanel-native-builder-1"]},
                "packages": packages, "relationships": relationships, "hasExtractedLicensingInfos": extracted_licenses}
        write_json(destination / (identifier + ".spdx.json"), sbom)
        for root, directories, files in os.walk(destination):
            Path(root).chmod(0o755)
            for name in files:
                Path(root, name).chmod(0o644)
        (destination / "bin/nginx").chmod(0o755)
    except BaseException:
        # The output was exclusively created by this invocation.
        shutil.rmtree(args.output)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args())


if __name__ == "__main__":
    main()
