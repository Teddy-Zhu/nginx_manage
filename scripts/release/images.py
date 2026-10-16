#!/usr/bin/env python3
"""Build fixed images in CI, then collect their digest-bound OCI metadata.

The merge step downloads manifests, configs and attestations, never image layers.
The Go publisher independently checks this graph before signing the release.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCANNER = "docker/buildkit-syft-scanner:1.12.0@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9"
LIMIT = 32 << 20


def read(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("invalid publication input file")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("publication input length is invalid")
    return data


def decode(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs)


def write(path, value):
    raw = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()
    if len(raw) > LIMIT:
        raise ValueError("image publication evidence exceeds 32 MiB")
    with path.open("xb") as destination:
        destination.write(raw)
    path.chmod(0o644)
    return {"path": path.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o644}


def image_repository(repository, image):
    return "ghcr.io/" + repository.lower() + "/" + ("panel" if image == "panel-launcher" else "nginx")


def identity(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", args.repository):
        raise ValueError("invalid repository identity")
    if not re.fullmatch(r"[0-9A-Za-z.+-]{1,128}", args.version) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.commit):
        raise ValueError("invalid source version or commit")
    run = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    if not re.fullmatch(r"[0-9]+-[0-9]+", run):
        raise ValueError("invalid workflow run identity")
    return {"schema": 1, "repository": args.repository, "version": args.version, "commit": args.commit}, run


def build(args):
    result, run = identity(args)
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture != args.architecture or platform.system() != "Linux":
        raise ValueError("image builds require the matching native Linux runner")
    if args.output.exists():
        raise ValueError("build receipt already exists")
    source = args.input / ("panel-linux-" + architecture)
    binaries = Path(".release/binaries")
    binaries.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / "nginxpanel", binaries / ("nginxpanel-" + architecture))
    launcher_sha256 = hashlib.sha256(read(binaries / ("nginxpanel-" + architecture), 192 << 20)).hexdigest()
    licenses = binaries / ("licenses-" + architecture)
    licenses.mkdir()
    licenses.chmod(0o755)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.txt"):
        shutil.copyfile(source / name, licenses / name)
        (licenses / name).chmod(0o644)
    result.update(architecture=architecture, images=[])
    for image, dockerfile, context in (
        ("panel-launcher", "deploy/docker/panel.Dockerfile", str(binaries)),
        ("nginx", "deploy/docker/nginx.Dockerfile", "."),
    ):
        repository = image_repository(args.repository, image)
        metadata = binaries / (image + ".build.json")
        command = ["docker", "buildx", "build", "--platform", "linux/" + architecture,
                   "--file", dockerfile, "--tag", repository + ":build-" + run + "-" + architecture,
                   "--output", "type=image,push=true,oci-mediatypes=true,oci-artifact=true",
                   "--attest", "type=provenance,mode=max,version=v0.2",
                   "--attest", "type=sbom,generator=" + SCANNER,
                   "--label", "org.nginxpanel.launcher.sha256=" + launcher_sha256,
                   "--metadata-file", str(metadata)]
        for name, value in (("source", "https://github.com/" + args.repository),
                            ("revision", args.commit), ("version", args.version)):
            command += ["--label", "org.opencontainers.image." + name + "=" + value]
        subprocess.run(command + [context], check=True, timeout=1200)
        digest = decode(read(metadata, 4 << 20))["containerimage.digest"]
        if not DIGEST.fullmatch(digest):
            raise ValueError("builder did not return an immutable image digest")
        result["images"].append({"id": image, "repository": repository, "digest": digest})
    write(args.output, result)


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        target = urllib.parse.urlsplit(url)
        if target.scheme != "https" or target.hostname not in ("ghcr.io", "pkg-containers.githubusercontent.com") or target.port not in (None, 443) or target.username or target.password or target.fragment:
            raise ValueError("registry redirect is outside the approved HTTPS hosts")
        redirected = super().redirect_request(request, response, code, message, headers, url)
        if target.hostname != urllib.parse.urlsplit(request.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    def __init__(self, repository):
        if not repository.startswith("ghcr.io/"):
            raise ValueError("only the approved GHCR repository is supported")
        self.path = repository.removeprefix("ghcr.io/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
        query = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:" + self.path + ":pull"})
        credentials = os.environ["GITHUB_ACTOR"] + ":" + os.environ["GH_TOKEN"]
        authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        token = decode(self.request("https://ghcr.io/token?" + query, {"Authorization": authorization}, 64 << 10))
        self.token = token["token"]
        if not isinstance(self.token, str) or not self.token or len(self.token) > 32768:
            raise ValueError("registry did not return a bounded pull token")

    def request(self, url, headers, limit):
        request = urllib.request.Request(url, headers=headers)
        try:
            with self.opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise ValueError("registry did not confirm metadata retrieval")
                raw = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            raise RuntimeError("registry metadata request failed with HTTP " + str(error.code)) from None
        if not raw or len(raw) > limit:
            raise ValueError("registry metadata exceeds the length bound")
        return raw

    def get(self, kind, reference, size=None):
        if kind not in ("manifests", "blobs") or not (DIGEST.fullmatch(reference) or kind == "manifests" and re.fullmatch(r"release-[0-9]+-[0-9]+", reference)):
            raise ValueError("invalid registry metadata selector")
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/octet-stream"}
        limit = 256 << 10 if kind == "manifests" else 16 << 20
        if size is not None:
            if not isinstance(size, int) or not 0 < size <= limit:
                raise ValueError("invalid OCI descriptor length")
            limit = size
        raw = self.request("https://ghcr.io/v2/" + self.path + "/" + kind + "/" + reference, headers, limit)
        if size is not None and len(raw) != size or DIGEST.fullmatch(reference) and "sha256:" + hashlib.sha256(raw).hexdigest() != reference:
            raise ValueError("registry metadata does not match its digest or length")
        return raw


def graph(registry, raw_index):
    index = decode(raw_index)
    if index.get("schemaVersion") != 2 or index.get("mediaType") != "application/vnd.oci.image.index.v1+json" or len(index.get("manifests", [])) not in (2, 4):
        raise ValueError("expected an OCI index with runnable and attestation manifests")
    blobs = {}
    metadata_bytes = len(raw_index)

    def fetch(descriptor, kind):
        nonlocal metadata_bytes
        digest = descriptor["digest"]
        if not DIGEST.fullmatch(digest):
            raise ValueError("invalid OCI content digest")
        if digest not in blobs:
            size = descriptor["size"]
            if not isinstance(size, int) or not 0 < size <= 16 << 20 or len(blobs) >= 24 or metadata_bytes + size > LIMIT * 3 // 4 - (64 << 10):
                raise ValueError("OCI metadata count or encoded size exceeds the publication bound")
            if "data" in descriptor:
                raw = base64.b64decode(descriptor["data"], validate=True)
                if not raw or len(raw) > 16 << 20 or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError("inline OCI metadata digest or length is invalid")
                blobs[digest] = raw
            else:
                blobs[digest] = registry.get(kind, digest, descriptor["size"])
            metadata_bytes += len(blobs[digest])
        if len(blobs[digest]) != descriptor["size"]:
            raise ValueError("OCI descriptor length changed")
        return decode(blobs[digest])

    platforms = []
    for descriptor in index["manifests"]:
        manifest = fetch(descriptor, "manifests")
        config = fetch(manifest["config"], "blobs")
        if descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
            layers = manifest.get("layers", [])
            if not 0 < len(layers) <= 4:
                raise ValueError("invalid attestation layer count")
            for layer in layers:
                if layer.get("mediaType") != "application/vnd.in-toto+json":
                    raise ValueError("unexpected attestation media type")
                fetch(layer, "blobs")
        else:
            target = descriptor["platform"]
            if target.get("os") != "linux" or target.get("architecture") not in ("amd64", "arm64") or config.get("architecture") != target["architecture"]:
                raise ValueError("unexpected runtime platform")
            platforms.append({"os": "linux", "architecture": target["architecture"],
                              "digest": descriptor["digest"], "config_digest": manifest["config"]["digest"],
                              "launcher_sha256": config["config"]["Labels"]["org.nginxpanel.launcher.sha256"]})
    evidence = {"schema": 1, "index": base64.b64encode(raw_index).decode(),
                "blobs": [{"digest": digest, "data": base64.b64encode(raw).decode()}
                          for digest, raw in sorted(blobs.items())]}
    return sorted(platforms, key=lambda p: p["architecture"]), evidence


def merge(args):
    publication, run = identity(args)
    sources = {}
    for architecture in ("amd64", "arm64"):
        receipt = decode(read(args.input / ("images-" + architecture + ".json"), 64 << 10))
        if any(receipt.get(key) != value for key, value in publication.items()) or receipt.get("architecture") != architecture or len(receipt.get("images", [])) != 2:
            raise ValueError("image build receipt identity changed")
        for image in receipt["images"]:
            image_id = image["id"]
            if image_id not in ("panel-launcher", "nginx") or image["repository"] != image_repository(args.repository, image_id) or not DIGEST.fullmatch(image["digest"]) or (image_id, architecture) in sources:
                raise ValueError("image build receipt contains an invalid or duplicate image")
            sources[image_id, architecture] = image
    args.output.mkdir()
    publication["images"] = []
    for image_id in ("panel-launcher", "nginx"):
        repository = image_repository(args.repository, image_id)
        registry = Registry(repository)
        expected = []
        references = []
        # Check both original indexes before creating the combined index. No
        # mutable source tag is ever used for this merge.
        for architecture in ("amd64", "arm64"):
            digest = sources[image_id, architecture]["digest"]
            platforms, _ = graph(registry, registry.get("manifests", digest))
            if len(platforms) != 1 or platforms[0]["architecture"] != architecture:
                raise ValueError("source index does not match its native build receipt")
            expected += platforms
            references.append(repository + "@" + digest)
        tag = "release-" + run
        subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", repository + ":" + tag, *references], check=True, timeout=120)
        raw = registry.get("manifests", tag)
        platforms, evidence = graph(registry, raw)
        if platforms != expected:
            raise ValueError("merged image platforms differ from the original builds")
        record = {"id": image_id, "repository": repository, "version": args.version, "commit": args.commit,
                  "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "platforms": platforms,
                  "evidence": write(args.output / (image_id + ".oci.json"), evidence)}
        publication["images"].append(record)
    write(args.output / "publication.json", publication)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("build", "merge"))
    for name in ("repository", "version", "commit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    args = parser.parse_args()
    if args.operation == "build":
        build(args)
    else:
        merge(args)


if __name__ == "__main__":
    main()
