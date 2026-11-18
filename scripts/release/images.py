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
import subprocess
import sys
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
    if image != "nginx":
        raise ValueError("unsupported image component")
    configured = os.environ.get("NGINX_IMAGE_REPOSITORY", "")
    if configured:
        if not re.fullmatch(r"docker\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*", configured) or len(configured) > 240:
            raise ValueError("NGINX_IMAGE_REPOSITORY must be docker.io/namespace/repository without a tag")
        return configured
    return "ghcr.io/" + repository.lower() + "/nginx"


def identity(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", args.repository):
        raise ValueError("invalid repository identity")
    if not re.fullmatch(r"[0-9][0-9A-Za-z.-]{0,127}", args.version) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.commit):
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
    binaries = Path(".release/binaries")
    binaries.mkdir(parents=True, exist_ok=True)
    launcher = binaries / ("nginxpanel-" + architecture)
    licenses = binaries / ("licenses-" + architecture)
    # The image workflow builds its own launcher; no core release is downloaded.
    if not launcher.is_file() or launcher.is_symlink() or launcher.stat().st_size == 0:
        raise ValueError("image launcher binary is missing")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.txt"):
        read(licenses / name, 16 << 20)
    result.update(architecture=architecture, images=[])
    image = "nginx"
    repository = image_repository(args.repository, image)
    metadata = binaries / (image + ".build.json")
    command = ["docker", "buildx", "build", "--platform", "linux/" + architecture,
               "--file", "deploy/docker/nginx.Dockerfile", "--tag", repository + ":build-" + run + "-" + architecture,
               "--output", "type=image,push=true,oci-mediatypes=true,oci-artifact=true",
               "--attest", "type=provenance,mode=max,version=v0.2",
               "--attest", "type=sbom,generator=" + SCANNER,
               "--metadata-file", str(metadata)]
    for name, value in (("source", "https://github.com/" + args.repository),
                        ("revision", args.commit), ("version", args.version)):
        command += ["--label", "org.opencontainers.image." + name + "=" + value]
    subprocess.run(command + ["."], check=True, timeout=1200)
    digest = decode(read(metadata, 4 << 20))["containerimage.digest"]
    if not DIGEST.fullmatch(digest):
        raise ValueError("builder did not return an immutable image digest")
    result["images"].append({"id": image, "repository": repository, "digest": digest})
    write(args.output, result)


class RegistryRedirectRejected(ValueError):
    pass


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, request, response, code, message, headers, url):
        try:
            target = urllib.parse.urlsplit(url)
            host, port = target.hostname, target.port
        except ValueError:
            raise RegistryRedirectRejected(f"registry redirect HTTP {code} has a malformed target") from None
        if target.scheme != "https" or port not in (None, 443):
            reason = "expected HTTPS on port 443"
        elif target.username is not None or target.password is not None or target.fragment:
            reason = "target contains user info or a fragment"
        elif host not in self.hosts:
            reason = "target host is not approved"
        else:
            reason = ""
        if reason:
            # The path and query can contain signed storage credentials.
            safe_host = host if host and re.fullmatch(r"[a-z0-9.-]{1,253}", host) else "<invalid host>"
            raise RegistryRedirectRejected(f"registry redirect HTTP {code} to {safe_host} rejected: {reason}")
        redirected = super().redirect_request(request, response, code, message, headers, url)
        if redirected is not None and host != urllib.parse.urlsplit(request.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


class RegistryNotFound(RuntimeError):
    pass


class Registry:
    def __init__(self, repository):
        host, _, self.path = repository.partition("/")
        if host == "docker.io" and re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*", self.path):
            self.origin, realm, service = "https://registry-1.docker.io", "https://auth.docker.io/token", "registry.docker.io"
            username, password = os.environ.get("DOCKERHUB_USERNAME", ""), os.environ.get("DOCKERHUB_TOKEN", "")
            hosts = {
                "registry-1.docker.io",
                "auth.docker.io",
                "production.cloudfront.docker.com",
                "production.cloudflare.docker.com",
                "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
                "docker-images-prod.s3.amazonaws.com",
                "docker-images-prod.s3.us-east-1.amazonaws.com",
                "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com",
            }
        elif host == "ghcr.io" and re.fullmatch(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*/nginx", self.path):
            self.origin, realm, service = "https://ghcr.io", "https://ghcr.io/token", "ghcr.io"
            username, password = os.environ["GITHUB_ACTOR"], os.environ["GH_TOKEN"]
            hosts = {"ghcr.io", "pkg-containers.githubusercontent.com"}
        else:
            raise ValueError("only canonical Docker Hub and project GHCR repositories are supported")
        if bool(username) != bool(password):
            raise ValueError("registry username and token must be provided together")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects(hosts))
        query = urllib.parse.urlencode({"service": service, "scope": "repository:" + self.path + ":pull"})
        self.token_url = realm + "?" + query
        self.allow_anonymous_blob_retry = host == "docker.io" and bool(username)
        self.anonymous_blob_token = None
        headers = {}
        if username:
            headers["Authorization"] = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
        self.token = self.pull_token(headers)

    def pull_token(self, headers):
        response = decode(self.request(self.token_url, headers, 64 << 10))
        token = response.get("token", response.get("access_token"))
        if not isinstance(token, str) or not token or len(token) > 32768:
            raise ValueError("registry did not return a bounded pull token")
        return token

    def request(self, url, headers, limit):
        request = urllib.request.Request(url, headers=headers)
        try:
            with self.opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise ValueError("registry did not confirm metadata retrieval")
                raw = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise RegistryNotFound("registry metadata was not found") from None
            raise RuntimeError("registry metadata request failed with HTTP " + str(error.code)) from None
        if not raw or len(raw) > limit:
            raise ValueError("registry metadata exceeds the length bound")
        return raw

    def get(self, kind, reference, size=None):
        if kind not in ("manifests", "blobs") or not (DIGEST.fullmatch(reference) or kind == "manifests" and re.fullmatch(r"(?:release-[0-9]+-[0-9]+|v[0-9][0-9A-Za-z_.-]{0,126})", reference)):
            raise ValueError("invalid registry metadata selector")
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/octet-stream"}
        limit = 256 << 10 if kind == "manifests" else 16 << 20
        if size is not None:
            if not isinstance(size, int) or not 0 < size <= limit:
                raise ValueError("invalid OCI descriptor length")
            limit = size
        url = self.origin + "/v2/" + self.path + "/" + kind + "/" + reference
        try:
            raw = self.request(url, headers, limit)
        except RegistryRedirectRejected as error:
            if kind != "blobs" or not self.allow_anonymous_blob_retry:
                raise
            # The published Docker Hub image is public. A pull token issued
            # without account credentials can use a different storage route.
            print(f"{error}; retrying blob with an anonymous Docker Hub pull token", file=sys.stderr)
            if self.anonymous_blob_token is None:
                self.anonymous_blob_token = self.pull_token({})
            raw = self.request(url, {**headers, "Authorization": "Bearer " + self.anonymous_blob_token}, limit)
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
            labels = config.get("config", {}).get("Labels", {})
            protocol = labels.get("org.nginxpanel.launcher.protocol", "")
            if protocol != "2":
                raise ValueError("image is missing the supported launcher protocol label")
            record = {"os": "linux", "architecture": target["architecture"],
                      "digest": descriptor["digest"], "config_digest": manifest["config"]["digest"],
                      "launcher_protocol": int(protocol)}
            if labels.get("org.nginxpanel.launcher.sha256", ""):
                raise ValueError("nginx image must not bind to a separately released panel binary")
            platforms.append(record)
    evidence = {"schema": 1, "index": base64.b64encode(raw_index).decode(),
                "blobs": [{"digest": digest, "data": base64.b64encode(raw).decode()}
                          for digest, raw in sorted(blobs.items())]}
    return sorted(platforms, key=lambda p: p["architecture"]), evidence


def merge(args):
    publication, run = identity(args)
    sources = {}
    for architecture in ("amd64", "arm64"):
        receipt = decode(read(args.input / ("images-" + architecture + ".json"), 64 << 10))
        if any(receipt.get(key) != value for key, value in publication.items()) or receipt.get("architecture") != architecture or not isinstance(receipt.get("images"), list) or len(receipt["images"]) != 1:
            raise ValueError("image build receipt identity changed")
        for image in receipt["images"]:
            image_id = image["id"]
            if image_id != "nginx" or image["repository"] != image_repository(args.repository, image_id) or not DIGEST.fullmatch(image["digest"]) or (image_id, architecture) in sources:
                raise ValueError("image build receipt contains an invalid or duplicate image")
            sources[image_id, architecture] = image
    args.output.mkdir()
    publication["images"] = []
    for image_id in ("nginx",):
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


def tag(args):
    identity(args)
    manifest = decode(read(args.input, 2 << 20))
    if manifest.get("repository") != args.repository or manifest.get("version") != args.version or manifest.get("assets") or len(manifest.get("images", [])) != 1:
        raise ValueError("version tags require the signed component-only manifest")
    image = manifest["images"][0]
    repository = image_repository(args.repository, image["id"])
    if image["repository"] != repository or image["version"] != args.version or image["commit"] != args.commit or not DIGEST.fullmatch(image["digest"]):
        raise ValueError("signed image source identity changed")
    registry = Registry(repository)
    try:
        existing = registry.get("manifests", args.version)
    except RegistryNotFound:
        existing = None
    if existing is not None:
        if "sha256:" + hashlib.sha256(existing).hexdigest() != image["digest"]:
            raise ValueError(f"{repository}:{args.version} 已发布且指向其他镜像摘要，请使用新的组件版本")
        return
    subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", repository + ":" + args.version,
                    repository + "@" + image["digest"]], check=True, timeout=120)
    if "sha256:" + hashlib.sha256(registry.get("manifests", args.version)).hexdigest() != image["digest"]:
        raise ValueError("published version tag does not match the signed digest")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("build", "merge", "tag"))
    for name in ("repository", "version", "commit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    args = parser.parse_args()
    if args.operation != "tag" and args.output is None:
        parser.error("--output is required for build and merge")
    if args.operation == "build":
        build(args)
    elif args.operation == "merge":
        merge(args)
    else:
        tag(args)


if __name__ == "__main__":
    main()
