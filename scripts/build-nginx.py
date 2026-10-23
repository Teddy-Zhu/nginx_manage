#!/usr/bin/env python3
"""Build the source installer's static Nginx inside its Docker build stage."""
import json
import os
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "release"))
from nginx import LOCK, build_runtime, output, read, runtime_archives

architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
if architecture != sys.argv[1]:
    raise ValueError("Nginx build container architecture differs from requested bundle")
lock_raw = read(LOCK, 64 << 10)
lock = json.loads(lock_raw)
if lock["schema"] != 1 or [source["id"] for source in lock["sources"]] != ["nginx", "openssl", "pcre2", "zlib"]:
    raise ValueError("unsupported native source lock")
destination = Path("/out/nginx")
for name in ("bin", "build", "licenses/toolchain"):
    (destination / name).mkdir(parents=True, exist_ok=True)
runtime_archives(destination)
env = dict(os.environ, CC="musl-gcc", SOURCE_DATE_EPOCH="0", LC_ALL="C", TZ="UTC")
for name in ("CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "LIBRARY_PATH", "CPATH", "OPENSSL_CONF", "OPENSSL_MODULES"):
    env.pop(name, None)
build_info = build_runtime(lock, architecture, destination, env)
symbols = {line.split()[-1] for line in output(["nm", str(destination / "bin/nginx")], limit=8 << 20).splitlines() if line.split()}
missing = set(lock["required_module_symbols"]) - symbols
if missing:
    raise ValueError("required Nginx modules are missing: " + ", ".join(sorted(missing)))
(destination / "build/nginx-V.txt").write_bytes(build_info)
(destination / "build/nginx-source-lock.json").write_bytes(lock_raw)
(destination / "bin/nginx").chmod(0o555)
