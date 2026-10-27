#!/usr/bin/env python3
"""Package the standalone demo and resolve the source template's download URL."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shlex
import tarfile
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument("bundle_url", help="The HTTP/HTTPS URL at which demo.tar.gz will be served")
parser.add_argument("--output", default="examples/software/dist")
args = parser.parse_args()
url = urllib.parse.urlsplit(args.bundle_url)
if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
    parser.error("bundle_url must be an HTTP/HTTPS URL without credentials")
root = Path(__file__).resolve().parent
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)
archive = io.BytesIO()
with gzip.GzipFile(fileobj=archive, mode="wb", mtime=0) as stream:
    with tarfile.open(fileobj=stream, mode="w") as bundle:
        for path in sorted((root / "demo").rglob("*")):
            if not path.is_file():
                continue
            content = path.read_bytes()
            item = tarfile.TarInfo(path.relative_to(root / "demo").as_posix())
            item.mode, item.size = 0o644, len(content)
            bundle.addfile(item, io.BytesIO(content))
payload = archive.getvalue()
(output / "demo.tar.gz").write_bytes(payload)
source = json.loads((root / "source.json").read_text())
install = source["applications"][0]["actions"]["install"]["command"][2]
install = install.replace("BUNDLE_URL", shlex.quote(args.bundle_url)).replace("BUNDLE_CHECKSUM", shlex.quote(hashlib.sha256(payload).hexdigest() + "  demo.tar.gz"))
source["applications"][0]["actions"]["install"]["command"][2] = install
(output / "source.json").write_text(json.dumps(source, ensure_ascii=False, indent=2) + "\n")
print(f"Generated {output / 'source.json'} and {output / 'demo.tar.gz'}")
