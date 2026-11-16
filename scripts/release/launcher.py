#!/usr/bin/env python3
"""Stage licenses for the image's independently built Go launcher."""
import argparse
from pathlib import Path
from stage import go_notices, read


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--go-packages", required=True, type=Path)
    args = parser.parse_args()
    destination = Path(".release/binaries") / ("licenses-" + args.architecture)
    destination.mkdir()
    (destination / "LICENSE").write_bytes(read("LICENSE", 256 << 10))
    (destination / "THIRD_PARTY_NOTICES.txt").write_bytes(go_notices(args.go_packages))
    for path in destination.iterdir():
        path.chmod(0o644)
    destination.chmod(0o755)


if __name__ == "__main__":
    main()
