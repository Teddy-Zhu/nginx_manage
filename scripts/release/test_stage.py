"""Regression checks for installed production dependency license collection."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from stage import node_records, notices


class NodeRecordsTests(unittest.TestCase):
    def setUp(self):
        self.previous_directory = Path.cwd()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(os.chdir, self.previous_directory)
        os.chdir(self.temporary.name)
        self.installed = Path("web/node_modules").resolve()
        self.installed.mkdir(parents=True)
        Path("web/package.json").write_text("{}")

    def package(self, name, *, optional=(), license=True):
        root = self.installed / name
        root.mkdir(parents=True)
        (root / "package.json").write_text(json.dumps({
            "name": name, "version": "1.0.0", "license": "MIT",
            "optionalDependencies": {dependency: "1.0.0" for dependency in optional},
        }))
        if license:
            (root / "LICENSE").write_text(f"License for {name}\n")
        return root

    def dependency(self, name, **children):
        return {"version": "1.0.0", "path": str(self.installed / name), **children}

    def test_uninstalled_optional_bindings_are_skipped_in_both_report_sections(self):
        self.package("bundler", optional=("android", "linux"))
        self.package("linux")
        for section in ("dependencies", "optionalDependencies"):
            with self.subTest(section=section):
                report = [{"dependencies": {"bundler": self.dependency("bundler", **{
                    section: {
                        "android": self.dependency("android", dependencies={
                            "unused-child": self.dependency("unused-child"),
                        }),
                        "linux": self.dependency("linux"),
                    },
                })}}]
                records = set()
                node_records(report, records)
                self.assertEqual({name for name, _, _ in records}, {"bundler", "linux"})
                output = notices(records)
                self.assertIn(b"License for linux", output)
                self.assertNotIn(b"android", output)

    def test_top_level_optional_dependency_can_be_absent(self):
        Path("web/package.json").write_text(json.dumps({
            "optionalDependencies": {"android": "1.0.0"},
        }))
        records = set()
        node_records([{"dependencies": {"android": self.dependency("android")}}], records)
        self.assertEqual(records, set())

    def test_missing_required_dependency_fails_even_if_report_claims_optional(self):
        for section in ("dependencies", "optionalDependencies"):
            with self.subTest(section=section):
                with self.assertRaisesRegex(ValueError, "required production dependency missing: required"):
                    node_records([{section: {"required": self.dependency("required")}}], set())

    def test_required_child_of_installed_optional_package_must_exist(self):
        Path("web/package.json").write_text(json.dumps({
            "optionalDependencies": {"bundler": "1.0.0"},
        }))
        self.package("bundler")
        with self.assertRaisesRegex(ValueError, "required production dependency missing: required"):
            node_records([{"optionalDependencies": {"bundler": self.dependency(
                "bundler", dependencies={"required": self.dependency("required")},
            )}}], set())

    def test_optional_paths_cannot_escape_installed_tree(self):
        Path("web/package.json").write_text(json.dumps({
            "optionalDependencies": {"android": "1.0.0"},
        }))
        outside = Path("outside").resolve()
        outside.mkdir()
        (self.installed / "escape").symlink_to(outside, target_is_directory=True)
        for path in (outside / "android", self.installed / "escape/android"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "production dependency outside installed tree"):
                    node_records([{"dependencies": {"android": {
                        "version": "1.0.0", "path": str(path),
                    }}}], set())

    def test_installed_optional_dependency_still_requires_license(self):
        self.package("bundler", optional=("linux",))
        self.package("linux", license=False)
        records = set()
        node_records([{"dependencies": {"bundler": self.dependency(
            "bundler", dependencies={"linux": self.dependency("linux")},
        )}}], records)
        with self.assertRaisesRegex(ValueError, "dependency license files missing or excessive: linux"):
            notices(records)

    def test_license_supplement_requires_matching_version_and_declaration(self):
        package = self.package("bundler", license=False)
        root = Path("deploy/release/licenses")
        root.mkdir(parents=True)
        (root / "bundler.LICENSE").write_text("Upstream copyright and license terms\n")
        source = "https://example.org/bundler/1.0.0/LICENSE"
        supplements = {"bundler@1.0.0": {
            "license": "MIT", "file": "bundler.LICENSE", "source": source,
        }}
        records = {("bundler", "1.0.0", str(package))}
        output = notices(records, supplements)
        self.assertIn(b"Upstream copyright and license terms", output)
        self.assertIn(source.encode(), output)
        with self.assertRaisesRegex(ValueError, "dependency license files missing or excessive"):
            notices({("bundler", "2.0.0", str(package))}, supplements)
        manifest = json.loads((package / "package.json").read_text())
        manifest["license"] = "Apache-2.0"
        (package / "package.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "license supplement does not match installed dependency"):
            notices(records, supplements)


if __name__ == "__main__":
    unittest.main()
