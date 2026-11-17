"""Independent stable/dev component versions and publication retries."""
import unittest

from identity import identity


class IdentityTests(unittest.TestCase):
    def test_independent_stable_version_without_a_source_tag(self):
        self.assertEqual(identity("nginx", "", "2.0.0", "44", "1", channel="stable"),
                         ("2.0.0", "nginx-v2.0.0", True))

    def test_dev_versions_are_unique_and_keep_the_dev_suffix(self):
        for base in ("2.0.1", "2.0.1-dev"):
            self.assertEqual(identity("nginx", "", base, "44", "2", channel="dev"),
                             ("2.0.1-44.2-dev", "nginx-v2.0.1-44.2-dev", True))

    def test_publication_reuses_exact_build_version(self):
        for channel, version in (("stable", "2.0.0"), ("dev", "2.0.1-44.2-dev")):
            self.assertEqual(identity("nginx", "", version, "99", "10", True, channel),
                             (version, "nginx-v" + version, True))

    def test_invalid_or_ambiguous_component_versions_are_rejected(self):
        for version, channel in (("2.0.0-dev", "stable"), ("v2.0.0", "stable"),
                                 ("02.0.0", "stable"), ("2.0.0+meta", "dev")):
            with self.subTest(version=version, channel=channel), self.assertRaises(ValueError):
                identity("nginx", "", version, "44", "1", channel=channel)
        with self.assertRaises(ValueError):
            identity("nginx", "nginx-v2.0.0", "2.0.0", "44", "1", channel="stable")

    def test_core_tag_and_dev_version_rules_are_unchanged(self):
        self.assertEqual(identity("panel", "v1.0.0", "", "44", "1"), ("1.0.0", "v1.0.0", False))
        self.assertEqual(identity("panel", "", "1.0.1-dev", "44", "1"),
                         ("1.0.1-44.1-dev", "v1.0.1-44.1-dev", True))
        with self.assertRaises(ValueError):
            identity("panel", "", "1.0.0", "44", "1", channel="stable")


if __name__ == "__main__":
    unittest.main()
