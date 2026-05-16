"""Tests for idamagic.core.context.PluginContext."""
import unittest

from idamagic.core.context import PluginContext


class TestPluginContextDefaults(unittest.TestCase):
    def test_defaults(self):
        ctx = PluginContext()
        self.assertIsNone(ctx.loaded_sha1)
        self.assertIsNone(ctx.version_hash)
        self.assertFalse(ctx.file_exists)
        self.assertFalse(ctx.ida_version_valid)
        self.assertEqual(ctx.upload_content_hashes, {})
        self.assertEqual(ctx.upload_container_hashes, {})

    def test_separate_default_factories(self):
        # Common dataclass bug: using a mutable default like
        # `field(default={})` instead of `field(default_factory=dict)`
        # makes the dict shared across instances. Verify two
        # PluginContexts don't share their dicts.
        a = PluginContext()
        b = PluginContext()
        a.upload_content_hashes["x"] = 1
        self.assertEqual(b.upload_content_hashes, {})


class TestUploadHelpers(unittest.TestCase):
    def test_add_content_entry(self):
        ctx = PluginContext()
        ctx.add_upload_content_entry("aaa", 5)
        self.assertEqual(ctx.upload_content_hashes, {"aaa": 5})

    def test_add_container_entry(self):
        ctx = PluginContext()
        ctx.add_upload_container_entry("bbb", 2)
        self.assertEqual(ctx.upload_container_hashes, {"bbb": 2})

    def test_remove_container_entry(self):
        ctx = PluginContext()
        ctx.add_upload_container_entry("bbb", 2)
        ctx.remove_upload_container_entry("bbb")
        self.assertNotIn("bbb", ctx.upload_container_hashes)

    def test_remove_missing_is_silent(self):
        # Previously the bare-globals version raised KeyError on
        # stale references during dropdown churn. The dataclass
        # version uses pop(key, None) so missing keys are silent.
        ctx = PluginContext()
        ctx.remove_upload_container_entry("never-existed")  # no raise

    def test_increment_indexes(self):
        ctx = PluginContext()
        ctx.upload_content_hashes = {"a": 0, "b": 1, "c": 3}
        ctx.increment_upload_content_indexes()
        # Index 0 is "Original File" by convention; entries above
        # 0 shift down by one.
        self.assertEqual(ctx.upload_content_hashes, {"a": 0, "b": 2, "c": 4})


if __name__ == "__main__":
    unittest.main()
