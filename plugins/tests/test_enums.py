"""Tests for idamagic.core.enums."""
import unittest

from idamagic.core.enums import ItemType, TabKind


class TestItemTypeFromString(unittest.TestCase):
    def test_round_trip(self):
        for member in ItemType:
            self.assertIs(ItemType.from_string(member.value), member)

    def test_strips_whitespace(self):
        # This is the trailing-whitespace defensive strip:
        # the original code had a literal "Procedure Group Tags "
        # (trailing space) in at least one branch, which routed to a
        # no-op. from_string strips so any such typo round-trips.
        self.assertIs(
            ItemType.from_string("Procedure Group Tags "),
            ItemType.PROC_GROUP_TAGS,
        )
        self.assertIs(
            ItemType.from_string("  Notes\t\n"),
            ItemType.NOTES,
        )

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            ItemType.from_string("Bogus")

    def test_none_raises(self):
        with self.assertRaises(ValueError):
            ItemType.from_string(None)


class TestItemTypeLegacyStr(unittest.TestCase):
    def test_legacy_str_matches_value(self):
        self.assertEqual(
            ItemType.PROC_GROUP_NOTES.legacy_str,
            "Procedure Group Notes",
        )


class TestTabKind(unittest.TestCase):
    def test_distinct_members(self):
        # Sanity check: the three tab kinds are all different.
        members = {TabKind.PROC_ORIGINAL, TabKind.DERIVED_FILE, TabKind.DERIVED_PROC}
        self.assertEqual(len(members), 3)


if __name__ == "__main__":
    unittest.main()
