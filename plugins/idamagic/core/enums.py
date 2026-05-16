"""
Enums for tab kinds and item types.

These replace two patterns from the original codebase:

1. Tab dispatch via QColor: the original used `tab_color.red() == 255`
   to mean "this is an original procedure tab" and `green() == 128` to
   mean "derived procedure tab". Tab colors are styling; using them as
   identity meant any theme change to tab colors would break tab
   routing (note edits would target the wrong endpoint, etc).

2. Item-type dispatch via string literals: ~30 callsites contained
   `if self.item_type == "Procedure Group Notes"`. A typo (or a stray
   trailing space) silently routed to a different branch. The original
   already had one such bug — `"Procedure Group Tags "` with trailing
   space appeared in at least one place.

Using enums:
  * makes typos a NameError at import time, not a silent runtime miss;
  * gives IDEs autocomplete;
  * makes refactoring tractable (rename in one place);
  * keeps tab-color free for actual styling.

Backwards compatibility: ItemType members have a .legacy_str property
that returns the old literal string. The few callsites that
interoperate with API payloads (where the string form is part of the
wire protocol) use that. Internal dispatch uses identity comparison
on the enum members.
"""
from __future__ import annotations

import enum


class TabKind(enum.Enum):
    """What kind of object a center-display tab is showing.

    PROC_ORIGINAL: a procedure from the file currently loaded in IDA.
    DERIVED_FILE:  a different file's overview (reached from a Match).
    DERIVED_PROC:  a procedure inside a different file (reached from
                   a procedure similarity).
    """

    PROC_ORIGINAL = "proc_original"
    DERIVED_FILE = "derived_file"
    DERIVED_PROC = "derived_proc"


class ItemType(enum.Enum):
    """
    What a list/tree row in the right-hand panels represents.

    The string values are the legacy display labels used by the
    previous code as both UI text and dispatch keys. They remain the
    UI text; dispatch should compare ``self.item_type is ItemType.X``.
    """

    # File-level (right panel of the upper widget)
    DERIVED_FILE_NOTE = "Derived file note"
    DERIVED_FILE_TAG = "Derived file tag"

    # Procedure-level (center display)
    NOTES = "Notes"
    TAGS = "Tags"
    PROC_GROUP_NOTES = "Procedure Group Notes"
    PROC_GROUP_TAGS = "Procedure Group Tags"

    @property
    def legacy_str(self) -> str:
        """The old literal string. Kept for any callsite that still
        needs to compare against bare strings (e.g. round-tripping
        text out of a Qt QStandardItem)."""
        return self.value

    @classmethod
    def from_string(cls, s: str) -> "ItemType":
        """Parse a legacy string back to an ItemType. Strips
        whitespace defensively so that the trailing-space bug in the
        original code can't bite again."""
        if s is None:
            raise ValueError("ItemType cannot be parsed from None")
        s = s.strip()
        for member in cls:
            if member.value == s:
                return member
        raise ValueError(f"Unknown ItemType string: {s!r}")
