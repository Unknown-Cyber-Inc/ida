"""Disassembly export for the "Upload disassembly" feature.

The export produces the same archive layout the Unknown Cyber backend has
always consumed (``binary.json`` + ``procedures/<startEA>.json``), but:

* it writes into a private temporary directory instead of next to the binary;
* every database modification it needs (rebase to 0, operand display
  normalisation, register-rename removal, optional function discovery) is
  wrapped in an IDA undo point and reverted when the export finishes;
* it reports progress and honours cancellation.
"""

from .disassembly import ExportCancelled, ExportError, ExportOptions, export_disassembly  # noqa: F401
