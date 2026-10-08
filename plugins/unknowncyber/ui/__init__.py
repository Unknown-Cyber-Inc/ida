"""Qt user interface for the Unknown Cyber plugin.

Widgets never call the network directly: they ask :class:`MainPanel`
(``main_widget.py``) for a client and run requests through
:class:`unknowncyber.workers.TaskGroup`, so the UI stays responsive and every
error is surfaced in an inline banner rather than a modal stack trace.
"""
