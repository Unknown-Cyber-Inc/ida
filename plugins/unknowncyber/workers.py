"""Run blocking work off the UI thread and deliver results back on it.

Rules
-----
* Network calls run in a worker thread.  They must never touch IDA's database
  or Qt widgets.
* Anything that reads the IDB runs on the main thread (use
  :func:`on_main_thread`).
* Results are delivered through Qt signals, which Qt marshals to the UI
  thread automatically.

Usage::

    run_async(lambda: client.list_procedures(binary_id),
              on_success=self._populate,
              on_error=self._show_error,
              owner=self)
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Callable, Optional

from .qt import QtCore, Signal

_log = logging.getLogger(__name__)


class _Worker(QtCore.QThread):
    succeeded = Signal(object)
    failed = Signal(object)

    def __init__(self, fn: Callable[[], Any], parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):  # noqa: D401 - QThread API
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - every error is reported to the UI
            _log.debug("background task failed:\n%s", traceback.format_exc())
            self.failed.emit(exc)
            return
        self.succeeded.emit(result)


class TaskGroup(QtCore.QObject):
    """Keeps worker references alive and lets an owner cancel callbacks.

    Widgets own one ``TaskGroup``; when the widget is destroyed or a new
    request supersedes an old one, stale results are ignored instead of
    mutating a widget that no longer wants them.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._workers = set()
        self._generation = 0

    @property
    def busy(self) -> bool:
        return bool(self._workers)

    def invalidate(self) -> None:
        """Ignore the results of every task started before this call."""
        self._generation += 1

    def run(
        self,
        fn: Callable[[], Any],
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_finished: Optional[Callable[[], None]] = None,
    ) -> None:
        generation = self._generation
        worker = _Worker(fn, self)
        self._workers.add(worker)

        def _done():
            self._workers.discard(worker)
            worker.deleteLater()
            if on_finished is not None and generation == self._generation:
                on_finished()

        def _ok(result):
            try:
                if on_success is not None and generation == self._generation:
                    on_success(result)
            finally:
                _done()

        def _err(exc):
            try:
                if generation != self._generation:
                    return
                if on_error is not None:
                    on_error(exc)
                else:
                    _log.error("unhandled background error: %s", exc)
            finally:
                _done()

        worker.succeeded.connect(_ok)
        worker.failed.connect(_err)
        worker.start()


def on_main_thread(fn: Callable[[], Any], *, write: bool = False) -> Any:
    """Execute *fn* on IDA's main thread and return its result.

    Safe to call from any thread.  Outside IDA (tests) it simply calls *fn*.
    """
    try:
        import ida_kernwin  # type: ignore
    except ImportError:
        return fn()

    if ida_kernwin.is_main_thread():
        return fn()

    box: dict = {}

    def _runner():
        try:
            box["result"] = fn()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc
        return 0

    flags = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    ida_kernwin.execute_sync(_runner, flags)
    if "error" in box:
        raise box["error"]
    return box.get("result")
