"""
Async API helper: run blocking API calls off the UI thread.

The cythereal_magic SDK supports async_req=True which returns a
future; the wrappers in idamagic.api then immediately call
.get() on that future, which blocks. That meant every API call
froze IDA's UI for the duration of the request. With a 30k-procedure
file, "Get Procedures" hung IDA for tens of seconds.

`run_api` runs the wrapper on a QThread, surfaces the result to the
UI thread through signals, and optionally shows a non-modal "working"
popup the user can see (but not click through).

Usage:

    from idamagic.core.async_api import run_api
    from idamagic.api import list_file_genomics

    def _on_procs_loaded(self, response):
        if response is None: return
        self.populate_proc_table(response.resource)

    def pushbutton_click(self):
        run_api(
            parent=self,
            fn=list_file_genomics,
            kwargs={"binary_id": self.ctx.version_hash, "info_msgs": [...]},
            on_success=self._on_procs_loaded,
            busy_message="Loading procedures from MAGIC…",
        )

Notes:
- The callback runs on the UI thread (via signal/slot), so it is
  safe to mutate widgets directly.
- `fn` must be safe to call from a worker thread. The cythereal SDK
  uses requests/urllib3 which are thread-safe; the wrappers in
  idamagic.api don't touch Qt, so they qualify.
- If the parent widget is destroyed while the worker is running,
  Qt will deliver the finished signal to a deleted slot. The wrapper
  guards against this by using a weakref to the parent.
"""
from __future__ import annotations

import logging
import weakref
from typing import Any, Callable, Dict, Optional, Tuple

from PyQt5 import QtCore, QtWidgets

logger = logging.getLogger(__name__)


class _ApiWorker(QtCore.QThread):
    """Runs a single API call and emits its result.

    finished_with_result emits a (ok, result, error) triple:
      - ok=True, result=<return value>, error=None  on success
      - ok=False, result=None, error=<Exception>    on raised exception

    We don't rely on the default QThread.finished signal because we
    also need to carry the function's return value back.
    """

    finished_with_result = QtCore.pyqtSignal(bool, object, object)

    def __init__(self, fn: Callable, args: Tuple, kwargs: Dict):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:  # type: ignore[override]
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:  # noqa: BLE001
            # Don't surface to the UI from this thread. Let the slot
            # handle it.
            logger.exception("Background API call %s raised", self._fn)
            self.finished_with_result.emit(False, None, exc)
            return
        self.finished_with_result.emit(True, result, None)


class _BusyDialog(QtWidgets.QDialog):
    """Non-modal, non-cancellable 'working' indicator.

    A real cancel is nontrivial (the SDK doesn't expose request
    cancellation), so for now this is informational only.
    """

    def __init__(self, message: str, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Working…")
        self.setModal(False)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel(message))
        bar = QtWidgets.QProgressBar()
        bar.setRange(0, 0)  # indeterminate
        layout.addWidget(bar)
        self.setLayout(layout)


def run_api(
    *,
    parent: QtWidgets.QWidget,
    fn: Callable,
    args: Tuple = (),
    kwargs: Optional[Dict[str, Any]] = None,
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    busy_message: Optional[str] = None,
) -> _ApiWorker:
    """
    Run ``fn(*args, **kwargs)`` on a worker thread.

    Returns the worker so the caller can keep a reference (preventing
    it from being garbage-collected before it finishes).

    on_success: called on the UI thread with the return value.
    on_error:   called on the UI thread with the exception.

    If ``busy_message`` is given, a small "working" dialog is shown
    while the call is in flight.
    """
    kwargs = kwargs or {}

    busy: Optional[_BusyDialog] = None
    if busy_message:
        busy = _BusyDialog(busy_message, parent)
        busy.show()

    weak_parent = weakref.ref(parent)

    worker = _ApiWorker(fn, args, kwargs)

    def _on_done(ok: bool, result: Any, error: Any) -> None:
        if busy is not None:
            try:
                busy.close()
            except Exception:
                pass

        # Guard against the parent being destroyed while we were
        # in flight. If it's gone, drop the result on the floor;
        # there's nothing to update.
        if weak_parent() is None:
            return

        if ok:
            if on_success is not None:
                try:
                    on_success(result)
                except Exception:
                    logger.exception("on_success callback raised")
        else:
            if on_error is not None:
                try:
                    on_error(error)
                except Exception:
                    logger.exception("on_error callback raised")
            else:
                logger.error("Async API call failed: %s", error)

    worker.finished_with_result.connect(_on_done)
    # Make sure the worker object is reaped when its thread finishes.
    worker.finished.connect(worker.deleteLater)
    worker.start()
    return worker
