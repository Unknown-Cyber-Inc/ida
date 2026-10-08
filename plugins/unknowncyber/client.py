"""Typed wrapper around the ``cythereal_magic`` SDK.

Design goals
------------
* One ``ApiClient`` per settings snapshot, built from an explicit
  ``Configuration`` (never the SDK's process-wide default, whose ``api_key``
  dict is shared between copies).
* TLS verification **on** by default, optional custom CA bundle.
* Every request carries a timeout.
* Every identifier that ends up in a URL path is validated first.
* SDK exceptions are translated into :class:`ApiError` with a message that is
  safe and useful to show to a user; raw bodies go to the log only.
* No Qt, no IDA imports: this module can be exercised from plain Python.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from . import config, models

_log = logging.getLogger(__name__)

HEX_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")
RVA_RE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
ID_RE = re.compile(r"^[0-9a-zA-Z_\-:.]{1,128}$")

DEFAULT_TIMEOUT = (10, 90)  # (connect, read) seconds
UPLOAD_TIMEOUT = (10, 900)
PAGE_SIZE = 25
SIMILARITY_MIN = 0.7
USER_AGENT = "unknowncyber-ida-plugin"


class ApiError(Exception):
    """A request failed.  ``str(exc)`` is suitable for display."""

    def __init__(self, message: str, status: Optional[int] = None, *, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable

    @property
    def not_found(self) -> bool:
        return self.status == 404

    @property
    def unauthorized(self) -> bool:
        return self.status in (401, 403)


class NotConfigured(ApiError):
    def __init__(self):
        super().__init__("The Unknown Cyber plugin is not configured. Open Settings and enter the API host and key.")


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------


def require_hash(value: str, what: str = "file hash") -> str:
    value = (value or "").strip().lower()
    if not HEX_HASH_RE.match(value):
        raise ApiError(f"Invalid {what}: {value[:16]!r}")
    return value


def require_rva(value: str) -> str:
    value = (value or "").strip().lower()
    if not RVA_RE.match(value):
        raise ApiError(f"Invalid procedure address: {value[:20]!r}")
    return value


def require_id(value: str, what: str = "id") -> str:
    value = (value or "").strip()
    if not ID_RE.match(value):
        raise ApiError(f"Invalid {what}: {value[:20]!r}")
    return value


def _field(obj: Any, *names: str, default: Any = None) -> Any:
    """Read ``names[0]`` (or an alias) from an SDK model object *or* a dict."""
    for name in names:
        if isinstance(obj, dict):
            if name in obj and obj[name] is not None:
                return obj[name]
        else:
            value = getattr(obj, name, None)
            if value is not None:
                return value
    return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class MagicClient:
    """Thin, validated facade over ``FilesApi`` and ``ProceduresApi``."""

    def __init__(self, settings: config.Settings):
        if not settings.is_configured:
            raise NotConfigured()
        import cythereal_magic  # imported lazily so the UI can report a missing dependency nicely

        cfg = _header_only_configuration(cythereal_magic)
        cfg.host = settings.api_base_url
        # The SDK sends api_key["key"] as a ?key= query parameter and api_key["X-API-KEY"] as a
        # request header.  Only the header form is configured so the key never appears in URLs.
        cfg.api_key = {"X-API-KEY": settings.api_key}  # fresh dict: never mutate the SDK-wide default
        cfg.api_key_prefix = {}
        cfg.verify_ssl = bool(settings.verify_tls)
        cfg.ssl_ca_cert = config.effective_ca_bundle(settings)
        cfg.assert_hostname = None
        cfg.debug = False
        self._settings = settings
        self._api_client = cythereal_magic.ApiClient(configuration=cfg)
        self._api_client.client_side_validation = False
        self._api_client.user_agent = USER_AGENT
        self._files = cythereal_magic.FilesApi(self._api_client)
        self._procs = cythereal_magic.ProceduresApi(self._api_client)
        self.dashboard_base_url = settings.dashboard_base_url

    # -- plumbing ------------------------------------------------------------
    def _call(self, fn, *args, timeout=DEFAULT_TIMEOUT, **kwargs):
        import urllib3.exceptions  # type: ignore
        from cythereal_magic.rest import ApiException  # type: ignore

        kwargs.setdefault("no_links", True)
        try:
            return fn(*args, _request_timeout=timeout, **kwargs)
        except ApiException as exc:
            raise self._translate(exc) from None
        except urllib3.exceptions.SSLError as exc:
            raise ApiError(
                "TLS certificate verification failed. If this is a self-hosted system, point the CA bundle setting (or UNKNOWNCYBER_CA_BUNDLE) at its CA certificate."
                f" ({exc.__class__.__name__})"
            ) from exc
        except urllib3.exceptions.MaxRetryError as exc:
            raise ApiError(f"Cannot reach {self._settings.api_base_url}: {_short(exc.reason)}", retryable=True) from exc
        except (urllib3.exceptions.TimeoutError, TimeoutError) as exc:
            raise ApiError("The request timed out.", retryable=True) from exc
        except urllib3.exceptions.HTTPError as exc:
            raise ApiError(f"Network error: {_short(exc)}", retryable=True) from exc
        except (OSError, ValueError) as exc:
            raise ApiError(f"Request failed: {_short(exc)}") from exc

    @staticmethod
    def _translate(exc) -> ApiError:
        status = getattr(exc, "status", None)
        body = getattr(exc, "body", None)
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        detail = ""
        if body:
            try:
                parsed = json.loads(body)
                errors = parsed.get("errors") or []
                parts = []
                for err in errors:
                    if isinstance(err, dict):
                        msg = err.get("message") or err.get("reason") or ""
                        param = err.get("parameter")
                        parts.append(f"{msg} ({param})" if param else msg)
                detail = "; ".join(p for p in parts if p) or str(parsed.get("message") or "")
            except (ValueError, AttributeError):
                detail = ""
        _log.debug("API error %s: %s", status, body)
        if status in (401, 403):
            msg = "The API key was rejected. Check it in Settings."
        elif status == 404:
            msg = "Not found on the Unknown Cyber server."
        elif status == 429:
            msg = "Rate limited by the server; try again shortly."
        elif status is not None and status >= 500:
            msg = f"The server returned an error ({status})."
        else:
            msg = f"Request failed ({status})."
        if detail:
            msg = f"{msg} {detail}"
        return ApiError(msg, status, retryable=status in (429, 502, 503, 504))

    # -- connectivity --------------------------------------------------------
    def ping(self) -> None:
        """Cheap authenticated request used by 'Test connection'.

        A 404 for the probe hash still proves that the host answers and the key
        is accepted; only auth/network failures propagate.
        """
        try:
            self._call(self._files.get_file, binary_id="ff9790d7902fea4c910b182f6e0b00221a40d616", read_mask="sha1")
        except ApiError as exc:
            if not exc.not_found:
                raise

    def dashboard_url(self, binary_id: str) -> str:
        return f"{self.dashboard_base_url}/files/{require_hash(binary_id)}"

    # -- files -----------------------------------------------------------------
    def get_file(self, binary_id: str, with_children: bool = True) -> Optional[models.FileInfo]:
        """Return :class:`FileInfo` or ``None`` when the file is unknown."""
        binary_id = require_hash(binary_id)
        kwargs: Dict[str, Any] = {"read_mask": "sha1,md5,sha256,status,filename,pipeline,create_time"}
        if with_children:
            kwargs["read_mask"] += ",children.*"
            kwargs["expand_mask"] = "children"
        try:
            resp = self._call(self._files.get_file, binary_id=binary_id, **kwargs)
        except ApiError as exc:
            if exc.not_found:
                return None
            raise
        res = _field(resp, "resource", default={})
        return models.FileInfo(
            sha1=str(_field(res, "sha1", default="")).lower(),
            md5=str(_field(res, "md5", default="")).lower(),
            sha256=str(_field(res, "sha256", default="")).lower(),
            status=str(_field(res, "status", default="") or ""),
            filename=str(_field(res, "filename", default="")),
            pipeline=_pipeline_dict(_field(res, "pipeline")),
            create_time=str(_field(res, "create_time", default="") or ""),
            children=_children(_field(res, "children")),
        )

    def upload_status(self, binary_id: str) -> models.UploadStatus:
        binary_id = require_hash(binary_id)
        resp = self._call(self._files.get_file, binary_id=binary_id, read_mask="status,pipeline,sha1,create_time")
        res = _field(resp, "resource", default={})
        return models.UploadStatus(
            binary_id=str(_field(res, "sha1", default=binary_id)).lower(),
            status=str(_field(res, "status", default="unknown") or "unknown"),
            pipeline=_pipeline_dict(_field(res, "pipeline")),
            create_time=str(_field(res, "create_time", default="") or ""),
        )

    def upload_binary(self, b64_payload: str, *, skip_unpack: bool, arch_bits: Optional[int]) -> str:
        """Upload a base64-encoded file.  Returns the server-side sha1."""
        kwargs: Dict[str, Any] = {"b64": True, "skip_unpack": bool(skip_unpack)}
        if arch_bits == 64:
            kwargs["use_64"] = True
        elif arch_bits == 32:
            kwargs["use_32"] = True
        resp = self._call(
            self._files.upload_file,
            filedata=[b64_payload],
            password="",
            tags=[],
            notes=[],
            timeout=UPLOAD_TIMEOUT,
            **kwargs,
        )
        resources = _as_list(_field(resp, "resources"))
        if not resources:
            raise ApiError("The server accepted the upload but returned no file record.")
        return str(_field(resources[0], "sha1", default="")).lower()

    def upload_disassembly(self, zip_path: str) -> str:
        resp = self._call(self._files.upload_disassembly, filedata=zip_path, timeout=UPLOAD_TIMEOUT)
        res = _field(resp, "resource", default={})
        sha1 = str(_field(res, "sha1", default="")).lower()
        if not sha1:
            raise ApiError("The server accepted the disassembly but returned no file record.")
        return sha1

    def list_file_matches(self, binary_id: str, page: int = 1) -> List[models.FileMatch]:
        binary_id = require_hash(binary_id)
        resp = self._call(
            self._files.list_file_matches,
            binary_id=binary_id,
            page_count=max(1, int(page)),
            page_size=PAGE_SIZE,
            expand_mask="matches",
            read_mask="sha1,max_similarity,filename",
        )
        out = []
        for m in _as_list(_field(resp, "resources")):
            out.append(
                models.FileMatch(
                    sha1=str(_field(m, "sha1", default="")).lower(),
                    max_similarity=float(_field(m, "max_similarity", default=0.0) or 0.0),
                    filename=str(_field(m, "filename", default="")),
                )
            )
        return out

    def list_file_notes(self, binary_id: str) -> List[models.Note]:
        resp = self._call(self._files.list_file_notes, binary_id=require_hash(binary_id))
        return [_note(n) for n in _as_list(_field(resp, "resources"))]

    def create_file_note(self, binary_id: str, text: str) -> models.Note:
        resp = self._call(self._files.create_file_note, note=_require_text(text), public=False, binary_id=require_hash(binary_id))
        return _note(_field(resp, "resource", default={}))

    def update_file_note(self, binary_id: str, note_id: str, text: str) -> None:
        self._call(
            self._files.update_file_note,
            binary_id=require_hash(binary_id),
            note_id=require_id(note_id, "note id"),
            note=_require_text(text),
            public=False,
            update_mask="note",
        )

    def delete_file_note(self, binary_id: str, note_id: str) -> None:
        self._call(self._files.delete_file_note, binary_id=require_hash(binary_id), note_id=require_id(note_id, "note id"), force=True)

    def list_file_tags(self, binary_id: str) -> List[models.Tag]:
        resp = self._call(self._files.list_file_tags, binary_id=require_hash(binary_id), expand_mask="tags")
        return [_tag(t) for t in _as_list(_field(resp, "resources"))]

    def create_file_tag(self, binary_id: str, name: str) -> models.Tag:
        resp = self._call(self._files.create_file_tag, binary_id=require_hash(binary_id), name=_require_text(name, 128))
        return _tag(_field(resp, "resource", default={}))

    def delete_file_tag(self, binary_id: str, tag_id: str) -> None:
        self._call(self._files.remove_file_tag, binary_id=require_hash(binary_id), tag_id=require_id(tag_id, "tag id"), force=True)

    # -- procedures (per file) --------------------------------------------------
    def list_procedures(self, binary_id: str) -> List[models.Procedure]:
        binary_id = require_hash(binary_id)
        resp = self._call(
            self._files.list_file_genomics,
            binary_id=binary_id,
            read_mask="*",
            order_by="start_ea",
            page_size=0,
            timeout=(10, 300),
        )
        res = _field(resp, "resource", default={})
        procs = []
        for p in _as_list(_field(res, "procedures")):
            procs.append(
                models.Procedure(
                    start_ea=str(_field(p, "start_ea", default="0x0")).lower(),
                    name=str(_field(p, "procedure_name", default="") or ""),
                    hard_hash=str(_field(p, "hard_hash", default="") or ""),
                    binary_id=str(_field(p, "binary_id", default=binary_id) or binary_id).lower(),
                    occurrence_count=_as_int(_field(p, "occurrence_count")),
                    block_count=_as_int(_field(p, "block_count")),
                    code_count=_as_int(_field(p, "code_count")),
                    status=str(_field(p, "status", default="") or ""),
                    note_count=len(_as_list(_field(p, "notes"))),
                    tag_count=len(_as_list(_field(p, "tags"))),
                    strings=[str(s) for s in _as_list(_field(p, "strings"))],
                    api_calls=[str(s) for s in _as_list(_field(p, "api_calls"))],
                )
            )
        return procs

    def get_procedure_code(self, binary_id: str, rva: str) -> models.ProcedureCode:
        resp = self._call(self._files.list_file_procedure_genomics, binary_id=require_hash(binary_id), rva=require_rva(rva))
        res = _field(resp, "resource", default={})
        blocks = []
        for block in _as_list(_field(res, "blocks")):
            blocks.append([str(line) for line in _as_list(_field(block, "code"))])
        return models.ProcedureCode(
            binary_id=str(_field(res, "binary_id", default=binary_id)).lower(),
            start_ea=str(_field(res, "start_ea", default=rva)).lower(),
            name=str(_field(res, "procedure_name", default="") or ""),
            blocks=blocks,
        )

    def rename_procedure(self, binary_id: str, rva: str, name: str) -> None:
        self._call(
            self._files.update_file_procedure_genomics,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
            procedure_name=_require_text(name, 256),
            update_mask="procedure_name",
        )

    def list_similar_procedures(self, binary_id: str, rva: str) -> List[models.SimilarProcedure]:
        resp = self._call(
            self._files.list_procedure_similarities,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
            read_mask="block_count,code_count,binary_id,start_ea",
            min_threshold=SIMILARITY_MIN,
            max_threshold=1.0,
            page_size=0,
        )
        out = []
        for p in _as_list(_field(resp, "resources")):
            out.append(
                models.SimilarProcedure(
                    binary_id=str(_field(p, "binary_id", default="")).lower(),
                    start_ea=str(_field(p, "start_ea", default="0x0")).lower(),
                    block_count=_as_int(_field(p, "block_count")),
                    code_count=_as_int(_field(p, "code_count")),
                )
            )
        return out

    def list_procedure_notes(self, binary_id: str, rva: str) -> List[models.Note]:
        resp = self._call(self._files.list_procedure_genomics_notes, binary_id=require_hash(binary_id), rva=require_rva(rva))
        return [_note(n) for n in _as_list(_field(resp, "resources"))]

    def create_procedure_note(self, binary_id: str, rva: str, text: str) -> models.Note:
        resp = self._call(
            self._files.create_procedure_genomics_note,
            note=_require_text(text),
            public=False,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
        )
        return _note(_field(resp, "resource", default={}))

    def update_procedure_note(self, binary_id: str, rva: str, note_id: str, text: str) -> None:
        self._call(
            self._files.update_procedure_genomics_note,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
            note_id=require_id(note_id, "note id"),
            note=_require_text(text),
            public=False,
            update_mask="note",
        )

    def delete_procedure_note(self, binary_id: str, rva: str, note_id: str) -> None:
        self._call(
            self._files.delete_procedure_genomics_note,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
            note_id=require_id(note_id, "note id"),
            force=True,
        )

    def list_procedure_tags(self, binary_id: str, rva: str) -> List[models.Tag]:
        resp = self._call(self._files.list_procedure_genomics_tags, binary_id=require_hash(binary_id), rva=require_rva(rva))
        return [_tag(t) for t in _as_list(_field(resp, "resources"))]

    def create_procedure_tag(self, binary_id: str, rva: str, name: str) -> models.Tag:
        resp = self._call(
            self._files.create_procedure_genomics_tag,
            name=_require_text(name, 128),
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
        )
        return _tag(_field(resp, "resource", default={}))

    def delete_procedure_tag(self, binary_id: str, rva: str, tag_id: str) -> None:
        self._call(
            self._files.delete_procedure_genomics_tag_by_id,
            binary_id=require_hash(binary_id),
            rva=require_rva(rva),
            tag_id=require_id(tag_id, "tag id"),
            force=True,
        )

    # -- procedure groups (keyed by hard hash) ----------------------------------
    def list_group_files(self, hard_hash: str) -> List[models.ContainingFile]:
        resp = self._call(
            self._procs.list_procedure_files,
            proc_hash=require_hash(hard_hash, "procedure hash"),
            read_mask="sha1,sha256,filename",
            expand_mask="files",
            page_size=0,
        )
        out = []
        for f in _as_list(_field(resp, "resources")):
            names = [str(_field(f, "filename", ""))]
            single = _field(f, "filename")
            name = names[0]
            if single and str(single) not in names:
                name = str(single)
            out.append(models.ContainingFile(sha1=str(_field(f, "sha1", default="")).lower(), filename=name))
        return out

    def list_group_notes(self, hard_hash: str) -> List[models.Note]:
        resp = self._call(self._procs.list_procedure_notes, proc_hash=require_hash(hard_hash, "procedure hash"), expand_mask="notes")
        return [_note(n) for n in _as_list(_field(resp, "resources"))]

    def create_group_note(self, hard_hash: str, text: str) -> models.Note:
        resp = self._call(
            self._procs.create_procedure_note, note=_require_text(text), public=False, proc_hash=require_hash(hard_hash, "procedure hash")
        )
        return _note(_field(resp, "resource", default={}))

    def update_group_note(self, hard_hash: str, note_id: str, text: str) -> None:
        self._call(
            self._procs.update_procedure_note,
            proc_hash=require_hash(hard_hash, "procedure hash"),
            note_id=require_id(note_id, "note id"),
            note=_require_text(text),
            public=False,
            update_mask="note",
        )

    def delete_group_note(self, hard_hash: str, note_id: str) -> None:
        self._call(
            self._procs.delete_procedure_note,
            proc_hash=require_hash(hard_hash, "procedure hash"),
            note_id=require_id(note_id, "note id"),
            force=True,
        )

    def list_group_tags(self, hard_hash: str) -> List[models.Tag]:
        resp = self._call(self._procs.list_procedure_tags, proc_hash=require_hash(hard_hash, "procedure hash"), expand_mask="tags")
        return [_tag(t) for t in _as_list(_field(resp, "resources"))]

    def create_group_tag(self, hard_hash: str, name: str) -> models.Tag:
        resp = self._call(self._procs.add_procedure_tag, proc_hash=require_hash(hard_hash, "procedure hash"), name=_require_text(name, 128))
        return _tag(_field(resp, "resource", default={}))

    def delete_group_tag(self, hard_hash: str, tag_id: str) -> None:
        self._call(
            self._procs.delete_procedure_tag,
            proc_hash=require_hash(hard_hash, "procedure hash"),
            tag_id=require_id(tag_id, "tag id"),
            force=True,
        )


def _header_only_configuration(cythereal_magic):
    """A ``Configuration`` that only ever emits the ``X-API-KEY`` header.

    The stock configuration advertises three schemes for every request: the
    header key, a ``?key=`` query parameter and HTTP Basic (which, with the
    default empty username/password, sends a meaningless ``Basic Og==``).
    Only the header scheme is kept.
    """

    class _HeaderOnlyConfiguration(cythereal_magic.Configuration):
        def auth_settings(self):
            return {
                "Api Key Header Authentication": {
                    "type": "api_key",
                    "in": "header",
                    "key": "X-API-KEY",
                    "value": self.get_api_key_with_prefix("X-API-KEY"),
                }
            }

    return _HeaderOnlyConfiguration()


# --------------------------------------------------------------------------
# Mapping helpers
# --------------------------------------------------------------------------


def _require_text(text: str, limit: int = 20000) -> str:
    text = (text or "").strip()
    if not text:
        raise ApiError("Text must not be empty.")
    if len(text) > limit:
        raise ApiError(f"Text is too long (limit {limit} characters).")
    return text


def _short(value: Any, limit: int = 160) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _note(obj: Any) -> models.Note:
    return models.Note(
        id=str(_field(obj, "id", default="")),
        text=str(_field(obj, "note", "text", default="") or ""),
        username=str(_field(obj, "username", default="") or ""),
        create_time=str(_field(obj, "create_time", default="") or ""),
    )


def _tag(obj: Any) -> models.Tag:
    return models.Tag(
        id=str(_field(obj, "id", default="")),
        name=str(_field(obj, "name", default="") or ""),
        username=str(_field(obj, "username", default="") or ""),
        create_time=str(_field(obj, "create_time", default="") or ""),
        color=str(_field(obj, "color", default="") or ""),
    )


def _pipeline_dict(pipeline: Any) -> Dict[str, str]:
    if pipeline is None:
        return {}
    if hasattr(pipeline, "to_dict"):
        try:
            pipeline = pipeline.to_dict()
        except Exception:  # noqa: BLE001
            return {}
    if not isinstance(pipeline, dict):
        return {}
    return {str(k): str(v) for k, v in pipeline.items() if v}


def _children(children: Any) -> List[models.AnalysisVersion]:
    """Map expanded ``children`` entries to selectable analysis versions.

    Only processed disassembly/IDB contents are listed (``service_data.type ==
    "disasm-contents"``), matching what the server produces for IDB and
    disassembly uploads.
    """
    out: List[models.AnalysisVersion] = []
    for child in _as_list(children):
        if isinstance(child, str):
            continue  # unexpanded id
        sha1 = str(_field(child, "sha1", default="") or "").lower()
        if not sha1:
            continue
        service_name = str(_field(child, "service_name", default="") or "")
        service_data = _field(child, "service_data", default={}) or {}
        obj_type = str(_field(service_data, "type", default="") or "")
        timestamp = str(_field(service_data, "time", default="") or "")
        if obj_type != "disasm-contents" or service_name not in ("alt_juice_handler", "webRequestHandler"):
            continue
        out.append(models.AnalysisVersion(label=timestamp or sha1[:12], binary_id=sha1, kind="content", timestamp=timestamp))
    out.sort(key=lambda v: v.timestamp)
    return out
