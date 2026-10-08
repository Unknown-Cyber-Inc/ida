"""Plain data classes shared between the API client and the UI.

The SDK's generated model objects are never handed to the UI; the client maps
them to these small, stable types so that UI code is insulated from SDK quirks
(e.g. some endpoints returning dicts and others returning objects).
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass(frozen=True)
class Note:
    id: str
    text: str
    username: str = ""
    create_time: str = ""


@dataclasses.dataclass(frozen=True)
class Tag:
    id: str
    name: str
    username: str = ""
    create_time: str = ""
    color: str = ""


@dataclasses.dataclass(frozen=True)
class FileMatch:
    sha1: str
    max_similarity: float
    filename: str


@dataclasses.dataclass(frozen=True)
class AnalysisVersion:
    """One selectable "version" of the loaded file on the server.

    ``binary_id`` is the hash used for genomics queries.  ``kind`` is
    ``"original"`` for the uploaded binary, ``"content"`` for a processed
    disassembly/IDB child and ``"container"`` for an upload whose processed
    child is not available yet.
    """

    label: str
    binary_id: str
    kind: str
    timestamp: str = ""


@dataclasses.dataclass(frozen=True)
class Procedure:
    start_ea: str  # RVA string as returned by the API, e.g. "0x1000"
    name: str
    hard_hash: str
    binary_id: str
    occurrence_count: int = 0
    block_count: int = 0
    code_count: int = 0
    status: str = ""
    note_count: int = 0
    tag_count: int = 0
    strings: List[str] = dataclasses.field(default_factory=list)
    api_calls: List[str] = dataclasses.field(default_factory=list)

    @property
    def rva(self) -> int:
        return int(self.start_ea, 16)

    @property
    def display_name(self) -> str:
        return f"{self.start_ea} - {self.name}" if self.name else self.start_ea


@dataclasses.dataclass(frozen=True)
class ProcedureCode:
    binary_id: str
    start_ea: str
    name: str
    blocks: List[List[str]]  # one list of code lines per basic block

    @property
    def text(self) -> str:
        return "\n\n".join("\n".join(block) for block in self.blocks)


@dataclasses.dataclass(frozen=True)
class SimilarProcedure:
    binary_id: str
    start_ea: str
    block_count: int
    code_count: int
    similarity: Optional[float] = None


@dataclasses.dataclass(frozen=True)
class ContainingFile:
    sha1: str
    filename: str

    @property
    def label(self) -> str:
        return self.filename if self.filename else self.sha1


@dataclasses.dataclass(frozen=True)
class FileInfo:
    """Server-side view of a file (any hash can be used as its id)."""

    sha1: str
    md5: str = ""
    sha256: str = ""
    status: str = ""
    filename: str = ""
    pipeline: Dict[str, str] = dataclasses.field(default_factory=dict)
    create_time: str = ""
    children: List[AnalysisVersion] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class UploadStatus:
    binary_id: str
    status: str  # pending / success / failure / unknown
    pipeline: Dict[str, str]
    create_time: str = ""

    @property
    def finished(self) -> bool:
        return self.status.lower() in ("success", "failure")


PIPELINE_LABELS = {
    "dashboard_report": "Label inference",
    "dashboard_campaign": "Campaign",
    "ioc_handler": "IOC extraction",
    "ioc_extract_handler": "IOC extraction",
    "proc_hash_signatures": "YARA generation",
    "variant_hash_signatures": "Variant signatures",
    "reputation_handler": "Maliciousness",
    "similarity_computation": "Similarity matching",
    "srl_archive": "Archive extraction",
    "srl_juice": "Genomic juicing",
    "alt_juice_handler": "Disassembly juicing",
    "srl_scanners": "AV scan report",
    "srl_unpacker": "Unpacking",
    "web_request_handler": "Filetype discovery",
}


def pipeline_label(key: str) -> str:
    return PIPELINE_LABELS.get(key, key.replace("_", " ").capitalize())
