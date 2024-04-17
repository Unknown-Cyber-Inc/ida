import json
import traceback
import logging

import cythereal_magic
from cythereal_magic.rest import ApiException
from .helpers import (
    get_file_architecture,
    process_api_exception,
    process_regular_exception,
)

logger = logging.getLogger(__name__)

magic_api_client = cythereal_magic.ApiClient()
magic_api_client.client_side_validation = False
ctmfiles = cythereal_magic.FilesApi(magic_api_client)
ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)

########################
# Files API
########################

def get_file(binary_id: str, read_mask: str, expand_mask:str, info_msgs: list = None):
    try:
        response = ctmfiles.get_file(
            binary_id=binary_id,
            no_links=True,
            read_mask=read_mask,
            expand_mask=expand_mask,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def upload_file(filedata: list, skip_unpack: bool, info_msgs: list = None):
    arch_32 = None
    arch_64 = None

    try:
        arch = get_file_architecture()
        if arch == "64-bit":
            arch_64 = True
        elif arch == "32-bit":
            arch_32 = True


        response = ctmfiles.upload_file(
            filedata=filedata,
            password="",
            tags=[],
            notes=[],
            skip_unpack=skip_unpack,
            no_links=True,
            b64=True,
            use_32 = arch_32,
            use_64 = arch_64,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def upload_disassembly(zip_path: str, info_msgs: list = None):
    try:
        response = ctmfiles.upload_disassembly(
            filedata=zip_path,
            no_links=True,
        )
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def list_file_notes(binary_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_file_notes(
            binary_id=binary_id, no_links=True, async_req=True
        )
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def list_file_tags(binary_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_file_tags(
            binary_id=binary_id,
            expand_mask="tags",
            no_links=True,
            async_req=True,
        )
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def list_file_matches(binary_id: str, page: int, info_msgs: list = None):
    try:
        response = ctmfiles.list_file_matches(
            binary_id=binary_id,
            expand_mask="matches",
            page_count=page,
            page_size=25,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, True, info_msgs)
    except Exception as exc:
        process_regular_exception(exc, False, [str(exc)])
        return None
    else:
        return response

def list_file_genomics(binary_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_file_genomics(
            binary_id=binary_id,
            read_mask="*",
            order_by="start_ea",
            no_links=True,
            page_size=0,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    else:
        return response

def create_file_note(binary_id: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.create_file_note(
            binary_id=binary_id,
            note=text,
            public=False,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    else:
        return response

def create_file_tag(binary_id: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.create_file_tag(
            binary_id=binary_id,
            name=text,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    else:
        return response

def update_file_note(binary_id: str, note_id: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.update_file_note(
            binary_id=binary_id,
            note_id=note_id,
            note=text,
            public=False,
            no_links=True,
            update_mask="note",
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    else:
        return text

def delete_file_note(binary_id: str, note_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.delete_file_note(
            binary_id=binary_id,
            note_id=note_id,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def remove_file_tag(binary_id: str, tag_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.remove_file_tag(
            binary_id=binary_id,
            tag_id=tag_id,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

########################
# Procedures API
########################

def list_procedure_similarities(binary_id: str, rva: str, read_mask: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_procedure_similarities(
            binary_id=binary_id,
            rva=rva,
            no_links=True,
            async_req=True,
            read_mask=read_mask,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def create_procedure_note(proc_hash: str, text: str, info_msgs: list = None):
    try:
        response = ctmprocs.create_procedure_note(
            proc_hash=proc_hash,
            note=text,
            public=False,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def add_procedure_tag(proc_hash: str, text: str, info_msgs: list = None):
    try:
        response = ctmprocs.add_procedure_tag(
            proc_hash=proc_hash,
            name=text,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def list_procedure_files(hard_hash: str, read_mask: str, expand_mask: str, info_msgs: list = None):
    try:
        response = ctmprocs.list_procedure_files(
            proc_hash=hard_hash,
            read_mask=read_mask,
            expand_mask=expand_mask,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def list_procedure_notes(hard_hash: str, info_msgs: list = None):
    try:
        response = ctmprocs.list_procedure_notes(
            proc_hash=hard_hash,
            expand_mask="notes",
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def list_procedure_tags(hard_hash: str, info_msgs: list = None):
    try:
        response = ctmprocs.list_procedure_tags(
            proc_hash=hard_hash,
            expand_mask="tags",
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def delete_procedure_note(hard_hash: str, note_id: str, info_msgs: list = None):
    try:
        response = ctmprocs.delete_procedure_note(
            proc_hash=hard_hash,
            note_id=note_id,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def delete_procedure_tag(hard_hash: str, tag_id: str, info_msgs: list = None):
    try:
        response = ctmprocs.delete_procedure_tag(
            proc_hash=hard_hash,
            tag_id=tag_id,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def update_procedure_note(hard_hash: str, note_id: str, text: str, info_msgs: list = None):
    try:
        response = ctmprocs.update_procedure_note(
            proc_hash=hard_hash,
            note_id=note_id,
            note=text,
            public=False,
            no_links=True,
            update_mask="note",
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

########################
# Procedure Genomics API
########################

def list_file_procedure_genomics(binary_id: str, rva: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_file_procedure_genomics(
            binary_id=binary_id,
            rva=rva,
            no_links=True,
            async_req=True
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def list_procedure_genomics_notes(binary_id: str, rva: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_procedure_genomics_notes(
            binary_id=binary_id,
            rva=rva,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def list_procedure_genomics_tags(binary_id: str, rva: str, info_msgs: list = None):
    try:
        response = ctmfiles.list_procedure_genomics_tags(
            binary_id=binary_id,
            rva=rva,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, None)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def create_procedure_genomics_note(binary_id: str, rva: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.create_procedure_genomics_note(
            binary_id=binary_id,
            rva=rva,
            note=text,
            public=False,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def create_procedure_genomics_tag(binary_id: str, rva: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.create_procedure_genomics_tag(
            binary_id=binary_id,
            rva=rva,
            name=text,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def update_procedure_genomics_note(binary_id: str, rva: str, note_id: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.update_procedure_genomics_note(
            binary_id=binary_id,
            rva=rva,
            note_id=note_id,
            note=text,
            public=False,
            no_links=True,
            update_mask="note",
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def update_file_procedure_genomics(binary_id: str, rva: str, text: str, info_msgs: list = None):
    try:
        response = ctmfiles.update_file_procedure_genomics(
            binary_id=binary_id,
            rva=rva,
            procedure_name=text,
            update_mask="procedure_name",
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def delete_procedure_genomics_note(binary_id: str, rva: str, note_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.delete_procedure_genomics_note(
            binary_id=binary_id,
            note_id=note_id,
            rva=rva,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response

def delete_procedure_genomics_tag_by_id(binary_id: str, rva: str, tag_id: str, info_msgs: list = None):
    try:
        response = ctmfiles.delete_procedure_genomics_tag_by_id(
            binary_id=binary_id,
            tag_id=tag_id,
            rva=rva,
            force=True,
            no_links=True,
            async_req=True,
        )
        response = response.get()
    except ApiException as exc:
        process_api_exception(exc, False, info_msgs)
        return None
    except Exception as exc:
        process_regular_exception(exc, False, None)
        return None
    return response
