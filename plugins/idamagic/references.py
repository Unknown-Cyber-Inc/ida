"""
    File holding the created global references to values and widgets used throughout
    the plugin.
"""

from PyQt5.QtWidgets import (
    QComboBox,
)

########################
# Hash References
########################
loaded_sha1: str
loaded_sha256: str
loaded_md5: str
version_hash: str
ida_sha256: str
ida_md5: str
upload_content_hashes: dict
upload_container_hashes: dict

def set_loaded_sha1(hash: str):
    """Set the global value for the loaded_sha1"""
    global loaded_sha1
    loaded_sha1 = hash


def get_loaded_sha1() -> str:
    """Return the global value for the loaded_sha1"""
    return loaded_sha1


def set_loaded_sha256(hash: str):
    """Set the global value for the loaded_sha256"""
    global loaded_sha256
    loaded_sha256 = hash


def get_loaded_sha256() -> str:
    """Return the global value for the loaded_sha256"""
    return loaded_sha256


def set_loaded_md5(hash: str):
    """Set the global value for the loaded_md5"""
    global loaded_md5
    loaded_md5 = hash


def get_loaded_md5() -> str:
    """Return the global value for the loaded_md5"""
    return loaded_md5


def set_version_hash(hash: str = None):
    """Set the global value for the version_hash"""
    global version_hash
    version_hash = hash


def get_version_hash() -> str:
    """Return the global value for the version_hash"""
    return version_hash


def set_ida_sha256(hash: str):
    """Set the global value for the ida_sha256"""
    global ida_sha256
    ida_sha256 = hash


def get_ida_sha256() -> str:
    """Return the global value for the ida_sha256"""
    return ida_sha256


def set_ida_md5(hash: str):
    """Set the global value for the ida_md5"""
    global ida_md5
    ida_md5 = hash


def get_ida_md5() -> str:
    """Return the global value for the ida_md5"""
    return ida_md5


def add_upload_content_entry(hash: str, index: int):
    """Add a hash to the upload_content_hashes"""
    global upload_content_hashes
    upload_content_hashes[hash] = index


def increment_upload_content_indexes():
    """
    Used when the original file is uploaded after an IDB or disassembly upload.

    Iterates over the upload_content_hashes dict, incrementing the stored index for
    each entry by 1.
    """
    global upload_content_hashes
    for c_hash in upload_content_hashes:
        if upload_content_hashes[c_hash] > 0:
            upload_content_hashes[c_hash] += 1


def set_upload_content_hashes(hash_dict: dict = {}):
    """Set the upload_content_hashes dict"""
    global upload_content_hashes
    upload_content_hashes = hash_dict


def get_upload_content_hashes() -> dict:
    """Return the global value for the upload_content_hashes"""
    return upload_content_hashes


def add_upload_container_entry(hash: str, index: int):
    """Add a hash to the upload_container_hashes"""
    global upload_container_hashes
    upload_container_hashes[hash] = index


def remove_upload_container_entry(hash: str):
    """Remove a hash from the upload_container_hashes dict"""
    global upload_container_hashes
    del upload_container_hashes[hash]


def set_upload_container_hashes(hashes: dict = {}):
    """Set the upload_container_hashes dict"""
    global upload_container_hashes
    upload_container_hashes = hashes


def get_upload_container_hashes() -> dict:
    """Return the global value for the upload_container_hashes"""
    return upload_container_hashes


########################
# Value References
########################
recent_upload_type: str
file_exists: bool

def set_recent_upload_type(upload_type: str = None):
    """Set the global value for the recent_upload_type"""
    global recent_upload_type
    recent_upload_type = upload_type


def get_recent_upload_type() -> str:
    """Return the global value for the recent_upload_type"""
    return recent_upload_type


def set_file_exists(exists: bool):
    """Set the global value for the file_exists"""
    global file_exists
    file_exists = exists


def get_file_exists() -> bool:
    """Return the global value for the file_exists"""
    return file_exists

########################
# Widget References
########################
dropdown: QComboBox

def set_dropdown_widget(dropdown_widget: QComboBox):
    """Set the global value for the dropdown widget"""
    global dropdown
    dropdown = dropdown_widget

def get_dropdown_widget() -> QComboBox:
    """Return the global value for the dropdown widget"""
    return dropdown
