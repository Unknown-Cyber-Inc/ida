"""
    File holding the created global references to values and widgets used throughout
    the plugin.
"""

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


def set_version_hash(hash: str):
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


def set_upload_content_hashes(hashes: dict):
    """Set the global value for the upload_content_hashes"""
    global upload_content_hashes
    upload_content_hashes = hashes


def get_upload_content_hashes() -> dict:
    """Return the global value for the upload_content_hashes"""
    return upload_content_hashes


def set_upload_container_hashes(hashes: dict):
    """Set the global value for the upload_container_hashes"""
    global upload_container_hashes
    upload_container_hashes = hashes


def get_upload_container_hashes() -> dict:
    """Return the global value for the upload_container_hashes"""
    return upload_container_hashes


########################
# Widget References
########################
