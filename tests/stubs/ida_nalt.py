import hashlib

_input_path = "/tmp/unknowncyber-tests/sample.exe"


def retrieve_input_file_md5():
    return hashlib.md5(b"sample").digest()


def retrieve_input_file_sha256():
    return hashlib.sha256(b"sample").digest()


ROOT_FILENAME = "sample.exe"


def get_root_filename():
    return ROOT_FILENAME


def get_input_file_path():
    return _input_path


def get_imagebase():
    return 0x400000
