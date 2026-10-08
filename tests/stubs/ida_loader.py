PATH_TYPE_IDB = 1
DBFL_TEMP = 0x08
saved = []


def get_path(kind):
    return "/tmp/unknowncyber-tests/sample.i64"


def get_file_type_name():
    return "Portable executable for 80386 (PE)"


def save_database(path, flags):
    saved.append((path, flags))
    with open(path, "wb") as fh:
        fh.write(b"IDA2" + b"\x00" * 64)
    return True
