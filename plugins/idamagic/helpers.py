"""Helper functions"""
import os
import hashlib
import logging
import base64
import random
import string

import ida_segment
import ida_nalt
import idc
import idaapi
import ida_loader

logger = logging.getLogger(__name__)


def convert_to_py_bytes():
    """Convert return from get_idb_byte_list to python bytes"""
    a = get_idb_byte_list()
    b = [int(item, 16) for item in a]
    c = [item.to_bytes(1, "big") for item in b]

    return b"".join(c)


def create_idb_file():
    """Create an idb file from the currently loaded database."""
    file_name = gen_random_idb_filename()
    ida_loader.save_database(file_name, 0)
    return file_name


def create_proc_name(proc):
    """If it exists, add procedure name to proc.start_ea"""
    proc_name = getattr(proc, "procedure_name", None)
    if proc_name:
        full_name = f"{proc.start_ea} - {proc_name}"
    else:
        full_name = None

    return full_name if proc_name else proc.start_ea


def encode_loaded_file(file_path):
    """Encode the currenly loaded file into base64"""
    with open(file_path, "rb") as file:
        file_bytes = base64.b64encode(file.read())
    return file_bytes


def gen_random_idb_filename(length=15):
    """Generates a random filename of default length 10"""
    chars = string.ascii_letters + string.digits
    rand_filename = "".join(random.choice(chars) for i in range(length))

    return f"{rand_filename}.i64"


def get_file_architecture():
    """
    Get the currently loaded files architecture.
    Only works when running IDA in 64 bit mode.
    """
    structure = idaapi.get_inf_structure()
    if structure.is_64bit():
        return "64-bit"
    return "32-bit" if structure.is_32bit() else "unknown"


def get_end_ea(obj):
    """
    Generalized function to get the correct end_ea property of an
    object

    Maintains backwards compatibility with IDA < 7.4
    """
    try:
        return obj.end_ea
    except AttributeError:
        return obj.endEA


def get_idb_byte_list() -> list:
    """Gather byte list from IDB file."""
    bytelist = list()
    seg = ida_segment.get_first_seg()
    while seg is not None:
        start_ea = get_start_ea(seg)
        end_ea = get_end_ea(seg)
        for ea in range(start_ea, end_ea):
            flags = idc.get_full_flags(ea)
            # Convert flags to 32-bit hex value
            numbers = f"{flags:08x}"
            # Get final 8 bits of the flags (actual bytes)
            bytelist.append(f"{numbers[-2:]}")
        seg = ida_segment.get_next_seg(start_ea)

    return bytelist


def get_linked_binary_expected_path():
    """Get the full path of the input file being analyzed."""
    # Maintain backwards compatibility with IDA < 7.4
    try:
        return ida_nalt.get_input_file_path()
    except (NameError, AttributeError):
        return idc.GetInputFilePath()


def get_linked_binary_name():
    """Returns the name of the original binary for the file currently being analyzed."""
    # Maintain backwards compatibility with IDA < 7.4
    try:
        return ida_nalt.get_root_filename()
    except (NameError, AttributeError):
        return idc.GetInputFile()


def get_loaded_idb_name():
    """Get the name of the input .idb file being analyzed."""
    return os.path.basename(idc.get_idb_path())


def get_loaded_idb_path():
    """Get the full path of the input .idb file being analyzed."""
    return idc.get_idb_path()


def get_start_ea(obj):
    """
    Generalized function to get the correct start_ea property of an
    object

    Maintains backwards compatibility with IDA < 7.4
    """
    try:
        return obj.start_ea
    except AttributeError:
        return obj.startEA


def hash_byte_string(byte_string, hashtype="sha1"):
    """Hash a given byte string"""
    hash_func = getattr(hashlib, hashtype.lower())
    digest = hash_func()

    digest.update(byte_string)

    return digest.hexdigest()


def hash_linked_binary_file(hashtype="sha1"):
    """Hash uploaded file.

    Returns
    -------
    str
        The hash of the file in hexadecimal format.
    """
    hash_func = getattr(hashlib, hashtype.lower())
    digest = hash_func()

    try:
        with open(get_linked_binary_expected_path(), "rb") as f:
            while True:
                block = f.read(2**10)  # Magic number: one-megabyte blocks.
                if not block:
                    break
                digest.update(block)

            return digest.hexdigest()
    except FileNotFoundError:
        print(
            "Original binary not accessible."
            + " Place binary in the directory containing the loaded idb file"
        )
        return None


def hash_nonloaded_file(path, hashtype="sha1"):
    """Hash a file that is not currently loaded.

    Returns
    -------
    str
        The hash of the file in hexadecimal format.
    """
    hash_func = getattr(hashlib, hashtype.lower())
    digest = hash_func()

    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(2**10)  # Magic number: one-megabyte blocks.
                if not block:
                    break
                digest.update(block)

            return digest.hexdigest()
    except FileNotFoundError:
        print(
            "Original binary not accessible."
            + " Place binary in the directory containing the loaded idb file"
        )
        return None


def to_bool(param, default=False):
    """Convert a string environment variable to a boolean value.

    * Strings are case insensitive.

    Parameters
    ----------
    param: str
    default: Any
        Value to return if the param is not a know boolean value.
    """
    try:
        param = param.lower()
    except AttributeError:
        # This will happen when param isn't a string
        pass

    if param in {1, "1", "true", "yes", "y", True}:
        return True

    if param in {0, "0", "false", "no", "n", "", False}:
        return False

    return default
