"""Helper functions"""
import os
import hashlib
import logging
import base64
import random
import string
import re
import json
import struct
import shutil
import traceback
import six
import networkx

import ida_segment
import ida_nalt
import idc
import idaapi
import ida_loader
import sark
import ida_funcs
import ida_name
import ida_ua
import idautils

from networkx.drawing import nx_pydot
from collections import namedtuple

logger = logging.getLogger(__name__)

MIN_STRING_LENGTH = 3

class FlowGraphError(Exception):
    """General exception for errors with the CFG."""

    pass


class JSONFlowGraph(object):
    def __init__(self, cfg=None):
        if cfg is None:
            # If no cfg provided, initialize empty graph.
            self.cfg = networkx.DiGraph()
        else:
            self.cfg = cfg

    @staticmethod
    def _format_adjacency_list(adj_dict):
        result = dict()

        for node in adj_dict:
            result[ea2str(node)] = [ea2str(i) for i in adj_dict[node]]

        return result

    def to_dict(self):
        return self._format_adjacency_list(self.cfg.adj)

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_dot(cls, dot):
        """
        Create CFG from dot-serialized string

        This is a modified version of `networkx.drawing.nx_pydot.read_dot()`

        Parameters
        ----------
        dot: str
            Dot formatted string.

        Returns
        -------
        JSONFlowGraph
            A new JSONFlowGraph created using the dot data.
        """

        # We need a function from the actual pydot library.
        pydot = nx_pydot.load_pydot()
        P = pydot.graph_from_dot_data(dot)
        cfg = nx_pydot.from_pydot(P)
        return cls(cfg=cfg)

    def update_block_attributes(self, blockEA, attr_dict):
        """
        Add or update attributes attached to a block

        Parameters
        ----------
        blockEA: int | long
            Address of block to update.
        attr_dict:
            Dictionary of attributes to add/update on block.
        """
        if blockEA not in self.cfg:
            raise FlowGraphError(
                "Attempting to update non-existent block {:#x}".format(blockEA)
            )

        self.cfg.add_node(blockEA, attr_dict=attr_dict)

    def split_block(self, blockEA, splitEA):
        """Split block in the CFG.
        Splits block at `blockEA` at `splitEA`. Does the following:

        * A new node at `splitEA` is created.
        * All edges from `blockEA` will now be from `splitEA`.
        * A new edge is created from `blockEA` to `splitEA`.

        Parameters
        ----------
        blockEA: int | long
        splitEA: int | long
        """
        # Ensure we have correct types
        if isinstance(blockEA, str):
            blockEA = str2ea(blockEA)
        if isinstance(splitEA, str):
            splitEA = str2ea(splitEA)

        # Add the new block
        self.cfg.add_node(splitEA)

        # Move all edges from blockEA to splitEA
        #
        # The remove_edges_from function is not
        # more efficient at is essentially does the same
        # thing: loops over edges and removes them.
        #
        # The list is necessary to avoid python complaining
        # about the dictionary changing during iteration.
        # The number of successors should be reasonably small,
        # so the performance impact will hopefully be minimal.
        for node in list(self.cfg.successors(blockEA)):
            # Remove the existing edge
            self.cfg.remove_edge(blockEA, node)
            # Add the new edge
            self.cfg.add_edge(splitEA, node)

        # Add edge to link the blocks being split.
        self.cfg.add_edge(blockEA, splitEA)

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

def get_disassembly(ea):
    return idc.GetDisasm(ea)

def hash_file(hashtype="sha1"):
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


ImportedFunction = namedtuple("APIFunc", "name module ea ord")


class Singleton(type):
    """Convert any class into a singleton.
    From: https://stackoverflow.com/a/6798042/558820

    Examples
    --------
    #Python2
    class MyClass(BaseClass):
        __metaclass__ = Singleton

    #Python3
    class MyClass(BaseClass, metaclass=Singleton):
        pass
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(
                *args, **kwargs
            )
        return cls._instances[cls]


@six.add_metaclass(Singleton)
class Imports(dict):
    """Mapping of RVA (ea - image_base) to API functions (`ImportedFunction`).

    This mapping is automatically built the first time this class is instantiated.

    This class is defined as a singleton so that the mapping is only ever built once.

    Any rebasing of the binary MUST be done before this class is instantiated for
    the first time.

    The keys of this dictionary are the RVA of the imported function and the values
    are `ImportedFunction` objects containing the details of the imported function.

    Using RVA so that it is independent of base. Manually converting from EA to rva
    so that we don't have to rely on a rebase to 0 having occurred.
    """

    def __init__(self):
        super(Imports, self).__init__()
        self._build_imports_mapping()

    def _import_mapper(self, ea, name, ord):
        """Callback passed to idaapi.enum_import_name.
        Inserts the current import into the dictionary of imported APIs
        """
        # Use ea name instead of rva because we use ea everywhere else.
        ea = ea2rva(ea)
        # If we don't have a name, skip it.
        if name is None:
            logger.warn(
                "No name provided by IDA for import at EA %#x. Skipping", ea
            )
            return True
        name = strip_parens(demangle(name))
        if ea in self and self[ea].name != name:
            raise ValueError(
                "Attempt to replace import {} at EA {:#x} with name {}.".format(
                    self[ea], ea, name
                )
            )
        self[ea] = ImportedFunction(
            ea=ea, ord=ord, name=name, module=self._curr_mod_name
        )
        return True

    def _build_imports_mapping(self):
        """Iterates over each of the import modules (dll's)
        and enumerates each of the APIs imported from them.
        enum_import_names implements a visitor pattern which passes
        each imported API name and it's EA in the import table to
        the callback function."""
        num_imps = idaapi.get_import_module_qty()
        # This instance variable is used for communicating with
        # the callback function _import_mapper. This variable
        # should be removed when this function exits.
        self._curr_mod_name = None
        for i in range(0, num_imps):
            try:
                self._curr_mod_name = idaapi.get_import_module_name(i)
                if not self._curr_mod_name:
                    continue
                idaapi.enum_import_names(i, self._import_mapper)
            except Exception as e:
                logger.warn(f"Unable to get import module name [{i}]")
        del self._curr_mod_name


def ea2rva(ea):
    """Convert an Effective Address (EA) to a Relative Virtual Address.

    EA is essentially the same thing as a Virtual Address. We use EA
    terminology because that's what IDA uses.

    EA = image_base + RVA
    """
    return ea - get_image_base()


def get_image_base():
    """Returns the base address of the PE image"""
    return idaapi.get_imagebase()


def rebase_to_zero():
    rebase_delta = 0 - get_image_base()
    idaapi.rebase_program(rebase_delta, idaapi.MSF_FIXONCE)


def get_heads(start=None, end=None):
    """Returns list of instructions (heads) between start and end."""
    return idautils.Heads(start, end)

def mark_as_function(start, end=4294967295):
    """Mark the bytes between start and end as a function."""
    # Maintain backwards compatibility with IDA < 7.4
    try:
        ida_funcs.add_func(start, end)
    except (NameError, AttributeError):
        idc.MakeFunction(start, end)


def mark_missed_procedures():
    just_saw_push_ebp = False
    lastEA = None
    for ea in get_heads():
        # See if ea is a function
        try:
            func = sark.get_func(ea)
            # If this is already a function, skip it.
            continue
        except sark.exceptions.SarkNoFunction:
            # Otherwise, let's continue.
            pass
        # If we find a "push ebp" followed by a "mov ebp, esp",
        # make this into a function.
        dis = get_disassembly(ea)
        if dis == "push    ebp":
            just_saw_push_ebp = True
            lastEA = ea
            continue
        elif just_saw_push_ebp and dis == "mov     ebp, esp":
            mark_as_function(lastEA)
        just_saw_push_ebp = False
        lastEA = ea


def demangle(name, disable_mask=None):
    """
    Attempt to demangle a name from IDA

    Parameters
    ----------
    name: str
        Name to demangle
    disable_mask: int | long
        Mask to pass through to idaapi demangle function.
        Default is idc.get_inf_attr(idc.INF_SHORT_DEMNAMES).
            idc.getLongPrm(idc.INF_SHORT_DN) in IDA7
        To disable mask, set disable_mask=0.

    Returns
    -------
    str
        The demangled name. If `name` could not be demangled,
        simply returns `name`. If strip_parans is True, will
        strip parenthesis regardless if demangling was sucessful.

    """
    if disable_mask is None:
        # Maintain backwards compatibility with IDA < 7.4
        try:
            disable_mask = idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)
        except AttributeError:
            disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)
    try:
        demangled_name = ida_name.demangle_name(
            name, disable_mask, ida_name.DQT_FULL
        )
    except (NameError, AttributeError):
        demangled_name = idaapi.demangle_name2(name, disable_mask)
    if demangled_name:
        return demangled_name
    return name


def strip_parens(string):
    """ " Remove parenthesis and internal content"""
    p = re.compile("\(.*\)")
    return p.sub("", string)

def get_function_name(ea, bare=True, full=False):
    """Get name of function at ea.
    Parameters
    ----------
        ea: int | long
            Address of function
        bare: bool
            If True, strip arguments, return values, etc. and only return name.
            Defaults to True.
            This option takes precedence over `full`.
        full: bool
            If True, return full function name, i.e. sets disable_mask to 0.
            Defaults to False.
            If `bare` is True, this option is ignored.
    """
    disable_mask = None
    if full and not bare:
        disable_mask = 0
    # Maintain backwards compatibility with IDA < 7.4
    try:
        name = demangle(idc.get_func_name(ea), disable_mask)
    except AttributeError:
        name = demangle(idc.GetFunctionName(ea), disable_mask)
    if bare:
        name = strip_parens(name)
    return name


def get_segment_name(ea):
    return idc.get_segm_name(ea)


def get_strings(procedure):
    """Iterate over the strings in this function.
    Yields
    -------
    str
        Strings referenced from the function.
    """
    for xref in procedure.xrefs_from:
        try:
            string = sark.get_string(xref.to)
            if hasattr(string, "decode"):
                string = string.decode("utf-8", "replace")
            if len(string) >= MIN_STRING_LENGTH:
                # Yield str instead of unicode because str is what is expected at the moment.
                yield string.encode("utf-8", "replace")
        except sark.exceptions.SarkNoString:
            pass


def get_api_calls(procedure):
    """Iterator over all api calls in the procedure."""
    for xref in procedure.xrefs_from:
        if xref.type.is_call or xref.type.is_jump:
            if xref.to in Imports():
                name = "{}".format(Imports()[xref.to].name)
                # Ensure valid utf-8 returned
                if hasattr(name, "decode"):
                    name = name.decode("utf-8", "replace")
                yield name


# List of registers to use when undoing automatic register renaming.
register_list = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "al",
    "cl",
    "dl",
    "bl",
    "ah",
    "ch",
    "dh",
    "bh",
    "es",
    "cs",
    "ss",
    "ds",
    "fs",
    "gs",
    "efl",
    "ctrl",
    "stat",
    "tags",
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
    "mxcsr",
    "ax",
    "cx",
    "dx",
    "bx",
]


def remove_register_renamings(func_t):
    """
    Explanation by Craig:
    Say a register is pushed as an argument into a known API call
    (known as in FLIRT has a signature).  Then IDA will rename the
    register to match the name of the argument.  This function removes
    all those renamings so that it just shows the register name instead.
    This works by iterating over each register name and removing any renaming
    each register has between the start and end address of the function.
    (This could probably be made more robust by iterating over chunk in the
    function).
    """
    for reg in register_list:
        idaapi.del_regvar(
            func_t, get_start_ea(func_t), get_end_ea(func_t), reg
        )


def set_operands_display_type(instruction_ea, op_n=-1, display="hex"):
    """Set display type of display for insruction's operands

    Supported types:

    * dec (Decimal number)
    * hex (Hexidecimal number)

    Examples
    --------

    * hex: "[eax + arg_1]" to "[eax + 0x4]"
    * dec: "[eax + arg_1]" to "[eax + 4]"

    Parameters
    ----------
    instruction_ea: long | int
        Address of instruction to modify
    display: str
        Display type to use.
    op_n: int
        Operand index to format. Value of -1 (default) applies formatting to
        all operands.
    """
    if display == "hex":
        idaapi.op_num(instruction_ea, op_n)
    elif display == "dec":
        idaapi.op_dec(instruction_ea, op_n)
    else:
        logger.error("Unsupported operand display type: {}".format(display))


def api_call_name(instruction):
    # If this isn't a call or jmp, bail out.
    if not (instruction.insn.is_call or instruction.insn.mnem == "jmp"):
        return None

    for xref in instruction.xrefs_from:
        if xref.type.is_call or xref.type.is_jump:
            if xref.to in Imports():
                # This is an instruction. We should only have
                # a single jmp or call xref
                try:
                    return Imports()[xref.to].name
                except KeyError:
                    # The target is not an API, so return None.
                    return None
    # We shouldn't reach here, but the fallback is nice.
    return None


def get_operand(ea, op):
    """Get the `op`_th operand of the instruction at address `ea`.

    In general, prefer the use of sark to interact with operands.

    This function exists because of a few corner cases the require
    directly interacting with an instruction or operand without
    using sark.

    Parameters
    ----------
    ea: long | int
        The address of the instruction to get the mnemonic for.
    op: int
        The index of the operand.

    Returns
    -------
    : Any
        The return value of the ida operation.
    """
    # Maintain backwards compatibility with IDA < 7.4
    try:
        return idc.print_operand(ea, op)
    except AttributeError:
        return idc.GetOpnd(ea, op)


def ea2str(ea):
    """Convert an Effective Address (EA) to string.
    Parameters
    ----------
    ea: long | int
        The address

    Returns
    -------
    ea: str
        Hex representation of the address. Pattern: "0x[0-9a-f]+"
    """
    return "{:#x}".format(ea)


def str2ea(ea):
    """Convert a string representation of an address (EA) back into int.
    Parameters
    ----------
    ea: str
        The string representation of the address. Expected to be output of ea2str.

    Returns
    -------
    long
        The ea as a long integer
    """
    return int(ea, base=16)


def get_dtype(obj):
    """
    Generalized function to get the correct dtype property of an
    object

    Maintains backwards compatibility with IDA < 7.4
    """
    try:
        return obj.dtype
    except AttributeError:
        return obj.dtyp


def dtype2ptr(dtype):
    """Convert data type into pointer type.
    Used when formatting memory operands

    Parameters
    ----------
    dtype: int
        The IDA datatype. op.dtype.
        For Python2.7, op.dtyp

    Returns
    -------
    : str
    """
    # Data types taken from sark.base.DTYP_TO_SIZE
    mapping = {
        ida_ua.dt_byte: "bptr",
        ida_ua.dt_word: "wptr",
        ida_ua.dt_dword: "dptr",
        ida_ua.dt_float: "dptr",  # Sark lists dt_float as a double size
        ida_ua.dt_fword: "fwptr",
        ida_ua.dt_qword: "qptr",
        ida_ua.dt_byte16: "b16ptr",
        ida_ua.dt_byte32: "b32ptr",
        ida_ua.dt_byte64: "b64ptr",
        # These are not present in Sark and were found by looking at idaapi.
        ida_ua.dt_tbyte: "tbptr",  # A tbyte (long double) can be either 10 or 12 bytes. Depends on processor.
        ida_ua.dt_string: "strptr",
        ida_ua.dt_unicode: "uniptr",
        ida_ua.dt_void: "voidptr",
        # These aren't likely to be operands, but including for completeness
        ida_ua.dt_bitfild: "bfldptr",
        ida_ua.dt_code: "codeptr",
        ida_ua.dt_packreal: "packptr",
        ida_ua.dt_ldbl: "ldblptr",
    }
    return mapping.get(dtype, "none")


def sign_unsigned(n):
    """Converts an unsigned int into a signed int.
    This is necessary because IDAPython's GetOperandValue
    incorrectly returns negative offsets as postive unsigned ints

    Positive numbers are returned correctly. It is safe to pass
    all offsets through this function.

    Parameters
    ----------
    n: int | long
        An unsigned integer

    Returns
    -------
    : int
        A signed integer
    """
    assert isinstance(n, int)

    # struct.pack/unpack convert between a string representation
    # of the bytes and the internal data structure.
    # This essentially converts the unsigned int into a string of bytes
    # and then interprets these bytes as a signed int.
    # This is essentially a manual cast from unsigned to signed
    #
    # Base the conversion on the size of the int. int.bit_length() returns
    # the number of bits needed to represent the integer in binary.
    # If the number of bits does not exactly line up with one of the sizes,
    # the number is positive, i.e. the sign bit is not set, so we  can
    # safely return the value unaltered.
    fmt = {
        32: "I",  # integer (four bytes)
        64: "Q",  # long long. Standard long is only considered 32 bits by struct. (8 bytes)
    }.get(n.bit_length(), None)
    if fmt is None:
        return n
    try:
        val = struct.unpack(fmt.lower(), struct.pack(fmt, n))[0]
    except struct.error:
        logger.exception("Error converting {} to unsigned".format(n))
        raise
    return val


def parse_sib(op_t):
    """Parse the SIB (Scaled Index Byte) for o_mem operands
    For operands of the form [edx*4+4219736] (this is an o_mem type), IDA
    does not parse the SIB for us. We have to do so ourselves.

    Using http://www.c-jump.com/CIS77/CPU/x86/X77_0100_sib_byte_layout.htm
    as reference for structure of the SIB.

    Parameters
    ----------
    op_t:

    Returns
    -------
    base: str
        Name of the base register
    index: str
        Name of the index register
    scale: int
        Scale size
    """
    # Only parse sib for o_mem operands when using the pc module.
    if idaapi.get_idp_name() != "pc" and op_t.type == idaapi.o_mem:
        return None, None, None

    # DEFINE hasSIB specflag1
    if not op_t.specflag1:
        # We don't have a sib to parse.
        return None, None, None

    # DEFINE sib specflag2
    # The and is because of a quirk in the way python represents binaries.
    # Python represents negative numbers as -0b001 which is equal to 0b110.
    # The or essentially converts the first to the second representation.
    # This makes debugging easier.
    # Eight bits because the sib is always a byte.
    sib = op_t.specflag2 & 0xFF

    # http://www.c-jump.com/CIS77/CPU/x86/X77_0100_sib_byte_layout.htm
    base = sib & 0b111
    index = sib >> 3 & 0b111
    scale = 2 ** (sib >> 6)

    # Convert base into register name

    return sark.get_register_name(base), sark.get_register_name(index), scale


def get_ida_version():
    try:
        version_string = idaapi.IDA_SDK_VERSION
        # Convert string to charlist with list(), then back to dot version
        # ie "800" -> ["8", "0", "0"] -> "8.0.0"
        dotted_version = ".".join(list(str(version_string)))
        return dotted_version
    except:
        return "8.2.230124"


def get_operand_value(ea, op):
    """Get the value of the `op`_th operand of instruction at address `ea`.
    In general, prefer the use of sark to interact with operands.

    This function exists because of a few corner cases the require
    directly interacting with an instruction or operand without
    using sark.

    Parameters
    ----------
    ea: long | int
        The address of the instruction to get the mnemonic for.
    op: int
        The index of the operand.

    Returns
    -------
    : Any
        The return value of the ida operation.
    """
    # Maintain backwards compatibility with IDA < 7.4
    try:
        return idc.get_operand_value(ea, op)
    except AttributeError:
        return idc.GetOperandValue(ea, op)


def get_procname(obj):
    """
    Generalized function to get the correct procname property of an
    object

    Maintains backwards compatibility with IDA < 7.4
    """
    try:
        return obj.procname
    except AttributeError:
        return obj.procName


def _prolog_format_operand(op, line_ea):
    """Format instruction operand into prolog syntax

    See docstring in `prolog_format_instruction` for details
    on how operands should be formatted.

    Parameters
    ----------
    op: sark.Operand
    line_ea: long | int
        The startEA of the line operand is on.

    Returns
    -------
    : str
    """

    # Sark doesn't provide a type alias for this
    FP_OPND = 11  # Floating Point (ST) Register

    # IDA Operand types are from optype_t definition in idasdk\includes\ua.hpp

    # IDA Operand type REG_OPND	= 1
    # Op is general register (includes XMM & MM regs)
    if op.type.is_reg:
        # Work around for https://github.com/tmr232/Sark/issues/67
        # Remove once this is fixed in sark.
        if get_dtype(op) == 0:
            return sark.get_register_name(op.reg_id, 1)
        # op.reg fails to lookup the size to name translation
        # of 40/80-bit Extended Precision floating point registers
        # and therefore fails to find the name of the register.
        # As in this case the name should be the only thing in
        # op.text, this is a crude hack to return that instead
        # See MAGIC-1100
        try:
            return op.reg
        # If KeyError: 5L
        except KeyError:
            return op.text

    # IDA Operand Type MEM_OPND = 2
    # Direct Memory Reference  (DATA)
    elif op.type.is_mem:
        set_operands_display_type(
            instruction_ea=line_ea, op_n=op.n, display="dec"
        )

        # The memory address referenced
        address = ""
        # Look for segment registers to start operand with.
        if re.match(".*fs:.*", op.text):
            address += "fs+"
        elif re.match(".*qs:.*", op.text):
            address += "qs+"
        elif re.match(".*ds:.*", op.text):
            address += "ds+"

        base, index, scale = parse_sib(op.op_t)
        offset = sign_unsigned(op.offset)
        # Backwards compatibility.
        # Previous code did not include base if it was ebp.
        if base is not None:
            if base == "ebp":
                base = ""
            else:
                base = base + "+"
            address += base + index + "*" + str(scale) + "{:+d}".format(offset)
        # If sib not set, fall back to previous methods
        elif op.text.startswith("["):
            # Assuming that if the operand starts with '[', it is of the form [offset + index * scale]
            address += op.text.strip("][")
        else:
            address += "{:d}".format(op.offset)

        return "{size}({address})".format(
            size=dtype2ptr(get_dtype(op)),
            address=address,
        )
    # IDA Operand Type PHRASE_OPND = 3
    # Memory Ref [Base Reg]
    # Memory Ref [Base Reg + Index Reg * Scale]
    # IDA Operand Type DISPL_OPND = 4
    # Memory Ref [Base Reg + Index Reg * Scale + Offset]
    # Memory Ref [Base Reg + Offset]
    #
    # Memory access using a phrase
    # Phrase: [base + index * scale + offset]
    # All but base are optional.
    elif op.type.is_phrase or op.type.is_displ:
        # Display operands using decimal format so that they
        # can be directly compared to the prolog output.
        set_operands_display_type(
            instruction_ea=line_ea, op_n=op.n, display="dec"
        )
        ptrtype = dtype2ptr(get_dtype(op))
        # We will at a minimum have a register.
        addr_expr = op.reg
        # For some reason, op.reg on a pc register sometimes returns None
        # Crude hack to get around this
        # See MAGIC-1100
        if addr_expr is None:
            addr_expr = "pc"
        if op.index:
            # If scale isn't present in disassembly, value
            # of op.scale will equal 1
            addr_expr += "+{}*{}".format(op.index, op.scale)
        if op.offset:
            # If there is no offset, the value of op.offset will be 0
            # Must use sign_unsigned on the offset. See comment in that function.
            # String formatting expression ensures the offset is always prefixed
            # by a sign (+/-).
            addr_expr += "{:+d}".format(sign_unsigned(op.offset))
            # addr_expr += "{:+d}".format(op.offset)
        return "{ptrtype}({addr_expr})".format(
            ptrtype=ptrtype,
            addr_expr=addr_expr,
        )

    # IDA Operand Type IMM_OPND = 5 (Immediate Value) or
    # Return an immediate as a decimal number so that simplification can interpret
    # math operations as expected.
    elif op.type.is_imm:
        # Using get_operand_value because IDA does some magic to determine
        # the correct value to return. This is a bit more reliable than
        # attempting to determine the correct field from sark.Operand to return.
        op_val = get_operand_value(line_ea, op.n)
        # Have to use string representation because the operands are concatenated
        # together later.
        return str(sign_unsigned(op_val))
    # IDA Operand Type FAR_OPND = 6 (Immediate Far Address - CODE) or
    # IDA Operand Type NEAR_OPND = 7 (Immediate Near Address - CODE)
    # Return an decimal so that semantics will correctly match with other
    # immediate values (immediate values must be decimals so that simplification
    # can correctly interpret the math equations.).
    elif op.type.is_far or op.type.is_near:
        # Using get_operand_value because IDA does some magic to determine
        # the correct value to return. This is a bit more reliable than
        # attempting to determine the correct field from sark.Operand to return.
        op_val = get_operand_value(line_ea, op.n)
        # Have to use string representation because the operands are concatenated
        # together later.
        return str(sign_unsigned(op_val))
    # IDA Operand Type FP_OPND = 11
    # Floating Point (ST) Register (st0 - st7)
    # Sark doesn't provide alias for type values > 7
    # x86 files are coming up as procname 'metapc'.
    elif op.type.type == 11 and get_procname(
        idaapi.get_inf_structure()
    ).lower() in ["metapc"]:
        opnd = get_operand(line_ea, op.n)
        # (CAL) Why does this logic exist? Can't we
        # just return the result of get_operand?
        if opnd == "st":
            return "st0"
        else:
            match = re.match("st\(([1-7])\)", opnd)
            if match:
                stregnum = match.group(1)
                return "st" + stregnum
            else:
                return None
    # On processor specific types, just convert to an atom by surrounding in single quotes
    elif op.type.name == "Processor_specific_type":
        return "'{}'".format(op.text)
    # Unknown operand op_type
    else:
        # Error logging is handled by the `prolog_format_instruction` function.
        return None


def prolog_format_instruction(instruction, line_ea):
    """Parses the instruction into Prolog syntax and returns it.

    Converts the assembly instruction into a prolog atom or function.

    If there are no operands in the assembly function, the mnemonic is returned.

    If there are operands, a function is returned containing a term per operand.

    Memory addresses are formatted as a function with the function name giving the
    size of the memory location and a single term that is an expresion evaluating
    to the memory address. So a memory access to a double word at address 0x40
    will be formatted `dptr(0x40)`. The function `dtype2ptr` contains a detailed list
    of the various sizes. The `Examples` section contains examples of other types
    of memory accesses.

    Examples
    --------

    * `ret` => `ret`
    * `mov eax ebx` => `mov(eax,ebx)`
    * `mov eax [ebx]` => `mov(eax,dptr(ebx))`
    * `mov eax [ebx+4]` => `mov(eax,dptr(ebx+4))`
    * `mov eax [ebx+esi*2-4]` => `mov(eax,dptr(ebx+esi*2-4))`
    * `mov eax fs:ebx` => `mov(eax,dptr(fs + ebx))`

    Parameters
    ----------
    instruction: sark.Instruction
        The instruction to parse.
    line_ea: long | int
        sark.Line.startEA of the line the instruction is on.

    Returns
    -------
    : str
    """
    operands = instruction.operands
    formatted_operands = list()

    for op in operands:
        # This is to catch IDA weirdness where FP instructions like fldz, fstp, & fucompp have empty
        # op_type 11 operands.
        if (op.type.type == 11) and (get_operand(line_ea, op.n) == ""):
            continue

        # IDA Operand Type VOID_OPND = 0
        # Void operator
        # This should never happen.
        if op.type.is_void:
            logger.error(
                "Found void operand in instruction {}".format(ea2str(line_ea))
            )
            continue

        formatted_op = _prolog_format_operand(op, line_ea)

        if formatted_op is None:
            logger.warning(
                "Error parsing operand: "
                "{{'op_index': {op_index}"
                " 'type': {type},"
                " 'type_num': {type_num},"
                " 'instruction': {instruction}"
                " 'op_text': {op_text}"
                "}}".format(
                    op_index=op.n,
                    type=op.type,
                    type_num=op.type.type,
                    instruction=sark.Line(line_ea).disasm,
                    op_text=op.text,
                )
            )
            return None
        else:
            # Inner single quotes cause prolog syntax errors, so escape them
            # Also escape inner backslashes, as if they don't find a character
            # to escape themselves they will continue looking until they find one
            # and if this escapes the final single quote, bjprocess will hang (ie '\x061\'')
            # See MAGIC-1085
            broken = formatted_op.split("'")
            # Cases:
            #     Len 1: String with no single quotes, ignore
            #     Len 3: String with only opening and closing single quotes, handle backslash
            #     Len >3: String with inner single quotes, handle backslash and single quotes
            if len(broken) > 1:
                broken_back = formatted_op.split("\\")
                formatted_op = "\\\\".join(broken_back)
                broken = formatted_op.split("'")
            if len(broken) > 3:
                # Toss out opening and closing blank strings
                broken = broken[1:-1]
                # Rejoin with escaped inner single quotes, then re-add starting and finishing single quotes
                together = "'{}'".format("\\'".join(broken))
                formatted_op = together

            formatted_operands.append(formatted_op)

    if formatted_operands:
        operands_str = "({})".format(",".join(formatted_operands))
    else:
        operands_str = ""

    instruction = "{mnem}{operands}".format(
        mnem=instruction.mnem, operands=operands_str
    )
    return instruction.lower()


def getUnixFileType():
    """Get the file type."""
    return ida_loader.get_file_type_name()


def get_input_file_name():
    """Returns the name of the file currently being analyzed."""
    # Maintain backwards compatibility with IDA < 7.4
    try:
        return ida_nalt.get_root_filename()
    except (NameError, AttributeError):
        return idc.GetInputFile()


def zip_disassembled(outdir):
    """Tar the binary.json and all procedure files."""
    try:
        shutil.make_archive(f"{get_input_file_name()}", "zip", outdir)
        zip_path = f"{get_input_file_name()}.zip"
        shutil.move(zip_path, outdir)
        return os.path.join(outdir, zip_path)
    except Exception as exc:
        print(f"Error: {exc}")


def parse_binary(main_hashes, orig_dir=None):
    """Parse the input binary and run it through the provided factory.

    Parameters
    ----------
    parser: AbstractBinaryParser
        The parser to run against the Binary. Defaults to JSONBinaryFactory.

    Returns
    -------
    varied

        Returns the result of parser.finish()
    """
    input_path = get_linked_binary_expected_path()
    if orig_dir is None:
        ida_dir = os.path.dirname(input_path)
        outdir = os.path.join(ida_dir, "outdir")
        if os.path.exists(outdir):
            try:
                shutil.rmtree(outdir)
            except OSError as exc:
                print(f"Error: {exc}")
    else:
        outdir = os.path.join(orig_dir, "outdir")

    proc_outdir = os.path.join(outdir, "procedures")

    try:
        os.mkdir(outdir)
        os.mkdir(proc_outdir)

        binary_id = hash_file()
        disassimly_hashes = get_disassembly_hashes(input_path)

        arch = get_file_architecture()

        bin_dict = {
            "md5": main_hashes["ida_md5"],
            "sha1": disassimly_hashes["sha1"],
            "sha256": main_hashes["ida_sha256"],
            "sha512": disassimly_hashes["sha512"],
            "unix_filetype": getUnixFileType(),
            "version": get_ida_version(),
            "disassembler": "ida",
	        "use_32": arch == "32-bit",
	        "use_64": arch == "64-bit",
	        "file_name": get_input_file_name(),
            "image_base": get_image_base(),
            "byte_data": convert_to_encoded_byte_string(),
        }

        bin_path = os.path.join(outdir, "binary.json")
        with open(bin_path, "w") as outfile:
            json.dump(bin_dict, outfile)

        logger.info("[{}] Started data extraction".format(binary_id))
        # Rebase to 0x0 so that we don't have to worry about the
        # difference between EA and RVA.
        rebase_to_zero()
        logger.debug("Searching for missed procedures")
        # Attempt to form functions out of the instructions that aren't currently in a function.

        mark_missed_procedures()
        logger.debug("Starting iteration of functions")

        count = 1

        imports = Imports()

        # A binary is modeled as a set of functions
        # Thus, we iterate over all functions to build model.
        for func in sark.functions():
            cfg = sark.get_nx_graph(func.ea)
            cfg_obj = JSONFlowGraph(cfg=cfg)

            proc_dict = {
                "blocks": list(),
                "is_library": func.flags & 0x4,  # idaapi.FUNC_LIB == 0x4
                "is_thunk": func.flags & 0x80,  # idaapi.FUNC_THUNK = 0x80
                "startEA": get_start_ea(func),
                "endEA": get_end_ea(func),
                "procedure_name": get_function_name(get_start_ea(func)),
                "segment_name": get_segment_name(get_end_ea(func)),
                "strings": list(),
                "api_calls": list(get_api_calls(func)),
                "cfg": cfg_obj.to_dict(),
            }

            remove_register_renamings(func.func_t)

            logger.debug("Starting procedure {:#x}".format(get_start_ea(func)))

            for block in sark.FlowChart(get_start_ea(func)):
                block_dict = {
                    "startEA": get_start_ea(block),
                    "endEA": get_end_ea(block),
                    "lines": list(),
                }

                logger.debug(
                    "Starting block {:#x}".format(get_start_ea(block))
                )

                for line in block.lines:
                    set_operands_display_type(
                        get_start_ea(line), display="hex"
                    )
                    try:
                        bytes = " ".join(
                            "{:02X}".format(x) for x in line.bytes
                        )
                        line_dict = {
                            "startEA": get_start_ea(line),
                            "endEA": get_end_ea(line),
                            "type": line.type,
                            "bytes": bytes,
                            "mnem": line.insn.mnem,
                            "operands": [i.text for i in line.insn.operands],
                            "prolog_format": prolog_format_instruction(
                                line.insn, get_start_ea(line)
                            ),
                            "api_call_name": api_call_name(line),
                            "is_call": line.insn.is_call,
                        }
                        block_dict["lines"].append(line_dict)
                    except sark.exceptions.SarkNoInstruction:
                        continue
                proc_dict["blocks"].append(block_dict)
            count += 1
            if count % 100 == 0:
                logger.info(
                    "[{}] Processed {} procedures so far".format(
                        binary_id, count
                    )
                )

            proc_path = os.path.join(
                proc_outdir, f"{proc_dict['startEA']}.json"
            )
            with open(proc_path, "w") as outfile:
                json.dump(proc_dict, outfile)

        logger.info("Finished parsing %s", binary_id)
        logger.info(f"Creating archive file {get_input_file_name()}.zip")
        zip_path = zip_disassembled(outdir)
        logger.info(f"Finished creating archive file {get_input_file_name()}.zip")

        return zip_path

    finally:
        pass
        # shutil.rmtree(outdir)

def convert_to_py_bytes():
    """Convert return from get_idb_byte_list to python bytes"""
    a = get_idb_byte_list()
    b = [int(item, 16) for item in a]
    c = [item.to_bytes(1, "big") for item in b]

    return b"".join(c)


def convert_to_encoded_byte_string():
    """Convert return from get_ida_byte_list to a base64-encoded string."""
    a = get_idb_byte_list()
    b = [int(item, 16) for item in a]
    c = [item.to_bytes(1, "big") for item in b]
    d = b"".join(c)

    return base64.b64encode(pad_byte_list(d)).decode("ascii")


def pad_byte_list(byte_list):
    padding_needed = (3 - len(byte_list) % 3) % 3
    return byte_list + b'\x00' * padding_needed


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


def encode_file(file_path):
    """Encode the currenly loaded file into base64"""
    with open(file_path, "rb") as file:
        file_bytes = base64.b64encode(file.read())
    return file_bytes


def gen_random_idb_filename(length=15):
    """Generates a random filename of default length 15"""
    chars = string.ascii_letters + string.digits
    rand_filename = "".join(random.choice(chars) for i in range(length))

    return f"{rand_filename}.i64"


def get_all_idb_hashes():
    """Hash loaded idb's contents.

    Returns
    -------
    dict
        The hashes of the IDB's contents in hexadecimal format.
    """
    byte_string = convert_to_py_bytes()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    sha1.update(byte_string)
    sha256.update(byte_string)
    md5.update(byte_string)

    return {
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


def get_disassembly_hashes(file_path):
    """Hash loaded idb's contents.

    Returns
    -------
    dict
        The hashes of the IDB's contents in hexadecimal format.
    """
    sha1 = hashlib.sha1()
    sha512 = hashlib.sha512()

    try:
        with open(file_path, "rb") as f:
            while True:
                block = f.read(2**10)  # Magic number: one-megabyte blocks.
                if not block:
                    break
                sha1.update(block)
                sha512.update(block)
            return {
                "sha1": sha1.hexdigest(),
                "sha512": sha512.hexdigest(),
            }
    except FileNotFoundError:
        print(
            "Original binary not accessible."
            + " Place binary in the directory containing the loaded idb file"
        )
        return None


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


def get_file_architecture():
    """
    Get the currently loaded files architecture.
    Only works when running IDA in 64 bit mode.
    """
    structure = idaapi.get_inf_structure()
    if structure.is_64bit():
        return "64-bit"
    return "32-bit" if structure.is_32bit() else "unknown"


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


def get_idb_name():
    """Get the name of the input .idb file being analyzed."""
    return os.path.basename(idc.get_idb_path())


def get_idb_path():
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

def process_api_exception(exp, console_only, info_msgs):
    """Prepare an APIException to be displayed."""
    from .widgets import ErrorPopup

    logger.debug(traceback.format_exc())
    if console_only:
        try:
            error_body = json.loads(exp.body)
            for error in error_body.get("errors", []):
                logger.info(error["reason"])
                print(error)
        except json.JSONDecodeError:
            print(str(exp))
            print("Received non-JSON response. Body:", exp.body)
            print("Possible API error. Check that the Unknown Cyber dashboard is online.")
        return None
    try:
        error_msgs = json.loads(exp.body)
        if error_msgs.get("errors", []):
            for error in error_msgs.get("errors"):
                logger.info(error["reason"])
    except json.JSONDecodeError:
        error_msgs = [
            "Possible API error. Check that the Unknown Cyber dashboard is online.",
            str(exp),
            "Received non-JSON response. Body: " + exp.body
        ]
    err_popup = ErrorPopup(info_msgs, error_msgs)
    err_popup.exec_()

def process_regular_exception(exp, console_only, info_msgs):
    """Prepare an Exception to be displayed."""
    from .widgets import ErrorPopup

    logger.debug(traceback.format_exc())
    if console_only:
        print("Unknown Error occurred")
        print(f"<{exp.__class__}>: {str(exp)}")
        # exit if this call fails so user can retry
        # (this func always returns None anyway)
        return None
    error_msgs = [
        "Unknown Error occurred",
        "<" + str(exp.__class__) + ">:" + str(exp) + ">",
    ]
    err_popup = ErrorPopup(info_msgs, error_msgs)
    err_popup.exec_()
    