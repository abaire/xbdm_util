import socket
from typing import Optional

# Despite the type field it appears that ordering is critical for GDB's processing
# (e.g., it always expects ESI to be register 8.
ORDERED_REGISTERS = [
    "Eax",
    "Ecx",
    "Edx",
    "Ebx",
    "Esp",
    "Ebp",
    "Esi",
    "Edi",
    "Eip",
    "EFlags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs",
    "ss_base",
    "ds_base",
    "es_base",
    "fs_base",
    "gs_base",
    "k_gs_base",
    "cr0",
    "cr2",
    "cr3",
    "cr4",
    "cr8",
    "efer",
    "ST0",
    "ST1",
    "ST2",
    "ST3",
    "ST4",
    "ST5",
    "ST6",
    "ST7",
    "fctrl",
    "fstat",
    "ftag",
    "fiseg",
    "fioff",
    "foseg",
    "fooff",
    "fop",
]

REGISTER_INFO = {
    "Ebp": (4, "data_ptr"),
    "Esp": (4, "data_ptr"),
    "Eip": (4, "code_ptr"),
    "EFlags": (4, "i386_eflags"),
    "Eax": (4, "int32"),
    "Ebx": (4, "int32"),
    "Ecx": (4, "int32"),
    "Edx": (4, "int32"),
    "Esi": (4, "int32"),
    "Edi": (4, "int32"),
    "Cr0NpxState": (4, "i386_cr0"),
    "ST0": (10, "i387_ext"),
    "ST1": (10, "i387_ext"),
    "ST2": (10, "i387_ext"),
    "ST3": (10, "i387_ext"),
    "ST4": (10, "i387_ext"),
    "ST5": (10, "i387_ext"),
    "ST6": (10, "i387_ext"),
    "ST7": (10, "i387_ext"),
    "fctrl": (4, "int", "float"),
    "fstat": (4, "int", "float"),
    "ftag": (4, "int", "float"),
    "fiseg": (4, "int", "float"),
    "fioff": (4, "int", "float"),
    "foseg": (4, "int", "float"),
    "fooff": (4, "int", "float"),
    "fop": (4, "int", "float"),
    "cs": (4, "int32"),
    "ss": (4, "int32"),
    "ds": (4, "int32"),
    "es": (4, "int32"),
    "fs": (4, "int32"),
    "gs": (4, "int32"),
    "ss_base": (4, "int32"),
    "ds_base": (4, "int32"),
    "es_base": (4, "int32"),
    "fs_base": (4, "int32"),
    "gs_base": (4, "int32"),
    "k_gs_base": (4, "int32"),
    "cr0": (4, "int32"),
    "cr2": (4, "int32"),
    "cr3": (4, "int32"),
    "cr4": (4, "int32"),
    "cr8": (4, "int32"),
    "efer": (4, "int32"),
}


_EFLAGS = [
    '<flags id="i386_eflags" size="4">',
    '<field name="CF" start="0" end="0"/>',
    '<field name="" start="1" end="1"/>',
    '<field name="PF" start="2" end="2"/>',
    '<field name="" start="3" end="3"/>',
    '<field name="AF" start="4" end="4"/>',
    '<field name="" start="5" end="5"/>',
    '<field name="ZF" start="6" end="6"/>',
    '<field name="SF" start="7" end="7"/>',
    '<field name="TF" start="8" end="8"/>',
    '<field name="IF" start="9" end="9"/>',
    '<field name="DF" start="10" end="10"/>',
    '<field name="OF" start="11" end="11"/>',
    '<field name="IOPL" start="12" end="13"/>',
    '<field name="NT" start="14" end="14"/>',
    '<field name="" start="15" end="15"/>',
    '<field name="RF" start="16" end="16"/>',
    '<field name="VM" start="17" end="17"/>',
    '<field name="AC" start="18" end="18"/>',
    '<field name="VIF" start="19" end="19"/>',
    '<field name="VIP" start="20" end="20"/>',
    '<field name="ID" start="21" end="21"/>',
    '<field name="" start="22" end="31"/>',
    "</flags>",
]

_CR0 = [
    '<flags id="i386_cr0" size="4">',
    '<field name="PG" start="31" end="31"/>',
    '<field name="CD" start="30" end="30"/>',
    '<field name="NW" start="29" end="29"/>',
    '<field name="AM" start="18" end="18"/>',
    '<field name="WP" start="16" end="16"/>',
    '<field name="NE" start="5" end="5"/>',
    '<field name="ET" start="4" end="4"/>',
    '<field name="TS" start="3" end="3"/>',
    '<field name="EM" start="2" end="2"/>',
    '<field name="MP" start="1" end="1"/>',
    '<field name="PE" start="0" end="0"/>',
    "</flags>",
]


def _build_target_xml() -> bytes:
    ret = ['<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target>']
    ret.append("<architecture>i386:intel</architecture>")
    ret.append('<feature name="i386.xbdm">')

    ret.extend(_EFLAGS)
    ret.extend(_CR0)

    for index, register in enumerate(ORDERED_REGISTERS):
        info = REGISTER_INFO[register]
        bitsize = info[0] * 8
        type = info[1]
        group = info[2] if len(info) > 2 else None

        group_field = f' group="{group}' if group is not None else ""
        ret.append(
            f'<reg name="{register}" bitsize="{bitsize}" type="{type}" regnum="{index}"{group_field}/>'
        )

    ret.append("</target>")

    return bytes(" ".join(ret), "utf-8")


RESOURCES = {"target.xml": _build_target_xml()}


def format_register_str(register: str, value: Optional[int]) -> str:
    """Returns the given value as a string representation of the given register."""
    bytesize = REGISTER_INFO[register][0]

    if value is None:
        return "x" * (2 * bytesize)

    if bytesize == 4:
        return "%08x" % socket.htonl(value)

    if bytesize == 10:
        network_ordered_value = socket.htonl(value & 0xFFFFFFFF) << 48
        network_ordered_value += socket.htonl((value >> 32) & 0xFFFFFFFF) << 16
        network_ordered_value += socket.htons((value >> 64) & 0xFFFF)
        return "%020x" % network_ordered_value

    assert False
    return ""
