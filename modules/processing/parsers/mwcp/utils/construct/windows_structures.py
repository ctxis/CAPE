"""
A central location to store common windows enumerations.
This module will be imported along with 'from mwcp.utils import construct'
"""

import datetime

import construct
from construct import this
from mwcp.utils.construct import helpers
from mwcp.utils.construct import windows_enums

# Visible interface. Add the classes and functions you would like to be available for users of construct
# library here.
__all__ = [
    'IMAGE_DOS_HEADER', 'IMAGE_FILE_HEADER', 'IMAGE_OPTIONAL_HEADER', 'IMAGE_NT_HEADERS', 'PEFILE_HEADER',
    'SOCKADDR_IN', 'PUBLICKEYSTRUC', 'PUBLICKEYBLOB', 'PRIVATEKEYBLOB', 'SYSTEMTIME', 'SystemTime'
]

"""PEFILE STRUCTURES"""

IMAGE_DOS_HEADER = construct.Struct(
    "e_magic" / construct.String(2),
    "e_cblp" / construct.Int16ul,
    "e_cp" / construct.Int16ul,
    "e_crlc" / construct.Int16ul,
    "e_cparhdr" / construct.Int16ul,
    "e_mimalloc" / construct.Int16ul,
    "e_maxalloc" / construct.Int16ul,
    "e_ss" / construct.Int16ul,
    "e_sp" / construct.Int16ul,
    "e_csum" / construct.Int16ul,
    "e_ip" / construct.Int16ul,
    "e_cs" / construct.Int16ul,
    "e_lfarlc" / construct.Int16ul,
    "e_ovno" / construct.Int16ul,
    "e_res1" / construct.Bytes(8),
    "e_oemid" / construct.Int16ul,
    "e_oeminfo" / construct.Int16ul,
    "e_res2" / construct.Bytes(20),
    "e_lfanew" / construct.Int32ul
)

IMAGE_FILE_HEADER = construct.Struct(
    "Machine" / construct.Int16ul,
    "NumberOfSections" / construct.Int16ul,
    "TimeDateStamp" / construct.Int32ul,
    "PointerToSymbolTable" / construct.Int32ul,
    "NumberOfSymbols" / construct.Int32ul,
    "SizeOfOptionalHeader" / construct.Int16ul,
    "Characteristics" / construct.Int32ul
)

IMAGE_OPTIONAL_HEADER = construct.Struct(
    "Magic" / construct.Int16ul,
    "MajorLinkerVersion" / construct.Byte,
    "MinorLinkerVersion" / construct.Byte,
    "SizeOfCode" / construct.Int32ul,
    "SizeOfInitializedData" / construct.Int32ul,
    "SizeOfUninitializedData" / construct.Int32ul,
    "AddressOfEntryPoint" / construct.Int32ul,
    "BaseOfCode" / construct.Int32ul,
    "BaseOfData" / construct.Int32ul,
    "ImageBase" / construct.Int32ul,
    "SectionAlignment" / construct.Int32ul,
    "FileAlignment" / construct.Int32ul,
    "MajorOperatingSystemVersion" / construct.Int16ul,
    "MinorOperatingSystemVersion" / construct.Int16ul,
    "MajorImageVersion" / construct.Int16ul,
    "MinorImageVersion" / construct.Int16ul,
    "MajorSubsystemVersion" / construct.Int16ul,
    "MinorSubsystemVersion" / construct.Int16ul,
    "Win32VersionValue" / construct.Int32ul,
    "SizeOfImage" / construct.Int32ul,
    "SizeOfHeaders" / construct.Int32ul,
    "CheckSum" / construct.Int32ul,
    "Subsystem" / construct.Int16ul,
    "DllCharacteristics" / construct.Int16ul,
    "SizeOfStackReserve" / construct.Int32ul,
    "SizeOfStackCommit" / construct.Int32ul,
    "SizeOfHeapReserve" / construct.Int32ul,
    "SizeOfHeapCommit" / construct.Int32ul,
    "LoaderFlags" / construct.Int32ul,
    "NumberOfRvaAndSizes" / construct.Int32ul,
)

IMAGE_NT_HEADERS = construct.Struct(
    "Signature" / construct.Int32ul,
    "FileHeader" / IMAGE_FILE_HEADER,
    "OptionalHeader" / IMAGE_OPTIONAL_HEADER
)

PEFILE_HEADER = construct.Struct(
    "DosHeader" / IMAGE_DOS_HEADER,
    construct.Seek(this.DosHeader.e_lfanew),
    "NTHeaders" / IMAGE_NT_HEADERS
)

"""WINSOCK STRUCTURES"""

SOCKADDR_IN = construct.Struct(
    "sin_family" / construct.Int16ul,
    "sin_port" / construct.Int16ub,
    "sin_addr" / helpers.IP4Address,
    "sin_zero" / construct.Bytes(8)
)

"""CRYPTO STRUCTURES"""

PUBLICKEYSTRUC = construct.Struct(
    "type" / construct.Byte,
    "version" / construct.Byte,
    "reserved" / construct.Int16ul,
    "algid" / windows_enums.AlgorithmID(construct.Int32ul),
)

PUBLICKEYBLOB = construct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    construct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    construct.Const("RSA1"),
    "bitlen" / construct.Int32ul,
    construct.Check((this.bitlen % 8) == 0),
    "pubexponent" / construct.Int32ul,
    "modulus" / construct.BytesInteger(this.bitlen / 8, swapped=True)
)

PRIVATEKEYBLOB = construct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    construct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    construct.Const("RSA2"),
    "bitlen" / construct.Int32ul,
    construct.Check((this.bitlen % 8) == 0),
    "pubexponent" / construct.Int32ul,
    "modulus" / construct.BytesInteger(this.bitlen / 8, swapped=True),
    "P" / construct.BytesInteger(this.bitlen / 16, swapped=True),
    "Q" / construct.BytesInteger(this.bitlen / 16, swapped=True),
    # d % (p - 1)
    "Dp" / construct.BytesInteger(this.bitlen / 16, swapped=True),
    # d % (q - 1)
    "Dq" / construct.BytesInteger(this.bitlen / 16, swapped=True),
    # ~(q % p)
    "Iq" / construct.BytesInteger(this.bitlen / 16, swapped=True),
    # Private Exponent
    "D" / construct.BytesInteger(this.bitlen / 8, swapped=True)
)

"""TIME STRUCTURES"""

SYSTEMTIME = construct.Struct(
    "wYear" / construct.Int16ul,
    "wMonth" / construct.Int16ul,
    "wDayOfWeek" / construct.Int16ul,
    "wDay" / construct.Int16ul,
    "wHour" / construct.Int16ul,
    "wMinute" / construct.Int16ul,
    "wSecond" / construct.Int16ul,
    "wMilliseconds" / construct.Int16ul,
)


# TODO: Implement _encode
class _SystemTimeAdapter(construct.Adapter):
    r"""
    Adapter to convert SYSTEMTIME structured data to datetime.datetime ISO format.

    >>> _SystemTimeAdapter(SYSTEMTIME).parse('\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02')
    '2013-09-18T09:46:21.754000'
    """
    def _decode(self, obj, context):
        return datetime.datetime(
            obj.wYear, obj.wMonth, obj.wDay, obj.wHour, obj.wMinute, obj.wSecond, obj.wMilliseconds * 1000
        ).isoformat()

# Hide the adapter
SystemTime = _SystemTimeAdapter(SYSTEMTIME)
