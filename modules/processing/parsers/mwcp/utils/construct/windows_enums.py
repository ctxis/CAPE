"""
A central location to store common windows enumerations.
This module will be imported along with 'from mwcp.utils import construct'
"""

from construct import *

# Visible interface. Add the classes and functions you would like to be available for users of construct
# library here.
__all__ = ['RegHive', 'LanguageIdentifier', 'KnownFolderID', 'AlgorithmID']


REGHIVES = {
    "HKCR": 0x80000000,
    "HKCU": 0x80000001,
    "HKLM": 0x80000002,
    "HKU":  0x80000003,
    "HKPD": 0x80000004,
    "HKCC": 0x80000005,
    "HKDD": 0x80000006,
}


def RegHive(subcon):
    r"""
    Converts an integer to registry hive enum.

    >>> RegHive(Int32ul).build("HKCU")
    '\x01\x00\x00\x80'
    >>> RegHive(Int32ul).parse('\x01\x00\x00\x80')
    'HKCU'
    """
    return Enum(subcon, **REGHIVES)


# TODO: Extend dictionary to incorporate more languages
LANGUAGEIDENTIFIERS = {
    "English (United States)": 0x409,
    "Korean": 0x412,
    "Chinese (PRC)": 0x804,
}


def LanguageIdentifier(subcon):
    r"""
    Converts an integer to language identifer enum

    >>> LanguageIdentifier(Int32ul).build("English (United States)")
    '\t\x04\x00\x00'
    >>> LanguageIdentifier(Int32ul).parse("\x04\x08\x00\x00")
    'Chinese (PRC)'
    """
    return Enum(subcon, **LANGUAGEIDENTIFIERS)


CSIDL = {
    'CSIDL_SYSTEM': 37,
    'CSIDL_COMMON_PROGRAMS': 23,
    'CSIDL_PROFILE': 40,
    'CSIDL_ALTSTARTUP': 29,
    'CSIDL_LOCAL_APPDATA': 28,
    'CSIDL_PRINTHOOD': 27,
    'CSIDL_FONTS': 20,
    'CSIDL_PROGRAM_FILES_COMMON': 43,
    'CSIDL_PROGRAM_FILESX86': 42,
    'CSIDL_MYDOCUMENTS': 5,
    'CSIDL_MYVIDEO': 14,
    'CSIDL_PROGRAM_FILES': 38,
    'CSIDL_ADMINTOOLS': 48,
    'CSIDL_COMMON_DOCUMENTS': 46,
    'CSIDL_CONNECTIONS': 49,
    'CSIDL_COMMON_ALTSTARTUP': 30,
    'CSIDL_DRIVES': 17,
    'CSIDL_RESOURCES_LOCALIZED': 57,
    'CSIDL_HISTORY': 34,
    'CSIDL_NETHOOD': 19,
    'CSIDL_CDBURN_AREA': 59,
    'CSIDL_COMMON_DESKTOPDIRECTORY': 25,
    'CSIDL_SYSTEMX86': 41,
    'CSIDL_COMMON_TEMPLATES': 45,
    'CSIDL_MYPICTURES': 39,
    'CSIDL_COMMON_VIDEO': 55,
    'CSIDL_COMMON_STARTMENU': 22,
    'CSIDL_COMMON_FAVORITES': 31,
    'CSIDL_INTERNET_CACHE': 32,
    'CSIDL_WINDOWS': 36,
    'CSIDL_COMMON_PICTURES': 54,
    'CSIDL_COMMON_APPDATA': 35,
    'CSIDL_DESKTOPDIRECTORY': 16,
    'CSIDL_RESOURCES': 56,
    'CSIDL_COMMON_MUSIC': 53,
    'CSIDL_COMMON_OEM_LINKS': 58,
    'CSIDL_NETWORK': 18,
    'CSIDL_COOKIES': 33,
    'CSIDL_COMPUTERSNEARME': 61,
    'CSIDL_COMMON_ADMINTOOLS': 47,
    'CSIDL_APPDATA': 26,
    'CSIDL_TEMPLATES': 21,
    'CSIDL_COMMON_STARTUP': 24,
    'CSIDL_MYMUSIC': 13,
    'CSIDL_PROGRAM_FILES_COMMONX86': 44
}


def KnownFolderID(subcon):
    r"""
    Converts an integer to a CSIDL (KNownFolderID) value

    >>> KnownFolderID(Int32ul).build("CSIDL_SYSTEM")
    '%\x00\x00\x00'
    >>> KnownFolderID(Int32ul).parse("\x18\x00\x00\x00")
    'CSIDL_COMMON_STARTUP'
    """
    return Enum(subcon, **CSIDL)


ALGIDS = {
    'CALG_DSS_SIGN': 0x00002200,
    'CALG_DES': 0x00006601,
    'CALG_DH_EPHEM': 0x0000aa02,
    'CALG_3DES': 0x00006603,
    'CALG_DESX': 0x00006604,
    'CALG_ECDH': 0x0000aa05,
    'CALG_NO_SIGN': 0x00002000,
    'CALG_DH_SF': 0x0000aa01,
    'CALC_SSL3_SHAMD5': 0x00008008,
    'CALG_3DES_112': 0x00006609,
    'CALG_SKIPJACK': 0x0000660a,
    'CALG_HASH_REPLACE_OWF': 0x0000800b,
    'CALG_CYLINK_MEK': 0x0000660c,
    'CALG_MD4': 0x00008002,
    'CALG_AES_128': 0x0000660e,
    'CALG_AES_192': 0x0000660f,
    'CALG_AES_256': 0x00006610,
    'CALG_AES': 0x00006611,
    'CALG_AGREEDKEY_ANY': 0x0000aa03,
    'CALG_SHA1': 0x00008004,
    'CALG_MAC': 0x00008005,
    'CALG_MD2': 0x00008001,
    'CALG_TLS1_MASTER': 0x00004c06,
    'CALG_RSA_SIGN': 0x00002400,
    'CALG_SCHANNEL_ENC_KEY': 0x00004c07,
    'CALG_HMAC': 0x00008009,
    'CALG_TLS1PRF': 0x0000800a,
    'CALG_TEK': 0x0000660b,
    'CALG_SHA_256': 0x0000800c,
    'CALG_SHA_384': 0x0000800d,
    'CALG_SHA_512': 0x0000800e,
    'CALG_HUGHES_MD5': 0x0000a003,
    'CALG_RC4': 0x00006801,
    'CALG_ECDSA': 0x00002203,
    'CALG_RC2': 0x00006602,
    'CALG_SEAL': 0x00006802,
    'CALG_SSL3_MASTER': 0x00004c01,
    'CALG_SCHANNEL_MASTER_HASH': 0x00004c02,
    'CALG_MD5': 0x00008003,
    'CALG_SCHANNEL_MAC_KEY': 0x00004c03,
    'CALG_KEY_KEYX': 0x0000aa04,
    'CALG_ECMQV': 0x0000a001,
    'CALG_PCT1_MASTER': 0x00004c04,
    'CALG_RSA_KEYX': 0x0000a400,
    'CALG_OID_INFO_CNG_ONLY': 0xffffffff,
    'CALG_SSL2_MASTER': 0x00004c05,
    'CALG_OID_INFO_PARAMETERS': 0xfffffffe,
}


def AlgorithmID(subcon):
    r"""
    Converts an integer to an AlgorithmID value

    >>> AlgorithmID(Int16ul).parse("\x00\xa4")
    'CALG_RSA_KEYX'
    >>> AlgorithmID(Int16ul).build("CALG_RC4")
    '\x01h'
    """
    return Enum(subcon, **ALGIDS)
