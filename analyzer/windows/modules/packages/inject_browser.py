from _winreg import *
import ctypes
from ctypes import wintypes
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class inject_browser(Package):
    """ CAPE browser dll analysis package."""
    
    # executable used for testing
    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options

    def prepAppInitDLL(self, dllpath):
        _GetShortPathNameA = ctypes.windll.kernel32.GetShortPathNameA
        _GetShortPathNameA.argtypes = [wintypes.LPCSTR, wintypes.LPSTR, wintypes.DWORD]
        _GetShortPathNameA.restype = wintypes.DWORD

        keyVal = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        try:
            key = OpenKey(HKEY_LOCAL_MACHINE, keyVal, 0, KEY_ALL_ACCESS)
        except WindowsError:
            log.error("Failed to open key HKEY_LOCAL_MACHINE\%s", keyVal)
            return
        
        # https://stackoverflow.com/questions/23598289/how-to-get-windows-short-file-name-in-python
        output_buf_size = 0
        while True:
            output_buf = ctypes.create_string_buffer(output_buf_size)
            needed = _GetShortPathNameA(dllpath, output_buf, output_buf_size)
            if output_buf_size >= needed:
                log.debug("Path successfully converted: " + output_buf.value)

                SetValueEx(key, "LoadAppInit_DLLs", 1, REG_DWORD, 1)
                SetValueEx(key, "RequireSignedAppInit_DLLs", 1, REG_DWORD, 0)
                SetValueEx(key, "AppInit_DLLs", 1, REG_SZ, output_buf.value)

                CloseKey(key)
                log.debug("Successfully set AppInitDLL")
                break
            else:
                output_buf_size = needed

    def start(self, path):
        # container_binary is the target of the injection by the malicous dll
        # for now I've set this to be Firefox but could be potentially set to be
        # any binary
        # container_binary = self.options["container_binary"]

        # need to convert to Windows short path
        container_binary = self.get_path("firefox")
        self.prepAppInitDLL(path)

        return self.execute(container_binary, "", path)
