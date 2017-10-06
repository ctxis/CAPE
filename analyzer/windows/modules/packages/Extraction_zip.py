# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
from subprocess import call
from lib.common.abstracts import Package
import logging

try:
    import re2 as re
except ImportError:
    import re

from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class Extraction_zip(Package):
    """CAPE Extraction zip analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["dll"] = "Extraction.dll"

        log.info("Timeout: " + str(self.config.timeout))
        
        #if self.config.timeout > 10:
        #    self.config.timeout = 5
        #    log.info("Timeout reset to: " + str(self.config.timeout))     

    def extract_zip(self, zip_path, extract_path, password, recursion_depth):
        """Extracts a nested ZIP file.
        @param zip_path: ZIP path
        @param extract_path: where to extract
        @param password: ZIP password
        @param recursion_depth: how deep we are in a nested archive
        """
        # Test if zip file contains a file named as itself.
        if self.is_overwritten(zip_path):
            log.debug("ZIP file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_zip_path = zip_path + ".old"
            shutil.move(zip_path, new_zip_path)
            zip_path = new_zip_path

        # Extraction.
        with ZipFile(zip_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))
            finally:
                if recursion_depth < 4:
                    # Extract nested archives.
                    for name in archive.namelist():
                        if name.endswith(".zip"):
                            # Recurse.
                            self.extract_zip(os.path.join(extract_path, name), extract_path, password, recursion_depth + 1)

    def is_overwritten(self, zip_path):
        """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
        @param zip_path: zip file path
        @return: comparison boolean
        """
        with ZipFile(zip_path, "r") as archive:
            try:
                # Test if zip file contains a file named as itself.
                for name in archive.namelist():
                    if name == os.path.basename(zip_path):
                        return True
                return False
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")

    def get_infos(self, zip_path):
        """Get information from ZIP file.
        @param zip_path: zip file path
        @return: ZipInfo class
        """
        try:
            with ZipFile(zip_path, "r") as archive:
                return archive.infolist()
        except BadZipfile:
            raise CuckooPackageError("Invalid Zip file")

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password")
        exe_regex = re.compile('(\.exe|\.scr|\.msi|\.bat|\.lnk)$',flags=re.IGNORECASE)
        zipinfos = self.get_infos(path)
        self.extract_zip(path, root, password, 0)
        self.options["dll"] = "Extraction.dll"

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Attempt to find a valid exe extension in the archive
                for f in zipinfos:
                    if exe_regex.search(f.filename):
                        file_name = f.filename
                        break
                # Default to the first one if none found
                file_name = file_name if file_name else zipinfos[0].filename
                log.debug("Missing file option, auto executing: {0}".format(file_name))
            else:
                raise CuckooPackageError("Empty ZIP archive")


        file_path = os.path.join(root, file_name)
        if file_name.lower().endswith(".lnk"):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = "/c start /wait \"\" \"{0}\"".format(file_path)
            return self.execute(cmd_path, cmd_args, file_path)
        else:
            return self.execute(file_path, self.options.get("arguments"), file_path)
