# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class CAPE_PlugXPayload(Package):
    """DLL analysis package."""
    #PATHS = [
    #    ("SystemRoot", "system32"),
    #]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["dll"] = "CAPE_PlugX.dll"
        
        log.info("Timeout: " + str(self.config.timeout))
        
        #if self.config.timeout > 10:
        #    self.config.timeout = 5
        #    log.info("Timeout reset to: " + str(self.config.timeout))             

    def start(self, path):
        self.options["dll"] = "CAPE_PlugX.dll"
        loaderpath = "bin\\loader.exe"
        #arguments = path
        arguments = "plugx " + path
        
        # we need to move out of the analyzer directory
        # due to a check in monitor dll
        basepath = os.path.dirname(path)
        newpath = os.path.join(basepath, os.path.basename(loaderpath))
        shutil.copy(loaderpath, newpath)
               
        log.info("[-] newpath : "+newpath)
        log.info("[-] arguments : "+arguments)
        #log.info("[-] Path: "+path)

        return self.execute(newpath, arguments, newpath)
