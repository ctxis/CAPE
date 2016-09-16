# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging
from subprocess import call
from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class DerusbiLoader(Package):
    """Derusbi analysis package."""
    #PATHS = [
    #    ("SystemRoot", "system32"),
    #]

    def start(self, path):
        loaderpath = "bin\\loader.exe"
        
        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for LoadLibrary
        if ext != ".dll":
            ext_path = path + ".dll"
            os.rename(path, ext_path)
            path = ext_path  
        
        #arguments = path
        arguments = "derusbi " + path
        
        # we need to move out of the analyzer directory
        # due to a check in monitor dll
        basepath = os.path.dirname(path)
        newpath = os.path.join(basepath, os.path.basename(loaderpath))
        shutil.copy(loaderpath, newpath)
               
        log.info("[-] newpath : "+newpath)
        log.info("[-] arguments : "+arguments)
        #log.info("[-] Path: "+path)

        return self.execute(newpath, arguments, newpath)
