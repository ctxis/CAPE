# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import os
import shutil
import subprocess
from lib.common.abstracts import Package
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

BUFSIZE = 10485760

def hash_file(method, path):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(path, "rb")
    h = method()
    while True:
        buf = f.read(BUFSIZE)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

class WGET(Package):
    """wget package: download and execute a sample from a URL.
        Download a version of wget and place in bin/ as wget.exe to use

        You can find the binary here: https://eternallybored.org/misc/wget
    """

    def start(self, url):

        arguments = self.options.get("arguments")
        tempfile = "download.bin"
        appdata = self.options.get("appdata")
        args = "bin/wget.exe -O \"{0}\"".format(tempfile)
        args += " {0}".format(url)

        try:
            p = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            out, err = p.communicate()
        except Exception:
            log.error("Unable to download with wget. Command: %s" % " ".join(args))
            return

        sha256 = hash_file(hashlib.sha256, tempfile)
        newname = os.path.join(os.path.dirname(tempfile), sha256) + ".exe"
        os.rename(tempfile, newname)

        if appdata:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv('APPDATA')
            path = os.path.join(basepath, os.path.basename(newname))
            shutil.copy(newname, path)
        else:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv('TEMP')
            path = os.path.join(basepath, os.path.basename(newname))
            shutil.copy(newname, path)

        return self.execute(path, arguments, path)
        