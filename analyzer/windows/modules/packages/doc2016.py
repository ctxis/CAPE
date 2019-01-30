# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

class DOC2016(Package):
    """Word analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options
        self.options["loader"] = "newloader.exe"
        self.options["loader_64"] = "newloader_x64.exe"

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "WINWORD.EXE"),
    ]

    def start(self, path):
        word = self.get_path_glob("Microsoft Office Word")
        if "." not in os.path.basename(path):
            new_path = path + ".doc"
            os.rename(path, new_path)
            path = new_path

        return self.execute(word, "\"%s\" /q" % path, path)
