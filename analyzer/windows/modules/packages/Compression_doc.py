# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Compression_doc(Package):
    """Word analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["dll"] = "Compression.dll"
        self.options["dll_64"] = "Compression_x64.dll"
        
    def start(self, path):
        self.options["dll"] = "Compression.dll"
        word = self.get_path("Microsoft Office Word")
        return self.execute(word, "\"%s\" /q" % path, path)
