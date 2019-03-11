# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class XLS(Package):
    """Excel analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
    ]

    def start(self, path):
        excel = self.get_path_glob("Microsoft Office Excel")
        if "." not in os.path.basename(path):
            new_path = path + ".xls"
            os.rename(path, new_path)
            path = new_path

        return self.execute(excel, "\"%s\" /e" % path, path)
