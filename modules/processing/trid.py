# This file is part of CAPE
# Tim Shelton
# tshelton@hawkdefense.com
# See the file 'docs/LICENSE' for copying permission.

import os.path
import subprocess

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class TrID(Processing):
    """Extract TrID output from file."""

    def run(self):
        """Run extract of trid output.
        @return: list of trid output.
        """
        self.key = "trid"
        strings = []

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

            trid_binary = self.options.get("identifier", "/home/cuckoo/trid/trid")
            definitions = self.options.get("definitions", "/home/cuckoo/trid/triddefs.trd")

	    output = subprocess.check_output([ trid_binary, "-d:%s" % definitions, self.file_path], stderr=subprocess.STDOUT)
	    strings = output.split('\n')
	    # trim data
	    strings = strings[6:-1]
        return strings
