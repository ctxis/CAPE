# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import subprocess
HAVE_RE2 = False
try:
    import re2 as re
    HAVE_RE2 = True
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class Strings(Processing):
    """Extract strings from the file.

    Requirement: FLOSS by FireEye
                https://github.com/fireeye/flare-floss
    """
    def get_text(self, text, begin, finish):
        try:
            start = text.index(begin) + len(begin)
            end = text.index(finish, start)
            return text[start:end]
        except ValueError:
            return ""

    def floss(self, file_path, floss_path="/usr/sbin/floss"):
        floss_shellcode_err = "ERROR:floss:FLOSS currently supports the following formats for string decoding and stackstrings: PE"
        strings = {}
        if not os.path.exists(self.file_path):
            raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

        p = subprocess.Popen([floss_path, file_path], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        ret = p.returncode

        if ret == 1 and floss_shellcode_err in stderr:
            # extract using shellcode flag
            p = subprocess.Popen([floss_path, "-s", file_path], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            ret = p.returncode

        to_find = re.findall(r'FLOSS .*', stdout)
        to_find.append("Finished execution")

        strings["static_ascii_strings"] = filter(None, self.get_text(stdout, to_find[0], to_find[1]).split('\n'))
        strings["static_utf16_strings"] = filter(None, self.get_text(stdout, to_find[1], to_find[2]).split('\n'))
        strings["decoded_strings"] = filter(None, self.get_text(stdout, to_find[2], to_find[3]).split('\n'))
        strings["extracted_stackstrings"] = filter(None, self.get_text(stdout, to_find[3], to_find[4]).split('\n'))

        # remove empty keys
        strings = dict((k, v) for k, v in strings.items() if v)
        strings['flossed'] = True
        return strings

    def extract_strings(self, file_path):
        strings = []
        if not os.path.exists(file_path):
            raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % file_path)

        try:
            data = open(file_path, "rb").read()
        except (IOError, OSError) as e:
            raise CuckooProcessingError("Error opening file %s" % e)

        nulltermonly = self.options.get("nullterminated_only", True)
        minchars = self.options.get("minchars", 5)

        endlimit = ""
        if not HAVE_RE2:
            endlimit = "8192"

        if nulltermonly:
            apat = "([\x20-\x7e]{" + str(minchars) + "," + endlimit + "})\x00"
            upat = "((?:[\x20-\x7e][\x00]){" + str(minchars) + "," + endlimit + "})\x00\x00"
        else:
            apat = "[\x20-\x7e]{" + str(minchars) + "," + endlimit + "}"
            upat = "(?:[\x20-\x7e][\x00]){" + str(minchars) + "," + endlimit + "}"

        strings = re.findall(apat, data)
        for ws in re.findall(upat, data):
            strings.append(str(ws.decode("utf-16le")))
        return strings


    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
                Returns a dict{} if using FLOSS or a list[] using fallback method
        """
        self.key = "strings"
        floss_path = self.options.get("floss_path", "/usr/sbin/floss")
        floss_enabled = self.options.get("floss_enabled", True)
        floss_max_file_size = self.options.get("floss_max_file_size", 0)
        floss_allowed = lambda file_path: floss_enabled and os.path.isfile(floss_path) and (not floss_max_file_size or os.path.getsize(file_path) / 1024 / 1024 <= floss_max_file_size)

        # Extract strings from the file that is being analysed
        if floss_allowed(self.file_path):
            strings = {}
            if self.task["category"] == "file":
                strings = self.floss(self.file_path, floss_path)
        else:
            if self.task["category"] == "file":
                strings = self.extract_strings(self.file_path)

        # Extract strings from dropped files and cape extracts
        for item in self.results.get('dropped', []) + self.results.get('CAPE', []):
            if floss_allowed(item['path']):
                item['strings'] = self.floss(item['path'], floss_path)
            else:
                item['strings'] = self.extract_strings(item['path'])

        return strings
