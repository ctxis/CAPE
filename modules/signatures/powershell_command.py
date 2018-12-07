# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

import base64

try:
    import re2 as re
except ImportError:
    import re

class PowershellCommandSuspicious(Signature):
    name = "powershell_command_suspicious"
    description = "Attempts to execute a suspicious powershell command"
    severity = 3
    confidence = 70
    categories = ["generic"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.3"
    evented = True

    def run(self):
        commands = [
            "bypass",
            "unrestricted",
            "YnlwYXNz",
            "J5cGFzc",
            "ieXBhc3",
            "dW5yZXN0cmljdGVk",
            "VucmVzdHJpY3RlZ",
            "1bnJlc3RyaWN0ZW",
            "-nop",
            "/nop",
            "-e ",
            "/e ",
            "-en ",
            "/en ",
            "-enc",
            "/enc",
            "-noni",
            "/noni",
            "start-process",
            "downloadfile(",
            "ZG93bmxvYWRmaWxlK",
            "Rvd25sb2FkZmlsZS",
            "kb3dubG9hZGZpbGUo",
            "system.net.webrequest",
            "start-bitstransfer",
            "invoke-item",
            "frombase64string(",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "powershell" in lower:
                for command in commands:
                    if command in lower:
                        ret = True
                        self.data.append({"command" : cmdline})
                        break
                if ("-w" in lower or "/w" in lower) and "hidden" in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

                # Decode base64 strings for reporting; will adjust this later to add detection matches against decoded content. We don't take into account here when a variable is used i.e. "$encoded = BASE64_CONTENT -enc $encoded" and so evasion from decoding the content is possible. Alternatively we could just try to hunt for base64 content in powershell command lines but this will need to be tested
                if "-e " in lower or "/e " in lower or "-en " in lower or "/en " in lower or "-enc" in lower or "/enc" in lower:
                    b64strings = re.findall(r'[-\/][eE][nNcCoOdDeEmMaA]{0,13}\ (\S+)', cmdline)
                    for b64string in b64strings:
                        encoded = str(b64string)
                        if re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', encoded):
                            decoded = base64.b64decode(encoded)
                            self.data.append({"decoded_base64_string" : decoded})

                if "frombase64string(" in lower:
                    b64strings = re.findall(r'[fF][rR][oO][mM][bB][aA][sS][eE]64[sS][tT][rR][iI][nN][gG]\([\"\'](\S+)[\"\']\)', cmdline)
                    for b64string in b64strings:
                        encoded = str(b64string)
                        if re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', encoded):
                            decoded = base64.b64decode(encoded)
                            self.data.append({"decoded_base64_string" : decoded})

        return ret
