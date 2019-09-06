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
from lib.cuckoo.common.utils import convert_to_printable
import base64
import binascii

try:
    import re2 as re
except ImportError:
    import re

class PowershellCommandSuspicious(Signature):
    name = "powershell_command_suspicious"
    description = "Attempts to execute suspicious powershell command arguments"
    severity = 3
    confidence = 70
    categories = ["commands"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1064"]

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
            "net.webrequest",
            "start-bitstransfer",
            "invoke-item",
            "frombase64string(",
            "convertto-securestring",
            "securestringtoglobalallocunicode",
            "downloadstring(",
            "shellexecute(",
            "downloaddata(",
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
                        b64 = True
                        encoded = str(b64string)
                        try:
                            base64.b64decode(encoded)
                        except binascii.Error:
                            b64 = False
                        if b64:
                            decoded = base64.b64decode(encoded)
                            if "\x00" in decoded:
                                decoded = base64.b64decode(encoded).decode('UTF-16') 
                            self.data.append({"decoded_base64_string" : convert_to_printable(decoded)})

                if "frombase64string(" in lower:
                    b64strings = re.findall(r'[fF][rR][oO][mM][bB][aA][sS][eE]64[sS][tT][rR][iI][nN][gG]\([\"\'](\S+)[\"\']\)', cmdline)
                    for b64string in b64strings:
                        b64 = True
                        encoded = str(b64string)
                        try:
                            base64.b64decode(encoded)
                        except binascii.Error:
                            b64 = False
                        if b64:
                            decoded = base64.b64decode(encoded)
                            if "\x00" in decoded:
                                decoded = base64.b64decode(encoded).decode('UTF-16') 
                            self.data.append({"decoded_base64_string" : convert_to_printable(decoded)})

        return ret

class PowershellRenamed(Signature):
    name = "powershell_renamed"
    description = "Powershell arguments were seen on a command line but powershell.exe was not called. Likely indictive of renamed/obfuscated powershell.exe or defining arguments in variables for later use"
    severity = 3
    confidence = 70
    categories = ["commands"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1064"]

    def run(self):
        commands = [
            "YnlwYXNz",
            "J5cGFzc",
            "ieXBhc3",
            "dW5yZXN0cmljdGVk",
            "VucmVzdHJpY3RlZ",
            "1bnJlc3RyaWN0ZW",
            "-nop",
            "/nop",
            "-noni",
            "/noni",
            "start-process",
            "downloadfile(",
            "ZG93bmxvYWRmaWxlK",
            "Rvd25sb2FkZmlsZS",
            "kb3dubG9hZGZpbGUo",
            "net.webrequest",
            "start-bitstransfer",
            "invoke-item",
            "frombase64string(",
            "convertto-securestring",
            "securestringtoglobalallocunicode",
            "downloadstring(",
            "shellexecute(",
            "downloaddata(",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "powershell" not in lower:
                for command in commands:
                    if command in lower:
                        ret = True
                        self.data.append({"command" : cmdline})
                        break
                if ("-w" in lower or "/w" in lower) and "hidden" in lower:
                    ret = True
                    self.data.append({"command" : cmdline})
                if ("-ex" in lower or "/ex" in lower) and ("bypass" in lower or "unrestricted" in lower):
                    ret = True
                    self.data.append({"command" : cmdline})

                # Decode base64 strings for reporting; will adjust this later to add detection matches against decoded content. We don't take into account here when a variable is used i.e. "$encoded = BASE64_CONTENT -enc $encoded" and so evasion from decoding the content is possible. Alternatively we could just try to hunt for base64 content in powershell command lines but this will need to be tested
                if "-e " in lower or "/e " in lower or "-en " in lower or "/en " in lower or "-enc" in lower or "/enc" in lower:
                    b64strings = re.findall(r'[-\/][eE][nNcCoOdDeEmMaA]{0,13}\ (\S+)', cmdline)
                    for b64string in b64strings:
                        encoded = str(b64string)
                        if re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', encoded):
                            ret = True
                            self.data.append({"command" : cmdline})
                            decoded = base64.b64decode(encoded)
                            if "\x00" in decoded:
                                decoded = base64.b64decode(encoded).decode('UTF-16')
                            self.data.append({"decoded_base64_string" : convert_to_printable(decoded)})

                if "frombase64string(" in lower:
                    b64strings = re.findall(r'[fF][rR][oO][mM][bB][aA][sS][eE]64[sS][tT][rR][iI][nN][gG]\([\"\'](\S+)[\"\']\)', cmdline)
                    for b64string in b64strings:
                        encoded = str(b64string)
                        if re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', encoded):
                            ret = True
                            self.data.append({"command" : cmdline})
                            decoded = base64.b64decode(encoded)
                            if "\x00" in decoded:
                                decoded = base64.b64decode(encoded).decode('UTF-16')
                            self.data.append({"decoded_base64_string" : convert_to_printable(decoded)})

        return ret

class PowershellReversed(Signature):
    name = "powershell_reversed"
    description = "Possible reversed powershell command arguments detected"
    severity = 3
    confidence = 70
    categories = ["commands"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1064"]

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
            "net.webrequest",
            "start-bitstransfer",
            "invoke-item",
            "frombase64string(",
            "convertto-securestring",
            "securestringtoglobalallocunicode",
            "downloadstring(",
            "shellexecute(",
            "downloaddata(",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for command in commands:
                if command[::-1] in lower:
                    ret = True
                    self.data.append({"command" : cmdline})
                    break
            if ("-w"[::-1] in lower or "/w"[::-1] in lower) and "hidden"[::-1] in lower:
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class PowershellVariableObfuscation(Signature):
    name = "powershell_variable_obfuscation"
    description = "A powershell command using multiple variables was executed possibly indicative of obfuscation"
    severity = 3
    confidence = 50
    categories = ["commands", "obuscation"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1064"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "powershell" in lower:
                if re.search('\$[^env=]*=.*\$[^env=]*=', lower):
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class PowerShellNetworkConnection(Signature):
    name = "powershell_network_connection"
    description = "PowerShell attempted to make a network connection"
    severity = 3
    confidence = 50
    categories = ["downloader"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    match = True
    ttp = ["T1086", "T1064"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
   
    filter_apinames = set(["InternetCrackUrlW","InternetCrackUrlA","URLDownloadToFileW","HttpOpenRequestW","InternetReadFile", "send", "WSAConnect"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname == "powershell.exe":
            if call["api"] == "URLDownloadToFileW":
                buff = self.get_argument(call, "FileName").lower()
                self.data.append({"request": buff })
            if call["api"] == "HttpOpenRequestW":
                buff = self.get_argument(call, "Path").lower()
                self.data.append({"request": buff })
            if call["api"] == "InternetCrackUrlW":
                buff = self.get_argument(call, "Url").lower()
                self.data.append({"request": buff })
            if call["api"] == "InternetCrackUrlA":
                buff = self.get_argument(call, "Url").lower()
                self.data.append({"request": buff })
            if call["api"] == "send":
                buff = self.get_argument(call, "buffer").lower()
                self.data.append({"request": buff })
            if call["api"] == "WSAConnect":
                buff = self.get_argument(call, "ip").lower()
                port = self.get_argument(call, "port").lower()
                if not buff.startswith(("10.","172.16.","192.168.")):
                    self.data.append({"request": "%s:%s" % (buff,port)})
        return None

    def on_complete(self):
        if self.data:
            return True
        else:
            return False
