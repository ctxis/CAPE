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

class PowershellCommand(Signature):
    name = "powershell_command"
    description = "Attempts to execute a powershell command with suspicious parameter/s"
    severity = 2
    confidence = 70
    weight = 0
    categories = ["generic"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.exec_policy = False
        self.user_profile = False
        self.hidden_window = False
        self.b64_encoded = False
        self.filedownload = False
        self.noninteractive = False
        self.startprocess = False
        self.webrequest = False
        self.bitstransfer = False
        self.invokeitem = False

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
        else:
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params

        if "powershell.exe" in cmdline and ("bypass" in cmdline or "unrestricted" in cmdline or "YnlwYXNz" in cmdline or "J5cGFzc" in cmdline or "ieXBhc3" in cmdline or "dW5yZXN0cmljdGVk" in cmdline or "VucmVzdHJpY3RlZ" in cmdline or "1bnJlc3RyaWN0ZW" in cmdline):
            self.exec_policy = True

        if "powershell.exe" in cmdline and "-nop" in cmdline:
            self.user_profile = True

        if "powershell.exe" in cmdline and "-w" in cmdline and "hidden" in cmdline:
            self.hidden_window = True

        if "powershell.exe" in cmdline and ("-enc" in cmdline or "-e " in cmdline):
            self.b64_encoded = True
            
        if "powershell.exe" in cmdline and "-noni" in cmdline:
            self.noninteractive = True
            
        if "powershell.exe" in cmdline and "start-process" in cmdline:
            self.startprocess = True

        if "powershell.exe" in cmdline and ("downloadfile(" in cmdline or "ZG93bmxvYWRmaWxlK" in cmdline or "Rvd25sb2FkZmlsZS" in cmdline or "kb3dubG9hZGZpbGUo" in cmdline):
            self.filedownload = True

        if "powershell.exe" in cmdline and "system.net.webrequest" in cmdline and "create(" in cmdline and "getresponse" in cmdline:
            self.webrequest = True

        if "powershell.exe" in cmdline and "start-bitstransfer" in cmdline:
            self.bitstransfer = True

        if "powershell.exe" in cmdline and "invoke-item" in cmdline:
            self.invokeitem = True

    def on_complete(self):
        if self.exec_policy:
            self.data.append({"execution_policy" : "Attempts to bypass execution policy"})
            self.severity = 3
            self.weight += 1

        if self.user_profile:
            self.data.append({"user_profile" : "Does not load current user profile"})
            self.severity = 3
            self.weight += 1

        if self.hidden_window:
            self.data.append({"hidden_window" : "Attempts to execute command with a hidden window"})
            self.weight += 1

        if self.b64_encoded:
            self.data.append({"b64_encoded" : "Uses a Base64 encoded command value"})
            self.weight += 1
            
        if self.noninteractive:
            self.data.append({"noninteractive" : "Creates a non-interactive prompt"})
            self.weight += 1

        if self.startprocess:
            self.data.append({"starts_process" : "Creates a new process"})
            self.weight += 1
        
        if self.filedownload:
            self.data.append({"file_download" : "Uses powershell to download a file"})
            self.severity = 3
            self.weight += 1

        if self.webrequest:
            self.data.append({"web_request" : "Uses powershell System.Net.WebRequest method to perform a HTTP request potentially to fetch a second stage file"})
            self.severity = 3
            self.weight += 1

        if self.bitstransfer:
            self.data.append({"bitsadmin_download" : "Uses BitsTransfer to download a file"})
            self.severity = 3
            self.weight += 1

        if self.invokeitem:
            self.data.append({"invoke_item" : "Potentially uses Invoke-Item to execute a file"})
            self.weight += 1

        if self.weight:
            return True
        return False
