# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    description = "Uses Windows utilities for basic functionality"
    severity = 2
    confidence = 80
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "at ",
            "at.exe",
            "attrib",
            "copy",
            "dir ",
            "dir.exe",
            "echo"
            "erase",
            "fsutil",
            "getmac",
            "ipconfig",
            "md ",
            "md.exe",
            "mkdir",
            "move ",
            "move.exe",
            "nbtstat",
            "net ",
            "net.exe",
            "netsh",
            "netstat",
            "nslookup",
            "ping",
            "powercfg"
            "qprocess",
            "query ",
            "query.exe",
            "quser",
            "qwinsta",
            "reg ",
            "reg.exe",
            "regsrv32",
            "ren ",
            "ren.exe",
            "rename",
            "route",
            "runas",
            "rwinsta",
            "sc ",
            "sc.exe",
            "schtasks",
            "set ",
            "set.exe",
            "shutdown",
            "systeminfo",
            "tasklist",
            "telnet",
            "tracert",
            "tree ",
            "tree.exe",
            "type",
            "ver ",
            "ver.exe",
            "whoami",
            "wmic",
            "wusa",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class SuspiciousCommandTools(Signature):
    name = "suspicious_command_tools"
    description = "Uses suspicious command line tools or Windows utilities"
    severity = 3
    confidence = 80
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "accesschk",
            "accessenum",
            "adexplorer",
            "adinsight",
            "adrestore",
            "autologon",
            "autoruns",
            "bcdedit",
            "bitsadmin",
            "bginfo",
            "cacls",
            "csvde",
            "del ",
            "del.exe",
            "dsquery",
            "icacls",
            "klist",
            "psexec",        
            "psfile",
            "psgetsid",
            "psinfo",
            "psping",
            "pskill",
            "pslist",
            "psloggedon",
            "psloglist",
            "pspasswd",
            "psservice",
            "psshutdown",
            "pssuspend",
            "rd ",
            "rd.exe",
            "rexec",
            "shareenum",
            "shellrunas",
            "taskkill",
            "volumeid",
            "vssadmin",
            "wbadmin",
            "wevtutil",
            "whois",
            "xcacls",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret
