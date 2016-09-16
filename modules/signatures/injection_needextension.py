# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InjectionExtension(Signature):
    name = "injection_needextension"
    description = "Attempted to execute a copy of itself but requires an .exe extension to work"
    severity = 3
    categories = ["injection"]
    authors = ["Accuvant"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        if call["status"] == False:
            procname = process["process_name"].lower()
            if procname.endswith(".exe") == False:
                procname += ".exe"
                apiarg1 = self.get_argument(call, "ApplicationName")
                apiarg2 = self.get_argument(call, "CommandLine")
                if apiarg1.endswith(procname) or apiarg2.endswith(procname):
                    return True