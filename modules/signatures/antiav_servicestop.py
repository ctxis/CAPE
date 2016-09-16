# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re

class AntiAVServiceStop(Signature):
    name = "antiav_servicestop"
    description = "Attempts to stop active services"
    severity = 3
    categories = ["anti-av"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.lastprocess = 0
        self.stoppedservices = []

    filter_apinames = set(["OpenServiceW", "OpenServiceA", "ControlService"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if (call["api"] == "OpenServiceA" or call["api"] == "OpenServiceW") and call["status"]:
            handle = int(call["return"], 16)
            self.handles[handle] = self.get_argument(call, "ServiceName")
        elif call["api"] == "ControlService":
            handle = int(self.get_argument(call, "ServiceHandle"), 16)
            code = int(self.get_argument(call, "ControlCode"), 10)
            if code == 1 and handle in self.handles and self.handles[handle] not in self.stoppedservices:
                self.stoppedservices.append(self.handles[handle])

        return None

    def on_complete(self):
        ret = False
        if self.stoppedservices:
            ret = True
            for service in self.stoppedservices:
                self.data.append({"servicename" : service })
        return ret
