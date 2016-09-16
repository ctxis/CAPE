# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

class Tor(Auxiliary):
    def start(self):
        if "tor" not in self.task.options:
            return

        torstart = self.options.get("torstart", "/usr/sbin/torstart")
        host = self.machine.ip
            
        if not os.path.exists(torstart):
            log.error("Tor startup script does not exist at path \"%s\", Tor "
                      "transparent proxy disabled", torstart)
            return

        pargs = [torstart, host]

        try:
            subprocess.call(pargs)
        except (OSError, ValueError):
            log.exception("Failed to start Tor transparent proxy for %s", host)
            return

        log.info("Started Tor transparent proxy for %s", host)

    def stop(self):
        if "tor" not in self.task.options:
            return

        torstop = self.options.get("torstop", "/usr/sbin/torstop")
        host = self.machine.ip
            
        if not os.path.exists(torstop):
            log.error("Tor shutdown script does not exist at path \"%s\"", torstop)
            return

        pargs = [torstop, host]

        try:
            subprocess.call(pargs)
        except (OSError, ValueError):
            log.exception("Failed to shutdown Tor transparent proxy for %s", host)
            return

        log.info("Shutdown Tor transparent proxy for %s", host)
