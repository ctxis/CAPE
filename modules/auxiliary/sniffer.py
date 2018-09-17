# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess
import ctypes

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.common.exceptions import CuckooOperationalError

log = logging.getLogger(__name__)


class Sniffer(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        # Get updated machine info
        self.machine = self.db.view_machine_by_label(self.machine.label)
        tcpdump = self.options.get("tcpdump", "/usr/sbin/tcpdump")
        bpf = self.options.get("bpf", "")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                 "%s" % self.task.id, "dump.pcap")
        host = self.machine.ip
        # Selects per-machine interface if available.
        if self.machine.interface:
            interface = self.machine.interface
        else:
            interface = self.options.get("interface")
        # Selects per-machine resultserver IP if available.
        if self.machine.resultserver_ip:
            resultserver_ip = str(self.machine.resultserver_ip)
        else:
            resultserver_ip = str(Config().resultserver.ip)
        # Get resultserver port from its instance because it could change dynamically.
        resultserver_port = str(ResultServer().port)

        if self.machine.resultserver_port:
            resultserver_port = str(self.machine.resultserver_port)
        else:
            resultserver_port = str(Config().resultserver.port)

        if not os.path.exists(tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network "
                      "capture aborted", tcpdump)
            return

        mode = os.stat(tcpdump)[stat.ST_MODE]
        if self.options.get("suid_check", True) and (mode & stat.S_ISUID) == 0 and os.geteuid() > 0:
            # now do a weak file capability check
            has_caps = False
            try:
                caplib = ctypes.cdll.LoadLibrary("libcap.so.2")
                if caplib:
                    caplist = caplib.cap_get_file(tcpdump)
                    if caplist:
                        has_caps = True
            except:
                pass
            if not has_caps:
                log.error("Tcpdump is not accessible from this user, "
                          "network capture aborted")
                return

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return

        pargs = [tcpdump, "-U", "-q", "-s", "0", "-i", interface, "-n"]

        # Trying to save pcap with the same user which cuckoo is running.
        try:
            user = getpass.getuser()
        except:
            pass
        else:
            pargs.extend(["-Z", user])

        pargs.extend(["-w", file_path])
        pargs.extend(["host", host])
        # Do not capture XMLRPC agent traffic.
        pargs.extend(["and", "not", "(", "dst", "host", host, "and", "dst", "port",
                      str(CUCKOO_GUEST_PORT), ")", "and", "not", "(", "src", "host",
                      host, "and", "src", "port", str(CUCKOO_GUEST_PORT), ")"])

        # Do not capture ResultServer traffic.
        pargs.extend(["and", "not", "(", "dst", "host", resultserver_ip,
                      "and", "dst", "port", resultserver_port, ")", "and",
                      "not", "(", "src", "host", resultserver_ip, "and",
                      "src", "port", resultserver_port, ")"])

        if bpf:
            pargs.extend(["and", "(", bpf, ")"])

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, close_fds=True)
        except (OSError, ValueError):
            log.exception("Failed to start sniffer (interface=%s, host=%s, "
                          "dump path=%s)", interface, host, file_path)
            return

        log.info("Started sniffer with PID %d (interface=%s, host=%s, "
                 "dump path=%s)", self.proc.pid, interface, host, file_path)

    def _check_output(self, out, err):
        if out:
            raise CuckooOperationalError(
                "Potential error while running tcpdump, did not expect "
                "standard output, got: %r." % out
            )

        err_whitelist_start = (
            "tcpdump: listening on ",
        )

        err_whitelist_ends = (
            "packet captured",
            "packets captured",
            "packet received by filter",
            "packets received by filter",
            "packet dropped by kernel",
            "packets dropped by kernel",
            "dropped privs to root",
        )

        for line in err.split("\n"):
            if not line or line.startswith(err_whitelist_start):
                continue

            if line.endswith(err_whitelist_ends):
                continue

            raise CuckooOperationalError(
                "Potential error while running tcpdump, did not expect "
                "the following standard error output: %r." % line
            )

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        # The tcpdump process was never started in the first place.
        if not self.proc:
            return

        # The tcpdump process has already quit, generally speaking this
        # indicates an error such as "permission denied".
        if self.proc.poll():
            out, err = self.proc.communicate()
            raise CuckooOperationalError(
                "Error running tcpdump to sniff the network traffic during "
                "the analysis; stdout = %r and stderr = %r. Did you enable "
                "the extra capabilities to allow running tcpdump as non-root "
                "user and disable AppArmor properly (the latter only applies "
                "to Ubuntu-based distributions with AppArmor, see also %s)?" %
                (out, err, "permission-denied-for-tcpdump")
            )


        try:
            self.proc.terminate()
        except:
            try:
                if not self.proc.poll():
                    log.debug("Killing sniffer")
                    self.proc.kill()
            except OSError as e:
                log.debug("Error killing sniffer: %s. Continue", e)
            except Exception as e:
                log.exception("Unable to stop the sniffer with pid %d: %s",
                                 self.proc.pid, e)

        # Ensure expected output was received from tcpdump.
        out, err = self.proc.communicate()
        self._check_output(out, err)

        del self.proc

