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
        remote = self.options.get("remote", False)
        remote_host = self.options.get("host", "")
        if remote:
            file_path = "/tmp/tcp.dump.%d" % self.task.id
        else:
            file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses","%s" % self.task.id, "dump.pcap")
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
            if not remote:
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
            pargs.extend(["and", "(", bpf, ")" ] )

        #pargs.extend(["'"])

        if remote and not remote_host:
            log.exception("Failed to start sniffer, remote enabled but no ssh string has been specified")
            return
        elif remote:

             try:
                from subprocess import DEVNULL # py3k
             except ImportError:
                DEVNULL = open(os.devnull, 'wb')

             f = open("/tmp/%d.sh" % self.task.id, "w")
             if f:
                  f.write( ' '.join(pargs)  + ' & PID=$!')
                  f.write("\n")
                  f.write( 'echo $PID > /tmp/%d.pid' % self.task.id )
                  f.write("\n")
                  f.close()

             remote_output = subprocess.check_output(['scp', '-q', "/tmp/%d.sh" % self.task.id, remote_host + ":/tmp/%d.sh" % self.task.id  ], stderr=DEVNULL)
             remote_output = subprocess.check_output(['ssh', remote_host, 'nohup', "/bin/bash", '/tmp/%d.sh' % self.task.id, '>','/tmp/log','2>','/tmp/err' ], stderr=subprocess.STDOUT)

             self.pid = subprocess.check_output(['ssh', remote_host, 'cat', '/tmp/%d.pid' % self.task.id ], stderr=DEVNULL).strip()
             log.info("Started remote sniffer @ %s with (interface=%s, host=%s, "
                  "dump path=%s, pid=%s)", remote_host, interface, host, file_path, self.pid)
             remote_output = subprocess.check_output(['ssh', remote_host, 'rm', '-f', '/tmp/%d.pid' % self.task.id, '/tmp/%d.sh' % self.task.id ], stderr=DEVNULL)

        else:
            try:
                self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (OSError, ValueError):
                log.exception("Failed to start sniffer (interface=%s, host=%s, "
                          "dump path=%s)", interface, host, file_path)
                return

            log.info("Started sniffer with PID %d (interface=%s, host=%s, "
                    "dump path=%s)", self.proc.pid, interface, host, file_path)

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        remote = self.options.get("remote", False)
        if remote: 
             remote_host = self.options.get("host", "")
             remote_args = [ 'ssh', remote_host, 'kill' , '-2', self.pid ]

             try:
                 from subprocess import DEVNULL # py3k
             except ImportError:
                 DEVNULL = open(os.devnull, 'wb')

             remote_output = subprocess.check_output(remote_args, stderr=DEVNULL)

             file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                 "%s" % self.task.id, "dump.pcap")
             file_path2 = "/tmp/tcp.dump.%d" % self.task.id

             remote_output = subprocess.check_output([ 'scp', '-q', remote_host + ":" + file_path2, file_path ], stderr=DEVNULL)
             remote_output = subprocess.check_output([ 'ssh', remote_host, 'rm', '-f', file_path2 ], stderr=DEVNULL)
             return

        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing sniffer")
                        self.proc.kill()
                except OSError as e:
                    log.debug("Error killing sniffer: %s. Continue", e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d: %s",
                                  self.proc.pid, e)
