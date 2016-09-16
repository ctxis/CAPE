# Copyright (C) 2010-2015 Cuckoo Foundation, Context Information Security. (kevin.oreilly@contextis.co.uk)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import logging
import subprocess
import os.path
import shutil
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VMwareServer(Machinery):
    """Virtualization layer for remote VMware Workstation Server using vmrun utility."""
    LABEL = "vmx_path"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmwareserver.path:
            raise CuckooMachineError("VMware vmrun path missing, "
                                     "please add it to vmwareserver.conf")

#        if not os.path.exists(self.options.vmwareserver.path):
#            raise CuckooMachineError("VMware vmrun not found in "
#                                     "specified path %s" %
#                                     self.options.vmwareserver.path)
        # Consistency checks.
#        for machine in self.machines():
#            vmx_path = machine.label

#            snapshot = self._snapshot_from_vmx(vmx_path)
#            self._check_vmx(vmx_path)
            self._check_snapshot(vmx_path, snapshot)

        # Base checks.
        super(VMwareServer, self)._initialize_check()

    def _check_vmx(self, vmx_path):
        """Checks whether a vmx file exists and is valid.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if file not found or not ending with .vmx
        """
        if not vmx_path.endswith(".vmx"):
            raise CuckooMachineError("Wrong configuration: vm path not "
                                     "ending with .vmx: %s)" % vmx_path)

        if not os.path.exists(vmx_path):
            raise CuckooMachineError("Vm file %s not found" % vmx_path)

    def _check_snapshot(self, vmx_path, snapshot):
        """Checks snapshot existance.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if snapshot not found
        """
        #check_string = "strace " + \
        check_string = self.options.vmwareserver.path + \
                       " -T ws-shared -h " + \
                       self.options.vmwareserver.vmware_url + \
                       " -u " + self.options.vmwareserver.username + \
                       " -p " + self.options.vmwareserver.password + \
                       " listSnapshots " + "\"" + vmx_path + "\""
        
        try:
            p = subprocess.Popen(check_string, shell=True)
            output, _ = p.communicate()
        except OSError as e:
            raise CuckooMachineError("Unable to get snapshot list for %s. "
                                     "Reason: %s" % (vmx_path, e))
        else:
            if output:
                return snapshot in output
            else:
                raise CuckooMachineError("Unable to get snapshot list for %s. "
                                         "No output from "
                                         "`vmrun listSnapshots`" % vmx_path)

    def start(self, vmx_path):
        """Start a virtual machine.
        @param vmx_path: path to vmx file.
        @raise CuckooMachineError: if unable to start.
        """
        snapshot = self._snapshot_from_vmx(vmx_path)

        # Preventive check
        if self._is_running(vmx_path):
            #raise CuckooMachineError("Machine %s is already running" % vmx_path)
            log.debug("Machine %s is already running, attempting to stop..." % vmx_path)
            self.stop(vmx_path)
            time.sleep(3)

        self._revert(vmx_path, snapshot)

        time.sleep(3)

        #start_string = "strace " + \
        start_string = self.options.vmwareserver.path + \
                       " -T ws-shared -h " + \
                       self.options.vmwareserver.vmware_url + \
                       " -u " + self.options.vmwareserver.username + \
                       " -p " + self.options.vmwareserver.password + \
                       " start " + "\"" + vmx_path + "\""
        
        log.debug("Starting vm %s" % vmx_path)
        
        try:
            p = subprocess.Popen(start_string, shell=True)
            if self.options.vmwareserver.mode.lower() == "gui":
                output, _ = p.communicate()
                if output:
                    raise CuckooMachineError("Unable to start machine "
                                             "%s: %s" % (vmx_path, output))
        except OSError as e:
            mode = self.options.vmwareserver.mode.upper()
            raise CuckooMachineError("Unable to start machine %s in %s "
                                     "mode: %s" % (vmx_path, mode, e))

    def stop(self, vmx_path):
        """Stops a virtual machine.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if unable to stop.
        """
        #stop_string =  "strace " + \
                       #self.options.vmwareserver.path + \
        stop_string =  self.options.vmwareserver.path + \
                       " -T ws-shared -h " + \
                       self.options.vmwareserver.vmware_url + \
                       " -u " + self.options.vmwareserver.username + \
                       " -p " + self.options.vmwareserver.password + \
                       " stop " + "\"" + vmx_path + "\" hard"

        log.debug("Stopping vm %s" % vmx_path)
        #log.debug("Stop string: %s" % stop_string)
 
        if self._is_running(vmx_path):
            try:
                if subprocess.call(stop_string, shell=True):
                    raise CuckooMachineError("Error shutting down "
                                             "machine %s" % vmx_path)
            except OSError as e:
                raise CuckooMachineError("Error shutting down machine "
                                         "%s: %s" % (vmx_path, e))
        else:

            log.warning("Trying to stop an already stopped machine: %s",
                        vmx_path)

    def _revert(self, vmx_path, snapshot):
        """Revets machine to snapshot.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        log.debug("Revert snapshot for vm %s: %s" % (vmx_path, snapshot))
        
        #revert_string = "strace " + \
                        #self.options.vmwareserver.path + \
        revert_string = self.options.vmwareserver.path + \
                        " -T ws-shared -h " + \
                        self.options.vmwareserver.vmware_url + \
                        " -u " + self.options.vmwareserver.username + \
                        " -p " + self.options.vmwareserver.password + \
                        " revertToSnapshot " + "\"" + vmx_path + "\" " + snapshot
               
        try:
            if subprocess.call(revert_string, shell=True):
                raise CuckooMachineError("Unable to revert snapshot for "
                                         "machine %s: vmrun exited with "
                                         "error" % vmx_path)
                                         
        except OSError as e:
            raise CuckooMachineError("Unable to revert snapshot for "
                                     "machine %s: %s" % (vmx_path, e))

    def _is_running(self, vmx_path):
        """Checks if virtual machine is running.
        @param vmx_path: path to vmx file
        @return: running status
        """
        #list_string = "strace " + \
                      #self.options.vmwareserver.path + \
        list_string = self.options.vmwareserver.path + \
                      " -T ws-shared -h " + \
                      self.options.vmwareserver.vmware_url + \
                      " -u " + self.options.vmwareserver.username + \
                      " -p " + self.options.vmwareserver.password + \
                      " list " + "\"" + vmx_path + "\""

        try:
            p = subprocess.Popen(list_string, stdout=subprocess.PIPE, shell=True)
            #p = subprocess.Popen(list_string,
            #p = subprocess.Popen([self.options.vmware.path, "list"],
                                 #stdout=subprocess.PIPE,
                                 #stderr=subprocess.PIPE)
            output, error = p.communicate()
        except OSError as e:
            raise CuckooMachineError("Unable to check running status for %s. "
                                     "Reason: %s" % (vmx_path, e))
        else:
            if output:
                return vmx_path in output
            else:
                raise CuckooMachineError("Unable to check running status "
                                         "for %s. No output from "
                                         "`vmrun list`" % vmx_path)

    def _snapshot_from_vmx(self, vmx_path):
        """Get snapshot for a given vmx file.
        @param vmx_path: configuration option from config file
        """
        vm_info = self.db.view_machine_by_label(vmx_path)
        return vm_info.snapshot

    def dump_memory(self, vmx_path, path):
        """Take a memory dump of the machine."""
        if not os.path.exists(vmx_path):
            raise CuckooMachineError("Can't find .vmx file {0}. Ensure to configure a fully qualified path in vmwareserver.conf (key = vmx_path)".format(vmx_path))

        try:
            subprocess.call([self.options.vmwareserver.path,
                            "-T ws-shared -h", self.options.vmwareserver.vmware_url,
                            "-u", self.options.vmwareserver.username, "-p", self.options.vmwareserver.password,
                            "snapshot",
                            vmx_path, "memdump"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("vmrun failed to take a memory dump of the machine with label %s: %s" % (vmx_path, e))

        vmwarepath, _ = os.path.split(vmx_path)
        latestvmem = max(glob.iglob(os.path.join(vmwarepath, "*.vmem")),
                         key=os.path.getctime)

        # We need to move the snapshot to the current analysis directory as
        # vmware doesn't support an option for the destination path :-/
        shutil.move(latestvmem, path)

        # Old snapshot can be deleted, as it isn't needed any longer.
        try:
            subprocess.call([self.options.vmwareserver.path,
                            "-T ws-shared -h", vmware_url,
                            "-u", self.options.vmwareserver.username, "-p", self.options.vmwareserver.password,
                            "deleteSnapshot",
                            vmx_path, "memdump"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("vmrun failed to delete the temporary snapshot in %s: %s" % (vmx_path, e))

        log.info("Successfully generated memory dump for virtual machine with label %s ", vmx_path)
