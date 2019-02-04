import logging
import requests
import json

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log = logging.getLogger(__name__)

s=requests.Session()
s.verify=False

host = ""
port = ""
username = ""
password = ""

class VMwareREST(Machinery):
    """Virtualization layer for remote VMware Workstation Server using vmrun utility."""
    LABEL = "id"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmwarerest.host:
            raise CuckooMachineError("VMwareREST hostname/IP address missing, "
                                     "please add it to vmwarerest.conf")
        self.host = self.options.vmwarerest.host
        if not self.options.vmwarerest.port:
            raise CuckooMachineError("VMwareREST server port address missing, "
                                     "please add it to vmwarerest.conf")
        self.port = str(self.options.vmwarerest.port)
        if not self.options.vmwarerest.username:
            raise CuckooMachineError("VMwareREST username missing, "
                                     "please add it to vmwarerest.conf")
        self.username = self.options.vmwarerest.username
        if not self.options.vmwarerest.password:
            raise CuckooMachineError("VMwareREST password missing, "
                                     "please add it to vmwarerest.conf")
        self.password = self.options.vmwarerest.password

        super(VMwareREST, self)._initialize_check()

        log.info("VMwareREST machinery module initialised (%s:%s).", self.host, self.port)

    def get_vms(self):
        vms=s.get('https://'+self.host+':'+str(self.port)+'/api/vms', auth=(self.username,self.password))
        if "Authentication failed" in vms.text:
            log.info("Authentication failed, please check credentials in vmwarerest.conf")
            return None
        return vms.json()

    def get_vmmoid(self, id):
        vms = self.get_vms()
        if vms:
            for vm in vms:
                if vm['path'].endswith(id + '.vmx'):
                    return vm['id']
        log.info("There was a problem getting vmmoid for vm %s", id)

    def set_vm_settings(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            status = s.put('https://'+self.host+':'+self.port+'/api/vms/'+vmmoid, data=json.dumps(testjson), auth=(self.username,self.password))
            if "Authentication failed" in status.text:
                log.info("Authentication failed, please check credentials in vmwarerest.conf")
                return None
        log.info("There was a problem setting settings for vm %s", id)

    def get_vm_settings(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            status = s.get('https://'+self.host+':'+self.port+'/api/vms/'+vmmoid, auth=(self.username,self.password))
            return status
        log.info("There was a problem getting settings for vm %s", id)

    def poweron_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            log.info("Powering on vm %s", id)
            status = s.put('https://'+self.host+':'+self.port+'/api/vms/'+vmmoid+'/power', auth=(self.username,self.password), data='on', headers={'content-type':'application/vnd.vmware.vmw.rest-v1+json'})
            if "Authentication failed" in status.text:
                log.info("Authentication failed, please check credentials in vmwarerest.conf: %s %s", self.username, self.password)
                return None
            return status
        log.info("There was a problem powering on vm %s", id)

    def poweroff_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            log.info("Powering off vm %s", id)
            status = s.put('https://'+self.host+':'+self.port+'/api/vms/'+vmmoid+'/power', auth=(self.username,self.password), data='off', headers={'content-type':'application/vnd.vmware.vmw.rest-v1+json'})
            return status
        log.info("There was a problem powering off vm %s", id)

    def get_power_for_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            status = s.get('https://'+self.host+':'+self.port+'/api/vms/'+vmmoid+'/power', auth=(self.username,self.password))
            return status
        log.info("There was a problem querying power status for vm %s", id)

    def start(self, id):
        """Start a virtual machine.
        @param id: path to vmx file.
        @raise CuckooMachineError: if unable to start.
        """
        log.info("Starting vm %s" % id)
        self.stop(id)
        self.poweron_vm(id)

    def stop(self, id):
        """Stops a virtual machine.
        @param id: path to vmx file
        @raise CuckooMachineError: if unable to stop.
        """
        if self._is_running(id):
            log.info("Stopping vm %s" % id)
            self.poweroff_vm(id)

    def _revert(self, id, snapshot):
        """Revets machine to snapshot.
        @param id: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            log.info("Revert snapshot for vm %s: %s" % (id, snapshot))
            self.poweroff_vm(vmmoid)

    def _is_running(self, id):
        """Checks if virtual machine is running.
        @param id: path to vmx file
        @return: running status
        """
        log.info("Checking vm %s" % id)
        power_state = self.get_power_for_vm(id)

        if 'poweredOn' in power_state.text:
            log.info("Vm %s is running" % id)
            return id
        else:
            log.info("Vm %s is not running" % id)
            return
