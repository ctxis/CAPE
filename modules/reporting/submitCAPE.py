# Copyright (C) 2015 Kevin O'Reilly kevin.oreilly@contextis.co.uk 
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

import os
import logging
import pprint

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

cape_package_list = [
        "Cerber", "Compression", "Compression_dll", "Compression_doc", "Compression_zip", "DumpOnAPI", "Doppelganging", "EvilGrab",
        "Extraction", "Extraction_dll", "Extraction_regsvr", "Extraction_zip", "Extraction_ps1", "Extraction_jar", "Hancitor",
        "Hancitor_doc", "Injection", "Injection_dll", "Injection_doc", "Injection_pdf", "Injection_zip", "Injection_ps1", "PlugX",
        "PlugXPayload", "PlugX_dll", "PlugX_doc", "PlugX_zip", "Sedreco", "Sedreco_dll", "Shellcode-Extraction", "TrickBot", "UPX",
        "UPX_dll", "Ursnif"
    ];

def pirpi_password(strings):
    string = strings[0]
    password = string[20] + string[39] + string[58] #+ strings[77]
    return password

class SubmitCAPE(Report):
    def process_cape_yara(self, cape_yara, detections):
        
        #if cape_yara["name"] == "Pirpi":
        #    detections.add('PirpiPassword')

        if cape_yara["name"] == "Sedreco" and 'Sedreco' not in detections:
            encrypt1 = cape_yara["addresses"].get("encrypt1")
            encrypt2 = cape_yara["addresses"].get("encrypt2")
            encrypt64_1 = cape_yara["addresses"].get("encrypt64_1")
            if encrypt1:
                self.task_options_stack.append("CAPE_var1={0}".format(encrypt1))
            if encrypt2:
                self.task_options_stack.append("CAPE_var2={0}".format(encrypt2))
            if encrypt64_1:
                self.task_options_stack.append("CAPE_var3={0}".format(encrypt64_1))
            detections.add('Sedreco')
            
        if cape_yara["name"] == "Cerber":
            detections.add('Cerber')                            
            
        if cape_yara["name"] == "Ursnif":
            decrypt_config64 = cape_yara["addresses"].get("decrypt_config64")
            decrypt_config32 = cape_yara["addresses"].get("decrypt_config32")
            if decrypt_config64:
                for item in self.task_options_stack:
                    if 'bp0' in item:
                        self.task_options_stack.remove(item)
                self.task_options_stack.append("bp0={0}".format(decrypt_config64))
                detections.add('Ursnif')
            elif decrypt_config32:
                if not any('bp0' in s for s in self.task_options_stack):
                    self.task_options_stack.append("bp0={0}".format(decrypt_config32))
                    detections.add('Ursnif')

            crypto64_1 = cape_yara["addresses"].get("crypto64_1")
            crypto32_1 = cape_yara["addresses"].get("crypto32_1")
            if crypto64_1:
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                ret_address = int(crypto64_1)
                self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                detections.add('Ursnif')
            elif crypto32_1:
                if not any('bp1' in s for s in self.task_options_stack):
                    ret_address = int(crypto32_1)
                    self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                    detections.add('Ursnif')

            crypto64_2 = cape_yara["addresses"].get("crypto64_2")
            crypto32_2 = cape_yara["addresses"].get("crypto32_2")
            if crypto64_2:
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                ret_address = int(crypto64_2)
                self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                detections.add('Ursnif')
            elif crypto32_2:
                if not any('bp1' in s for s in self.task_options_stack):
                    ret_address = int(crypto32_2)
                    self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                    detections.add('Ursnif')

            crypto64_3 = cape_yara["addresses"].get("crypto64_3")
            crypto32_3 = cape_yara["addresses"].get("crypto32_3")
            if crypto64_3:
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                ret_address = int(crypto64_3)
                self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                detections.add('Ursnif')
            elif crypto32_3:
                if not any('bp1' in s for s in self.task_options_stack):
                    ret_address = int(crypto32_3)
                    self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                    detections.add('Ursnif')
    
            crypto64_4 = cape_yara["addresses"].get("crypto64_4")
            crypto32_4 = cape_yara["addresses"].get("crypto32_4")
            if crypto64_4:
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                ret_address = int(crypto64_4)
                self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                detections.add('Ursnif')
            elif crypto32_4:
                if not any('bp1' in s for s in self.task_options_stack):
                    ret_address = int(crypto32_4)
                    self.task_options_stack.append("bp1={0}".format(str(ret_address)))
                    detections.add('Ursnif')
    
        if cape_yara["name"] == "TrickBot":
            detections.add('TrickBot')

        if cape_yara["name"] == "Hancitor":
            detections.add('Hancitor')

    def run(self, results):
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        filesdict = {}
        report = dict(results)
        db = Database()
        detections = set()

        self.task_options = self.task["options"]

        if self.task_options and 'disable_cape=1' in self.task_options:        
            return
            
        parent_package = report["info"].get("package")
            
        ##### Initial static hits from CAPE's yara signatures
        #####
        if "target" in results:
            target = results["target"]
            if "file" in target:
                file = target["file"]
                if "cape_yara" in file:
                    for entry in file["cape_yara"]:
                        self.process_cape_yara(entry, detections)
                        
        if "procdump" in results:
            if results["procdump"] is not None:
                for file in results["procdump"]:
                    if "cape_yara" in file:
                        for entry in file["cape_yara"]:
                            self.process_cape_yara(entry, detections)
        
        if "CAPE" in results:
            if results["CAPE"] is not None:
                for file in results["CAPE"]:
                    if "cape_yara" in file:
                        for entry in file["cape_yara"]:
                            self.process_cape_yara(entry, detections)
                            
        if "dropped" in results:
            if results["dropped"] is not None:
                for file in results["dropped"]:
                    if "cape_yara" in file:
                        for entry in file["cape_yara"]:
                            self.process_cape_yara(entry, detections)

        ##### Dynamic CAPE hits
        ##### Packers, injection or other generic dumping
        #####
        if "signatures" in results:
            for entry in results["signatures"]:
                if entry["name"] == "InjectionCreateRemoteThread" or entry["name"] == "InjectionProcessHollowing" or entry["name"] == "InjectionSetWindowLong" or entry["name"] == "InjectionInterProcess":
                    if report["info"].has_key("package"):
                        if parent_package=='doc':
                            detections.add('Injection_doc')    
                            continue
                        if parent_package=='dll' or parent_package=='regsvr':
                            detections.add('Injection_dll')    
                            continue
                        if parent_package=='zip':
                            detections.add('Injection_zip')    
                            continue
                        if parent_package=='pdf':
                            detections.add('Injection_pdf')    
                            continue
                        detections.add('Injection')
                
                elif entry["name"] == "Extraction":
                    if report["info"].has_key("package"):
                        if parent_package=='doc':
                        #    detections.add('Extraction_doc')
                        # Word triggers this so removed
                            continue
                        if parent_package=='zip':
                            detections.add('Extraction_zip')
                            continue
                        if parent_package=='ps1':
                            detections.add('Extraction_ps1')
                            continue
                        if parent_package=='dll':
                            detections.add('Extraction_dll')
                            continue
                        if parent_package=='regsvr':
                            detections.add('Extraction_regsvr')    
                            continue
                        if parent_package=='jar':
                            detections.add('Extraction_jar')
                            continue
                        detections.add('Extraction')
                
                elif entry["name"] == "Compression":
                    if report["info"].has_key("package"):
                        if parent_package=='zip':
                            detections.add('Compression_zip')    
                            continue                            
                        if parent_package=='dll' or parent_package=='regsvr':
                            detections.add('Compression_dll')    
                            continue                            
                        if parent_package=='doc':
                            detections.add('Compression_doc')    
                            continue                            
                        detections.add('Compression')
                    
                elif entry["name"] == "Doppelganging":
                    if report["info"].has_key("package"):
                        detections.add('Doppelganging')
                    
        ##### Specific malware family packages
        #####
                elif entry["name"] == "PlugX":
                    if report["info"].has_key("package"):
                        if parent_package=='PlugXPayload':
                            detections.add('PlugXPayload')   
                            continue
                        if parent_package=='zip':
                            detections.add('PlugX_zip')
                            continue
                        if parent_package=='doc':
                            detections.add('PlugX_doc')    
                            continue
                        if parent_package=='dll':
                            detections.add('PlugX_dll')    
                            continue
                        detections.add('PlugX')

                elif entry["name"] == "PlugX fuzzy":
                    if report["info"].has_key("package"):
                        if parent_package=='PlugXPayload':
                            detections.add('PlugXPayload_fuzzy')
                            continue
                        if parent_package=='zip':
                            detections.add('PlugX_fuzzy_zip')    
                            continue
                        if parent_package=='doc':
                            detections.add('PlugX_fuzzy_doc')
                            continue
                        if parent_package=='dll':
                            detections.add('PlugX_fuzzy_dll')                              
                            continue
                        detections.add('PlugX_fuzzy')    
                                            
                elif entry["name"] == "EvilGrab":
                    if report["info"].has_key("package"):
                        detections.add('EvilGrab')
        
        # We only want to submit a single job if we have a
        # malware detection. A given package should do 
        # everything we need for its respective family.
        package = None
        
        if 'PlugX_fuzzy' in detections:
            package = 'PlugX_fuzzy'
        elif 'PlugXPayload_fuzzy' in detections:
            package = 'PlugXPayload_fuzzy'			
        elif 'PlugX_fuzzy_zip' in detections:
            package = 'PlugX_fuzzy_zip'
        elif 'PlugX_fuzzy_doc' in detections:
            package = 'PlugX_fuzzy_doc'
        elif 'PlugX_fuzzy_dll' in detections:
            package = 'PlugX_fuzzy_dll'
            
        # We may have both 'fuzzy' and non 'fuzzy'
        # but only want to submit non.
        if 'PlugX' in detections:
            package = 'PlugX'
        elif 'PlugXPayload' in detections:
            package = 'PlugXPayload'
        elif 'PlugX_zip' in detections:
            package = 'PlugX_zip'
        elif 'PlugX_doc' in detections:
            package = 'PlugX_doc'
        elif 'PlugX_dll' in detections:
            package = 'PlugX_dll'
            
        if 'EvilGrab' in detections:
            package = 'EvilGrab'	
            
        if 'Sedreco' in detections:
            if parent_package=='dll':
                package = 'Sedreco_dll'
            else:
                package = 'Sedreco'
            
        if 'Cerber' in detections:
            package = 'Cerber'	
            
        if 'TrickBot' in detections:
            package = 'TrickBot'

        if 'Ursnif' in detections:
            package = 'Ursnif'	
            
        if 'Hancitor' in detections:
            if parent_package=='doc' or parent_package=='Injection_doc':
                package = 'Hancitor_doc'

        # we want to switch off automatic process dumps in CAPE submissions
        if self.task_options and 'procdump=1' in self.task_options:
            self.task_options = self.task_options.replace(u"procdump=1", u"procdump=0", 1)
        if self.task_options_stack:
            self.task_options=','.join(self.task_options_stack)            
            
        if package and package != parent_package:
            self.task_custom="Parent_Task_ID:%s" % report["info"]["id"]
            if report["info"].has_key("custom") and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom,report["info"]["custom"])

            task_id = db.add_path(file_path=self.task["target"],
                                    package=package,
                                    timeout=self.task["timeout"],
                                    options=self.task_options,
                                    priority=self.task["priority"]+1,   # increase priority to expedite related submission
                                    machine=self.task["machine"],
                                    platform=self.task["platform"],
                                    memory=self.task["memory"],
                                    enforce_timeout=self.task["enforce_timeout"],
                                    clock=None,
                                    tags=None,
                                    parent_id=int(report["info"]["id"]))
            if task_id:
                log.info(u"CAPE detection on file \"{0}\": {1} - added as CAPE task with ID {2}".format(self.task["target"], package, task_id))
            else:
                log.warn("Error adding CAPE task to database: {0}".format(package))
            
        else: # nothing submitted, only 'dumpers' left
            if parent_package in cape_package_list:
                return            

            self.task_custom="Parent_Task_ID:%s" % report["info"]["id"]
            if report["info"].has_key("custom") and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom,report["info"]["custom"])

            for dumper in detections:
                task_id = db.add_path(file_path=self.task["target"],
                                package=dumper,
                                timeout=self.task["timeout"],
                                options=self.task_options,
                                priority=self.task["priority"]+1,   # increase priority to expedite related submission
                                machine=self.task["machine"],
                                platform=self.task["platform"],
                                memory=self.task["memory"],
                                enforce_timeout=self.task["enforce_timeout"],
                                clock=None,
                                tags=None,
                                parent_id=int(report["info"]["id"]))
                if task_id:
                    log.info(u"CAPE detection on file \"{0}\": {1} - added as CAPE task with ID {2}".format(self.task["target"], dumper, task_id))
                else:
                    log.warn("Error adding CAPE task to database: {0}".format(dumper))
        return
