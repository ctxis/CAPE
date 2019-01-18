# encoding: utf-8
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
import requests

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

reporting_conf = Config("reporting")
distributed = reporting_conf.submitCAPE.distributed
report_key = reporting_conf.submitCAPE.keyword

cape_package_list = [
        "Cerber", "Compression", "Compression_dll", "Compression_doc", "Compression_zip", "Compression_js", "Compression_pdf", 
        "DumpOnAPI", "Doppelganging", "EvilGrab", "Extraction", "Extraction_dll", "Extraction_regsvr", "Extraction_zip", 
        "Extraction_ps1", "Extraction_jar", "Extraction_pdf", "Extraction_js", "Hancitor", "Hancitor_doc", "Injection", 
        "Injection_dll", "Injection_doc", "Injection_pdf", "Injection_zip", "Injection_ps1", "Injection_js", "PlugX", 
        "PlugXPayload", "PlugX_dll", "PlugX_doc", "PlugX_zip", "QakBot", "RegBinary", "Sedreco",
        "Sedreco_dll", "Shellcode-Extraction", "Trace", "Trace_dll", "TrickBot", "TrickBot_doc", "UPX", "UPX_dll", "Ursnif"
    ];

class SubmitCAPE(Report):
    def process_cape_yara(self, cape_yara, detections):
        
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

        if cape_yara["name"] == "QakBot":
            anti_sandbox = cape_yara["addresses"].get("anti_sandbox")
            if anti_sandbox:
                anti_sandbox = anti_sandbox + 19 # Offset of "JLE" instruction from Yara hit
                for item in self.task_options_stack:
                    if 'bp0' in item:
                        self.task_options_stack.remove(item)
                self.task_options_stack.append("bp0={0}".format(anti_sandbox))
                detections.add('QakBot')
            decrypt_config = cape_yara["addresses"].get("decrypt_config1")
            if decrypt_config:
                decrypt_config = decrypt_config + 16 # Offset of "CALL" (decrypt)
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                self.task_options_stack.append("bp1={0}".format(decrypt_config))
                detections.add('QakBot')
            decrypt_config = cape_yara["addresses"].get("decrypt_config2")
            if decrypt_config:
                decrypt_config = decrypt_config + 30 # Offset of "CALL" (decrypt)
                for item in self.task_options_stack:
                    if 'bp1' in item:
                        self.task_options_stack.remove(item)
                self.task_options_stack.append("bp1={0}".format(decrypt_config))
                detections.add('QakBot')

    def submit_task(self, target, package, timeout, task_options, priority, machine, platform, memory, enforce_timeout, clock, tags, parent_id):

        db = Database()

        if os.path.exists(target):
            task_id = False
            if distributed:
                options = {
                    "package": package,
                    "timeout": timeout,
                    "options": task_options,
                    "priority": priority,
                    #"machine": machine,
                    "platform": platform,
                    "memory": memory,
                    "enforce_timeout": enforce_timeout,
                    "clock": clock,
                    "tags": tags,
                    "parent_id": parent_id,
                } 
                multipart_file = [("file", (os.path.basename(target), open(target, "rb")))]
                try:
                    res = requests.post(reporting_conf.submitCAPE.url , files=multipart_file, data=options)
                    if res and res.ok:
                        task_id = res.json()["data"]["task_ids"][0]
                except Exception as e:
                    log.error(e)
            else:
                task_id = db.add_path(
                            file_path=target,
                            package=package,
                            timeout=timeout,
                            options=task_options,
                            priority=priority,   # increase priority to expedite related submission
                            machine=machine,
                            platform=platform,
                            memory=memory,
                            enforce_timeout=enforce_timeout,
                            clock=None,
                            tags=None,
                            parent_id=parent_id,
                )
            if task_id:
                log.info(u"CAPE detection on file \"{0}\": {1} - added as CAPE task with ID {2}".format(target, package, task_id))
            else:
                log.warn("Error adding CAPE task to database: {0}".format(package))
        else:
            log.info("File doesn't exists")

    def run(self, results):

        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        filesdict = {}
        report = dict(results)
        detections = set()

        # allow custom extractors
        if report_key in results:
            return

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
        
        for pattern in ("procdump", "CAPE", "dropped"):
            if pattern in results:
                if results[pattern] is not None:
                    for file in results[pattern]:
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
                        if parent_package=='js':
                            detections.add('Injection_js')
                            continue
                        if parent_package=='exe':
                            detections.add('Injection')
                            continue
                
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
                        if parent_package=='pdf':
                            detections.add('Extraction_pdf')    
                            continue
                        if parent_package=='js':
                            detections.add('Extraction_js')
                            continue
                        if parent_package=='exe':
                            detections.add('Extraction')
                            continue
                
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
                        if parent_package=='pdf':
                            detections.add('Compression_pdf')    
                            continue
                        if parent_package=='js':
                            detections.add('Compression_js')
                            continue
                        if parent_package=='exe':
                            detections.add('Compression')
                            continue
                    
                elif entry["name"] == "Doppelganging":
                    if report["info"].has_key("package") and parent_package=='exe':
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
                        if parent_package=='exe':
                            detections.add('PlugX')
                            continue

                elif entry["name"] == "EvilGrab":
                    if report["info"].has_key("package") and parent_package=='exe':
                        detections.add('EvilGrab')
        
        # We only want to submit a single job if we have a
        # malware detection. A given package should do 
        # everything we need for its respective family.
        package = None

        if 'PlugXPayload' in detections:
            package = 'PlugXPayload'
        elif 'PlugX_zip' in detections:
            package = 'PlugX_zip'
        elif 'PlugX_doc' in detections:
            package = 'PlugX_doc'
        elif 'PlugX_dll' in detections:
            package = 'PlugX_dll'
        elif 'PlugX' in detections:
            package = 'PlugX'

        if 'EvilGrab' in detections and parent_package=='exe':
            package = 'EvilGrab'

        if 'Sedreco' in detections:
            if parent_package=='dll':
                package = 'Sedreco_dll'
            elif parent_package=='exe':
                package = 'Sedreco'
            
        if 'Cerber' in detections and parent_package=='exe':
            package = 'Cerber'	
            
        if 'TrickBot' in detections:
            if parent_package=='doc':
                package = 'TrickBot_doc'
            elif parent_package=='exe':
                package = 'TrickBot'

        if 'Ursnif' in detections:
            if parent_package=='doc' or parent_package=='Injection_doc':
                package = 'Ursnif_doc'
            elif parent_package=='exe' or parent_package=='Injection':
                package = 'Ursnif'
            
        if 'Hancitor' in detections:
            if parent_package=='doc' or parent_package=='Injection_doc':
                package = 'Hancitor_doc'
            elif parent_package=='exe' or parent_package=='Injection' or parent_package=='Compression':
                package = 'Hancitor'

        if 'QakBot' in detections and parent_package=='exe':
            package = 'QakBot'	

        #if 'RegBinary' in detections or 'CreatesLargeKey' in detections and parent_package=='exe':
        if 'RegBinary' in detections and parent_package=='exe':
            package = 'RegBinary'	

        # we want to switch off automatic process dumps in CAPE submissions
        if self.task_options and 'procdump=1' in self.task_options:
            self.task_options = self.task_options.replace(u"procdump=1", u"procdump=0", 1)
        if self.task_options_stack:
            self.task_options=','.join(self.task_options_stack)            
            
        if package and package != parent_package:
            self.task_custom="Parent_Task_ID:%s" % report["info"]["id"]
            if report["info"].has_key("custom") and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom,report["info"]["custom"])
            
            self.submit_task(
                self.task["target"],
                package,
                self.task["timeout"],
                self.task_options,
                self.task["priority"]+1,   # increase priority to expedite related submission
                self.task["machine"],
                self.task["platform"],
                self.task["memory"],
                self.task["enforce_timeout"],
                None,
                None,
                int(report["info"]["id"])
            )
            
        else: # nothing submitted, only 'dumpers' left
            if parent_package in cape_package_list:
                return            

            self.task_custom="Parent_Task_ID:%s" % report["info"]["id"]
            if report["info"].has_key("custom") and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom,report["info"]["custom"])

            for dumper in detections:
                self.submit_task(
                    self.task["target"],
                    dumper,
                    self.task["timeout"],
                    self.task_options,
                    self.task["priority"]+1,   # increase priority to expedite related submission
                    self.task["machine"],
                    self.task["platform"],
                    self.task["memory"],
                    self.task["enforce_timeout"],
                    None,
                    None,
                    int(report["info"]["id"])
            )
        return
