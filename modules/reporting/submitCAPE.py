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

def pirpi_password(strings):
    string = strings[0]
    password = string[20] + string[39] + string[58] #+ strings[77]
    return password

class SubmitCAPE(Report):
    def run(self, results):
        #self.noinject = self.options.get("noinject", False)
        #self.resublimit = int(self.options.get("resublimit",1))
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        filesdict = {}
        report = dict(results)
        db = Database()
        detections = set()

        ##### Initial static hits from CAPE's yara signatures
        #####
        if "target" in results:
            target = results["target"]
            if "file" in target:
                file = target["file"]
                if "cape_yara" in file:
                    for entry in file["cape_yara"]:
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue

                        #if entry["name"] == "Pirpi":
                        #    detections.add('CAPE_PirpiPassword')
        
                        if entry["name"] == "Azzy":
                            #for address in entry["addresses"]:
                                #self.task_options_stack.append("breakpoint{0}={1}".format(index, address)
                            self.task_options_stack.append("breakpoint={0}".format(entry["addresses"][0]))
                            detections.add('CAPE_Azzy')
                            
                        #if entry["name"] == "CAPE EvilGrab":
                        #    detections.add('CAPE_EvilGrab')                            

                        if entry["name"] == "CAPE_Dridex":
                            self.task_options_stack.append("breakpoint={0}".format(entry["addresses"][0]))
                            detections.add('CAPE_Dridex')
                            
        ##### Dynamic CAPE hits
        ##### Packers, injection or other generic dumping
        #####
        if "signatures" in results:
            for entry in results["signatures"]:
                if entry["name"] == "injection_runpe" or entry["name"] == "injection_createremotethread":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        if parent_package=='doc':
                            detections.add('CAPE_Injection_doc')    
                            continue
                        if parent_package=='dll':
                            detections.add('CAPE_Injection_dll')    
                            continue
                        if parent_package=='zip':
                            detections.add('CAPE_Injection_zip')    
                            continue
                        detections.add('CAPE_Injection')
                
                elif entry["name"] == "extraction_rwx":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        if parent_package=='doc':
                        #    detections.add('CAPE_Extraction_doc')
                        # Word triggers this so removed
                            continue
                        if parent_package=='zip':
                            detections.add('CAPE_Extraction_zip')    
                            continue
                        if parent_package=='dll':
                            detections.add('CAPE_Extraction_dll')    
                            continue
                        if parent_package=='regsvr':
                            detections.add('CAPE_Extraction_regsvr')    
                            continue
                        detections.add('CAPE_Extraction')
                
                elif entry["name"] == "CAPE Compression":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        if parent_package=='dll':
                            detections.add('CAPE_Compression_dll')    
                            continue                            
                        if parent_package=='doc':
                            detections.add('CAPE_Compression_doc')    
                            continue                            
                        detections.add('CAPE_Compression')
                    
        ##### Malware families
        #####

                elif entry["name"] == "CAPE PlugX":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        if parent_package=='PlugXPayload':
                            detections.add('CAPE_PlugXPayload')   
                            continue
                        if parent_package=='zip':
                            detections.add('CAPE_PlugX_zip')
                            continue
                        if parent_package=='doc':
                            detections.add('CAPE_PlugX_doc')    
                            continue
                        if parent_package=='dll':
                            detections.add('CAPE_PlugX_dll')    
                            continue
                        detections.add('CAPE_PlugX')

                elif entry["name"] == "CAPE PlugX fuzzy":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        if parent_package=='PlugXPayload':
                            detections.add('CAPE_PlugXPayload_fuzzy')
                            continue
                        if parent_package=='zip':
                            detections.add('CAPE_PlugX_fuzzy_zip')    
                            continue
                        if parent_package=='doc':
                            detections.add('CAPE_PlugX_fuzzy_doc')
                            continue
                        if parent_package=='dll':
                            detections.add('CAPE_PlugX_fuzzy_dll')                              
                            continue
                        detections.add('CAPE_PlugX_fuzzy')    
                                            
                elif entry["name"] == "CAPE Derusbi":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        detections.add('CAPE_Derusbi')
                    
                elif entry["name"] == "CAPE EvilGrab":
                    if report["info"].has_key("package"):
                        parent_package = report["info"].get("package")
                        if parent_package.startswith('CAPE'):
                            continue
                        detections.add('CAPE_EvilGrab')
        
        # We only want to submit a single job if we have a
        # malware detection. A given package should do 
        # everything we need for its respective family.
        package = None
        
        if 'CAPE_PlugX_fuzzy' in detections:
            package = 'CAPE_PlugX_fuzzy'
        elif 'CAPE_PlugXPayload_fuzzy' in detections:
            package = 'CAPE_PlugXPayload_fuzzy'			
        elif 'CAPE_PlugX_fuzzy_zip' in detections:
            package = 'CAPE_PlugX_fuzzy_zip'
        elif 'CAPE_PlugX_fuzzy_doc' in detections:
            package = 'CAPE_PlugX_fuzzy_doc'
        elif 'CAPE_PlugX_fuzzy_dll' in detections:
            package = 'CAPE_PlugX_fuzzy_dll'
            
        # We may have both 'fuzzy' and non 'fuzzy'
        # but only want to submit non.
        if 'CAPE_PlugX' in detections:
            package = 'CAPE_PlugX'
        elif 'CAPE_PlugXPayload' in detections:
            package = 'CAPE_PlugXPayload'
        elif 'CAPE_PlugX_zip' in detections:
            package = 'CAPE_PlugX_zip'
        elif 'CAPE_PlugX_doc' in detections:
            package = 'CAPE_PlugX_doc'
        elif 'CAPE_PlugX_dll' in detections:
            package = 'CAPE_PlugX_dll'
            
        if 'CAPE_Derusbi' in detections:
            package = 'CAPE_Derusbi'	
            
        if 'CAPE_EvilGrab' in detections:
            package = 'CAPE_EvilGrab'	
            
        if 'CAPE_Crossfire' in detections:
            if parent_package=='dll':
                package = 'CAPE_Crossfire_dll'
            else:
                package = 'CAPE_Crossfire'
            
        if self.task_options_stack:
            self.task_options=','.join(self.task_options_stack)            
            
        if package:
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
                                    tags=None)
            if task_id:
                log.info(u"CAPE detection on file \"{0}\": {1} - added as CAPE task with ID {2}".format(self.task["target"], package, task_id))
            else:
                log.warn("Error adding CAPE task to database: {0}".format(package))
            
        else: #nothing submitted, only 'dumpers' left, let's do them all
            for dumper in detections:
                # only submit Extraction if no other dumpers are detected
                #if len(detections) > 1 and dumper.startswith('CAPE_Extraction'):
                #    continue
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
                                tags=None)
                if task_id:
                    log.info(u"CAPE detection on file \"{0}\": {1} - added as CAPE task with ID {2}".format(self.task["target"], dumper, task_id))
                else:
                    log.warn("Error adding CAPE task to database: {0}".format(dumper))
