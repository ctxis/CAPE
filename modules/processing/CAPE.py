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
    
import sys
import os
import binascii
import logging
try:
    import re2 as re
except ImportError:
    import re
import subprocess
import tempfile
import random
import imp

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from struct import unpack_from, calcsize
from socket import inet_ntoa
#from collections import defaultdict, OrderedDict
import collections

parser_path = os.path.dirname(__file__)
parser_path += "/parsers"
if parser_path not in sys.path:
    sys.path.append(parser_path)
from malwareconfig import JavaDropper
from plugxconfig import plugx
from mwcp import malwareconfigreporter

CAPE_YARA_RULEPATH = \
    os.path.join(CUCKOO_ROOT, "data", "yara", "index_CAPE.yar")

BUFSIZE = 10485760

# CAPE output types
# To correlate with cape\cape.h in monitor

PROCDUMP                = 0
COMPRESSION             = 1
INJECTION_PE            = 3
INJECTION_SHELLCODE     = 4
EXTRACTION_PE           = 8
EXTRACTION_SHELLCODE    = 9
PLUGX_PAYLOAD           = 0x10
PLUGX_CONFIG            = 0x11    
EVILGRAB_PAYLOAD        = 0x14
EVILGRAB_DATA           = 0x15
UPX                     = 0x1000

log = logging.getLogger(__name__)

def convert(data):
    if isinstance(data, unicode):
        return str(data)
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

def upx_unpack(raw_data):
    upxfile = tempfile.NamedTemporaryFile(delete=False)
    upxfile.write(raw_data)
    upxfile.close()
    try:
        ret = subprocess.call("(upx -d %s)" %upxfile.name, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        log.error("CAPE: UPX Error %s", e)
        os.unlink(upxfile.name)
        return
    
    if ret == 0:
        log.info("CAPE: UPX - Statically unpacked binary %s.", upxfile.name)
        return upxfile.name
    elif ret == 127:
        log.error("CAPE: Error - UPX not installed.")
    elif ret == 2:
        log.error("CAPE: Error - UPX 'not packed' exception.")
    else:
        log.error("CAPE: Unknown error - check UPX is installed and working.")
        
    os.unlink(upxfile.name)
    return
        
class CAPE(Processing):
    """Dropped files analysis."""

    def process_file(self, file_path, CAPE_files, append_file):
        """Process file.
        @return: nothing
        """
        strings = []
        buf = self.options.get("buffer", BUFSIZE)
            
        if file_path.endswith("_info.txt"):
            return
            
        texttypes = [
            "ASCII",
            "Windows Registry text",
            "XML document text",
            "Unicode text",
        ]

        if os.path.exists(file_path + "_info.txt"):
            with open(file_path + "_info.txt", 'r') as f:
                metastring = f.readline()
        else:
            metastring=""

        file_info = File(file_path, metastring).get_all()

        # Get the file data
        with open(file_info["path"], "r") as drop_open:
            filedata = drop_open.read(buf + 1)
        if len(filedata) > buf:
            file_info["data"] = binascii.b2a_hex(filedata[:buf] + " <truncated>")
        else:
            file_info["data"] = binascii.b2a_hex(filedata)
            
        metastrings = metastring.split(",")
        if len(metastrings) > 1:
            file_info["pid"] = metastrings[1]
        if len(metastrings) > 2:
            file_info["process_path"] = metastrings[2]
            file_info["process_name"] = metastrings[2].split("\\")[-1]
        if len(metastrings) > 3:
            file_info["module_path"] = metastrings[3]

        file_info["cape_type_code"] = 0
        file_info["cape_type"] = ""
            
        if metastrings != "":
            try:
                file_info["cape_type_code"] = int(metastrings[0])
            except Exception as e:
                pass
            if file_info["cape_type_code"] == COMPRESSION:
                file_info["cape_type"] = "Decompressed PE Image"
            if file_info["cape_type_code"] == INJECTION_PE:
                file_info["cape_type"] = "Injected PE Image"
                if len(metastrings) > 4:
                    file_info["target_path"] = metastrings[4]
                    file_info["target_process"] = metastrings[4].split("\\")[-1]
                    file_info["target_pid"] = metastrings[5]
            if file_info["cape_type_code"] == INJECTION_SHELLCODE:
                file_info["cape_type"] = "Injected Shellcode/Data"
                if len(metastrings) > 4:
                    file_info["target_path"] = metastrings[4]
                    file_info["target_process"] = metastrings[4].split("\\")[-1]
                    file_info["target_pid"] = metastrings[5]
            if file_info["cape_type_code"] == EXTRACTION_PE:
                file_info["cape_type"] = "Extracted PE Image"
                if len(metastrings) > 4:
                    file_info["virtual_address"] = metastrings[4]
            if file_info["cape_type_code"] == EXTRACTION_SHELLCODE:
                file_info["cape_type"] = "Extracted Shellcode"
                if len(metastrings) > 4:
                    file_info["virtual_address"] = metastrings[4]
            type_strings = file_info["type"].split()
            if type_strings[0] == ("PE32+"):
                file_info["cape_type"] += ": 64-bit "
                if type_strings[2] == ("(DLL)"):
                    file_info["cape_type"] += "DLL"
                else:
                    file_info["cape_type"] += "executable"
            if type_strings[0] == ("PE32"):
                file_info["cape_type"] += ": 32-bit "
                if type_strings[2] == ("(DLL)"):
                    file_info["cape_type"] += "DLL"
                else:
                    file_info["cape_type"] += "executable"
            # PlugX
            if file_info["cape_type_code"] == PLUGX_CONFIG:
                file_info["cape_type"] = "PlugX Config"
                plugx_parser = plugx.PlugXConfig()
                config_output = plugx_parser.parse_config(filedata, len(filedata))
                if config_output:
                    file_info["plugx_config"] = config_output
                append_file = True
            if file_info["cape_type_code"] == PLUGX_PAYLOAD:
                file_info["cape_type"] = "PlugX Payload"
                type_strings = file_info["type"].split()
                if type_strings[0] == ("PE32+"):
                    file_info["cape_type"] += ": 64-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"
                if type_strings[0] == ("PE32"):
                    file_info["cape_type"] += ": 32-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"                
            # EvilGrab
            if file_info["cape_type_code"] == EVILGRAB_PAYLOAD:
                file_info["cape_type"] = "EvilGrab Payload"
                type_strings = file_info["type"].split()
                if type_strings[0] == ("PE32+"):
                    file_info["cape_type"] += ": 64-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"
                if type_strings[0] == ("PE32"):
                    file_info["cape_type"] += ": 32-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"
            if file_info["cape_type_code"] == EVILGRAB_DATA:
                file_info["cape_type"] = "EvilGrab Data"
                append_file = True
            # UPX
            if file_info["cape_type_code"] == UPX:
                file_info["cape_type"] = "Unpacked PE Image"
                if type_strings[0] == ("PE32+"):
                    file_info["cape_type"] += ": 64-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"
                if type_strings[0] == ("PE32"):
                    file_info["cape_type"] += ": 32-bit "
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"                        
        
        # Process CAPE Yara hits
        for hit in file_info["cape_yara"]:
            cape_name = hit["name"]
            try:
                file_info["cape_type"] = hit["meta"]["cape_type"]
            except:
                #log.error("CAPE Yara signature has no CAPE type metadata: %s", cape_name)
                file_info["cape_type"] = "CAPE Detection: <Type missing>"
            # UPX Check and unpack
            if cape_name == 'UPX':
                log.info("CAPE: Found UPX Packed sample - attempting to unpack")
                unpacked_file = upx_unpack(filedata)
                if unpacked_file and os.path.exists(unpacked_file):
                    unpacked_yara = File(unpacked_file).get_yara(CAPE_YARA_RULEPATH)
                    for unpacked_hit in unpacked_yara:
                        unpacked_name = unpacked_hit["name"]
                        if unpacked_name == 'UPX':
                            # Failed to unpack
                            log.info("CAPE: Failed to unpack UPX")
                            os.unlink(unpacked_file)
                            break
                    if not os.path.exists(self.CAPE_path):
                        os.makedirs(self.CAPE_path)
                    newname = os.path.join(self.CAPE_path, os.path.basename(unpacked_file))
                    os.rename(unpacked_file, newname)
                    infofd = open(newname + "_info.txt", "a")
                    infofd.write(os.path.basename(unpacked_file) + "\n")
                    infofd.close()

                    # Recursive process of unpacked file
                    self.process_file(newname, CAPE_files, True)
                
            # Java Dropper Check
            #if cape_name == 'JavaDropper':
            #    log.info("CAPE: Found Java Dropped, attemping to unpack")
            #    unpacked_file = JavaDropper.run(unpacked_file)
            #    cape_name = yara_scan(unpacked_file)
            #
            #    if cape_name == 'JavaDropper':
            #        log.info("CAPE: Failed to unpack JavaDropper")
            #        #return

            # Attempt to import a parser for the yara hit
            # DC3-MWCP
            try:
                mwcp = malwareconfigreporter.malwareconfigreporter()
                kwargs = {}
                mwcp.run_parser(cape_name, data=filedata, **kwargs)
                if mwcp.errors == []:
                    log.info("CAPE: Imported DC3-MWCP parser %s", cape_name)
                    mwcp_loaded = True
                else:
                    for error in mwcp.errors:
                        #log.info("CAPE: DC3-MWCP parser error: %s", error.readline())
                        log.info("CAPE: DC3-MWCP parser error: %s", error)
                        mwcp_loaded = False
            except ImportError:
                mwcp_loaded = False
            
            # malwareconfig
            try:
                malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malwareconfig")
                file, pathname, description = imp.find_module(cape_name,[malwareconfig_parsers])
                module = imp.load_module(cape_name, file, pathname, description)
                malwareconfig_loaded = True
                log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
            except ImportError:
                #log.error("CAPE: Unable to import malwareconfig.com parser %s", cape_name)
                malwareconfig_loaded = False
            
            # Get config data
            if mwcp_loaded:
                try:
                    file_info["cape_config"] = convert(mwcp.metadata)
                    file_info["cape_name"] = format(cape_name)
                    append_file = True
                except Exception as e:
                    log.error("CAPE: DC3-MWCP config parsing error with %s: %s", cape_name, e)            
            elif malwareconfig_loaded:
                try:
                    file_info["cape_config"] = {} 
                    for (key, value) in module.config(filedata).iteritems():
                        file_info["cape_config"].update({key: [value]}) 
                    file_info["cape_name"] = format(cape_name)
                    append_file = True
                except Exception as e:
                    log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
            
        if append_file == True:
            CAPE_files.append(file_info)
    
    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        self.key = "CAPE"
        output = ""
        CAPE_files = []

        # Process dynamically dumped CAPE files
        for dir_name, dir_names, file_names in os.walk(self.CAPE_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                self.process_file(file_path, CAPE_files, True)
                
        # Finally static processing of submitted file
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)
            
            self.process_file(self.file_path, CAPE_files, False)
            
        return CAPE_files
