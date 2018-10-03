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
import shutil
import json
import binascii
import logging
try:
    import re2 as re
except ImportError:
    import re
import subprocess
import tempfile
import hashlib
import random
import imp
import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError
from struct import unpack_from, calcsize
from socket import inet_ntoa
import collections

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

ssdeep_threshold = 90

parser_path = os.path.dirname(__file__)
parser_path += "/parsers"
if parser_path not in sys.path:
    sys.path.append(parser_path)
from malwareconfig import JavaDropper
from plugxconfig import plugx
from mwcp import malwareconfigreporter

BUFSIZE = 10485760

# CAPE output types
# To correlate with cape\cape.h in monitor

PROCDUMP                = 0
COMPRESSION             = 1
INJECTION_PE            = 3
INJECTION_SHELLCODE     = 4
INJECTION_SECTION       = 5
EXTRACTION_PE           = 8
EXTRACTION_SHELLCODE    = 9
PLUGX_PAYLOAD           = 0x10
PLUGX_CONFIG            = 0x11    
EVILGRAB_PAYLOAD        = 0x14
EVILGRAB_DATA           = 0x15
SEDRECO_DATA            = 0x20
URSNIF_CONFIG           = 0x24
URSNIF_PAYLOAD          = 0x25
CERBER_CONFIG           = 0x30
CERBER_PAYLOAD          = 0x31
HANCITOR_CONFIG         = 0x34
HANCITOR_PAYLOAD        = 0x35
QAKBOT_CONFIG           = 0x38
QAKBOT_PAYLOAD          = 0x39
UPX                     = 0x1000

log = logging.getLogger(__name__)

def hash_file(method, path):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(path, "rb")
    h = method()
    while True:
        buf = f.read(BUFSIZE)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

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

def upx_harness(raw_data):
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
        sha256 = hash_file(hashlib.sha256, upxfile.name)
        newname = os.path.join(os.path.dirname(upxfile.name), sha256)
        os.rename(upxfile.name, newname)
        log.info("CAPE: UPX - Statically unpacked binary %s.", upxfile.name)
        return newname
    elif ret == 127:
        log.error("CAPE: Error - UPX not installed.")
    elif ret == 2:
        log.error("CAPE: Error - UPX 'not packed' exception.")
    else:
        log.error("CAPE: Unknown error - check UPX is installed and working.")
        
    os.unlink(upxfile.name)
    return
        
class CAPE(Processing):
    """CAPE output file processing."""

    cape_config = {}
    
    def upx_unpack(self, file_data, CAPE_output):
        unpacked_file = upx_harness(file_data)
        if unpacked_file and os.path.exists(unpacked_file):
            unpacked_yara = File(unpacked_file).get_yara("CAPE")
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
            shutil.move(unpacked_file, newname)
            infofd = open(newname + "_info.txt", "a")
            infofd.write(os.path.basename(unpacked_file) + "\n")
            infofd.close()

            # Recursive process of unpacked file
            upx_extract = self.process_file(newname, CAPE_output, True)
            if upx_extract["type"]:
                upx_extract["cape_type"] = "UPX-extracted "
                type_strings = upx_extract["type"].split()
                if type_strings[0] == ("PE32+"):
                    upx_extract["cape_type"] += " 64-bit "
                    if type_strings[2] == ("(DLL)"):
                        upx_extract["cape_type"] += "DLL"
                    else:
                        upx_extract["cape_type"] += "executable"
                if type_strings[0] == ("PE32"):
                    upx_extract["cape_type"] += " 32-bit "
                    if type_strings[2] == ("(DLL)"):
                        upx_extract["cape_type"] += "DLL"
                    else:
                        upx_extract["cape_type"] += "executable"  
        
    def process_file(self, file_path, CAPE_output, append_file):
        """Process file.
        @return: file_info
        """
        global cape_config
        cape_name = ""
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
        with open(file_info["path"], "r") as file_open:
            file_data = file_open.read(buf + 1)
        if len(file_data) > buf:
            file_info["data"] = binascii.b2a_hex(file_data[:buf] + " <truncated>")
        else:
            file_info["data"] = binascii.b2a_hex(file_data)
            
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
            if file_info["cape_type_code"] == INJECTION_SECTION:
                file_info["cape_type"] = "Injected Section"
                if len(metastrings) > 4:
                    file_info["section_handle"] = metastrings[4]
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
                plugx_config = plugx_parser.parse_config(file_data, len(file_data))
                if not "cape_config" in cape_config and plugx_config:
                    cape_config["cape_config"] = {}
                    for key, value in plugx_config.items():
                        cape_config["cape_config"].update({key: [value]})
                    cape_name = "PlugX"
                else:
                    log.error("CAPE: PlugX config parsing failure - size many not be handled.")
                append_file = False
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
                cape_name = "EvilGrab"
                file_info["cape_type"] = "EvilGrab Data"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                if file_info["size"] == 256 or file_info["size"] == 260:
                    ConfigItem = "filepath"
                    ConfigData = format(file_data)
                    cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                if file_info["size"] > 0x1000:
                    append_file = True
                else:
                    append_file = False
            # Sedreco
            if file_info["cape_type_code"] == SEDRECO_DATA:
                cape_name = "Sedreco"
                cape_config["cape_type"] = "Sedreco Config"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                if len(metastrings) > 4:
                    SedrecoConfigIndex = metastrings[4]
                if SedrecoConfigIndex == '0x0':
                    ConfigItem = "Timer1"
                elif SedrecoConfigIndex == '0x1':
                    ConfigItem = "Timer2"
                elif SedrecoConfigIndex == '0x2':
                    ConfigItem = "Computer Name"
                elif SedrecoConfigIndex == '0x3':
                    ConfigItem = "C&C1"
                elif SedrecoConfigIndex == '0x4':
                    ConfigItem = "C&C2"
                elif SedrecoConfigIndex == '0x5':
                    ConfigItem = "Operation Name"
                elif SedrecoConfigIndex == '0x6':
                    ConfigItem = "Keylogger MaxBuffer"
                elif SedrecoConfigIndex == '0x7':
                    ConfigItem = "Keylogger MaxTimeout"
                elif SedrecoConfigIndex == '0x8':
                    ConfigItem = "Keylogger Flag"
                elif SedrecoConfigIndex == '0x9':
                    ConfigItem = "C&C3"
                else: 
                    ConfigItem = "Unknown"
                ConfigData = format(file_data)
                if ConfigData:
                    cape_config["cape_config"].update({ConfigItem: [ConfigData]})
                append_file = False
            # Cerber
            if file_info["cape_type_code"] == CERBER_CONFIG:
                file_info["cape_type"] = "Cerber Config"
                cape_config["cape_type"] = "Cerber Config"
                cape_name = "Cerber"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                ConfigItem = "JSON Data"
                parsed = json.loads(file_data.rstrip(b'\0'))
                ConfigData = json.dumps(parsed, indent=4, sort_keys=True)
                cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                append_file = True
            if file_info["cape_type_code"] == CERBER_PAYLOAD:
                file_info["cape_type"] = "Cerber Payload"
                cape_config["cape_type"] = "Cerber Payload"
                cape_name = "Cerber"
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
                append_file = True
            # Ursnif
            if file_info["cape_type_code"] == URSNIF_CONFIG:
                file_info["cape_type"] = "Ursnif Config"
                cape_config["cape_type"] = "Ursnif Config"
                cape_name = "Ursnif"
                malwareconfig_loaded = False
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malwareconfig")
                    file, pathname, description = imp.find_module(cape_name,[malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except ImportError:
                    log.info("CAPE: malwareconfig.com parser: No module named %s", cape_name)
                if malwareconfig_loaded:
                    try:
                        if not "cape_config" in cape_config:
                            cape_config["cape_config"] = {}
                        malwareconfig_config = module.config(file_data)
                        if isinstance(malwareconfig_config, list):
                            for (key, value) in malwareconfig_config[0].iteritems():
                                cape_config["cape_config"].update({key: [value]}) 
                        elif isinstance(malwareconfig_config, dict):
                            for (key, value) in malwareconfig_config.iteritems():
                                cape_config["cape_config"].update({key: [value]})
                    except Exception as e:
                        log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
                append_file = False
            # Hancitor
            if file_info["cape_type_code"] == HANCITOR_PAYLOAD:
                cape_name = "Hancitor"
                cape_config["cape_type"] = "Hancitor Payload"
                file_info["cape_type"] = "Hancitor Payload"
            if file_info["cape_type_code"] == HANCITOR_CONFIG:
                cape_name = "Hancitor"
                cape_config["cape_type"] = "Hancitor Config"
                file_info["cape_type"] = "Hancitor Config"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                ConfigStrings = file_data.split('\0')
                ConfigStrings = filter(None, ConfigStrings)
                ConfigItem = "Campaign Code"
                cape_config["cape_config"].update({ConfigItem: [ConfigStrings[0]]})
                GateURLs = ConfigStrings[1].split('|')
                for index, value in enumerate(GateURLs):
                    ConfigItem = "Gate URL " + str(index+1)
                    cape_config["cape_config"].update({ConfigItem: [value]})
                append_file = False
            # QakBot
            if file_info["cape_type_code"] == QAKBOT_CONFIG:
                file_info["cape_type"] = "QakBot Config"
                cape_config["cape_type"] = "QakBot Config"
                cape_name = "QakBot"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                for line in file_data.splitlines():
                    if '=' in line:
                        index = line.split('=')[0]
                        data = line.split('=')[1]
                    if index == '10':
                        ConfigItem = "Botnet name"
                        ConfigData = data
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '11':
                        ConfigItem = "Number of C2 servers"
                        ConfigData = data
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '47':
                        ConfigItem = "Bot ID"
                        ConfigData = data
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '3':
                        ConfigItem = "Config timestamp"
                        ConfigData = datetime.datetime.fromtimestamp(int(data)).strftime('%H:%M:%S %d-%m-%Y')
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '22':
                        values = data.split(':')
                        ConfigItem = "Password #1"
                        ConfigData = values[2]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "Username #1"
                        ConfigData = values[1]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "C2 #1"
                        ConfigData = values[0]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '23':
                        values = data.split(':')
                        ConfigItem = "Password #2"
                        ConfigData = values[2]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "Username #2"
                        ConfigData = values[1]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "C2 #2"
                        ConfigData = values[0]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '24':
                        values = data.split(':')
                        ConfigItem = "Password #3"
                        ConfigData = values[2]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "Username #3"
                        ConfigData = values[1]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "C2 #3"
                        ConfigData = values[0]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '25':
                        values = data.split(':')
                        ConfigItem = "Password #4"
                        ConfigData = values[2]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "Username #4"
                        ConfigData = values[1]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "C2 #4"
                        ConfigData = values[0]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                    if index == '26':
                        values = data.split(':')
                        ConfigItem = "Password #5"
                        ConfigData = values[2]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "Username #5"
                        ConfigData = values[1]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                        ConfigItem = "C2 #5"
                        ConfigData = values[0]
                        if ConfigData:
                            cape_config["cape_config"].update({ConfigItem: [ConfigData]})                
                append_file = False
            if file_info["cape_type_code"] == QAKBOT_PAYLOAD:
                file_info["cape_type"] = "QakBot Payload"
                cape_config["cape_type"] = "QakBot Payload"
                cape_name = "QakBot"
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
                append_file = True
            # UPX package output
            if file_info["cape_type_code"] == UPX:
                file_info["cape_type"] = "Unpacked PE Image"
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
        
        # Process CAPE Yara hits
        for hit in file_info["cape_yara"]:
            # Check to see if file is packed with UPX
            if hit["name"] == "UPX":
                log.info("CAPE: Found UPX Packed sample - attempting to unpack")
                self.upx_unpack(file_data, CAPE_output)
                
            # Check for a payload or config hit
            try:
                if "payload" in hit["meta"]["cape_type"].lower() or "config" in hit["meta"]["cape_type"].lower():
                    file_info["cape_type"] = hit["meta"]["cape_type"]                      
                    cape_name = hit["name"]
            except:
                pass
            type_strings = file_info["type"].split()
            if "-bit" not in file_info["cape_type"]:
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
                        
            suppress_parsing_list = ["Cerber", "Ursnif", "QakBot"];

            if hit["name"] in suppress_parsing_list:
                continue

            # Attempt to import a parser for the hit
            # DC3-MWCP
            mwcp_loaded = False
            if cape_name:
                try:
                    mwcp = malwareconfigreporter.malwareconfigreporter(analysis_path=self.analysis_path)
                    kwargs = {}
                    mwcp.run_parser(cape_name, data=file_data, **kwargs)
                    if mwcp.errors == []:
                        log.info("CAPE: Imported DC3-MWCP parser %s", cape_name)
                        mwcp_loaded = True
                    else:
                        error_lines = mwcp.errors[0].split("\n")
                        for line in error_lines:
                            if line.startswith('ImportError: '):
                                log.info("CAPE: DC3-MWCP parser: %s", line.split(': ')[1])
                except ImportError:
                    pass
                
            # malwareconfig
            malwareconfig_loaded = False
            if cape_name and mwcp_loaded == False:
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malwareconfig")
                    file, pathname, description = imp.find_module(cape_name,[malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except ImportError:
                    log.info("CAPE: malwareconfig.com parser: No module named %s", cape_name)
            
            # Get config data
            if mwcp_loaded:
                try:
                    if not "cape_config" in cape_config:
                        cape_config["cape_config"] = {}
                        cape_config["cape_config"] = convert(mwcp.metadata)
                    else:
                        cape_config["cape_config"].update(convert(mwcp.metadata))
                except Exception as e:
                    log.error("CAPE: DC3-MWCP config parsing error with %s: %s", cape_name, e)            
            elif malwareconfig_loaded:
                try:
                    if not "cape_config" in cape_config:
                        cape_config["cape_config"] = {}
                    malwareconfig_config = module.config(file_data)
                    if isinstance(malwareconfig_config, list):
                        for (key, value) in malwareconfig_config[0].iteritems():
                            cape_config["cape_config"].update({key: [value]}) 
                    elif isinstance(malwareconfig_config, dict):
                        for (key, value) in malwareconfig_config.iteritems():
                            cape_config["cape_config"].update({key: [value]})
                except Exception as e:
                    log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
            
            if "cape_config" in cape_config:
                if cape_config["cape_config"] == {}:
                    del cape_config["cape_config"]
            
        if cape_name:
            if "cape_config" in cape_config:
                    cape_config["cape_name"] = format(cape_name)
            if not "cape" in self.results:
                if cape_name != "UPX":
                    self.results["cape"] = cape_name

        # Remove duplicate payloads from web ui
        for cape_file in CAPE_output:
            if file_info["size"] == cape_file["size"]:
                if HAVE_PYDEEP:
                    ssdeep_grade = pydeep.compare(file_info["ssdeep"], cape_file["ssdeep"])
                    if ssdeep_grade >= ssdeep_threshold:
                        append_file = False
                if file_info["entrypoint"] and file_info["entrypoint"] == cape_file["entrypoint"] \
                    and file_info["ep_bytes"] == cape_file["ep_bytes"]:
                    append_file = False

        if append_file == True:
            CAPE_output.append(file_info)
        return file_info
    
    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        global cape_config
        cape_config = {}
        self.key = "CAPE"
        CAPE_output = []

        if hasattr(self, "CAPE_path"):
            # Process dynamically dumped CAPE files
            for dir_name, dir_names, file_names in os.walk(self.CAPE_path):
                for file_name in file_names:
                    file_path = os.path.join(dir_name, file_name)
            # We want to exclude duplicate files from display in ui
                    if len(file_name) <= 64:
                        self.process_file(file_path, CAPE_output, True)
                    else:
                        self.process_file(file_path, CAPE_output, False)
        # We want to process procdumps too just in case they might
        # be detected as payloads and trigger config parsing
        if hasattr(self, "procdump_path"):
            for dir_name, dir_names, file_names in os.walk(self.procdump_path):
                for file_name in file_names:
                    file_path = os.path.join(dir_name, file_name)
            # We set append_file to False as we don't wan't to include
            # the files by default in the CAPE tab
                    self.process_file(file_path, CAPE_output, False)
        # We want to process dropped files too 
        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                self.process_file(file_path, CAPE_output, False)
        # Finally static processing of submitted file
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)
            
            self.process_file(self.file_path, CAPE_output, False)
            
        if "cape_config" in cape_config:
            CAPE_output.append(cape_config)
        
        return CAPE_output
