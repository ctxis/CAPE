# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import binascii
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
from collections import defaultdict, OrderedDict

from decoders import JavaDropper

BUFSIZE = 10485760

def upx_unpack(raw_data):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(raw_data)
    f.close()
    try:
        subprocess.call("(upx -d %s)" %f.name, shell=True)
    except Exception as e:
        print 'UPX Error {0}'.format(e)
        os.unlink(f.name)
        return
    
    return f.name

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
        if os.path.exists(file_path + "_info.txt"):
            guest_paths = [line.strip() for line in open(file_path + "_info.txt")]
        else:
            guest_paths = []
            
        file_info = File(file_path=file_path,guest_paths=guest_paths).get_all()
        # Used by ElasticSearch to find the file on disk
        # since they are in random generated directories
        if Config("reporting").get("elasticsearchdb").get("enabled"):
            file_info["dropdir"] = file_path.split("/")[-2]
        texttypes = [
            "ASCII",
            "Windows Registry text",
            "XML document text",
            "Unicode text",
        ]

        with open(file_info["path"], "r") as drop_open:
            filedata = drop_open.read(buf + 1)
        if len(filedata) > buf:
            file_info["data"] = binascii.b2a_hex(filedata[:buf] + " <truncated>")
        else:
            file_info["data"] = binascii.b2a_hex(filedata)
            
        nulltermonly = self.options.get("nullterminated_only", True)
        minchars = self.options.get("minchars", 5)
       
        if nulltermonly:
            apat = "([\x20-\x7e]{" + str(minchars) + ",})\x00"
            strings.append(re.findall(apat, filedata))
            upat = "((?:[\x20-\x7e][\x00]){" + str(minchars) + ",})\x00\x00"
            strings.append([str(ws.decode("utf-16le")) for ws in re.findall(upat, filedata)])
        else:
            apat = "([\x20-\x7e]{" + str(minchars) + ",})\x00"
            strings.append(re.findall(apat, filedata))
            upat = "(?:[\x20-\x7e][\x00]){" + str(minchars) + ",}"
            strings.append([str(ws.decode("utf-16le")) for ws in re.findall(upat, filedata)])
        
        file_info["strings"] = strings
            
        # Process Yara hits
        for hit in file_info["yara"]:
            name = hit["name"]
            # UPX Check and unpack
            if name == 'UPX':
                print "[!] Found UPX Packed sample, Attempting to unpack"
                unpacked_file = upx_unpack(filedata)
                unpacked_yara = File(unpacked_file).get_yara()
                for unpacked_hit in unpacked_yara:
                    unpacked_name = unpacked_hit["name"]
                    if unpacked_name == 'UPX':
                        # Failed to unpack
                        print "[!] Failed to unpack UPX"
                        os.unlink(unpacked_file)
                        #return
                if os.path.exists(unpacked_file):
                    if not os.path.exists(self.CAPE_path):
                        os.makedirs(self.CAPE_path)
                    new_CAPE_folder = os.path.join(self.CAPE_path, str(random.randint(100000000, 9999999999)))
                    os.makedirs(new_CAPE_folder)
                    newname = os.path.join(new_CAPE_folder, os.path.basename(unpacked_file))
                    print 'unpacked_file {0}, newname {1}'.format(unpacked_file, newname)
                    os.rename(unpacked_file, newname)
                    infofd = open(newname + "_info.txt", "a")
                    infofd.write(os.path.basename(unpacked_file) + "\n")
                    infofd.close()

                    # Recursive process of unpacked file
                    self.process_file(newname, CAPE_files, True)
                
            # Java Dropper Check
            if name == 'JavaDropper':
                print "[!] Found Java Dropped, attemping to unpack"
                unpacked_file = JavaDropper.run(unpacked_file)
                name = yara_scan(unpacked_file)

                if name == 'JavaDropper':
                    print "[!] Failed to unpack JavaDropper"
                    #return

            # Attempt to import a decoder for the yara hit
            try:
                decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "decoders")
                file, pathname, description = imp.find_module(name,[decoders])
                module = imp.load_module(name, file, pathname, description)
                print "[+] Importing Decoder: {0}".format(name)
            except ImportError:
                print '[!] Unable to import decoder {0}'.format(name)
                #return

            # Get config data
            try:
                file_info["cape_config"] = module.config(filedata)
                file_info["cape_name"] = format(name)
                # Switch append_file only if decoded config
                append_file = True
            except Exception as e:
                print 'Conf Data error with {0}. Due to {1}'.format(name, e)
                #return ['Error', 'Error Parsing Config']
            
        # PlugX config files
        # TODO make generic
        for path in guest_paths:
            if path.endswith(".bin"):
                ConfigParser = PlugXConfig()
                config_output = ConfigParser.parse_config(filedata, len(filedata))
                if config_output:
                    file_info["plugx_config"] = config_output
                append_file = True
            
        if append_file == True:
            CAPE_files.append(file_info)
    
    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        self.key = "CAPE"
        output = ""
        CAPE_files = []

        # Static processing of submitted file
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)
            
            self.process_file(self.file_path, CAPE_files, False)
            
        # Now process dynamically dumped CAPE files
        for dir_name, dir_names, file_names in os.walk(self.CAPE_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                self.process_file(file_path, CAPE_files, True)
                
        return CAPE_files

# PlugX config analysis version 1.2
# Author: Fabien Perigaud <fabien.perigaud@cassidian.com>
# Based on poisonivy.py by Andreas Schuster.     
class PlugXConfig():
    """Locate and parse the PlugX configuration"""

    persistence = defaultdict(lambda: "Unknown", {0: "Service + Run Key", 1: "Service", 2: "Run key", 3: "None"})
    regs = defaultdict(lambda: "Unknown", {0x80000000: "HKEY_CLASSES_ROOT",
                                           0x80000001: "HKEY_CURRENT_USER",
                                           0x80000002: "HKEY_LOCAL_MACHINE",
                                           0x80000003: "HKEY_USERS",
                                           0x80000005: "HKEY_CURRENT_CONFIG" })

    @staticmethod
    def get_str_utf16le(buff):
        tstrend = buff.find("\x00\x00")
        tstr = buff[:tstrend + (tstrend & 1)]
        return tstr.decode('utf_16le')

    @staticmethod
    def get_proto(proto):
        ret = []
        if proto & 0x1:
            ret.append("TCP")
        if proto & 0x2:
            ret.append("HTTP")
        if proto & 0x4:
            ret.append("UDP")
        if proto & 0x8:
            ret.append("ICMP")
        if proto & 0x10:
            ret.append("DNS")
        if proto > 0x1f:
            ret.append("OTHER_UNKNOWN")
        return ' / '.join(ret)

    @staticmethod
    def get_proto2(proto):
        protos = ["???", "???", "????", "TCP", "HTTP", "DNS", "UDP", "ICMP", "RAW", "???", "???"]
        try:
            ret = protos[proto] + "(%d)" % proto
        except:
            ret = "UNKNOWN (%d)" % proto
        return ret

    def parse_config(self, cfg_blob, cfg_sz):
    
        config_output = OrderedDict()
        
        if cfg_sz in (0xbe4, 0x150c, 0x1510, 0x170c, 0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
            if cfg_sz == 0x1510:
                cfg_blob = cfg_blob[12:]
            elif cfg_sz in (0x36a4, 0x4ea4):
                cfg_blob = cfg_blob
            else:
                cfg_blob = cfg_blob[8:]

            # Flags
            if cfg_sz == 0xbe4:
                desc = "<L"
            elif cfg_sz in (0x36a4, 0x4ea4):
                desc = "<10L"
            else:
                desc = "<11L"
            flags = unpack_from(desc, cfg_blob)
            cfg_blob = cfg_blob[calcsize(desc):]
            config_output.update({'Flags': (["%r" % (k != 0) for k in flags])})

            # 2 timers
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            config_output.update({'Timer 1': timer_str})
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            config_output.update({'Timer 2': timer_str})

            # Timetable
            timetable = cfg_blob[:0x2a0]
            cfg_blob = cfg_blob[0x2a0:]
            space = False
            for k in xrange(len(timetable)):
                if timetable[k] != "\x01":
                    space = True
            if space:
                config_output.update({'TimeTable': 'Custom'})

            # Custom DNS
            (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob)
            custom_dns = cfg_blob[:0x10]
            cfg_blob = cfg_blob[0x10:]
            if dns1 not in (0, 0xffffffff):
                config_output.update({'Custom DNS 1': inet_ntoa(custom_dns[:4])})
            if dns2 not in (0, 0xffffffff):
                config_output.update({'Custom DNS 2': inet_ntoa(custom_dns[4:8])})
            if dns3 not in (0, 0xffffffff):
                config_output.update({'Custom DNS 3': inet_ntoa(custom_dns[8:12])})
            if dns4 not in (0, 0xffffffff):
                config_output.update({'Custom DNS 4': inet_ntoa(custom_dns[12:16])})

            # CC
            num_cc = 4 if cfg_sz not in (0x36a4, 0x4ea4) else 16
            get_proto = self.get_proto if cfg_sz not in (0x36a4, 0x4ea4) else self.get_proto2
            for k in xrange(num_cc):
                (proto, cc_port, cc_address) = unpack_from('<2H64s', cfg_blob)
                cfg_blob = cfg_blob[0x44:]
                proto = get_proto(proto)
                cc_address = cc_address.split('\x00')[0]
                if cc_address != "":
                    config_output.update({'C&C Address': ("%s:%d (%s)" % (str(cc_address), cc_port, proto))})

            # Additional URLs
            num_url = 4 if cfg_sz not in (0x36a4, 0x4ea4) else 16
            for k in xrange(num_url):
                url = cfg_blob[:0x80].split('\x00')[0]
                cfg_blob = cfg_blob[0x80:]
                if len(url) > 0 and str(url) != "HTTP://":
                    config_output.update({'URL': str(url)})

            # Proxies
            for k in xrange(4):
                ptype, port, proxy, user, passwd = unpack_from('<2H64s64s64s', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<2H64s64s64s'):]
                if proxy[0] != '\x00':
                    config_output.update({'Proxy': ("%s:%d" % (proxy.split('\x00')[0], port))})
                    if user[0] != '\x00':
                        config_output.update({'Proxy credentials': ("%s / %s\0" % (user, passwd))})

            str_sz = 0x80 if cfg_sz == 0xbe4 else 0x200

            # Persistence
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                persistence_type = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                persistence = self.persistence[persistence_type]
                config_output.update({'Persistence Type': persistence})
            install_dir = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            config_output.update({'Install Dir': install_dir.encode('ascii','ignore')})
            # Service
            service_name = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            config_output.update({'Service Name': service_name.encode('ascii','ignore')})
            service_disp = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            config_output.update({'Service Disp': service_disp.encode('ascii','ignore')})
            service_desc = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            config_output.update({'Service Desc': service_desc.encode('ascii','ignore')})
            # Run key
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                reg_hive = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                reg_key = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                reg_value = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Registry hive': self.regs[reg_hive].encode('ascii','ignore')})
                config_output.update({'Registry key': reg_key.encode('ascii','ignore')})
                config_output.update({'Registry value': reg_value.encode('ascii','ignore')})

            # Net injection
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                inject = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                config_output.update({'Net injection': ("%r\0" % (inject == 1))})
                i = 4 if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4) else 1
                for k in xrange(i):
                    inject_in = self.get_str_utf16le(cfg_blob[:str_sz])
                    cfg_blob = cfg_blob[str_sz:]
                    if inject_in != "":
                        config_output.update({'Net injection process': inject_in.encode('ascii','ignore')})

            # Elevation injection
            if cfg_sz in (0x2d58, 0x36a4, 0x4ea4):
                inject = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                config_output.update({'Elevation injection': ("%r\0" % (inject == 1))})
                for k in xrange(4):
                    inject_in = self.get_str_utf16le(cfg_blob[:str_sz])
                    cfg_blob = cfg_blob[str_sz:]
                    if inject_in != "":
                        config_output.update({'Elevation injection process': inject_in.encode('ascii','ignore')})

            # Memo / Pass / Mutex
            if cfg_sz in (0xbe4, 0x150c, 0x1510, 0x170c, 0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                online_pass = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Online Pass': online_pass.encode('ascii','ignore')})
                memo = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Memo': memo.encode('ascii','ignore')})
            if cfg_sz in (0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                mutex = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Mutex': mutex.encode('ascii','ignore')})

            if cfg_sz in (0x170c,):
                app = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Application Name': app.encode('ascii','ignore')})

            # Screenshots
            if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                (screenshots, freq, zoom, color, qual, days) = unpack_from('<6L', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<6L'):]
                config_output.update({'Screenshots': ("%r\0" % (screenshots != 0))})
                config_output.update({'Screenshots params': ("%d sec / Zoom %d / %d bits / Quality %d / Keep %d days\0" % (freq, zoom, color, qual, days))})
                screen_path = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                config_output.update({'Screenshots path': screen_path.encode('ascii','ignore')})
            
            # Lateral
            if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                udp_enabled, udp_port, tcp_enabled, tcp_port = unpack_from('<4L', cfg_blob)
                if tcp_enabled == 1:
                    config_output.update({'Lateral movement TCP port': ("%d\0" % tcp_port)})
                if udp_enabled == 1:
                    config_output.update({'Lateral movement UDP port': ("%d\0" % udp_port)})
                cfg_blob = cfg_blob[calcsize('<4L'):]

            if cfg_sz in (0x254c, 0x2d58, 0x36a4, 0x4ea4):
                icmp_enabled, icmp_port = unpack_from('<2L', cfg_blob)
                if icmp_enabled == 1:
                    config_output.update({'Lateral movement ICMP port (?)': ("%d\0" % icmp_port)})
                cfg_blob = cfg_blob[calcsize('<2L'):]

            if cfg_sz in (0x36a4, 0x4ea4):
                protoff_enabled, protoff_port = unpack_from('<2L', cfg_blob)
                if protoff_enabled == 1:
                    config_output.update({'Lateral movement Protocol 0xff port (?)': ("%d\0" % protoff_port)})
                cfg_blob = cfg_blob[calcsize('<2L'):]

            if cfg_sz in (0x36a4, 0x4ea4):
                (p2p_scan,) = unpack_from('<L', cfg_blob)
                if p2p_scan != 0:
                    config_output.update({'P2P Scan LAN range': ("%r\0" % True)})
                cfg_blob = cfg_blob[calcsize('<L'):]
                p2p_start = cfg_blob[:4*calcsize('<L')]
                cfg_blob = cfg_blob[4*calcsize('<L'):]
                p2p_stop = cfg_blob[:4*calcsize('<L')]
                cfg_blob = cfg_blob[4*calcsize('<L'):]
                for i in xrange(4):
                    if p2p_start[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')] != "\0\0\0\0":
                        config_output.update({'P2P Scan range %d start': (i,socket.inet_ntoa(p2p_start[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')]))})
                        config_output.update({'P2P Scan range %d stop': (i,socket.inet_ntoa(p2p_stop[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')]))})

            if cfg_sz in (0x36a4, 0x4ea4):
                mac_addr = cfg_blob[:6]
                if mac_addr != "\0\0\0\0\0\0":
                    config_output.update({'Mac Address black list': ("%02x" % k for k in mac_addr)})
                cfg_blob = cfg_blob[6:]

            if cfg_sz in (0x4ea4,):
                for k in xrange(8):
                    process_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        config_output.update({'Process black list': process_name.encode('ascii','ignore')})
                for k in xrange(8):
                    file_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        config_output.update({'File black list': file_name.encode('ascii','ignore')})
                for k in xrange(8):
                    reg_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        config_output.update({'Registry black list': reg_name.encode('ascii','ignore')})

        else:
            return None

        return config_output