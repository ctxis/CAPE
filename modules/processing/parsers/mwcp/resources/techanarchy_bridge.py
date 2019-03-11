#!/usr/bin/env python
"""
technanarchy_bridge -- library to execute techanarchy ratdecoders and parse output for DC3-MWCP framework
"""
from __future__ import print_function
from future.builtins import str, zip
from six import iteritems

import os
import re
import subprocess
import sys

from io import BytesIO

# Allowing for two tabs to accommodate Publisher
TECHANARCHY_OUTPUT_RE = r"""Key: (.*?)\t{1,2} Value: (.*)"""
TECHANARCHY_DIRECTORY = 'RATDecoders'
SCRIPT_CREATION_STRING = """import os
from mwcp import Parser
from mwcp import resources
from mwcp.resources import techanarchy_bridge

class TechAnarchy(Parser):
    def __init__(self,reporter=None):
        Parser.__init__(self,
                description='Techanarchy %s RATdecoder using bridge',
                author='TA',
                reporter=reporter
                )

    def run(self):
        scriptpath = os.path.join(os.path.dirname(resources.__file__), '%s', '%s' + '.py')
        techanarchy_bridge.run_decoder(self.reporter, scriptpath)

"""
"""
    New key/fields added that are not current MWCP key pairs should be added to one of the lists
    below. C2 url keys are added to the domain key list.
"""
DIRECTORY_FIELD_LIST = ['Install Dir', 'InstallDir', 'InstallPath', 'Install Folder',
                        'Install Folder1', 'Install Folder2', 'Install Folder3',
                        'Folder Name', 'FolderName', 'pluginfoldername', 'nombreCarpeta']
DOMAIN_KEY_LIST = ['Domains', 'Domain', 'dns']
FILENAME_FIELD_LIST = ['InstallName', 'Install Name', 'Exe Name',
                       'Jar Name', 'JarName', 'StartUp Name', 'File Name',
                       'USB Name', 'Log File', 'Install File Name']
FILEPATH_CONCATENATE_PAIR_LIST = {'Install Path': 'Install Name',
                                  'Install Directory': 'Install File Name'}
FTP_FIELD_PAIRS = {'FTP Server': 'FTP Folder',
                   'FTPHost': 'FTPPort', 'FTPHOST': 'FTPPORT'}
INJECTIONPROCESS_FIELD_LIST = ['Process Injection', 'Injection', 'Inject Exe']
INTERVAL_FIELD_LIST = ['FTP Interval', 'Remote Delay', 'RetryInterval']
MISSIONID_FIELD_LIST = ['Campaign ID', 'CampaignID', 'Campaign Name',
                        'Campaign', 'ID', 'prefijo']
MUTEX_FIELD_LIST = ['Mutex', 'Mutex Main', 'Mutex 4', 'MUTEX',
                    'mutex', 'Mutex Grabber', 'Mutex Per']
NONC2_URL_FIELD_LIST = ['Screen Rec Link', 'WebPanel', 'Plugins']

""" The following list is used when only a password is available, that is a password without
    a corresponding username. See username below if you have a username/password pair.
"""
PASSWORD_ONLY_FIELD_LIST = ['Password', 'password']

""" Note: The username/password list are zipped together in pairs from the following
    two lists. There is a password only list above.
"""
USERNAME_FIELD_LIST = ['FTP UserName', 'FTPUserName', 'FTPUSER']
PASSWORD_FIELD_LIST = ['FTP Password', 'FTPPassword', 'FTPPASS']

REGISTRYPATH_FIELD_LIST = ['Domain', 'Reg Key', 'StartupName', 'Active X Key', 'ActiveX Key',
                           'Active X Startup', 'Registry Key', 'Startup Key', 'REG Key HKLM',
                           'REG Key HKCU', 'HKLM Value', 'RegistryKey', 'HKCUKey', 'HKCU Key',
                           'Registry Value', 'keyClase', 'regname', 'registryname',
                           'Custom Reg Key', 'Custom Reg Name', 'Custom Reg Value', 'HKCU',
                           'HKLM', 'RegKey1', 'RegKey2', 'Custom Reg Key', 'Reg Value']
VERSION_FIELD_LIST = ['Version', 'version']

"""
    End of key mapping lists
"""

def map_ta_fields(data, reporter, field_list, mwcp_key):
    for field in field_list:
        if data.get(field):
            reporter.add_metadata(mwcp_key, data[field])
def map_ta_domain_fields(data, reporter):
    for domain_key in DOMAIN_KEY_LIST:
        if domain_key in data:
            """ Hack here to handle a LuxNet case where a registry path is stored
                under the Domain key. """
            if data[domain_key].count('\\') < 2:
                domain_list = []
                if '|' in data[domain_key]:
                    """ The '|' is a separator character so strip it if
                        it is the last character so the split does not produce
                        an empty string i.e. '' """
                    domain_list = data[domain_key].rstrip('|').split('|')
                elif '*' in data[domain_key]:
                    """ The '*' is a separator character so strip it if
                        it is the last character """
                    domain_list = data[domain_key].rstrip('*').split('*')
                else:
                    domain_list = [data[domain_key]]
                for addport in domain_list:
                    if ":" in addport:
                        addr, port = addport.split(":")
                        if addr and port:
                            reporter.add_metadata(
                                "c2_socketaddress", [addr, port, "tcp"])
                    elif 'p1' in data or 'p2' in data:
                        if 'p1' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[domain_key], data['p1'], 'tcp'])
                        if 'p2' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[domain_key], data['p2'], 'tcp'])
                    elif 'Port' in data or 'Port1' in data or 'Port2' in data:
                        if 'Port' in data:
                            # CyberGate has a separator character in the field
                            # remove it here
                            data['Port'] = data['Port'].rstrip('|').strip('|')
                            for port in data['Port']:
                                reporter.add_metadata("c2_socketaddress", [
                                    addport, data['Port'], 'tcp'])
                        if 'Port1' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                addport, data['Port1'], 'tcp'])
                        if 'Port2' in data:
                            reporter.add_metadata("c2_socketaddress", [
                                addport, data['Port2'], 'tcp'])
                    elif domain_key == 'Domain' and ("Client Control Port" in data or "Client Transfer Port" in data):
                        if "Client Control Port" in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data['Domain'], data['Client Control Port'], "tcp"])
                        if "Client Transfer Port" in data:
                            reporter.add_metadata("c2_socketaddress", [data['Domain'], data[
                                'Client Transfer Port'], "tcp"])
                    else:
                        reporter.add_metadata('c2_address', data[domain_key])


def map_domainX_fields(data, reporter):
    SUFFIX_LIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
                   '11', '12', '13', '14', '15', '16', '17', '18', '19', '20']
    SPECIAL_HANDLING_LIST = ['Domain1', 'Domain2']
    for suffix in SUFFIX_LIST:
        field = 'Domain' + suffix
        if field in data:
            if data[field] != ':0':
                if ':' in data[field]:
                    address, port = data[field].split(':')
                    reporter.add_metadata('c2_socketaddress', [
                        address, port, 'tcp'])
                else:
                    if field in SPECIAL_HANDLING_LIST:
                        if "Port" in data:
                            reporter.add_metadata("c2_socketaddress", [
                                data[field], data['Port'], "tcp"])
                        elif "Port" + suffix in data:
                            # assume tcp and c2--use per scriptname
                            # customization if this doesn't hold
                            reporter.add_metadata("c2_socketaddress", [
                                data[field], data['Port' + suffix], "tcp"])
                        else:
                            reporter.add_metadata("c2_address", data[field])
                    else:
                        reporter.add_metadata('c2_address', data[field])


def map_networkgroup_nonc2_fields(data, reporter):
    map_ta_fields(data, reporter, NONC2_URL_FIELD_LIST, 'url')


def map_network_fields(data, reporter):
    map_networkgroup_nonc2_fields(data, reporter)


def map_ftp_fields(data, reporter):
    SPECIAL_HANDLING_PAIRS = {'FTP Address': 'FTP Port'}
    for host, port in iteritems(SPECIAL_HANDLING_PAIRS):
        ftpdirectory = ''
        if 'FTP Directory' in data:
            ftpdirectory = data['FTP Directory']
        mwcpkey = ''
        if host in data:
            ftpinfo = "ftp://" + data[host]
            mwcpkey = 'c2_url'
        if port in data:
            if mwcpkey:
                ftpinfo += ':' + data[port]
            else:
                ftpinfo = [data[port], 'tcp']
                mwcpkey = 'port'
        if ftpdirectory:
            if mwcpkey == 'c2_url':
                ftpinfo += '/' + ftpdirectory
                reporter.add_metadata(mwcpkey, ftpinfo)
            elif mwcpkey:
                reporter.add_metadata(mwcpkey, ftpinfo)
                reporter.add_metadata('directory', ftpdirectory)
            else:
                reporter.add_metadata('directory', ftpdirectory)
        elif mwcpkey:
            reporter.add_metadata(mwcpkey, ftpinfo)

    for address, port in iteritems(FTP_FIELD_PAIRS):
        if address in data:
            if port in data:
                reporter.add_metadata(
                    "c2_url", "ftp://" + data[address] + "/" + data[port])
            else:
                reporter.add_metadata("c2_url", "ftp://" + data[address])

def map_version_fields(data, reporter):
    map_ta_fields(data, reporter, VERSION_FIELD_LIST, 'version')


def map_mutex_fields(data, reporter):
    SPECIAL_HANDLING = 'Mutex'
    for mutex_key in MUTEX_FIELD_LIST:
        if mutex_key in data:
            if mutex_key != SPECIAL_HANDLING:
                reporter.add_metadata('mutex', data[mutex_key])
            else:
                if data[mutex_key] != 'false' and data[mutex_key] != 'true':
                    reporter.add_metadata('mutex', data[mutex_key])


def map_missionid_fields(data, reporter):
    map_ta_fields(data, reporter, MISSIONID_FIELD_LIST, 'missionid')


def map_injectionprocess_fields(data, reporter):
    map_ta_fields(data, reporter, INJECTIONPROCESS_FIELD_LIST,
                  'injectionprocess')


def map_filepath_fields(scriptname, data, reporter):
    IGNORE_SCRIPT_LIST = ['Pandora', 'Punisher']
    for pname, fname in iteritems(FILEPATH_CONCATENATE_PAIR_LIST):
        if scriptname not in IGNORE_SCRIPT_LIST:
            if pname in data:
                if fname in data:
                    reporter.add_metadata(
                        "filepath", data[pname].rstrip("\\") + "\\" + data[fname])
                else:
                    reporter.add_metadata('directory', data[pname])
            elif fname in data:
                reporter.add_metadata('filename', data[fname])
        else:
            if pname in data:
                reporter.add_metadata('directory', data[pname])
            if fname in data:
                reporter.add_metadata('filename', data[fname])


def map_directory_fields(data, reporter):
    map_ta_fields(data, reporter, DIRECTORY_FIELD_LIST, 'directory')


def map_username_password_fields(data, reporter):
    for username, password in zip(USERNAME_FIELD_LIST, PASSWORD_FIELD_LIST):
        if username in data and password in data:
            reporter.add_metadata(
                'credential', [data[username], data[password]])
        elif password in data:
            reporter.add_metadata('password', data[password])
        elif username in data:
            reporter.add_metadata('username', data[username])

    map_ta_fields(data, reporter, PASSWORD_ONLY_FIELD_LIST, 'password')


def map_interval_fields(data, reporter):
    map_ta_fields(data, reporter, INTERVAL_FIELD_LIST, 'interval')


def check_for_backslashes(ta_key, mwcp_key, data, reporter):
    IGNORE_FIELD_LIST = ['localhost', 'localhost*']
    if '\\' in data[ta_key]:
        reporter.add_metadata(mwcp_key, data[ta_key])
    elif '.' not in data[ta_key] and data[ta_key] not in IGNORE_FIELD_LIST:
        reporter.add_metadata(mwcp_key, data[ta_key])


def map_registrypath_fields(data, reporter):
    SPECIAL_HANDLING = 'Domain'
    for ta_key in REGISTRYPATH_FIELD_LIST:
        if ta_key in data:
            if ta_key == SPECIAL_HANDLING:
                check_for_backslashes(ta_key, 'registrypath', data, reporter)
            else:
                reporter.add_metadata('registrypath', data[ta_key])


def map_filename_fields(data, reporter):
    map_ta_fields(data, reporter, FILENAME_FIELD_LIST, 'filename')


def map_key_fields(data, reporter):
    if "EncryptionKey" in data:
        reporter.add_metadata("key", data["EncryptionKey"])


def map_ta_jar_fields(data, reporter):
    """This routine is for the unrecom family"""
    jarinfo = ''
    mwcpkey = ''
    if 'jarfoldername' in data:
        jarinfo = data['jarfoldername']
        mwcpkey = 'directory'
    if 'jarname' in data:
        # if a directory is added put in the \\
        if jarinfo:
            jarinfo += '\\' + data['jarname']
            mwcpkey = 'filepath'
        else:
            mwcpkey = 'filename'
            jarinfo = data['jarname']
        if 'extensionname' in data:
            jarinfo += '.' + data['extensionname']
    reporter.add_metadata(mwcpkey, jarinfo)


def map_ta_to_mwcp_keys(scriptname, data, reporter):
    """
    Updates to field mapping code belongs below here

    scriptname can be use to make per decoder customizations
    """
    map_ta_domain_fields(data, reporter)
    map_domainX_fields(data, reporter)
    map_key_fields(data, reporter)
    map_ftp_fields(data, reporter)
    map_network_fields(data, reporter)
    map_version_fields(data, reporter)
    map_mutex_fields(data, reporter)
    map_missionid_fields(data, reporter)
    map_injectionprocess_fields(data, reporter)
    map_filepath_fields(scriptname, data, reporter)
    map_directory_fields(data, reporter)
    map_username_password_fields(data, reporter)
    map_registrypath_fields(data, reporter)
    map_interval_fields(data, reporter)
    map_filename_fields(data, reporter)
    map_network_fields(data, reporter)
    map_directory_fields(data, reporter)
    """
        The following field mappings only apply to the script unrecom
    """
    if scriptname == 'unrecom':
        map_ta_jar_fields(data, reporter)


def run_decoder(reporter, script, scriptname=""):
    """
    Run a RATdecoder and report output

    reporter: DC3-MWCP reporter object
    script: path of script to execute
    scriptname: This is the name of the decoder script, which is used for decoder specific logic.
                It defaults to the basename of the script with the .py removed

    """
    if not scriptname:
        scriptname = os.path.basename(script)[:-3]

    tempdir = reporter.managed_tempdir()
    outputfile = os.path.join(tempdir, "techanarchy_output")

    if reporter.interpreter_path():
        command = [reporter.interpreter_path(), script,
                   reporter.filename(), outputfile]
    else:
        command = [script, reporter.filename(), outputfile]

    reporter.debug("Running %s using %s" % (scriptname, " ".join(command)))

    popen_object = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = popen_object.communicate(None)

    termhandle = BytesIO(stdout)
    for line in termhandle:
        reporter.debug(line.rstrip())

    termhandle = BytesIO(stderr)
    for line in termhandle:
        reporter.debug(line.rstrip())

    if popen_object.returncode != 0:
        reporter.debug("Error running script. Return code: %i" %
                       popen_object.returncode)

    configlist = []
    try:
        with open(outputfile, "rb") as f:
            configlist = [line.rstrip("\n\r") for line in f]
    except Exception as e:
        reporter.debug("Error reading script output file: %s" % str(e))

    output_re = re.compile(TECHANARCHY_OUTPUT_RE)
    output_data = {}

    for item in configlist:
        match = output_re.search(item)
        if match:
            key = match.group(1)
            value = match.group(2)
            reporter.add_metadata("other", {key: value})
            if value:
                if key in output_data:
                    reporter.debug("collision on output key: %s" % key)
                output_data[key] = value
        else:
            reporter.debug("Could not parse output item: %s" % item)

    data = output_data

    map_ta_to_mwcp_keys(scriptname, data, reporter)


def main():
    if len(sys.argv) < 2:
        print("usage: techanarchy_bridge.py NAME ")
        print("NAME should be decoder basename without .py extension.")
        print(
            "when run as a script from the 'parsers' directory, makes an "
            "DC3-MWCP parser for the specified malware family")
        exit(1)

    scriptname = sys.argv[1]

    output = SCRIPT_CREATION_STRING % (
        scriptname, TECHANARCHY_DIRECTORY, scriptname)

    with open(scriptname + "_TA_malwareconfigparser.py", "w") as f:
        f.write(output)


if __name__ == '__main__':
    main()
