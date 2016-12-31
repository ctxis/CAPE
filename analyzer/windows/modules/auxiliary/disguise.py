# Copyright (C) 2010-2016 Cuckoo Foundation., KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from _winreg import (OpenKey, CreateKeyEx, SetValueEx, CloseKey, QueryInfoKey, EnumKey,
        EnumValue, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_SET_VALUE, KEY_READ,
        REG_SZ, REG_DWORD)
from random import randint

from lib.common.abstracts import Auxiliary
from lib.common.rand import random_integer, random_string

log = logging.getLogger(__name__)

class Disguise(Auxiliary):
    """Disguise the analysis environment."""

    def change_productid(self):
        """Randomizes Windows ProductId.
        The Windows ProductId is occasionally used by malware
        to detect public setups of Cuckoo, e.g., Malwr.com.
        """
        key = OpenKey(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_SET_VALUE)

        value = "{0}-{1}-{2}-{3}".format(random_integer(5), random_integer(3),
                                         random_integer(7), random_integer(5))

        SetValueEx(key, "ProductId", 0, REG_SZ, value)
        CloseKey(key)

    def set_office_mrus(self):
        """Adds randomized MRU's to Office software(s).
        Occasionally used by macros to detect sandbox environments.
        """
        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = list()
        basePaths = [
            "C:\\",
            "C:\\Windows\\Logs\\",
            "C:\\Windows\\Temp\\",
            "C:\\Program Files\\",
        ]
        extensions = {
            "Word": ["doc", "docx", "docm", "rtf"],
            "Excel": ["xls", "xlsx", "csv"],
            "PowerPoint": ["ppt", "pptx"],
        }
        try:
            officeKey = OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ)
            for currentKey in xrange(0, QueryInfoKey(officeKey)[0]):
                isVersion = True
                officeVersion = EnumKey(officeKey, currentKey)
                if "." in officeVersion:
                    for intCheck in officeVersion.split("."):
                        if not intCheck.isdigit():
                            isVersion = False
                            break

                    if isVersion:
                        installedVersions.append(officeVersion)

            CloseKey(officeKey)
        except WindowsError:
                # Office isn't installed at all
                return
        
        for oVersion in installedVersions:
            for software in extensions:
                values = list()
                mruKeyPath = ""
                productPath = r"{0}\{1}\{2}".format(baseOfficeKeyPath, oVersion, software)
                try:
                    productKey = OpenKey(HKEY_CURRENT_USER, productPath, 0, KEY_READ)
                    CloseKey(productKey)
                    mruKeyPath = r"{0}\File MRU".format(productPath)
                    try:
                        mruKey = OpenKey(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_READ)
                    except WindowsError:
                        mruKey = CreateKeyEx(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_READ)
                    displayValue = False
                    for mruKeyInfo in xrange(0, QueryInfoKey(mruKey)[1]):
                        currentValue = EnumValue(mruKey, mruKeyInfo)
                        if currentValue[0] == "Max Display":
                            displayValue = True
                        values.append(currentValue)
                    CloseKey(mruKey)
                except WindowsError:
                    # An Office version was found in the registry but the
                    # software (Word/Excel/PowerPoint) was not installed.
                    values = "notinstalled"

                if values != "notinstalled" and len(values) < 5:
                    mruKey = OpenKey(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_SET_VALUE)
                    if not displayValue:
                        SetValueEx(mruKey, "Max Display", 0, REG_DWORD, 25)

                    for i in xrange(1, randint(10, 30)):
                        rString = random_string(minimum=11, charset="0123456789ABCDEF")
                        if i % 2:
                            baseId = "T01D1C" + rString
                        else:
                            baseId = "T01D1D" + rString
                        setVal = "[F00000000][{0}][O00000000]*{1}{2}.{3}".format(
                            baseId, basePaths[randint(0, len(basePaths)-1)],
                            random_string(minimum=3, maximum=15,
                                charset="abcdefghijkLMNOPQURSTUVwxyz_0369"),
                            extensions[software][randint(0, len(extensions[software])-1)])
                        name = "Item {0}".format(i)
                        SetValueEx(mruKey, name, 0, REG_SZ, setVal)
                    CloseKey(mruKey)

    def start(self):
        self.change_productid()
        self.set_office_mrus()
        return True
