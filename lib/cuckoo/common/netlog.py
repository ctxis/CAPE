# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import struct
import datetime
import string

try:
    import bson
    HAVE_BSON = True
except ImportError:
    HAVE_BSON = False
else:
    # The BSON module provided by pymongo works through its "BSON" class.
    if hasattr(bson, "BSON"):
        bson_decode = lambda d: bson.BSON(d).decode()
    # The BSON module provided by "pip install bson" works through the
    # "loads" function (just like pickle etc.)
    elif hasattr(bson, "loads"):
        bson_decode = lambda d: bson.loads(d)
    else:
        HAVE_BSON = False

from lib.cuckoo.common.defines import REG_SZ, REG_EXPAND_SZ
from lib.cuckoo.common.defines import REG_DWORD_BIG_ENDIAN
from lib.cuckoo.common.defines import REG_DWORD_LITTLE_ENDIAN
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.logtbl import table as LOGTBL
from lib.cuckoo.common.utils import get_filename_from_path, default_converter

log = logging.getLogger(__name__)

###############################################################################
# Generic BSON based protocol - by rep
# Allows all kinds of languages / sources to generate input for Cuckoo,
# thus we can reuse report generation / signatures for other API trace sources.
###############################################################################

TYPECONVERTERS = {
    "h": lambda v: "0x%08x" % default_converter(v),
    "p": lambda v: "0x%.08x" % default_converter(v)
}

# 20 Mb max message length.
MAX_MESSAGE_LENGTH = 20 * 1024 * 1024

def check_names_for_typeinfo(arginfo):
    argnames = [i[0] if type(i) in (list, tuple) else i for i in arginfo]

    converters = []
    for i in arginfo:
        if type(i) in (list, tuple):
            r = TYPECONVERTERS.get(i[1], None)
            if not r:
                log.debug("Analyzer sent unknown format "
                          "specifier '{0}'".format(i[1]))
                r = default_converter
            converters.append(r)
        else:
            converters.append(default_converter)

    return argnames, converters


class BsonParser(object):
    def __init__(self, handler):
        self.handler = handler
        self.infomap = {}

        if not HAVE_BSON:
            log.critical("Starting BsonParser, but bson is not available! (install with `pip install bson`)")

    def close(self):
        pass

    def read_next_message(self):
        data = self.handler.read(4)
        blen = struct.unpack("I", data)[0]
        if blen > MAX_MESSAGE_LENGTH:
            log.critical("BSON message larger than MAX_MESSAGE_LENGTH, "
                         "stopping handler.")
            return False

        data += self.handler.read(blen-4)

        try:
            dec = bson_decode(data)
        except Exception as e:
            log.warning("BsonParser decoding problem {0} on "
                        "data[:50] {1}".format(e, repr(data[:50])))
            return False

        mtype = dec.get("type", "none")
        index = dec.get("I", -1)
        tid = dec.get("T", 0)
        time = dec.get("t", 0)
        caller = dec.get("R", 0)
        parentcaller = dec.get("P", 0)
        repeated = dec.get("r", 0)

        context = [index, repeated, 1, 0, tid, time, caller, parentcaller]

        if mtype == "info":
            # API call index info message, explaining the argument names, etc.
            name = dec.get("name", "NONAME")
            arginfo = dec.get("args", [])
            category = dec.get("category")

            # Bson dumps that were generated before cuckoomon exported the
            # "category" field have to get the category using the old method.
            if not category:
                # Try to find the entry/entries with this api name.
                category = [_ for _ in LOGTBL if _[0] == name]

                # If we found an entry, take its category, otherwise we take
                # the default string "unknown."
                category = category[0][1] if category else "unknown"

            argnames, converters = check_names_for_typeinfo(arginfo)
            self.infomap[index] = name, arginfo, argnames, converters, category

        elif mtype == "debug":
            log.info("Debug message from monitor: "
                     "{0}".format(dec.get("msg", "")))

        elif mtype == "new_process":
            # new_process message from VMI monitor.
            vmtime = datetime.datetime.fromtimestamp(dec.get("starttime", 0))
            procname = dec.get("name", "NONAME")
            ppid = 0
            modulepath = "DUMMY"

            self.handler.log_process(context, vmtime, None, ppid,
                                     modulepath, procname)

        else:
            # Regular api call.
            if index not in self.infomap:
                log.warning("Got API with unknown index - monitor needs "
                            "to explain first: {0}".format(dec))
                return True

            apiname, arginfo, argnames, converters, category = self.infomap[index]
            args = dec.get("args", [])

            if len(args) != len(argnames):
                log.warning("Inconsistent arg count (compared to arg names) "
                            "on {2}: {0} names {1}".format(dec, argnames,
                                                           apiname))
                return True

            argdict = dict((argnames[i], converters[i](args[i]))
                           for i in range(len(args)))

            if apiname == "__process__":
                # Special new process message from cuckoomon.
                timelow = argdict["TimeLow"] & 0xFFFFFFFF
                timehigh = argdict["TimeHigh"] & 0xFFFFFFFF
                # FILETIME is 100-nanoseconds from 1601 :/
                vmtimeunix = (timelow + (timehigh << 32))
                vmtimeunix = vmtimeunix / 10000000.0 - 11644473600
                vmtime = datetime.datetime.fromtimestamp(vmtimeunix)

                pid = argdict["ProcessIdentifier"]
                ppid = argdict["ParentProcessIdentifier"]
                modulepath = argdict["ModulePath"]
                procname = get_filename_from_path(modulepath)

                self.handler.log_process(context, vmtime, pid, ppid,
                                         modulepath, procname)
                return True

            elif apiname == "__thread__":
                pid = argdict["ProcessIdentifier"]
                self.handler.log_thread(context, pid)
                return True
            elif apiname == "__environ__":
                self.handler.log_environ(context, argdict)
                return True

            # elif apiname == "__anomaly__":
                # tid = argdict["ThreadIdentifier"]
                # subcategory = argdict["Subcategory"]
                # msg = argdict["Message"]
                # self.handler.log_anomaly(subcategory, tid, msg)
                # return True

            context[2] = argdict.pop("is_success", 1)
            context[3] = argdict.pop("retval", 0)
            arguments = argdict.items()
            arguments += dec.get("aux", {}).items()

            self.handler.log_call(context, apiname, category, arguments)

        return True
