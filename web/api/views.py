import json
import os
import socket
import sys
import tarfile
from datetime import datetime, timedelta
import random
import tempfile
import requests

from django.conf import settings
from wsgiref.util import FileWrapper
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import render
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from ratelimit.decorators import ratelimit
from StringIO import StringIO
from bson.objectid import ObjectId
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.utils import store_temp_file, delete_folder
from lib.cuckoo.common.utils import convert_to_printable, validate_referrer
from lib.cuckoo.core.database import Database, Task
from lib.cuckoo.core.database import TASK_REPORTED

# Config variables
apiconf = Config("api")
limiter = apiconf.api.get("ratelimit")
repconf = Config("reporting")

if repconf.mongodb.enabled:
    import pymongo
    results_db = pymongo.MongoClient(
                     settings.MONGO_HOST,
                     settings.MONGO_PORT
                 )[settings.MONGO_DB]

es_as_db = False
if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch
    es_as_db = True
    baseidx = repconf.elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(
         hosts = [{
             "host": repconf.elasticsearchdb.host,
             "port": repconf.elasticsearchdb.port,
         }],
         timeout = 60
     )

db = Database()

# Default rate limit variables
rateblock = False
raterps = None
raterpm = None

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition
    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def update_options(gw, orig_options):
    options = orig_options
    if gw:
        if orig_options:
            options = orig_options + ",setgw=%s" % (gw)
        else:
            options = "setgw=%s" % (gw)
        if settings.GATEWAYS_IP_MAP.has_key(gw) and settings.GATEWAYS_IP_MAP[gw]:
            options += ",gwname=%s" % (settings.GATEWAYS_IP_MAP[gw])

    return options

# Same jsonize function from api.py except we can now return Django
# HttpResponse objects as well. (Shortcut to return errors)
def jsonize(data, response=False):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data or HttpResponse object with json data
    """
    if response:
        jdata = json.dumps(data, sort_keys=False, indent=4)
        return HttpResponse(jdata,
                            content_type="application/json; charset=UTF-8")
    else:
        return json.dumps(data, sort_keys=False, indent=4)

# Chunked file reading. Useful for large files like memory dumps.
def validate_task(tid):
    task = db.view_task(tid)
    if not task:
        resp = {"error": True,
                "error_value": "Task does not exist"}
        return resp

    if task.status != TASK_REPORTED:
        resp = {"error": True,
                "error_value": "Task is still being analyzed"}
        return resp

    return {"error": False}

def createProcessTreeNode(process):
    """Creates a single ProcessTreeNode corresponding to a single node in the tree observed cuckoo.
    @param process: process from cuckoo dict.
    """
    process_node_dict = {"pid" : process["pid"],
                         "name" : process["name"],
                         "spawned_processes" : [createProcessTreeNode(child_process) for child_process in process["children"]]
                        }
    return process_node_dict

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    conf = apiconf.get_config()
    parsed = {}
    # Parse out the config for the API
    for section in conf:
        if section not in parsed:
            parsed[section] = {}
        for option in conf[section]:
            if option == "__name__":
                pass
            else:
                cfgvalue = conf[section][option]
                if cfgvalue == "yes":
                    newvalue = True
                elif cfgvalue == "no":
                    newvalue = False
                else:
                    newvalue = cfgvalue
                if option not in parsed[section]:
                    parsed[section][option] = newvalue

    # Fill in any blanks to normalize the API config Dict
    for key in parsed:
        if key == "api":
            pass
        else:
            if "rps" not in parsed[key].keys():
                parsed[key]["rps"] = "None"
            if "rpm" not in parsed[key].keys():
                parsed[key]["rpm"] = "None"
            # Set rates to None if the API is disabled
            if not parsed[key]["enabled"]:
                parsed[key]["rps"] = "None"
                parsed[key]["rpm"] = "None"

    return render(request, "api/index.html",
                             {"config": parsed})

# Queue up a file for analysis
if apiconf.filecreate.get("enabled"):
    raterps = apiconf.filecreate.get("rps", None)
    raterpm = apiconf.filecreate.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
@csrf_exempt
def tasks_create_file(request):
    resp = {}
    if request.method == "POST":
        # Check if this API function is enabled
        if not apiconf.filecreate.get("enabled"):
            resp = {"error": True,
                    "error_value": "File Create API is Disabled"}
            return jsonize(resp, response=True)
        # Check if files are actually provided
        if request.FILES.getlist("file") == []:
            resp = {"error": True, "error_value": "No file was submitted"}
            return jsonize(resp, response=True)
        resp["error"] = False
        # Parse potential POST options (see submission/views.py)
        quarantine = request.POST.get("quarantine", "")
        pcap = request.POST.get("pcap", "")
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        priority = force_int(request.POST.get("priority"))
        options = request.POST.get("options", "")
        machine = request.POST.get("machine", "")
        platform = request.POST.get("platform", "")
        tags = request.POST.get("tags", None)
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        clock = request.POST.get("clock", None)
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        gateway = request.POST.get("gateway",None)
        shrike_url = request.POST.get("shrike_url", None)
        shrike_msg = request.POST.get("shrike_msg", None)
        shrike_sid = request.POST.get("shrike_sid", None)
        shrike_refer = request.POST.get("shrike_refer", None)

        task_ids = []
        task_machines = []
        vm_list = []
        for vm in db.list_machines():
            vm_list.append(vm.label)

        if machine.lower() == "all":
            if not apiconf.filecreate.get("allmachines"):
                resp = {"error": True,
                        "error_value": "Machine=all is disabled using the API"}
                return jsonize(resp, response=True)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            # Error if its not
            else:
                resp = {"error": True,
                        "error_value": ("Machine '{0}' does not exist. "
                                        "Available: {1}".format(machine,
                                        ", ".join(vm_list)))}
                return jsonize(resp, response=True)
        # Parse a max file size to be uploaded
        max_file_size = apiconf.filecreate.get("upload_limit")
        if not max_file_size or int(max_file_size) == 0:
            max_file_size = 5 * 1048576
        else:
            max_file_size = int(max_file_size) * 1048576

        if gateway and gateway in settings.GATEWAYS:
            if "," in settings.GATEWAYS[gateway]:
                tgateway = random.choice(settings.GATEWAYS[gateway].split(","))
                ngateway = settings.GATEWAYS[tgateway]
            else:
                ngateway = settings.GATEWAYS[gateway]
            if options:
                options += ","
            options += "setgw=%s" % (ngateway)

        # Check if we are allowing multiple file submissions
        multifile = apiconf.filecreate.get("multifile")
        if multifile:
            # Handle all files
            for sample in request.FILES.getlist("file"):
                if sample.size == 0:
                    resp = {"error": True,
                            "error_value": "You submitted an empty file"}
                    return jsonize(resp, response=True)
                if sample.size > max_file_size:
                    resp = {"error": True,
                            "error_value": "File size exceeds API limit"}
                    return jsonize(resp, response=True)

                
                tmp_path = store_temp_file(sample.read(), sample.name)
                if pcap:
                    if sample.name.lower().endswith(".saz"):
                        saz = saz_to_pcap(tmp_path)
                        if saz:
                            try:
                                os.remove(tmp_path)
                            except:
                                pass
                            path = saz  
                        else:
                             resp = {"error": True,
                                     "error_value": "Failed to convert SAZ to PCAP"}
                             return jsonize(resp, response=True)
                    else:
                        path = tmp_path
                    task_id = db.add_pcap(file_path=path)
                    task_ids.append(task_id)
                    continue 
            
                if quarantine:
                    path = unquarantine(tmp_path)
                    try:
                        os.remove(tmp_path)
                    except:
                        pass

                else:
                    path = tmp_path

                for entry in task_machines:
                    try:
                        task_ids_new = db.demux_sample_and_add_to_db(file_path=path,
                                          package=package,
                                          timeout=timeout,
                                          priority=priority,
                                          options=options,
                                          machine=entry,
                                          platform=platform,
                                          tags=tags,
                                          custom=custom,
                                          memory=memory,
                                          enforce_timeout=enforce_timeout,
                                          clock=clock,
                                          shrike_url=shrike_url,
                                          shrike_msg=shrike_msg,
                                          shrike_sid=shrike_sid,
                                          shrike_refer=shrike_refer
                                          )
                    except CuckooDemuxError as e:
                        resp = {"error": True,
                                "error_value": e}
                        return jsonize(resp, response=True)

                    if task_ids_new:
                        task_ids.extend(task_ids_new)
        else:
            # Grab the first file
            sample = request.FILES.getlist("file")[0]
            if sample.size == 0:
                resp = {"error": True,
                        "error_value": "You submitted an empty file"}
                return jsonize(resp, response=True)
            if sample.size > max_file_size:
                resp = {"error": True,
                        "error_value": "File size exceeds API limit"}
                return jsonize(resp, response=True)
            if len(request.FILES.getlist("file")) > 1:
                resp["warning"] = ("Multi-file API submissions disabled - "
                                   "Accepting first file")
            tmp_path = store_temp_file(sample.read(), sample.name)
            if pcap:
                if sample.name.lower().endswith(".saz"):
                    saz = saz_to_pcap(tmp_path)
                    if saz:
                        path = saz
                        try:
                            os.remove(tmp_path)
                        except:
                            pass
                    else:
                        resp = {"error": True,
                                "error_value": "Failed to convert PCAP to SAZ"}
                        return jsonize(resp, response=True)
                else:
                    path = tmp_path
                task_id = db.add_pcap(file_path=path)
                task_ids.append(task_id)

            if quarantine:
                path = unquarantine(tmp_path)
                try:
                    os.remove(tmp_path)
                except:
                    pass
            else:
                path = tmp_path

            for entry in task_machines:
                if not pcap:
                    task_ids_new = db.demux_sample_and_add_to_db(file_path=path,
                                          package=package,
                                          timeout=timeout,
                                          priority=priority,
                                          options=options,
                                          machine=entry,
                                          platform=platform,
                                          tags=tags,
                                          custom=custom,
                                          memory=memory,
                                          enforce_timeout=enforce_timeout,
                                          clock=clock,
                                          shrike_url=shrike_url,
                                          shrike_msg=shrike_msg,
                                          shrike_sid=shrike_sid,
                                          shrike_refer=shrike_refer
                                          )
                    if task_ids_new:
                        task_ids.extend(task_ids_new)

        if len(task_ids) > 0:
            resp["data"] = {}
            resp["data"]["task_ids"] = task_ids
            callback = apiconf.filecreate.get("status")
            if len(task_ids) == 1:
                resp["data"]["message"] = "Task ID {0} has been submitted".format(
                               str(task_ids[0]))
                if callback:
                    resp["url"] = ["{0}/submit/status/{1}/".format(
                                  apiconf.api.get("url"), task_ids[0])]
            else:
                resp["data"] = {}
                resp["data"]["task_ids"] = task_ids
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(
                               ", ".join(str(x) for x in task_ids))
                if callback:
                    resp["url"] = list()
                    for tid in task_ids:
                        resp["url"].append("{0}/submit/status/{1}".format(
                                           apiconf.api.get("url"), tid))
        else:
            resp = {"error": True,
                    "error_value": "Error adding task to database"}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return jsonize(resp, response=True)

if apiconf.urlcreate.get("enabled"):
    raterps = apiconf.urlcreate.get("rps", None)
    raterpm = apiconf.urlcreate.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
@csrf_exempt
def tasks_create_url(request):
    resp = {}
    if request.method == "POST":
        if not apiconf.urlcreate.get("enabled"):
            resp = {"error": True, "error_value": "URL Create API is Disabled"}
            return jsonize(resp, response=True)

        resp["error"] = False
        url = request.POST.get("url", None)
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        priority = force_int(request.POST.get("priority"))
        options = request.POST.get("options", "")
        machine = request.POST.get("machine", "")
        platform = request.POST.get("platform", "")
        tags = request.POST.get("tags", None)
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        clock = request.POST.get("clock", None)
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        gateway = request.POST.get("gateway",None)
        referrer = validate_referrer(request.POST.get("referrer",None))
        shrike_url = request.POST.get("shrike_url", None)
        shrike_msg = request.POST.get("shrike_msg", None)
        shrike_sid = request.POST.get("shrike_sid", None)
        shrike_refer = request.POST.get("shrike_refer", None)

        task_ids = []
        task_machines = []
        vm_list = []
        task_gateways = []
        for vm in db.list_machines():
            vm_list.append(vm.label)

        if not url:
            resp = {"error": True, "error_value": "URL value is empty"}
            return jsonize(resp, response=True)

        if machine.lower() == "all":
            if not apiconf.filecreate.get("allmachines"):
                resp = {"error": True,
                        "error_value": "Machine=all is disabled using the API"}
                return jsonize(resp, response=True)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            # Error if its not
            else:
                resp = {"error": True,
                        "error_value": ("Machine '{0}' does not exist. "
                                        "Available: {1}".format(machine,
                                        ", ".join(vm_list)))}
                return jsonize(resp, response=True)

        if referrer:
            if options:
                options += ","
            options += "referrer=%s" % (referrer)

        orig_options = options

        if gateway and gateway.lower() == "all":
            for e in settings.GATEWAYS:
                if ipaddy_re.match(settings.GATEWAYS[e]):
                    task_gateways.append(settings.GATEWAYS[e])
        elif gateway and gateway in settings.GATEWAYS:
            if "," in settings.GATEWAYS[gateway]:
                if request.POST.get("all_gw_in_group"):
                    tgateway = settings.GATEWAYS[gateway].split(",")
                    for e in tgateway:
                        task_gateways.append(settings.GATEWAYS[e]) 
                else:
                    tgateway = random.choice(settings.GATEWAYS[gateway].split(","))
                    task_gateways.append(settings.GATEWAYS[tgateway])
            else:
                task_gateways.append(settings.GATEWAYS[gateway])

        if not task_gateways:
            # To reduce to the default case
            task_gateways = [None]

        for gw in task_gateways:
            options = update_options(gw, orig_options)

            for entry in task_machines:
                task_id = db.add_url(url=url,
                             package=package,
                             timeout=timeout,
                             priority=priority,
                             options=options,
                             machine=entry,
                             platform=platform,
                             tags=tags,
                             custom=custom,
                             memory=memory,
                             enforce_timeout=enforce_timeout,
                             clock=clock,
                             shrike_url=shrike_url,
                             shrike_msg=shrike_msg,
                             shrike_sid=shrike_sid,
                             shrike_refer=shrike_refer
                             )
                if task_id:
                    task_ids.append(task_id)
                 
        if len(task_ids):
            resp["data"] = {}
            resp["data"]["task_ids"] = task_ids
            resp["data"]["message"] = "Task ID {0} has been submitted".format(
                           str(task_ids[0]))
            if apiconf.urlcreate.get("status"):
                resp["url"] = ["{0}/submit/status/{1}".format(
                              apiconf.api.get("url"), task_ids[0])]
        else:
            resp = {"error": True,
                    "error_value": "Error adding task to database"}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return jsonize(resp, response=True)

# Download a file from VT for analysis
if apiconf.vtdl.get("enabled"):
    raterps = apiconf.vtdl.get("rps", None)
    raterpm = apiconf.vtdl.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
@csrf_exempt
def tasks_vtdl(request):
    resp = {}
    if request.method == "POST":
        # Check if this API function is enabled
        if not apiconf.vtdl.get("enabled"):
            resp = {"error": True,
                    "error_value": "VTDL Create API is Disabled"}
            return jsonize(resp, response=True)
        
        vtdl = request.POST.get("vtdl".strip(),None)
        resp["error"] = False
        # Parse potential POST options (see submission/views.py)
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        priority = force_int(request.POST.get("priority"))
        options = request.POST.get("options", "")
        machine = request.POST.get("machine", "")
        platform = request.POST.get("platform", "")
        tags = request.POST.get("tags", None)
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        clock = request.POST.get("clock", None)

        task_machines = []
        vm_list = []
        task_ids = []

        for vm in db.list_machines():
            vm_list.append(vm.label)

        if machine.lower() == "all":
            if not apiconf.filecreate.get("allmachines"):
                resp = {"error": True,
                        "error_value": "Machine=all is disabled using the API"}
                return jsonize(resp, response=True)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            # Error if its not
            else:
                resp = {"error": True,
                        "error_value": ("Machine '{0}' does not exist. "
                                        "Available: {1}".format(machine,
                                        ", ".join(vm_list)))}
                return jsonize(resp, response=True)
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        shrike_url = request.POST.get("shrike_url", None)
        shrike_msg = request.POST.get("shrike_msg", None)
        shrike_sid = request.POST.get("shrike_sid", None)
        shrike_refer = request.POST.get("shrike_refer", None)
        gateway = request.POST.get("gateway",None)

        if not vtdl:
            resp = {"error": True, "error_value": "vtdl (hash list) value is empty"}
            return jsonize(resp, response=True)

        if (not settings.VTDL_PRIV_KEY and not settings.VTDL_INTEL_KEY) or not settings.VTDL_PATH:
            resp = {"error": True, "error_value": "You specified VirusTotal but must edit the file and specify your VTDL_PRIV_KEY or VTDL_INTEL_KEY variable and VTDL_PATH base directory"}
            return jsonize(resp, response=True)
        else:
            base_dir = tempfile.mkdtemp(prefix='cuckoovtdl',dir=settings.VTDL_PATH)
            hashlist = []
            if "," in vtdl:
                hashlist=vtdl.split(",")
            else:
                hashlist.append(vtdl)
            onesuccess = False

            for h in hashlist:
                filename = base_dir + "/" + h
                if settings.VTDL_PRIV_KEY:
                    url = 'https://www.virustotal.com/vtapi/v2/file/download'
                    params = {'apikey': settings.VTDL_PRIV_KEY, 'hash': h}
                else:
                    url = 'https://www.virustotal.com/intelligence/download/'
                    params = {'apikey': settings.VTDL_INTEL_KEY, 'hash': h}
                try:
                    r = requests.get(url, params=params, verify=True)
                except requests.exceptions.RequestException as e:
                    resp = {"error": True, "error_value": "Error completing connection to VirusTotal: {0}".format(e)}
                    return jsonize(resp, response=True)
                if r.status_code == 200:
                    try:
                        f = open(filename, 'wb')
                        f.write(r.content)
                        f.close()
                    except:
                        resp = {"error": True, "error_value": "Error writing VirusTotal download file to temporary path"}
                        return jsonize(resp, response=True)

                    onesuccess = True

                    for entry in task_machines:
                        task_ids_new = db.demux_sample_and_add_to_db(file_path=filename, package=package, timeout=timeout, options=options, priority=priority,
                                                                     machine=entry, custom=custom, memory=memory, enforce_timeout=enforce_timeout, tags=tags, clock=clock,
                                                                     shrike_url=shrike_url, shrike_msg=shrike_msg, shrike_sid=shrike_sid, shrike_refer=shrike_refer)
                        task_ids.extend(task_ids_new)
                elif r.status_code == 403:
                    resp = {"error": True, "error_value": "API key provided is not a valid VirusTotal key or is not authorized for VirusTotal downloads"}
                    return jsonize(resp, response=True)

            if not onesuccess:
                resp = {"error": True, "error_value": "Provided hash(s) not found on VirusTotal {0}".format(hashlist)}
                return jsonize(resp, response=True)
         
        if len(task_ids) > 0:
            resp["data"] = {}
            resp["data"]["task_ids"] = task_ids
            callback = apiconf.filecreate.get("status")
            if len(task_ids) == 1:
                resp["data"]["message"] = "Task ID {0} has been submitted".format(
                               str(task_ids[0]))
                if callback:
                    resp["url"] = ["{0}/submit/status/{1}/".format(
                                  apiconf.api.get("url"), task_ids[0])]
            else:
                resp["data"]["task_ids"] = task_ids
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(
                               ", ".join(str(x) for x in task_ids))
                if callback:
                    resp["url"] = list()
                    for tid in task_ids:
                        resp["url"].append("{0}/submit/status/{1}".format(
                                           apiconf.api.get("url"), tid))
        else:
            resp = {"error": True,
                    "error_value": "Error adding task to database"}

    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return jsonize(resp, response=True)

# Return Sample information.
if apiconf.fileview.get("enabled"):
    raterps = apiconf.fileview.get("rps", None)
    raterpm = apiconf.fileview.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def files_view(request, md5=None, sha1=None, sha256=None, sample_id=None):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.fileview.get("enabled"):
        resp = {"error": True,
                "error_value": "File View API is Disabled"}
        return jsonize(resp, response=True)

    resp = {}
    if md5 or sha1 or sha256 or sample_id:
        resp["error"] = False
        if md5:
            if not apiconf.fileview.get("md5"):
                resp = {"error": True,
                        "error_value": "File View by MD5 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(md5=md5)
        elif sha1:
            if not apiconf.fileview.get("sha1"):
                resp = {"error": True,
                        "error_value": "File View by SHA1 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(sha1=sha1)
        elif sha256:
            if not apiconf.fileview.get("sha256"):
                resp = {"error": True,
                        "error_value": "File View by SHA256 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(sha256=sha256)
        elif sample_id:
            if not apiconf.fileview.get("id"):
                resp = {"error": True,
                        "error_value": "File View by ID is Disabled"}
                return jsonize(resp, response=True)

            sample = db.view_sample(sample_id)
        if sample:
            resp["data"] = sample.to_dict()
        else:
            resp = {"error": True, "error_value": "Sample not found in database"}

    return jsonize(resp, response=True)

# Return Task ID's and data that match a hash.
if apiconf.tasksearch.get("enabled"):
    raterps = apiconf.tasksearch.get("rps", None)
    raterpm = apiconf.tasksearch.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_search(request, md5=None, sha1=None, sha256=None):
    resp = {}
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.tasksearch.get("enabled"):
        resp = {"error": True,
                "error_value": "Task Search API is Disabled"}
        return jsonize(resp, response=True)

    if md5 or sha1 or sha256:
        resp["error"] = False
        if md5:
            if not apiconf.tasksearch.get("md5"):
                resp = {"error": True,
                        "error_value": "Task Search by MD5 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(md5=md5)
        elif sha1:
            if not apiconf.tasksearch.get("sha1"):
                resp = {"error": True,
                        "error_value": "Task Search by SHA1 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(sha1=sha1)
        elif sha256:
            if not apiconf.tasksearch.get("sha256"):
                resp = {"error": True,
                        "error_value": "Task Search by SHA256 is Disabled"}
                return jsonize(resp, response=True)

            sample = db.find_sample(sha256=sha256)
        if sample:
            sid = sample.to_dict()["id"]
            resp["data"] = list()
            tasks = db.list_tasks(sample_id=sid)
            for task in tasks:
                buf = task.to_dict()
                # Remove path information, just grab the file name
                buf["target"] = buf["target"].split("/")[-1]
                resp["data"].append(buf)
        else:
            resp = {"data": [], "error": False}

    return jsonize(resp, response=True)

# Return Task ID's and data that match a hash.
if apiconf.extendedtasksearch.get("enabled"):
    raterps = apiconf.extendedtasksearch.get("rps", None)
    raterpm = apiconf.extendedtasksearch.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
@csrf_exempt
def ext_tasks_search(request):
    resp = {}
    if request.method != "POST":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.extendedtasksearch.get("enabled"):
        resp = {"error": True,
                "error_value": "Extended Task Search API is Disabled"}
        return jsonize(resp, response=True)

    option = request.POST.get("option", "")
    dataarg = request.POST.get("argument", "")

    if option and dataarg:
        records = ""
        if repconf.mongodb.enabled:
            if option == "name":
                records = results_db.analysis.find({"target.file.name": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "type":
                records = results_db.analysis.find({"target.file.type": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "string":
                records = results_db.analysis.find({"strings" : {"$regex" : dataarg, "$options" : "-1"}}).sort([["_id", -1]])
            elif option == "ssdeep":
                records = results_db.analysis.find({"target.file.ssdeep": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "crc32":
                records = results_db.analysis.find({"target.file.crc32": dataarg}).sort([["_id", -1]])
            elif option == "file":
                records = results_db.analysis.find({"behavior.summary.files": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "command":
                records = results_db.analysis.find({"behavior.summary.executed_commands": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "resolvedapi":
                records = results_db.analysis.find({"behavior.summary.resolved_apis": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "key":
                records = results_db.analysis.find({"behavior.summary.keys": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "mutex":
                records = results_db.analysis.find({"behavior.summary.mutexes": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "domain":
                records = results_db.analysis.find({"network.domains.domain": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "ip":
                records = results_db.analysis.find({"network.hosts.ip": dataarg}).sort([["_id", -1]])
            elif option == "signature":
                records = results_db.analysis.find({"signatures.description": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "signame":
                records = results_db.analysis.find({"signatures.name": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "malfamily":
                records = results_db.analysis.find({"malfamily": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "url":
                records = results_db.analysis.find({"target.url": dataarg}).sort([["_id", -1]])
            elif option == "iconhash":
                records = results_db.analysis.find({"static.pe.icon_hash": dataarg}).sort([["_id", -1]])
            elif option == "iconfuzzy":
                records = results_db.analysis.find({"static.pe.icon_fuzzy": dataarg}).sort([["_id", -1]])
            elif option == "imphash":
                records = results_db.analysis.find({"static.pe.imphash": dataarg}).sort([["_id", -1]])
            elif option == "surialert":
                records = results_db.analysis.find({"suricata.alerts.signature": {"$regex" : dataarg, "$options" : "-i"}}).sort([["_id", -1]])
            elif option == "surihttp":
                records = results_db.analysis.find({"suricata.http": {"$regex" : dataarg, "$options" : "-i"}}).sort([["_id", -1]])
            elif option == "suritls":
                records = results_db.analysis.find({"suricata.tls": {"$regex" : dataarg, "$options" : "-i"}}).sort([["_id", -1]])
            elif option == "clamav":
                records = results_db.analysis.find({"target.file.clamav": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "yaraname":
                records = results_db.analysis.find({"target.file.yara.name": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "procmemyara":
                records = results_db.analysis.find({"procmemory.yara.name": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "virustotal":
                records = results_db.analysis.find({"virustotal.results.sig": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "comment":
                records = results_db.analysis.find({"info.comments.Data": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
            elif option == "md5":
                records = results_db.analysis.find({"target.file.md5": dataarg}).sort([["_id", -1]])
            elif option == "sha1":
                records = results_db.analysis.find({"target.file.sha1": dataarg}).sort([["_id", -1]])
            elif option == "sha256":
                records = results_db.analysis.find({"target.file.sha256": dataarg}).sort([["_id", -1]])
            elif option == "sha512":
                records = results_db.analysis.find({"target.file.sha512": dataarg}).sort([["_id", -1]])
            else:
                resp = {"error": True,
                        "error_value": "Invalid Option. '%s' is not a valid option." % option}
                return jsonize(resp, response=True)

        if es_as_db:
            if term == "name":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.name: %s" % value)["hits"]["hits"]
            elif term == "type":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.type: %s" % value)["hits"]["hits"]
            elif term == "string":
                records = es.search(index=fullidx, doc_type="analysis", q="strings: %s" % value)["hits"]["hits"]
            elif term == "ssdeep":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.ssdeep: %s" % value)["hits"]["hits"]
            elif term == "crc32":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.crc32: %s" % value)["hits"]["hits"]
            elif term == "file":
                records = es.search(index=fullidx, doc_type="analysis", q="behavior.summary.files: %s" % value)["hits"]["hits"]
            elif term == "command":
                records = es.search(index=fullidx, doc_type="analysis", q="behavior.summary.executed_commands: %s" % value)["hits"]["hits"]
            elif term == "resolvedapi":
                records = es.search(index=fullidx, doc_type="analysis", q="behavior.summary.resolved_apis: %s" % value)["hits"]["hits"]
            elif term == "key":
                records = es.search(index=fullidx, doc_type="analysis", q="behavior.summary.keys: %s" % value)["hits"]["hits"]
            elif term == "mutex":
                records = es.search(index=fullidx, doc_type="analysis", q="behavior.summary.mutex: %s" % value)["hits"]["hits"]
            elif term == "domain":
                records = es.search(index=fullidx, doc_type="analysis", q="network.domains.domain: %s" % value)["hits"]["hits"]
            elif term == "ip":
                records = es.search(index=fullidx, doc_type="analysis", q="network.hosts.ip: %s" % value)["hits"]["hits"]
            elif term == "signature":
                records = es.search(index=fullidx, doc_type="analysis", q="signatures.description: %s" % value)["hits"]["hits"]
            elif term == "signame":
                records = es.search(index=fullidx, doc_type="analysis", q="signatures.name: %s" % value)["hits"]["hits"]
            elif term == "malfamily":
                records = es.search(index=fullidx, doc_type="analysis", q="malfamily: %s" % value)["hits"]["hits"]
            elif term == "url":
                records = es.search(index=fullidx, doc_type="analysis", q="target.url: %s" % value)["hits"]["hits"]
            elif term == "imphash":
                records = es.search(index=fullidx, doc_type="analysis", q="static.pe.imphash: %s" % value)["hits"]["hits"]
            elif term == "iconhash":
                records = es.search(index=fullidx, doc_type="analysis", q="static.pe.icon_hash: %s" % value)["hits"]["hits"]
            elif term == "iconfuzzy":
                records = es.search(index=fullidx, doc_type="analysis", q="static.pe.icon_fuzzy: %s" % value)["hits"]["hits"]
            elif term == "surialert":
                records = es.search(index=fullidx, doc_type="analysis", q="suricata.alerts.signature: %s" % value)["hits"]["hits"]
            elif term == "surihttp":
                records = es.search(index=fullidx, doc_type="analysis", q="suricata.http: %s" % value)["hits"]["hits"]
            elif term == "suritls":
                records = es.search(index=fullidx, doc_type="analysis", q="suricata.tls: %s" % value)["hits"]["hits"]
            elif term == "clamav":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.clamav: %s" % value)["hits"]["hits"]
            elif term == "yaraname":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.yara.name: %s" % value)["hits"]["hits"]
            elif term == "procmemyara":
                records = es.search(index=fullidx, doc_type="analysis", q="procmemory.yara.name: %s" % value)["hits"]["hits"]
            elif term == "virustotal":
                records = es.search(index=fullidx, doc_type="analysis", q="virustotal.results.sig: %s" % value)["hits"]["hits"]
            elif term == "comment":
                records = es.search(index=fullidx, doc_type="analysis", q="info.comments.Data: %s" % value)["hits"]["hits"]
            elif term == "md5":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.md5: %s" % value)["hits"]["hits"]
            elif term == "sha1":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.sha1: %s" % value)["hits"]["hits"]
            elif term == "sha256":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.sha256: %s" % value)["hits"]["hits"]
            elif term == "sha512":
                records = es.search(index=fullidx, doc_type="analysis", q="target.file.sha512: %s" % value)["hits"]["hits"]
            else:
                resp = {"error": True,
                        "error_value": "Invalid Option. '%s' is not a valid option." % option}
                return jsonize(resp, response=True)

        if records:
            ids = list()
            for results in records:
                if repconf.mongodb.enabled:
                    ids.append(results["info"]["id"])
                if es_as_db:
                    ids.append(results["_source"]["info"]["id"])
            resp = {"error": False, "data": ids}
        else:
            resp = {"error": True,
                    "error_value": "Unable to retrieve records"}
    else:
        if not option:
            resp = {"error": True,
                    "error_value": "No option provided."}
        if not dataarg:
            resp = {"error": True,
                    "error_value": "No argument provided."}
        if not option and not dataarg:
            resp = {"error": True,
                    "error_value": "No option or argument provided."}

    return jsonize(resp, response=True)

# Return Task ID's and data within a range of Task ID's
if apiconf.tasklist.get("enabled"):
    raterps = apiconf.tasklist.get("rps", None)
    raterpm = apiconf.tasklist.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_list(request, offset=None, limit=None, window=None):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.tasklist.get("enabled", None):
        resp = {"error": True,
                "error_value": "Task List API is Disabled"}
        return jsonize(resp, response=True)

    resp = {}
    # Limit checks
    if not limit:
        limit = int(apiconf.tasklist.get("defaultlimit"))
    if int(limit) > int(apiconf.tasklist.get("maxlimit")):
        resp = {"warning": "Task limit exceeds API configured limit."}
        limit = int(apiconf.tasklist.get("maxlimit"))

    completed_after = request.GET.get("completed_after")
    if completed_after:
        completed_after = datetime.fromtimestamp(int(completed_after))

    if not completed_after and window:
        maxwindow = apiconf.tasklist.get("maxwindow")
        if maxwindow > 0:
            if int(window) > maxwindow:
                resp = {"error": True,
                        "error_value": "The Window You Specified is greater than the configured maximum"}
                return jsonize(resp, response=True)
        completed_after = datetime.now() - timedelta(minutes=int(window))

    status = request.GET.get("status")

    if offset:
        offset = int(offset)
    resp["data"] = list()
    resp["config"] = "Limit: {0}, Offset: {1}".format(limit, offset)
    resp["buf"] = 0

    for row in db.list_tasks(limit=limit, details=True, offset=offset,
                             completed_after=completed_after,
                             status=status,
                             order_by=Task.completed_on.desc()):
        resp["buf"] += 1
        task = row.to_dict()
        task["guest"] = {}
        if row.guest:
            task["guest"] = row.guest.to_dict()

        task["errors"] = []
        for error in row.errors:
            task["errors"].append(error.message)

        task["sample"] = {}
        if row.sample_id:
            sample = db.view_sample(row.sample_id)
            task["sample"] = sample.to_dict()

        if task["target"]:
            task["target"] = convert_to_printable(task["target"])

        resp["data"].append(task)

    return jsonize(resp, response=True)

if apiconf.taskview.get("enabled"):
    raterps = apiconf.taskview.get("rps", None)
    raterpm = apiconf.taskview.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_view(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskview.get("enabled"):
        resp = {"error": True, "error_value": "Task View API is Disabled"}
        return jsonize(resp, response=True)

    resp = {}
    task = db.view_task(task_id, details=True)
    resp["error"] = False
    if task:
        entry = task.to_dict()
        entry["target"] = entry["target"].split("/")[-1]
        entry["guest"] = {}
        if task.guest:
            entry["guest"] = task.guest.to_dict()

        entry["errors"] = []
        for error in task.errors:
            entry["errors"].append(error.message)

        entry["sample"] = {}
        if task.sample_id:
            sample = db.view_sample(task.sample_id)
            entry["sample"] = sample.to_dict()

        resp["data"] = entry
    else:
        resp = {"error": True, "error_value": "Task not found in database"}

    return jsonize(resp, response=True)

if apiconf.taskresched.get("enabled"):
    raterps = apiconf.taskresched.get("rps", None)
    raterpm = apiconf.taskresched.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_reschedule(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskresched.get("enabled"):
        resp = {"error": True,
                "error_value": "Task Reschedule API is Disabled"}
        return jsonize(resp, response=True)

    if not db.view_task(task_id):
        resp = {"error": True,
                "error_value": "Task ID does not exist in the database"}
        return jsonize(resp, response=True)

    resp = {}
    if db.reschedule(task_id):
        resp["error"] = False
        resp["data"] = "Task ID {0} has been rescheduled".format(task_id)
    else:
        resp = {"error": True,
                "error_value": ("An error occured while trying to reschedule "
                                "Task ID {0}".format(task_id))}

    return jsonize(resp, response=True)

if apiconf.taskdelete.get("enabled"):
    raterps = apiconf.taskdelete.get("rps", None)
    raterpm = apiconf.taskdelete.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_delete(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskdelete.get("enabled"):
        resp = {"error": True,
                "error_value": "Task Deletion API is Disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    resp = {}
    if db.delete_task(task_id):
        resp["error"] = False
        delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                   "%s" % task_id))
        resp["data"] = "Task ID {0} has been deleted".format(task_id)
    else:
        resp = {"error": True,
                "error_value": ("An error occured when trying to delete "
                                "task {0}".format(task_id))}

    return jsonize(resp, response=True)

if apiconf.taskstatus.get("enabled"):
    raterps = apiconf.taskstatus.get("rps", None)
    raterpm = apiconf.taskstatus.get("rpm", None)
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_status(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskstatus.get("enabled"):
        resp = {"error": True,
                "error_value": "Task status API is disabled"}
        return jsonize(resp, response=True)

    status = db.view_task(task_id).to_dict()["status"]
    if not status:
        resp = {"error": True,
                "error_value": "Task does not exist"}
    else:
        resp = {"error": False,
                "data": status}

    return jsonize(resp, response=True)

if apiconf.taskreport.get("enabled"):
    raterps = apiconf.taskreport.get("rps")
    raterpm = apiconf.taskreport.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_report(request, task_id, report_format="json"):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskreport.get("enabled"):
        resp = {"error": True,
                "error_value": "Task Deletion API is Disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    resp = {}
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                          "%s" % task_id, "reports")

    # Report validity check
    if len(os.listdir(srcdir)) == 0:
        resp = {"error": True,
                "error_value": "No reports created for task %s" % task_id}

    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "metadata": "report.metadata.xml",
    }

    if report_format.lower() in formats:
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                   "%s" % task_id, "reports",
                                   formats[report_format.lower()])
        if os.path.exists(report_path):
            if report_format == "json":
                content = "application/json; charset=UTF-8"
                ext = "json"
            elif report_format.startswith("html"):
                content = "text/html"
                ext = "html"
            elif report_format == "maec" or report_format == "metadata":
                content = "text/xml"
                ext = "xml"
            elif export_format == "pdf":
                content = "application/pdf"
                ext = "pdf"
            fname = "%s_report.%s" % (task_id, ext)
            with open(report_path, "rb") as report_data:
                data = report_data.read()
            resp = HttpResponse(data, content_type=content)
            resp["Content-Length"] = str(len(data))
            resp["Content-Disposition"] = "attachment; filename=" + fname
            return resp

        else:
            resp = {"error": True,
                    "error_value": "Reports directory does not exist"}
            return jsonize(resp, response=True)

    elif report_format.lower() == "all":
        if not apiconf.taskreport.get("all"):
            resp = {"error": True,
                    "error_value": "Downloading all reports in one call is"
                    "disabled"}
            return jsonize(resp, response=True)

        fname = "%s_reports.tar.bz2" % task_id
        s = StringIO()
        tar = tarfile.open(name=fname, fileobj=s, mode="w:bz2")
        for rep in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, rep), arcname=rep)
        tar.close()
        resp = HttpResponse(s.getvalue(),
                            content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True,
                "error_value": "Invalid report format specified"}
        return jsonize(resp, response=True)

if apiconf.taskiocs.get("enabled"):
    raterps = apiconf.taskiocs.get("rps")
    raterpm = apiconf.taskiocs.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_iocs(request, task_id, detail=None):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskiocs.get("enabled"):
        resp = {"error": True,
                "error_value": "IOC download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    buf = {}
    if repconf.mongodb.get("enabled") and not buf:
        buf = results_db.analysis.find_one({"info.id": int(task_id)})
    if es_as_db and not buf:
        tmp = es.search(
                  index=fullidx,
                  doc_type="analysis",
                  q="info.id: \"%s\"" % task_id
               )["hits"]["hits"]
        if tmp:
            buf = tmp[-1]["_source"]
        else:
            buf = None
    if buf is None:
        resp = {"error": True, "error_value": "Sample not found in database"}
        return jsonize(resp, response=True)
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                             "%s" % task_id, "reports", "report.json")
        with open(jfile, "r") as jdata:
            buf = json.load(jdata)
    if not buf:
        resp = {"error": True,
                "error_value": "Unable to retrieve report to parse for IOCs"}
        return jsonize(resp, response=True)

    data = {}
    data["malfamily"] = buf["malfamily"]
    data["malscore"] = buf["malscore"]
    data["info"] = buf["info"]
    del data["info"]["custom"]
    # The machines key won't exist in cases where an x64 binary is submitted
    # when there are no x64 machines.
    if "machine" in data["info"] and data["info"]["machine"]:
        del data["info"]["machine"]["manager"]
        del data["info"]["machine"]["label"]
        del data["info"]["machine"]["id"]
    data["signatures"] = []
    # Grab sigs
    for sig in buf["signatures"]:
        del sig["alert"]
        data["signatures"].append(sig)
    # Grab target file info
    if "target" in buf.keys():
        data["target"] = buf["target"]
        if data["target"]["category"] == "file":
            del data["target"]["file"]["path"]
            del data["target"]["file"]["guest_paths"]
    data["network"] = {}
    if "network" in buf.keys():
        data["network"]["traffic"] = {}
        for netitem in ["tcp", "udp", "irc", "http", "dns", "smtp", "hosts", "domains"]:
            if netitem in buf["network"]:
                data["network"]["traffic"][netitem + "_count"] = len(buf["network"][netitem])
            else:
                data["network"]["traffic"][netitem + "_count"] = 0
        data["network"]["traffic"]["http"] = buf["network"]["http"]
        data["network"]["hosts"] = buf["network"]["hosts"]
        data["network"]["domains"] = buf["network"]["domains"]
    data["network"]["ids"] = {}
    if "suricata" in buf.keys() and isinstance(buf["suricata"], dict):
        data["network"]["ids"]["totalalerts"] = len(buf["suricata"]["alerts"])
        data["network"]["ids"]["alerts"] = buf["suricata"]["alerts"]
        data["network"]["ids"]["http"] = buf["suricata"]["http"]
        data["network"]["ids"]["totalfiles"] = len(buf["suricata"]["files"])
        data["network"]["ids"]["files"] = list()
        for surifile in buf["suricata"]["files"]:
            if "file_info" in surifile.keys():
                tmpfile = surifile
                tmpfile["sha1"] = surifile["file_info"]["sha1"]
                tmpfile["md5"] = surifile["file_info"]["md5"]
                tmpfile["sha256"] = surifile["file_info"]["sha256"]
                tmpfile["sha512"] = surifile["file_info"]["sha512"]
                del tmpfile["file_info"]
                data["network"]["ids"]["files"].append(tmpfile)
    data["static"] = {}
    if "static" in buf.keys():
        pe = {}
        pdf = {}
        office = {}
        if "peid_signatures" in buf["static"] and buf["static"]["peid_signatures"]:
            pe["peid_signatures"] = buf["static"]["peid_signatures"]
        if "pe_timestamp" in buf["static"] and buf["static"]["pe_timestamp"]:
            pe["pe_timestamp"] = buf["static"]["pe_timestamp"]
        if "pe_imphash" in buf["static"] and buf["static"]["pe_imphash"]:
            pe["pe_imphash"] = buf["static"]["pe_imphash"]
        if "pe_icon_hash" in buf["static"] and buf["static"]["pe_icon_hash"]:
            pe["pe_icon_hash"] = buf["static"]["pe_icon_hash"]
        if "pe_icon_fuzzy" in buf["static"] and buf["static"]["pe_icon_fuzzy"]:
            pe["pe_icon_fuzzy"] = buf["static"]["pe_icon_fuzzy"]
        if "Objects" in buf["static"] and buf["static"]["Objects"]:
            pdf["objects"] = len(buf["static"]["Objects"])
        if "Info" in buf["static"] and buf["static"]["Info"]:
            if "PDF Header" in buf["static"]["Info"].keys():
                pdf["header"] = buf["static"]["Info"]["PDF Header"]
        if "Streams" in buf["static"]:
            if "/Page" in buf["static"]["Streams"].keys():
                pdf["pages"] = buf["static"]["Streams"]["/Page"]
        if "Macro" in buf["static"] and buf["static"]["Macro"]:
            if "Analysis" in buf["static"]["Macro"]:
                office["signatures"] = {}
                for item in buf["static"]["Macro"]["Analysis"]:
                    office["signatures"][item] = []
                    for indicator, desc in buf["static"]["Macro"]["Analysis"][item]:
                        office["signatures"][item].append((indicator, desc))
            if "Code" in buf["static"]["Macro"]:
                office["macros"] = len(buf["static"]["Macro"]["Code"])
        data["static"]["pe"] = pe
        data["static"]["pdf"] = pdf
        data["static"]["office"] = office

    data["files"] = {}
    data["files"]["modified"] = []
    data["files"]["deleted"] = []
    data["registry"] = {}
    data["registry"]["modified"] = []
    data["registry"]["deleted"] = []
    data["mutexes"] = []
    data["executed_commands"] = []
    data["dropped"] = []

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "write_files" in buf["behavior"]["summary"]:
            data["files"]["modified"] = buf["behavior"]["summary"]["write_files"]
        if "delete_files" in buf["behavior"]["summary"]:
            data["files"]["deleted"] = buf["behavior"]["summary"]["delete_files"]
        if "write_keys" in buf["behavior"]["summary"]:
            data["registry"]["modified"] = buf["behavior"]["summary"]["write_keys"]
        if "delete_keys" in buf["behavior"]["summary"]:
            data["registry"]["deleted"] = buf["behavior"]["summary"]["delete_keys"]
        if "mutexes" in buf["behavior"]["summary"]:
            data["mutexes"] = buf["behavior"]["summary"]["mutexes"]
        if "executed_commands" in buf["behavior"]["summary"]:
            data["executed_commands"] = buf["behavior"]["summary"]["executed_commands"]

    data["process_tree"] = {}
    if "behavior" in buf and "processtree" in buf["behavior"] and len(buf["behavior"]["processtree"]) > 0:
        data["process_tree"] = {"pid" : buf["behavior"]["processtree"][0]["pid"],
                                "name" : buf["behavior"]["processtree"][0]["name"],
                                "spawned_processes": [createProcessTreeNode(child_process) for child_process in buf["behavior"]["processtree"][0]["children"]]
                                }
    if "dropped" in buf:
        for entry in buf["dropped"]:
            tmpdict = {}
            if entry["clamav"]:
                tmpdict['clamav'] = entry["clamav"]
            if entry["sha256"]:
                tmpdict['sha256'] = entry["sha256"]
            if entry["md5"]:
                tmpdict['md5'] = entry["md5"]
            if entry["yara"]:
                tmpdict['yara'] = entry["yara"]
            if entry["type"]:
                tmpdict["type"] = entry["type"]
            if entry["guest_paths"]:
                tmpdict["guest_paths"] = entry["guest_paths"]
            data["dropped"].append(tmpdict)

    if not detail:
        resp = {"error": False, "data": data}
        return jsonize(resp, response=True)

    if "static" in buf:
        if "pe_versioninfo" in buf["static"] and buf["static"]["pe_versioninfo"]:
            data["static"]["pe"]["pe_versioninfo"] = buf["static"]["pe_versioninfo"]

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "read_files" in buf["behavior"]["summary"]:
            data["files"]["read"] = buf["behavior"]["summary"]["read_files"]
        if "read_keys" in buf["behavior"]["summary"]:
            data["registry"]["read"] = buf["behavior"]["summary"]["read_keys"]

    if buf["network"] and "http" in buf["network"]:
        data["network"]["http"] = {}
        for req in buf["network"]["http"]:
            if "host" in req:
                data["network"]["http"]["host"] = req["host"]
            else:
                data["network"]["http"]["host"] = ""
            if "data" in req and "\r\n" in req["data"]:
                data["network"]["http"]["data"] = req["data"].split("\r\n")[0]
            else:
                data["network"]["http"]["data"] = ""
            if "method" in req:
                data["network"]["http"]["method"] = req["method"]
            else:
                data["network"]["http"]["method"] = ""
                if "user-agent" in req:
                    data["network"]["http"]["ua"] = req["user-agent"]
                else:
                    data["network"]["http"]["ua"] = ""

    if "strings" in buf.keys():
        data["strings"] = buf["strings"]
    else:
        data["strings"] = ["No Strings"]

    resp = {"error": False, "data": data}
    return jsonize(resp, response=True)

if apiconf.taskscreenshot.get("enabled"):
    raterps = apiconf.taskscreenshot.get("rps")
    raterpm = apiconf.taskscreenshot.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_screenshot(request, task_id, screenshot="all"):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskscreenshot.get("enabled"):
        resp = {"error": True,
                "error_value": "Screenshot download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                          "%s" % task_id, "shots")

    if len(os.listdir(srcdir)) == 0:
        resp = {"error": True,
                "error_value": "No screenshots created for task %s" % task_id}
        return jsonize(resp, response=True)

    if screenshot == "all":
        fname = "%s_screenshots.tar.bz2" % task_id
        s = StringIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for shot in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, shot), arcname=shot)
        tar.close()
        resp = HttpResponse(s.getvalue(),
                            content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        shot = srcdir + "/" + screenshot.zfill(4) + ".jpg"
        if os.path.exists(shot):
            with open(shot, "rb") as picture:
                data = picture.read()
            return HttpResponse(data, content_type="image/jpeg")

        else:
            resp = {"error": True,
                    "error_value": "Screenshot does not exist"}
            return jsonize(resp, response=True)

if apiconf.taskpcap.get("enabled"):
    raterps = apiconf.taskpcap.get("rps")
    raterpm = apiconf.taskpcap.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_pcap(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskpcap.get("enabled"):
        resp = {"error": True,
                "error_value": "PCAP download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id,
                          "dump.pcap")
    if os.path.exists(srcfile):
        with open(srcfile, "rb") as pcap:
            data = pcap.read()
        fname = "%s_dump.pcap" % task_id
        resp = HttpResponse(data, content_type="application/vnd.tcpdump.pcap")
        resp["Content-Length"] = str(len(data))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True,
                "error_value": "PCAP does not exist"}
        return jsonize(resp, response=True)

if apiconf.taskdropped.get("enabled"):
    raterps = apiconf.taskdropped.get("rps")
    raterpm = apiconf.taskdropped.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_dropped(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True,
                "error_value": "Dropped File download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                          "%s" % task_id, "files")

    if not len(os.listdir(srcdir)):
        resp = {"error": True,
                "error_value": "No files dropped for task %s" % task_id}
        return jsonize(resp, response=True)

    else:
        fname = "%s_dropped.tar.bz2" % task_id
        s = StringIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for dirfile in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, dirfile), arcname=dirfile)
        tar.close()
        resp = HttpResponse(s.getvalue(),
                            content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

if apiconf.tasksurifile.get("enabled"):
    raterps = apiconf.tasksurifile.get("rps")
    raterpm = apiconf.tasksurifile.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_surifile(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True,
                "error_value": "Suricata File download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                          "%s" % task_id, "logs", "files.zip")

    if os.path.exists(srcfile):
        with open(srcfile, "rb") as surifile:
            data = surifile.read()
        fname = "%s_surifiles.zip" % task_id
        resp = HttpResponse(data, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(data))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True,
                "error_value": "No suricata files captured for task %s" % task_id}
        return jsonize(resp, response=True)

if apiconf.rollingsuri.get("enabled"):
    raterps = apiconf.rollingsuri.get("rps")
    raterpm = apiconf.rollingsuri.get("rpm")
    rateblock = True

@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
    
def tasks_rollingsuri(request, window=60):
    window = int(window)
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.rollingsuri.get("enabled"):
        resp = {"error": True,
                "error_value": "Suricata Rolling Alerts API is disabled"}
        return jsonize(resp, response=True)
    maxwindow = apiconf.rollingsuri.get("maxwindow")
    if maxwindow > 0:
        if window > maxwindow:
            resp = {"error": True,
                    "error_value": "The Window You Specified is greater than the configured maximum"}
            return jsonize(resp, response=True)
         
    gen_time = datetime.now() - timedelta(minutes=window)
    dummy_id = ObjectId.from_datetime(gen_time)
    result = list(results_db.analysis.find({"suricata.alerts": {"$exists": True}, "_id": {"$gte": dummy_id}},{"suricata.alerts":1,"info.id":1}))
    resp=[]
    for e in result:
        for alert in e["suricata"]["alerts"]:
            alert["id"] = e["info"]["id"]
            resp.append(alert)

    return jsonize(resp, response=True)
if apiconf.rollingshrike.get("enabled"):
    raterps = apiconf.rollingshrike.get("rps")
    raterpm = apiconf.rollingshrike.get("rpm")
    rateblock = True

@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)

def tasks_rollingshrike(request, window=60, msgfilter=None):
    window = int(window)
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.rollingshrike.get("enabled"):
        resp = {"error": True,
                "error_value": "Rolling Shrike API is disabled"}
        return jsonize(resp, response=True)
    maxwindow = apiconf.rollingshrike.get("maxwindow")
    if maxwindow > 0:
        if window > maxwindow:
            resp = {"error": True,
                    "error_value": "The Window You Specified is greater than the configured maximum"}
            return jsonize(resp, response=True)

    gen_time = datetime.now() - timedelta(minutes=window)
    dummy_id = ObjectId.from_datetime(gen_time)
    if msgfilter: 
       result = results_db.analysis.find({"info.shrike_url": {"$exists": True, "$ne":None }, "_id": {"$gte": dummy_id},"info.shrike_msg": {"$regex" : msgfilter, "$options" : "-1"}},{"info.id":1,"info.shrike_msg":1,"info.shrike_sid":1,"info.shrike_url":1,"info.shrike_refer":1},sort=[("_id", pymongo.DESCENDING)])
    else:   
        result = results_db.analysis.find({"info.shrike_url": {"$exists": True, "$ne":None }, "_id": {"$gte": dummy_id}},{"info.id":1,"info.shrike_msg":1,"info.shrike_sid":1,"info.shrike_url":1,"info.shrike_refer":1},sort=[("_id", pymongo.DESCENDING)])

    resp=[]
    for e in result:
        tmp = {}
        tmp["id"] = e["info"]["id"]
        tmp["shrike_msg"] = e["info"]["shrike_msg"]
        tmp["shrike_sid"] = e["info"]["shrike_sid"]
        tmp["shrike_url"] = e["info"]["shrike_url"]
        if e["info"].has_key("shrike_refer") and e["info"]["shrike_refer"]:
            tmp["shrike_refer"]=e["info"]["shrike_refer"]
        resp.append(tmp)

    return jsonize(resp, response=True)

if apiconf.taskprocmemory.get("enabled"):
    raterps = apiconf.taskprocmemory.get("rps")
    raterpm = apiconf.taskprocmemory.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_procmemory(request, task_id, pid="all"):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskprocmemory.get("enabled"):
        resp = {"error": True,
                "error_value": "Process memory download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    # Check if any process memory dumps exist
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id,
                          "memory")
    if not os.path.exists(srcdir):
        resp = {"error": True,
                "error_value": "No memory dumps saved"}
        return jsonize(resp, response=True)

    if pid == "all":
        if not apiconf.taskprocmemory.get("all"):
            resp = {"error": True,
                    "error_value": "Downloading of all process memory dumps "
                                   "is disabled"}
            return jsonize(resp, response=True)

        fname = "%s_procdumps.tar.bz2" % task_id
        s = StringIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for memdump in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, memdump), arcname=memdump)
        tar.close()
        resp = HttpResponse(s.getvalue(),
                            content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
    else:
        srcfile = srcdir + "/" + pid + ".dmp"
        if os.path.exists(srcfile):
            if apiconf.taskprocmemory.get("compress"):
                fname = srcfile.split("/")[-1]
                s = StringIO()
                tar = tarfile.open(fileobj=s, mode="w:bz2")
                tar.add(srcfile, arcname=fname)
                tar.close()
                resp = HttpResponse(s.getvalue(),
                                    content_type="application/octet-stream;")
                archive = "%s-%s_dmp.tar.bz2" % (task_id, pid)
                resp["Content-Length"] = str(len(s.getvalue()))
                resp["Content-Disposition"] = "attachment; filename=" + archive
            else:
                mime = "application/octet-stream"
                fname = "%s-%s.dmp" % (task_id, pid)
                resp = StreamingHttpResponse(FileWrapper(open(srcfile), 8096),
                                             content_type=mime)
                # Specify content length for StreamingHTTPResponse
                resp["Content-Length"] = os.path.getsize(srcfile)
                resp["Content-Disposition"] = "attachment; filename=" + fname
        else:
            resp = {"error": True,
                    "error_value": "Process memory dump does not exist for "
                                   "pid %s" % pid}
            return jsonize(resp, response=True)

    return resp

if apiconf.taskfullmemory.get("enabled"):
    raterps = apiconf.taskfullmemory.get("rps")
    raterpm = apiconf.taskfullmemory.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def tasks_fullmemory(request, task_id):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.taskfullmemory.get("enabled"):
        resp = {"error": True,
                "error_value": "Full memory download API is disabled"}
        return jsonize(resp, response=True)

    check = validate_task(task_id)
    if check["error"]:
        return jsonize(check, response=True)

    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        chunk_size = 8192
        response = StreamingHttpResponse(FileWrapper(open(file_path), chunk_size),
                                   content_type=content_type)
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response
    else:
        resp = {"error": True,
                "error_value": "Memory dump not found for task " + task_id}
        return jsonize(resp, response=True)

if apiconf.sampledl.get("enabled"):
    raterps = apiconf.sampledl.get("rps")
    raterpm = apiconf.sampledl.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def get_files(request, stype, value):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.sampledl.get("enabled"):
        resp = {"error": True,
                "error_value": "Sample download API is disabled"}
        return jsonize(resp, response=True)

    if stype == "md5":
        file_hash = db.find_sample(md5=value).to_dict()["sha256"]
    elif stype == "sha1":
        file_hash = db.find_sample(sha1=value).to_dict()["sha256"]
    elif stype == "task":
        check = validate_task(value)
        if check["error"]:
            return jsonize(check, response=True)

        sid = db.view_task(value).to_dict()["sample_id"]
        file_hash = db.view_sample(sid).to_dict()["sha256"]
    elif stype == "sha256":
        file_hash = value
    sample = os.path.join(CUCKOO_ROOT, "storage", "binaries", file_hash)
    if os.path.exists(sample):
        mime = "application/octet-stream"
        fname = "%s.bin" % file_hash
        resp = StreamingHttpResponse(FileWrapper(open(sample), 8096),
                                     content_type=mime)
        resp["Content-Length"] = os.path.getsize(sample)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True,
                "error_value": "Sample %s was not found" % file_hash}
        return jsonize(file_hash, response=True)

if apiconf.machinelist.get("enabled"):
    raterps = apiconf.machinelist.get("rps")
    raterpm = apiconf.machinelist.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def machines_list(request):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.machinelist.get("enabled"):
        resp = {"error": True,
                "error_value": "Machine list API is disabled"}
        return jsonize(resp, response=True)

    resp = {}
    resp["data"] = []
    resp["error"] = False
    machines = db.list_machines()
    for row in machines:
        resp["data"].append(row.to_dict())
    return jsonize(resp, response=True)

if apiconf.machineview.get("enabled"):
    raterps = apiconf.machineview.get("rps")
    raterpm = apiconf.machineview.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def machines_view(request, name=None):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    if not apiconf.machineview.get("enabled"):
        resp = {"error": True,
                "error_value": "Machine view API is disabled"}
        return jsonize(resp, response=True)

    resp = {}
    machine = db.view_machine(name=name)
    if machine:
        resp["data"] = machine.to_dict()
        resp["error"] = False
    else:
        resp["error"] = True
        resp["error_value"] = "Machine not found"
    return jsonize(resp, response=True)

if apiconf.cuckoostatus.get("enabled"):
    raterps = apiconf.cuckoostatus.get("rps")
    raterpm = apiconf.cuckoostatus.get("rpm")
    rateblock = True
@ratelimit(key="ip", rate=raterps, block=rateblock)
@ratelimit(key="ip", rate=raterpm, block=rateblock)
def cuckoo_status(request):
    if request.method != "GET":
        resp = {"error": True, "error_value": "Method not allowed"}
        return jsonize(resp, response=True)

    resp = {}
    if not apiconf.cuckoostatus.get("enabled"):
        resp["error"] = True
        resp["error_value"] = "Cuckoo Status API is disabled"
    else:
        resp["error"] = False
        resp["data"] = dict(
            version=CUCKOO_VERSION,
            hostname=socket.gethostname(),
            machines=dict(
                total=len(db.list_machines()),
                available=db.count_machines_available()
            ),
            tasks=dict(
                total=db.count_tasks(),
                pending=db.count_tasks("pending"),
                running=db.count_tasks("running"),
                completed=db.count_tasks("completed"),
                reported=db.count_tasks("reported")
            ),
        )
    return jsonize(resp, response=True)

def limit_exceeded(request, exception):
    resp = {"error": True, "error_value": "Rate limit exceeded for this API"}
    return jsonize(resp, response=True)
