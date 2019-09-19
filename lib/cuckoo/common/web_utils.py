import os
import sys
import json
import magic
import logging
import hashlib
import requests

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))
sys.path.append(CUCKOO_ROOT)

from django.shortcuts import redirect, render
from django.http import HttpResponse

hashes = {
    32: hashlib.md5,
    40: hashlib.sha1,
    64: hashlib.sha256,
    128: hashlib.sha512,
}

log = logging.getLogger(__name__)


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


def get_file_content(paths):
    content = False
    for path in paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                content = f.read()
            break
    return content


def get_magic_type(data):
    try:
        if os.path.exists(data):
            return magic.from_file(data)
        else:
            return magic.from_buffer(data)
    except Exception as e:
        print(e)

    return False


def download_file(api, content, request, db, task_ids, url, params, headers, service, filename, package, timeout, options, priority, machine, gateway, clock, custom, memory, enforce_timeout, referrer, tags, orig_options, task_gateways, task_machines, static, fhash=False):
    onesuccess = False
    if not content:
        try:
            r = requests.get(url, params=params, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(e)
            if api:
                return "error", jsonize({"error": "Provided hash not found on {}".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error":  "Provided hash not found on {}".format(service)})

        if r.status_code == 200 and r.content != "Hash Not Present" and "The request requires higher privileges than provided by the access token" not in r.content:
            content = r.content
        elif r.status_code == 403:
            if api:
                return "error", jsonize({"error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(service)})
        else:
            if api:
                return "error", jsonize({"error": "Was impossible to download from {0}".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error": "Was impossible to download from {0}".format(service)})

    if not content:
        if api:
            return "error", jsonize({"error": "Error downloading file from {}".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Error downloading file from {}".format(service)})

    try:
        if fhash:
            retrieved_hash = hashes[len(fhash)](content).hexdigest()
            if retrieved_hash != fhash.lower():
                if api:
                    return "error", jsonize({"error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(fhash, retrieved_hash)}, response=True)
                else:
                    return "error", render(request, "error.html", {"error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(fhash, retrieved_hash)})

        f = open(filename, 'wb')
        f.write(content)
        f. close()
    except:
        if api:
            return "error", jsonize({"error": "Error writing {} download file to temporary path".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Error writing {} download file to temporary path".format(service)})

    onesuccess = True
    if filename:
        if disable_x64 is True:
            magic_type = get_magic_type(filename)
            if magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
                if len(request.FILES) == 1:
                    return "error", render(request, "error.html",
                            {"error": "Sorry no x64 support yet"})

    for entry in task_machines:
        task_ids_new = db.demux_sample_and_add_to_db(file_path=filename, package=package, timeout=timeout, options=options, priority=priority,
                                                        machine=entry, custom=custom, memory=memory, enforce_timeout=enforce_timeout, tags=tags, clock=clock, static=static)
        if isinstance(task_ids, list):
            task_ids.extend(task_ids_new)

    if not onesuccess:
        if api:
            return "error", jsonize({"error": "Provided hash not found on {}".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Provided hash not found on {}".format(service)})
    return "ok", task_ids
