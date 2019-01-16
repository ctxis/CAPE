# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

try:
    import re2 as re
except ImportError:
    import re

import datetime
import os
import shutil
import json
import zipfile
import tempfile
import zlib

import subprocess
from bson.binary import Binary
from bson.binary import Binary
from django.conf import settings
from wsgiref.util import FileWrapper
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from django.core.exceptions import PermissionDenied
from urllib import quote
sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, Task, TASK_PENDING
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
import modules.processing.network as network

TASK_LIMIT = 25

# Used for displaying enabled config options in Django UI
enabledconf = dict()
for cfile in ["reporting", "processing", "auxiliary"]:
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if confdata[item].has_key("enabled"):
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
            else:
                enabledconf[item] = False

if enabledconf["mongodb"]:
    import pymongo
    from bson.objectid import ObjectId
    results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

es_as_db = False
if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch
    essearch = Config("reporting").elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True
    baseidx = Config("reporting").elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(hosts = [{
             "host": settings.ELASTIC_HOST,
             "port": settings.ELASTIC_PORT,
         }],
         timeout = 60)

maxsimilar = int(Config("reporting").malheur.maxsimilar)

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition
    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


def get_analysis_info(db, id=-1, task=None):
    if not task:
        task = db.view_task(id)
    if not task:
        return None

    new = task.to_dict()
    if new["category"] in ["file", "pcap"] and new["sample_id"] != None:
        new["sample"] = db.view_sample(new["sample_id"]).to_dict()
        filename = os.path.basename(new["target"])
        new.update({"filename": filename})

    if new.has_key("machine") and new["machine"]:
        machine = new["machine"]
        machine = machine.strip('.vmx')
        machine = os.path.basename(machine)
        new.update({"machine": machine})

    if enabledconf["mongodb"]:
        rtmp = results_db.analysis.find_one(
                   {"info.id": int(new["id"])},
                   {
                       "info": 1, "virustotal_summary": 1, "cape": 1,
                       "info.custom":1, "info.shrike_msg":1, "malscore": 1, "malfamily": 1,
                       "network.pcap_sha256": 1,
                       "mlist_cnt": 1, "f_mlist_cnt": 1, "info.package": 1, "target.file.clamav": 1,
                       "suri_tls_cnt": 1, "suri_alert_cnt": 1, "suri_http_cnt": 1, "suri_file_cnt": 1,
                      "trid" : 1
                   }, sort=[("_id", pymongo.DESCENDING)]
               )

    if es_as_db:
        rtmp = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % str(new["id"])
               )["hits"]["hits"]
        if len(rtmp) > 1:
            rtmp = rtmp[-1]["_source"]
        elif len(rtmp) == 1:
            rtmp = rtmp[0]["_source"]
        else:
            pass

    if rtmp:
        if rtmp.has_key("cape"):
            new["cape"] = rtmp["cape"]
        if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
            new["virustotal_summary"] = rtmp["virustotal_summary"]
        if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
            new["mlist_cnt"] = rtmp["mlist_cnt"]
        if rtmp.has_key("f_mlist_cnt") and rtmp["f_mlist_cnt"]:
            new["f_mlist_cnt"] = rtmp["f_mlist_cnt"]
        if rtmp.has_key("info") and rtmp["info"].has_key("custom") and rtmp["info"]["custom"]:
            new["custom"] = rtmp["info"]["custom"]
        if enabledconf.has_key("display_shrike") and enabledconf["display_shrike"] and rtmp.has_key("info") and rtmp["info"].has_key("shrike_msg") and rtmp["info"]["shrike_msg"]:
            new["shrike_msg"] = rtmp["info"]["shrike_msg"]
        if rtmp.has_key("suri_tls_cnt") and rtmp["suri_tls_cnt"]:
            new["suri_tls_cnt"] = rtmp["suri_tls_cnt"]
        if rtmp.has_key("suri_alert_cnt") and rtmp["suri_alert_cnt"]:
            new["suri_alert_cnt"] = rtmp["suri_alert_cnt"]
        if rtmp.has_key("suri_file_cnt") and rtmp["suri_file_cnt"]:
            new["suri_file_cnt"] = rtmp["suri_file_cnt"]
        if rtmp.has_key("suri_http_cnt") and rtmp["suri_http_cnt"]:
            new["suri_http_cnt"] = rtmp["suri_http_cnt"]
        if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
            new["mlist_cnt"] = rtmp["mlist_cnt"]
        if rtmp.has_key("f_mlist_cnt") and rtmp["f_mlist_cnt"]:
            new["f_mlist_cnt"] = rtmp["f_mlist_cnt"]
        if rtmp.has_key("malscore"):
            new["malscore"] = rtmp["malscore"]
        if rtmp.has_key("malfamily") and rtmp["malfamily"]:
            new["malfamily"] = rtmp["malfamily"]
        if "network" in rtmp and "pcap_sha256" in rtmp["network"]:
            new["pcap_sha256"] = rtmp["network"]["pcap_sha256"]
        if rtmp.has_key("info") and rtmp["info"].has_key("custom") and rtmp["info"]["custom"]:
            new["custom"] = rtmp["info"]["custom"]
        if rtmp.has_key("info") and rtmp["info"].has_key("package") and rtmp["info"]["package"]:
            new["package"] = rtmp["info"]["package"]
        if rtmp.has_key("target") and rtmp["target"].has_key("file") and rtmp["target"]["file"].has_key("clamav"):
            new["clamav"] = rtmp["target"]["file"]["clamav"]
        if rtmp.has_key("target") and rtmp["target"].has_key("file") and rtmp["target"]["file"].has_key("trid"):
            new["trid"] = rtmp["target"]["file"]["trid"]

        if "display_shrike" in enabledconf and enabledconf["display_shrike"] and rtmp.has_key("info") and rtmp["info"].has_key("shrike_msg") and rtmp["info"]["shrike_msg"]:
            new["shrike_msg"] = rtmp["info"]["shrike_msg"]

        if settings.MOLOCH_ENABLED:
            if settings.MOLOCH_BASE[-1] != "/":
                settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
            new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')

    return new

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, page=1):
    page = int(page)
    db = Database()
    if page == 0:
        page = 1
    off = (page - 1) * TASK_LIMIT

    tasks_files = db.list_tasks(limit=TASK_LIMIT, offset=off, category="file", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=TASK_LIMIT, offset=off, category="url", not_status=TASK_PENDING)
    tasks_pcaps = db.list_tasks(limit=TASK_LIMIT, offset=off, category="pcap", not_status=TASK_PENDING)
    analyses_files = []
    analyses_urls = []
    analyses_pcaps = []

    # Vars to define when to show Next/Previous buttons
    paging = dict()
    paging["show_file_next"] = "show"
    paging["show_url_next"] = "show"
    paging["show_pcap_next"] = "show"
    paging["next_page"] = str(page + 1)
    paging["prev_page"] = str(page - 1)

    tasks_files_number = db.count_matching_tasks(category="file", not_status=TASK_PENDING)
    tasks_urls_number = db.count_matching_tasks(category="url", not_status=TASK_PENDING)
    tasks_pcaps_number = db.count_matching_tasks(category="pcap", not_status=TASK_PENDING)
    pages_files_num = tasks_files_number / TASK_LIMIT + 1
    pages_urls_num = tasks_urls_number / TASK_LIMIT + 1
    pages_pcaps_num = tasks_pcaps_number / TASK_LIMIT + 1
    files_pages = []
    urls_pages = []
    pcaps_pages = []
    if pages_files_num < 11 or page < 6:
        files_pages = range(1, min(10, pages_files_num)+1)
    elif page > 5:
        files_pages = range(min(page-5, pages_files_num-10)+1, min(page + 5, pages_files_num)+1)
    if pages_urls_num < 11 or page < 6:
        urls_pages = range(1, min(10, pages_urls_num)+1)
    elif page > 5:
        urls_pages = range(min(page-5, pages_urls_num-10)+1, min(page + 5, pages_urls_num)+1)
    if pages_pcaps_num < 11 or page < 6:
        pcaps_pages = range(1, min(10, pages_pcaps_num)+1)
    elif page > 5:
        pcaps_pages = range(min(page-5, pages_pcaps_num-10)+1, min(page + 5, pages_pcaps_num)+1)

    # On a fresh install, we need handle where there are 0 tasks.
    buf = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_file = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_file_prev"] = "show"
    else:
        paging["show_file_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_url = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_url_prev"] = "show"
    else:
        paging["show_url_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_pcap = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_pcap_prev"] = "show"
    else:
        paging["show_pcap_prev"] = "hide"

    if tasks_files:
        for task in tasks_files:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_file:
                paging["show_file_next"] = "hide"
            if page <= 1:
                paging["show_file_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_files.append(new)
    else:
        paging["show_file_next"] = "hide"

    if tasks_urls:
        for task in tasks_urls:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_url:
                paging["show_url_next"] = "hide"
            if page <= 1:
                paging["show_url_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_urls.append(new)
    else:
        paging["show_url_next"] = "hide"

    if tasks_pcaps:
        for task in tasks_pcaps:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_pcap:
                paging["show_pcap_next"] = "hide"
            if page <= 1:
                paging["show_pcap_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_pcaps.append(new)
    else:
        paging["show_pcap_next"] = "hide"

    paging["files_page_range"] = files_pages
    paging["urls_page_range"] = urls_pages
    paging["pcaps_page_range"] = pcaps_pages
    paging["current_page"] = page
    analyses_files.sort(key=lambda x: x["id"], reverse=True)
    return render(request, "analysis/index.html",
            {"files": analyses_files, "urls": analyses_urls, "pcaps": analyses_pcaps,
             "paging": paging, "config": enabledconf})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render(request, "analysis/pending.html",
                              {"tasks": pending})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if request.is_ajax():
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one(
                {
                    "info.id": int(task_id),
                    "behavior.processes.process_id": pid
                },
                {
                    "behavior.processes.process_id": 1,
                    "behavior.processes.calls": 1
                }
            )

        if es_as_db:
            record = es.search(
                        index=fullidx,
                        doc_type="analysis",
                        q="behavior.processes.process_id: \"%s\" and info.id:"\
                          "\"%s\"" % (pid, task_id)
                     )['hits']['hits'][0]['_source']

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        if pagenum >= 0 and pagenum < len(process["calls"]):
            objectid = process["calls"][pagenum]
            if enabledconf["mongodb"]:
                chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

            if es_as_db:
                chunk = es.search(
                            index=fullidx,
                            doc_type="calls",
                            q="_id: \"%s\"" % objectid,
                        )["hits"]["hits"][0]["_source"]
        else:
            chunk = dict(calls=[])

        return render(request, "analysis/behavior/_chunk.html",
                                  {"chunk": chunk})
    else:
        raise PermissionDenied


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def filtered_chunk(request, task_id, pid, category, apilist):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    @param apilist: comma-separated list of APIs to include, if preceded by ! specifies to exclude the list
    """
    if request.is_ajax():
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one(
                {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
                {"behavior.processes.process_id": 1, "behavior.processes.calls": 1}
            )
        if es_as_db:
            #print "info.id: \"%s\" and behavior.processes.process_id: \"%s\"" % (task_id, pid)
            record = es.search(
                         index=fullidx,
                         doc_type="analysis",
                         q="info.id: \"%s\" and behavior.processes.process_id: \"%s\"" % (task_id, pid),
                     )['hits']['hits'][0]['_source']

        if not record:
            raise PermissionDenied

        # Extract embedded document related to your process from response collection.
        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == int(pid):
                process = pdict

        if not process:
            raise PermissionDenied

        # Create empty process dict for AJAX view.
        filtered_process = {"process_id": pid, "calls": []}

        exclude = False
        apilist = apilist.strip()
        if len(apilist) and apilist[0] == '!':
            exclude = True
        apilist = apilist.lstrip('!')
        apis = apilist.split(',')
        apis[:] = [s.strip().lower() for s in apis if len(s.strip())]

        # Populate dict, fetching data from all calls and selecting only appropriate category/APIs.
        for call in process["calls"]:
            if enabledconf["mongodb"]:
                chunk = results_db.calls.find_one({"_id": call})
            if es_as_db:
                chunk = es.search(
                            index=fullidx,
                            doc_type="calls",
                            q="_id: \"%s\"" % call,
                        )['hits']['hits'][0]['_source']
            for call in chunk["calls"]:
                if category == "all" or call["category"] == category:
                    if len(apis) > 0:
                        add_call = -1
                        for api in apis:
                            if call["api"].lower() == api:
                                if exclude == True:
                                    add_call = 0
                                else:
                                    add_call = 1
                                break
                        if (exclude == True and add_call != 0) or (exclude == False and add_call == 1):
                            filtered_process["calls"].append(call)
                    else:
                        filtered_process["calls"].append(call)

        return render(request, "analysis/behavior/_chunk.html",
                                  {"chunk": filtered_process})
    else:
        raise PermissionDenied

def gen_moloch_from_suri_http(suricata):
    if "http" in suricata and suricata["http"]:
        for e in suricata["http"]:
            if e.has_key("srcip") and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])),safe='')
            if e.has_key("dstip") and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])),safe='')
            if e.has_key("dstport") and e["dstport"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["dstport"])),safe='')
            if e.has_key("srcport") and e["srcport"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["srcport"])),safe='')
            if e.has_key("hostname") and e["hostname"]:
                e["moloch_http_host_url"] = settings.MOLOCH_BASE + "?date=-1&expression=host.http" + quote("\x3d\x3d\x22%s\x22" % (e["hostname"]),safe='')
            if e.has_key("uri") and e["uri"]:
                e["moloch_http_uri_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["uri"].encode("utf8")),safe='')
            if e.has_key("ua") and e["ua"]:
                e["moloch_http_ua_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.user-agent" + quote("\x3d\x3d\x22%s\x22" % (e["ua"].encode("utf8")),safe='')
            if e.has_key("method") and e["method"]:
                e["moloch_http_method_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (e["method"]),safe='')
    return suricata

def gen_moloch_from_suri_alerts(suricata):
    if "alerts" in suricata and suricata["alerts"]:
        for e in suricata["alerts"]:
            if e.has_key("srcip") and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])),safe='')
            if e.has_key("dstip") and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])),safe='')
            if e.has_key("dstport") and e["dstport"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]),e["protocol"].lower()),safe='')
            if e.has_key("srcport") and e["srcport"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["srcport"]),e["protocol"].lower()),safe='')
            if e.has_key("sid") and e["sid"]:
                e["moloch_sid_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22suri_sid\x3a%s\x22" % (e["sid"]),safe='')
            if e.has_key("signature") and e["signature"]:
                e["moloch_msg_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22suri_msg\x3a%s\x22" % (re.sub(r"[\W]","_",e["signature"])),safe='')
    return suricata

def gen_moloch_from_suri_file_info(suricata):
    if "files" in suricata and suricata["files"]:
        for e in suricata["files"]:
            if e.has_key("srcip") and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])),safe='')
            if e.has_key("dstip") and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])),safe='')
            if e.has_key("dp") and e["dp"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dp"]),"tcp"),safe='')
            if e.has_key("sp") and e["sp"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["sp"]),"tcp"),safe='')
            if e.has_key("http_uri") and e["http_uri"]:
                e["moloch_uri_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["http_uri"]),safe='')
            if e.has_key("http_host") and e["http_host"]:
                e["moloch_host_url"] = settings.MOLOCH_BASE + "?date=-1&expression=http.host" + quote("\x3d\x3d\x22%s\x22" % (e["http_host"]),safe='')
            if e.has_key("file_info"):
                if e["file_info"].has_key("clamav") and e["file_info"]["clamav"]:
                    e["moloch_clamav_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22clamav\x3a%s\x22" % (re.sub(r"[\W]","_",e["file_info"]["clamav"])),safe='')
                if e["file_info"].has_key("md5") and e["file_info"]["md5"]:
                    e["moloch_md5_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22md5\x3a%s\x22" % (e["file_info"]["md5"]),safe='')
                if e["file_info"].has_key("sha256") and e["file_info"]["sha256"]:
                    e["moloch_sha256_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22sha256\x3a%s\x22" % (e["file_info"]["sha256"]),safe='')
                if e["file_info"].has_key("yara") and e["file_info"]["yara"]:
                    for sign in e["file_info"]["yara"]:
                        if sign.has_key("name"):
                            sign["moloch_yara_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22yara\x3a%s\x22" % (sign["name"]),safe='')
    return suricata

def gen_moloch_from_suri_tls(suricata):
    if "tls" in suricata and suricata["tls"]:
        for e in suricata["tls"]:
            if e.has_key("srcip") and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])),safe='')
            if e.has_key("dstip") and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])),safe='')
            if e.has_key("dstport") and e["dstport"]:
                e["moloch_dst_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]),"tcp"),safe='')
            if e.has_key("srcport") and e["srcport"]:
                e["moloch_src_port_url"] = settings.MOLOCH_BASE + "?date=-1&expression=port" + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["srcport"]),"tcp"),safe='')
    return suricata

def gen_moloch_from_antivirus(virustotal):
    if virustotal and virustotal.has_key("scans"):
        for key in virustotal["scans"]:
            if virustotal["scans"][key]["result"]:
                 virustotal["scans"][key]["moloch"] = settings.MOLOCH_BASE + "?date=-1&expression=" + quote("tags\x3d\x3d\x22VT:%s:%s\x22" % (key,virustotal["scans"][key]["result"]),safe='')
    return virustotal

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surialert(request,task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)},{"suricata.alerts": 1},sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_alerts(suricata)

    return render(request, "analysis/surialert.html",
                              {"analysis": report,
                               "config": enabledconf})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def shrike(request,task_id):
    shrike = results_db.analysis.find_one({"info.id": int(task_id)},{"info.shrike_url": 1,"info.shrike_msg": 1,"info.shrike_sid":1, "info.shrike_refer":1},sort=[("_id", pymongo.DESCENDING)])
    if not shrike:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    return render(request, "analysis/shrike.html",
                              {"shrike": shrike})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surihttp(request,task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)},{"suricata.http": 1},sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_http(suricata)

    return render(request, "analysis/surihttp.html",
                              {"analysis": report,
                               "config": enabledconf})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def suritls(request,task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)},{"suricata.tls": 1},sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_tls(suricata)

    return render(request, "analysis/suritls.html",
                              {"analysis": report,
                               "config": enabledconf})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surifiles(request,task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)},{"info.id": 1,"suricata.files": 1},sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_file_info(suricata)

    return render(request, "analysis/surifiles.html",
                              {"analysis": report,
                               "config": enabledconf})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def antivirus(request,task_id):
    rtmp = results_db.analysis.find_one({"info.id": int(task_id)},{"virustotal": 1,"info.category": 1},sort=[("_id", pymongo.DESCENDING)])
    if not rtmp:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        if rtmp.has_key("virustotal"):
            rtmp["virustotal"]=gen_moloch_from_antivirus(rtmp["virustotal"])

    return render(request, "analysis/antivirus.html",
                              {"analysis": rtmp})

@csrf_exempt
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def search_behavior(request, task_id):
    if request.method == 'POST':
        query = request.POST.get('search')
        results = []
        search_pid = None
        search_tid = None
        match = re.search("pid=(?P<search_pid>\d+)", query)
        if match:
            search_pid = int(match.group("search_pid"))
        match = re.search("tid=(?P<search_tid>\d+)", query)
        if match:
            search_tid = match.group("search_tid")

        if search_pid:
            query = query.replace("pid=" + str(search_pid), "")
        if search_tid:
            query = query.replace("tid=" + search_tid, "")

        query = query.strip()

        query = re.compile(query)

        # Fetch anaylsis report
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one(
                {"info.id": int(task_id)}
            )
        if es_as_db:
            esquery = es.search(
                          index=fullidx,
                          doc_type="analysis",
                          q="info.id: \"%s\"" % task_id,
                      )["hits"]["hits"][0]
            esidx = esquery["_index"]
            record = esquery["_source"]

        # Loop through every process
        for process in record["behavior"]["processes"]:
            if search_pid and process["process_id"] != search_pid:
                continue

            process_results = []

            if enabledconf["mongodb"]:
                chunks = results_db.calls.find({
                    "_id": { "$in": process["calls"] }
                })
            if es_as_db:
                # I don't believe ES has a similar function to MongoDB's $in
                # so we'll just iterate the call list and query appropriately
                chunks = list()
                for callitem in process["calls"]:
                    data = es.search(
                               index = esidx,
                               doc_type="calls",
                               q="_id: %s" % callitem
                               )["hits"]["hits"][0]["_source"]
                    chunks.append(data)

            for chunk in chunks:
                for call in chunk["calls"]:
                    if search_tid and call["thread_id"] != search_tid:
                        continue
                    # TODO: ES can speed this up instead of parsing with
                    # Python regex.
                    if query.search(call['api']):
                        process_results.append(call)
                    else:
                        for argument in call['arguments']:
                            if query.search(argument['name']) or query.search(argument['value']):
                                process_results.append(call)
                                break

            if len(process_results) > 0:
                results.append({
                    'process': process,
                    'signs': process_results
                })

        return render(request, "analysis/behavior/_search_results.html",
                                  {"results": results})
    else:
        raise PermissionDenied

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def report(request, task_id):
    db = Database()
    if enabledconf["mongodb"]:
        report = results_db.analysis.find_one(
                     {"info.id": int(task_id)},
                     sort=[("_id", pymongo.DESCENDING)]
                 )
    if es_as_db:
        query = es.search(
                    index=fullidx,
                    doc_type="analysis",
                    q="info.id : \"%s\"" % task_id
                 )["hits"]["hits"][0]
        report = query["_source"]
        # Extract out data for Admin tab in the analysis page
        esdata = {"index": query["_index"], "id": query["_id"]}
        report["es"] = esdata
    if not report:
        return render(request, "error.html",
                                  {"error": "The specified analysis does not exist"})

    children = 0
    # If compressed, decompress CAPE data
    if "CAPE" in report:
        try:
            report["CAPE"] = json.loads(zlib.decompress(report["CAPE"]))
        except:
            # In case compressresults processing module is not enabled
            pass
        session = db.Session()
        children = [c for c in session.query(Task.id,Task.package).filter(Task.parent_id == task_id)]

    # If compressed, decompress procdump, behaviour analysis (enhanced & summary)
    if "procdump" in report:
        try:
            report["procdump"] = json.loads(zlib.decompress(report["procdump"]))
        except:
            pass

    if "enhanced" in report["behavior"]:
        try:
            report["behavior"]["enhanced"] = json.loads(zlib.decompress(report["behavior"]["enhanced"]))
        except:
            pass
    if "summary" in report["behavior"]:
        try:
            report["behavior"]["summary"] = json.loads(zlib.decompress(report["behavior"]["summary"]))
        except:
            pass

    if settings.MOLOCH_ENABLED and "suricata" in report:
        suricata = report["suricata"]
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        report["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,task_id),safe='')
        if isinstance(suricata, dict):
            suricata = gen_moloch_from_suri_http(suricata)
            suricata = gen_moloch_from_suri_alerts(suricata)
            suricata = gen_moloch_from_suri_file_info(suricata)
            suricata = gen_moloch_from_suri_tls(suricata)

    if settings.MOLOCH_ENABLED and "virustotal" in report:
            report["virustotal"] = gen_moloch_from_antivirus(report["virustotal"])

    # Creating dns information dicts by domain and ip.
    if "network" in report and "domains" in report["network"]:
        domainlookups = dict((i["domain"], i["ip"]) for i in report["network"]["domains"])
        iplookups = dict((i["ip"], i["domain"]) for i in report["network"]["domains"])
        for i in report["network"]["dns"]:
            for a in i["answers"]:
                iplookups[a["data"]] = i["request"]
    else:
        domainlookups = dict()
        iplookups = dict()

    similar = []
    similarinfo = []
    if enabledconf["malheur"]:
        malheur_file = os.path.join(CUCKOO_ROOT, "storage", "malheur", "malheur.txt")
        classes = dict()
        ourclassname = None
        try:
            with open(malheur_file, "r") as malfile:
                for line in malfile:
                    if line[0] == '#':
                            continue
                    parts = line.strip().split(' ')
                    classname = parts[1]
                    if classname != "rejected":
                        if classname not in classes:
                            classes[classname] = []
                        addval = dict()
                        addval["id"] = parts[0][:-4]
                        addval["proto"] = parts[2][:-4]
                        addval["distance"] = parts[3]
                        if addval["id"] == task_id:
                            ourclassname = classname
                        else:
                            classes[classname].append(addval)
            if ourclassname:
                similar = classes[ourclassname]
                for sim in similar[:maxsimilar]:
                    siminfo = get_analysis_info(db, id=int(sim["id"]))
                    if siminfo:
                        similarinfo.append(siminfo)
                if similarinfo:
                    buf = sorted(similarinfo, key=lambda z: z["id"], reverse=True)
                    similarinfo = buf

        except:
            pass

    vba2graph = False
    vba2graph_svg_content = ""
    vba2graph_svg_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "vba2graph", "svg", "vba2graph.svg")
    if os.path.exists(vba2graph_svg_path):
        vba2graph_svg_content = open(vba2graph_svg_path, "rb").read()
        vba2graph = True

    bingraph = False
    bingraph_svg_content = ""
    bingraph_svg_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "bingraph", "ent.svg")
    if os.path.exists(bingraph_svg_path):
        bingraph_svg_content = open(bingraph_svg_path, "rb").read()
        bingraph = True

    return render(request, "analysis/report.html",
        {
            "analysis": report,
            "children" : children,
            "domainlookups": domainlookups,
            "iplookups": iplookups,
            "similar": similarinfo,
            "settings": settings,
            "config": enabledconf,
            "graphs": {
                "vba2graph": {"enabled": vba2graph, "content": vba2graph_svg_content},
                "bingraph": {"enabled": bingraph, "content": bingraph_svg_content},

            },
        }
    )

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def file(request, category, task_id, dlfile):
    file_name = dlfile
    cd = ""

    extmap = {
        "memdump" : ".dmp",
        "memdumpstrings" : ".dmp.strings",
    }

    if category == "sample":
        path = os.path.join(CUCKOO_ROOT, "storage", "binaries", dlfile)
        #file_name += ".bin"
    elif category in ("samplezip", "droppedzip", "CAPE", "CAPEZIP"):
        # ability to download password protected zip archives
        path = ""
        if category == "samplezip":
            path = os.path.join(CUCKOO_ROOT, "storage", "binaries", file_name)
        elif category == "droppedzip":
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "files", file_name)
        elif category.startswith("CAPE"):
            buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "CAPE", file_name)
            if os.path.isdir(buf):
                # Backward compat for when each dropped file was in a separate dir
                # Grab smaller file name as we store guest paths in the
                # [orig file namoka
                # ahora e]_info.exe
                dfile = min(os.listdir(buf), key=len)
                path = os.path.join(buf, dfile)
                #file_name = dfile + ".bin"
            else:
                path = buf
                #file_name += ".bin"
        TMPDIR = "/tmp"
        if path and category in ("samplezip", "droppedzip", "CAPEZIP"):
            try:
                cmd = ["7z", "a", "-y", "-pinfected", os.path.join(TMPDIR, file_name + ".zip"), path]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                output = e.output
            file_name += ".zip"
            path = os.path.join(TMPDIR, file_name)
            cd = "application/zip"
    elif category == "rtf":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "rtf_objects", file_name)
    elif category == "pcap":
        file_name += ".pcap"
        # Forcefully grab dump.pcap, serve it as [sha256].pcap
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "dump.pcap")
        cd = "application/vnd.tcpdump.pcap"
    elif category == "screenshot":
        file_name += ".jpg"
        #print file_name
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "shots", file_name)
        cd = "image/jpeg"
    elif category == "usage":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "aux", "usage.svg")
        file_name = "usage.svg"
        cd = "image/svg+xml"
    elif category in extmap:
        file_name += extmap[category]
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "memory", file_name)
        if not os.path.exists(path):
            file_name += ".zip"
            path += ".zip"
            cd = "application/zip"
    elif category == "dropped":
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                           task_id, "files", file_name)
        if os.path.isdir(buf):
            # Backward compat for when each dropped file was in a separate dir
            # Grab smaller file name as we store guest paths in the
            # [orig file name]_info.exe
            dfile = min(os.listdir(buf), key=len)
            path = os.path.join(buf, dfile)
            #file_name = dfile + ".bin"
        else:
            path = buf
            #file_name += ".bin"
    elif category == "procdump":
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                           task_id, "procdump", file_name)
        if os.path.isdir(buf):
            # Backward compat for when each dropped file was in a separate dir
            # Grab smaller file name as we store guest paths in the
            # [orig file name]_info.exe
            dfile = min(os.listdir(buf), key=len)
            path = os.path.join(buf, dfile)
            #file_name = dfile + ".bin"
        else:
            path = buf
            #file_name += ".bin"
    # Just for suricata dropped files currently
    elif category == "zip":
        file_name = "files.zip"
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "logs", "files.zip")
        cd = "application/zip"
    elif category == "suricata":
        file_name = "file." + dlfile
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            task_id, "logs", "files", file_name)
    else:
        return render(request, "error.html",
                                  {"error": "Category not defined"})

    if not cd:
        cd = "application/octet-stream"

    try:
        resp = StreamingHttpResponse(FileWrapper(open(path), 8192),
                                     content_type=cd)
    except:
        return render(request, "error.html",
                                  {"error": "File not found"})

    resp["Content-Length"] = os.path.getsize(path)
    resp["Content-Disposition"] = "attachment; filename=" + file_name
    return resp

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def procdump(request, task_id, process_id, start, end):
    origname = process_id + ".dmp"
    tmpdir = None
    tmp_file_path = None

    if enabledconf["mongodb"]:
        analysis = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    if es_as_db:
        analysis = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % task_id
                   )["hits"]["hits"][0]["_source"]

    dumpfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id,
                            "memory", origname)
    if not os.path.exists(dumpfile):
        dumpfile += ".zip"
        if not os.path.exists(dumpfile):
            return render(request, "error.html",
                                        {"error": "File not found"})
        f = zipfile.ZipFile(dumpfile, "r")
        tmpdir = tempfile.mkdtemp(prefix="cuckooprocdump_", dir=settings.TEMP_PATH)
        tmp_file_path = f.extract(origname, path=tmpdir)
        f.close()
        dumpfile = tmp_file_path
    try:
        file_item = open(dumpfile, "rb")
    except IOError:
        file_item = None

    file_name = "{0}_{1:x}.dmp".format(process_id, int(start, 16))

    if file_item and analysis and "procmemory" in analysis:
        for proc in analysis["procmemory"]:
            if proc["pid"] == int(process_id):
                data = ""
                for memmap in proc["address_space"]:
                    for chunk in memmap["chunks"]:
                        if int(chunk["start"], 16) >= int(start, 16) and int(chunk["end"], 16) <= int(end, 16):
                            file_item.seek(chunk["offset"])
                            data += file_item.read(int(chunk["size"], 16))
                if len(data):
                    content_type = "application/octet-stream"
                    response = HttpResponse(data, content_type=content_type)
                    response["Content-Disposition"] = "attachment; filename={0}".format(file_name)
                    break

    if file_item:
        file_item.close()
    try:
        if tmp_file_path:
            os.unlink(tmp_file_path)
        if tmpdir:
            os.rmdir(tmpdir)
    except:
        pass

    if response:
        return response

    return render(request, "error.html",
                                  {"error": "File not found"})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def filereport(request, task_id, category):
    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "maec5": "report.maec-5.0.json",
        "metadata": "report.metadata.xml",
        "misp": "misp.json"
    }

    if category in formats:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", formats[category])
        file_name = str(task_id) + "_" + formats[category]
        content_type = "application/octet-stream"

        if os.path.exists(file_path):
            response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
            response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

            return response

    return render(request, "error.html",
                              {"error": "File not found"})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(file_path), 8192),
                                   content_type=content_type)
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response
    else:
        return render(request, "error.html",
                                  {"error": "File not found"})
@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_strings(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings")
    filename = None
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(file_path), 8192),
                                   content_type=content_type)
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response
    else:
        return render(request, "error.html",
                                  {"error": "File not found"})

def perform_search(term, value):
    if enabledconf["mongodb"] and enabledconf["elasticsearchdb"] and essearch and not term:
        return es.search(index=fullidx, doc_type="analysis", q="%s*" % value, sort='task_id:desc')["hits"]["hits"]
    term_map = {
        "name" : "target.file.name",
        "type" : "target.file.type",
        "string" : "strings",
        "ssdeep" : "target.file.ssdeep",
        "trid" : "trid",
        "crc32" : "target.file.crc32",
        "file" : "behavior.summary.files",
        "command" : "behavior.summary.executed_commands",
        "resolvedapi" : "behavior.summary.resolved_apis",
        "key" : "behavior.summary.keys",
        "mutex" : "behavior.summary.mutexes",
        "domain" : "network.domains.domain",
        "ip" : "network.hosts.ip",
        "signature" : "signatures.description",
        "signame" : "signatures.name",
        "malfamily" : "malfamily",
        "url" : "target.url",
        "iconhash" : "static.pe.icon_hash",
        "iconfuzzy" : "static.pe.icon_fuzzy",
        "imphash" : "static.pe.imphash",
        "surihttp" : "suricata.http",
        "suritls" : "suricata.tls",
        "surisid" : "suricata.alerts.sid",
        "surialert" : "suricata.alerts.signature",
        "surimsg" : "suricata.alerts.signature",
        "suriurl" : "suricata.http.uri",
        "suriua" : "suricata.http.ua",
        "surireferrer" : "suricata.http.referrer",
        "suritlssubject" : "suricata.tls.subject",
        "suritlsissuerdn" : "suricata.tls.issuer",
        "suritlsfingerprint" : "suricata.tls.fingerprint",
        "clamav" : "target.file.clamav",
        "yaraname" : "target.file.yara.name",
        "capeyara" : "target.file.cape_yara.name",
        "procmemyara" : "procmemory.yara.name",
        "virustotal" : "virustotal.results.sig",
        "comment" : "info.comments.Data",
        "shrikemsg" : "info.shrike_msg",
        "shrikeurl" : "info.shrike_url",
        "shrikerefer" : "info.shrike_refer",
        "shrikesid" : "info.shrike_sid",
        "custom" : "info.custom",
        "md5" : "target.file.md5",
        "sha1" : "target.file.sha1",
        "sha256" : "target.file.sha256",
        "sha512" : "target.file.sha512",
    }

    query_val =  { "$regex" : value, "$options" : "-i"}
    if term == "surisid":
        try:
            query_val = int(value)
        except:
            pass
    if not term:
        value = value.lower()
        query_val = value
        if re.match(r"^([a-fA-F\d]{32})$", value):
            term = "md5"
        elif re.match(r"^([a-fA-F\d]{40})$", value):
            term = "sha1"
        elif re.match(r"^([a-fA-F\d]{64})$", value):
            term = "sha256"
        elif re.match(r"^([a-fA-F\d]{128})$", value):
            term = "sha512"

    if term not in term_map:
        raise ValueError

    if enabledconf["mongodb"]:
        return results_db.analysis.find({term_map[term] : query_val}).sort([["_id", -1]])
    if es_as_db:
        return es.search(index=fullidx, doc_type="analysis", q=term_map[term] + ": %s" % value)["hits"]["hits"]

def perform_malscore_search(value):
    query_val =  {"$gte" : float(value)}
    if enabledconf["mongodb"]:
        return results_db.analysis.find({"malscore" : query_val}).sort([["_id", -1]])

@csrf_exempt
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        if term:
            # Check on search size. But malscore can be a single digit number.
            if term != "malscore" and len(value) < 3:
                return render(request, "analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Search term too short, minimum 3 characters required"})
            # name:foo or name: foo
            value = value.lstrip()
            term = term.lower()

        try:
            if term == "malscore":
                records = perform_malscore_search(value)
            else:
                records = perform_search(term, value)
        except ValueError:
            if term:
                return render(request, "analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Invalid search term: %s" % term})
            else:
                return render(request, "analysis/search.html",
                                          {"analyses": None,
                                           "term": None,
                                           "error": "Unable to recognize the search syntax"})

        # Get data from cuckoo db.
        db = Database()
        analyses = []
        for result in records:
            new = None
            if enabledconf["mongodb"] and enabledconf["elasticsearchdb"] and essearch and not term:
                new = get_analysis_info(db, id=int(result["_source"]["task_id"]))
            if enabledconf["mongodb"] and new is None:
                new = get_analysis_info(db, id=int(result["info"]["id"]))
            if es_as_db:
                new = get_analysis_info(db, id=int(result["_source"]["info"]["id"]))
            if not new:
                continue
            analyses.append(new)
        return render(request, "analysis/search.html",
                                  {"analyses": analyses,
                                   "config": enabledconf,
                                   "term": request.POST["search"],
                                   "error": None})
    else:
        return render(request, "analysis/search.html",
                                  {"analyses": None,
                                   "term": None,
                                   "error": None})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def remove(request, task_id):
    """Remove an analysis.
    @todo: remove folder from storage.
    """
    if enabledconf["mongodb"]:
        analyses = results_db.analysis.find({"info.id": int(task_id)})
        # Checks if more analysis found with the same ID, like if process.py was run manually.
        if analyses.count() > 1:
            message = "Multiple tasks with this ID deleted."
        elif analyses.count() == 1:
            message = "Task deleted."

        if analyses.count() > 0:
            # Delete dups too.
            for analysis in analyses:
                # Delete calls.
                for process in analysis.get("behavior", {}).get("processes", []):
                    for call in process["calls"]:
                        results_db.calls.remove({"_id": ObjectId(call)})
                # Delete analysis data.
                results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
        else:
            return render(request, "error.html",
                                      {"error": "The specified analysis does not exist"})
    if es_as_db:
        analyses = es.search(
                       index=fullidx,
                       doc_type="analysis",
                       q="info.id: \"%s\"" % task_id
                   )["hits"]["hits"]
        if len(analyses) > 1:
            message = "Multiple tasks with this ID deleted."
        elif len(analyses) == 1:
            message = "Task deleted."
        if len(analyses) > 0:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Check if behavior exists
                if analysis["_source"]["behavior"]:
                    for process in analysis["_source"]["behavior"]["processes"]:
                        for call in process["calls"]:
                            es.delete(
                                index=esidx,
                                doc_type="calls",
                                id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
                )

    # Delete from SQL db.
    db = Database()
    db.delete_task(task_id)

    return render(request, "success_simple.html",
                              {"message": message})

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pcapstream(request, task_id, conntuple):
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    if enabledconf["mongodb"]:
        conndata = results_db.analysis.find_one({ "info.id": int(task_id) },
            { "network.tcp": 1, "network.udp": 1, "network.sorted_pcap_sha256": 1},
            sort=[("_id", pymongo.DESCENDING)])

    if es_as_db:
        conndata = es.search(
                    index=fullidx,
                    doc_type="analysis",
                    q="info.id : \"%s\"" % task_id
                 )["hits"]["hits"][0]["_source"]

    if not conndata:
        return render(request, "standalone_error.html",
            {"error": "The specified analysis does not exist"})

    try:
        if proto == "udp": connlist = conndata["network"]["udp"]
        else: connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"],i["dport"],i["src"],i["dst"]) == (sport,dport,src,dst),
            connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render(request, "standalone_error.html",
            {"error": "Could not find the requested stream"})

    try:
        # This will check if we have a sorted PCAP
        test_pcap = conndata["network"]["sorted_pcap_sha256"]
        # if we do, build out the path to it
        pcap_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                 task_id, "dump_sorted.pcap")
        fobj = open(pcap_path, "rb")
    except Exception as e:
        #print str(e)
        return render(request, "standalone_error.html",
            {"error": "The required sorted PCAP does not exist"})

    packets = list(network.packets_for_stream(fobj, offset))
    fobj.close()

    return HttpResponse(json.dumps(packets), content_type="application/json")

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def comments(request, task_id):
    if request.method == "POST" and settings.COMMENTS:
        comment = request.POST.get("commentbox", "")
        if not comment:
            return render(request, "error.html",
                                      {"error": "No comment provided."})

        if enabledconf["mongodb"]:
            report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
        if es_as_db:
            query = es.search(
                        index=fullidx,
                        doc_type="analysis",
                        q="info.id : \"%s\"" % task_id
                    )["hits"]["hits"][0]
            report = query["_source"]
            esid = query["_id"]
            esidx = query["_index"]
        if "comments" in report["info"]:
            curcomments = report["info"]["comments"]
        else:
            curcomments = list()
        buf = dict()
        buf["Timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        escape_map = {
            '&' : "&amp;",
            '\"' : "&quot;",
            '\'' : "&apos;",
            '<' : "&lt;",
            '>' : "&gt;",
            '\n' : "<br />",
            }
        buf["Data"] = "".join(escape_map.get(thechar, thechar) for thechar in comment)
        # status can be posted/removed
        buf["Status"] = "posted"
        curcomments.insert(0, buf)
        if enabledconf["mongodb"]:
            results_db.analysis.update({"info.id": int(task_id)},{"$set":{"info.comments":curcomments}}, upsert=False, multi=True)
        if es_as_db:
            es.update(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
                    body={
                        "doc":{
                            "info":{
                                "comments": curcomments
                            }
                        }
                    }
                 )
        return redirect('report', task_id=task_id)

    else:
        return render(request, "error.html",
                                  {"error": "Invalid Method"})

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def configdownload(request, task_id, cape_name):

    db = Database()
    cd = "text/plain"
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {"error": "Task ID {} does not existNone".format(task_id)})

    rtmp = None
    if enabledconf["mongodb"]:
        rtmp = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    if es_as_db:
        rtmp = es.search(index=fullidx, doc_type="analysis", q="info.id: \"%s\"" % str(task_id))["hits"]["hits"]
        if len(rtmp) > 1:
            rtmp = rtmp[-1]["_source"]
        elif len(rtmp) == 1:
            rtmp = rtmp[0]["_source"]
        else:
            pass

    if rtmp:
        if "CAPE" in rtmp:
            try:
                rtmp["CAPE"] = json.loads(zlib.decompress(rtmp["CAPE"]))
            except:
                # In case compress results processing module is not enabled
                pass
            for cape in rtmp["CAPE"]:
                if "cape_name" in cape and cape["cape_name"] == cape_name:
                    filepath = tempfile.NamedTemporaryFile(delete=False)
                    for key in cape["cape_config"]:
                        filepath.write("{}\t{}\n".format(key, cape["cape_config"][key]))
                    filepath.close()
                    filename = cape['cape_name'] + "_config.txt"
                    newpath = os.path.join(os.path.dirname(filepath.name), filename)
                    shutil.move(filepath.name, newpath)
                    try:
                        resp = StreamingHttpResponse(FileWrapper(open(newpath), 8192), content_type=cd)
                        resp["Content-Length"] = os.path.getsize(newpath)
                        resp["Content-Disposition"] = "attachment; filename=" + filename
                        return resp
                    except Exception as e:
                        return render(request, "error.html", {"error": "{}".format(e)})
        else:
            return render(request, "error.html", {"error": "CAPE for task {} does not exist.".format(task_id)})
    else:
        return render(request, "error.html",
                      {"error": "Could not retrieve results for task {} from db.".format(task_id)})
