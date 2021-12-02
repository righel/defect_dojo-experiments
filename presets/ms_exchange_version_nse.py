#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
import tempfile

test_type_id = 116  # Nmap Scan


def run(dojo_api, product_id, engagement_id, preset_name, endpoints, config={}):
    logging.debug("Running custom preset %s ...", __file__)

    date = datetime.now()
    report_file = os.path.join(config["NMAP_REPORTS_DIR"], "engagement_%s_%s.xml" % (engagement_id, date.isoformat()))
    nmap_script = os.path.join(config["NMAP_SCRIPTS_DIR"], "ms-exchange-version.nse")

    targets_file = tempfile.NamedTemporaryFile(mode='w+')
    targets_file.write('\n'.join([e["host"] for e in endpoints]))
    targets_file.flush()

    # run nmap scan
    cmd = "nmap -v0 -p http* --script %s -oX %s -iL %s" % (nmap_script, report_file, targets_file.name)
    logging.debug("Running nmap command: %s", cmd)
    os.system(cmd)

    # upload report DefectDojo
    upload_scan = dojo_api.upload_scan(
        engagement_id,  # engagement_id
        "Nmap Scan",  # scan_type
        report_file,  # file
        True,  # active
        False,  # verified
        True,  # close_old_findings
        True,  # skip_duplicates
        date.strftime("%Y-%m-%d"),  # scan_date,
        tags=preset_name
        # minimum_severity="Low"
    )

    if upload_scan.success:
        test_id = upload_scan.data["test"]
        logging.info("Scan report pushed, created test id=%s." % test_id)
    else:
        logging.error("Failed to push Nmap scan report for engagement id=%s" % (engagement_id))
        sys.exit(1)

    # uploading the nmap report will create new endpoints for the product
    # get all endpoints for this product # TODO: use pagination
    endpoints = dojo_api._request('GET', 'endpoints/', params={"product": product_id, "limit": 1000})
    if not endpoints.success:
        logging.error("Failed to get endpoints for engagement: %s", engagement_id)
        sys.exit(1)

    endpoints = endpoints.data["results"]

    # parse xml report
    for e in parse_report(report_file):
        # push ms exchange version findings to DefectDojo
        endpoint = get_endpoint_id(endpoints, e["host"], e["port"], e["protocol"])
        if not endpoint:
            endpoint = dojo_api._request(
                'POST',
                'endpoints/',
                data={
                    "product": product_id,
                    "host": e["host"],
                    "port": e["port"],
                    "protocol": e["protocol"]
                }
            )
            if not endpoint.success:
                logging.error("Failed to create endpoint: %s://%s:%s error: %s" % (e["protocol"], e["host"], e["port"], endpoint.data))
                continue

        push_version_finding(dojo_api, engagement_id, test_id, e["version"], endpoint)


def get_endpoint_id(endpoints, host, port, protocol):
    # TODO: store endpoints in a more efficient data structure (dict)
    for endpoint in endpoints:
        if(endpoint["host"].strip() == host.strip() and int(endpoint["port"]) == int(port) and endpoint["protocol"].strip() == protocol.strip()):
            return endpoint

    return None


def parse_report(report_file):
    tree = ET.parse(report_file)
    root = tree.getroot()

    endpoints = []
    xml_report = ET.parse(report_file)
    root = xml_report.getroot()

    for host in root.findall("host"):
        target_hosts = set()
        # target ip address
        addresses = host.findall("address")
        for address in addresses:
            target_hosts.add(address.attrib["addr"])

        # target hostnames
        hostnames = host.findall("hostnames/hostname")
        for hostname in hostnames:
            target_hosts.add(hostname.attrib["name"])

        for port_element in host.findall("ports/port"):
            for script_element in port_element.findall('script[@id="ms-exchange-version"]'):
                for component_element in script_element.findall('table'):
                    for target_host in target_hosts:
                        endpoints.append({
                            "host": target_host,
                            "port": port_element.attrib["portid"],
                            "protocol": port_element.attrib["protocol"],
                            "version": component_element.attrib["key"]
                        })

    return endpoints


def push_version_finding(dojo_api, engagement_id, test_id, version, endpoint):
    response = dojo_api._request(
        'POST',
        'findings/',
        data={
            "title": "ms_exchange_v_%s" % version,  # title,
            "description": "Microsoft Exchange Server Version %s" % version,
            "test": test_id,
            "found_by": [test_type_id],
            "severity": "Info",
            "numerical_severity": 0,
            "active": True,
            "verified": False,
            "duplicate": False,
            "false_p": False,
            "endpoints": [endpoint["id"]]
        })

    if response.success:
        logging.debug("Pushed finding  finding_id=%s engagement_id=%s endpoint %s:%s", response.data["id"], engagement_id, endpoint["host"], endpoint["port"])
        return response.data["id"]
    else:
        logging.error("Failed to create finding for engagement_id=%s endpoint %s:%s: %s", engagement_id, endpoint["host"], endpoint["port"], response.message)

    return None
