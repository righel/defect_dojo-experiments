#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

test_type_id = 116  # Nmap Scan


def run(dojo_api, engagement_id, preset_name, endpoints, config={}):
    logging.debug("Running custom preset %s ...", __file__)

    for endpoint in endpoints:
        report_file = os.path.join(config["NMAP_REPORTS_DIR"], "%s_%s.xml" % (endpoint["host"], endpoint["port"]))
        nmap_script = os.path.join(config["NMAP_SCRIPTS_DIR"], "ms-exchange-version.nse")

        # run nmap scan
        cmd = "nmap -v0 --script %s -p %s -oX %s %s" % (nmap_script, endpoint["port"], report_file, endpoint["host"])
        logging.debug("Running nmap command: %s", cmd)
        os.system(cmd)

        date = datetime.now()

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
        )

        if upload_scan.success:
            test_id = upload_scan.data["test"]
            logging.info("Scan report pushed, created test id=%s." % test_id)
        else:
            logging.error(upload_scan.message)
            sys.exit("Failed to push Nmap scan report for engagement id=%s, endpoint=%s: %s" % (engagement_id, endpoint["host"], endpoint["port"]))

        # parse xml report
        versions = parse_report(report_file)

        # push findings to DefectDojo
        for version in versions:
            push_version_finding(dojo_api, engagement_id, test_id, version, endpoint)


def parse_report(report_file):
    tree = ET.parse(report_file)
    root = tree.getroot()

    versions = []

    for host in root.findall('host'):
        xml_report = ET.parse(report_file)
        root = xml_report.getroot()

        for host in root.findall("host"):
            for port_element in host.findall("ports/port"):
                for script_element in port_element.findall('script'):
                    for component_element in script_element.findall('table'):
                        versions.append(component_element.attrib["key"])

    return versions


def push_version_finding(dojo_api, engagement_id, test_id, version, endpoint):
    response = dojo_api._request(
        'POST',
        'findings/',
        data={
            "title": "ms_exchange_v_%s" % version,  # title,
            "description": "Microsoft Exchange Server Version %s" % version,
            "test": test_id,
            "found_by": [test_type_id],
            "severity": "Informational",
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
