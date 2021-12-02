#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Perform scans for active engagements, using the preset defined in the engagement and push findings to DefectDojo.
"""

import logging
import argparse
from defectdojo_api import defectdojo_apiv2 as defectdojo
from dotenv import dotenv_values

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

parser = argparse.ArgumentParser(description='Process all active engagements.')
args = parser.parse_args()

config = dotenv_values(".env")


def main():
    # get engagements
    dojo_api = get_dojo_api_client(config)
    engagements = dojo_api.list_engagements()
    if engagements.success:
        for engagement in engagements.data["results"]:
            if(engagement["active"] == True):
                logging.info("Processing engagement: %s ...", engagement["name"])

                # get engagement preset
                preset = dojo_api._request('GET', 'engagement_presets/%s' % engagement["preset"])
                if not preset.success:
                    logging.error("Failed to get preset for engagement: %s", engagement["name"])
                    continue

                # get engagement endpoints
                endpoints = dojo_api._request('GET', 'endpoints', {"product": engagement["product"]})
                if endpoints.success:
                    endpoints = endpoints.data["results"]

                    run_engagement_preset(
                        preset.data["title"],
                        engagement["product"],
                        engagement["id"],
                        endpoints
                    )


def run_engagement_preset(preset_name, product_id, engagement_id, endpoints):
    logging.info("Running engagement preset: %s ...", preset_name)

    dojo_api = get_dojo_api_client(config)

    # TODO:
    #   * create a list of targets for running nmap only once per port
    #   * run the nmap scan in a remote host using Fabric? Celery?

    # set engagement to "In Progress" if not already
    update_engagement_status(dojo_api, engagement_id, "In Progress")

    # import custom preset
    preset = getattr(__import__("presets", fromlist=[preset_name]), preset_name)

    preset.run(
        dojo_api,
        product_id,
        engagement_id,
        preset_name,
        endpoints,
        config=config,
    )


def update_engagement_status(dojo_api, engagement_id, status):
    response = dojo_api.set_engagement(engagement_id, status=status)

    if response.success:
        logging.debug("Update engagement id=%s status to %s", engagement_id, status)
    else:
        logging.error("Failed to update engagement id=%s status", engagement_id)


def get_dojo_api_client(config):
    return defectdojo.DefectDojoAPIv2(
        config["DOJO_HOST"],
        config["DOJO_API_TOKEN"],
        config["DOJO_USER"],
        debug=config["DOJO_USER"] == "TRUE",
        verify_ssl=config["DOJO_VERIFY_SSL"] == "TRUE"
    )


if __name__ == '__main__':
    main()
