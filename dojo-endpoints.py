#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Update the list of endpoints of a product[s] in DefectDojo.
"""

import logging
import argparse
import csv
import sys
from shodan import Shodan
from defectdojo_api import defectdojo_apiv2 as defectdojo
from dotenv import dotenv_values

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

parser = argparse.ArgumentParser(description='Get product[s] endpoints via [csv/shodan/censys/nmap].')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--cpe', help="product cpe", type=str)
group.add_argument('--all', help="process all products", action='store_true')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--csv', help="csv endpoints file, format format: \"127.0.0.1\",\"7800\",\"tcp\"", type=str)

args = parser.parse_args()
config = dotenv_values(".env")
discovery_methods = ["shodan_query", "censys_query", "nmap_scan"]


def main():

    if args.cpe:
        logging.info("Searching for products matching cpe: %s", args.cpe)
        update_product_endpoints(args.cpe)

    if args.all:
        logging.info("Fetching all products endpoints...")
        raise NotImplementedError


def update_product_endpoints(cpe):
    dojo_api = get_dojo_api_client(config)
    products = dojo_api.list_products(name=cpe)
    if products.success:
        product = products.data["results"][0]
        logging.info("Product: %s", product["name"])

        if args.csv:
            endpoints = load_product_endpoints_from_csv(args.csv)
            add_product_endpoints(product["id"], endpoints)
            return

        # get discovery method
        for meta in product["product_meta"]:
            if meta["name"] in discovery_methods:
                logging.info("Found discovery method %s for %s ...", meta["name"], product["name"])
                endpoints = get_product_endpoints(product, meta["name"], meta["value"])
                add_product_endpoints(product["id"], endpoints)
                sys.exit(0)

        logging.error("No discovery method found for product %s", product["name"])


def add_product_endpoints(product_id, endpoints):
    dojo_api = get_dojo_api_client(config)
    logging.debug("Adding %s endpoints to product id=%s ...", len(endpoints), product_id)
    # this is highly inefficient, but there is no way to bulk-add endpoints
    for endpoint in endpoints:
        response = dojo_api._request(
            'POST',
            'endpoints/',
            data={
                "product": product_id,
                "host": endpoint[0],
                "port": endpoint[1],
                "protocol": endpoint[2]
            })

        endpoint_str = "Endpoint %s://%s:%s already exists for product id=%s." % (endpoint[2], endpoint[0], endpoint[1], product_id)

        if(response.success):
            logging.debug("Endpoint %s added to DefectDojo." % endpoint_str)
        else:
            if "endpoint with this data already exists for this product" in response.data:
                logging.debug(endpoint_str)
            else:
                logging.error("Failed to add % endpoint_strendpoint to DefectDojo: %s", endpoint_str, response.data)


def get_dojo_api_client(config):
    return defectdojo.DefectDojoAPIv2(
        config["DOJO_HOST"],
        config["DOJO_API_TOKEN"],
        config["DOJO_USER"],
        debug=config["DOJO_USER"] == "TRUE",
        verify_ssl=config["DOJO_VERIFY_SSL"] == "TRUE"
    )


def get_shodan_api_client(config):
    return Shodan(config["SHODAN_API_TOKEN"])


def get_product_endpoints(product, discovery_method, discovery_payload):
    if discovery_method == "shodan_query":
        return get_shodan_endpoints(discovery_payload)

    if discovery_method == "censys_query":
        return get_censys_endpoints(discovery_payload)

    if discovery_method == "nmap_scan":
        return get_nmap_endpoints(discovery_payload)


def load_product_endpoints_from_csv(file):
    with open(file, newline='') as csvfile:
        return list(csv.reader(csvfile))


def get_shodan_endpoints(discovery_payload):
    logging.debug("[Shodan] Searching for endpoints with query: %s", discovery_payload)
    shodan_api = get_shodan_api_client(config)
    results = shodan_api.search(discovery_payload)  # TODO pagination
    for result in results["matches"]:
        yield (result["ip_str"], result["port"])


def get_censys_endpoints(discovery_payload):
    raise NotImplementedError


def get_nmap_endpoints(discovery_payload):
    raise NotImplementedError


if __name__ == '__main__':
    main()
