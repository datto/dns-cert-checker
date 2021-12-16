#!/usr/bin/env python3

# This file is part of DNS Certificate Checker.
#
# Copyright Datto, Inc.
# Author: Scott Conway <sconway@datto.com>
#
# Licensed under the Mozilla Public License Version 2.0
# Fedora-License-Identifier: MPLv2.0
# SPDX-2.0-License-Identifier: MPL-2.0
# SPDX-3.0-License-Identifier: MPL-2.0
#
# DNS Certificate Checker is free software.
# For more information on the license, see LICENSE.
# For more information on free software,
# see <https://www.gnu.org/philosophy/free-sw.en.html>.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at <https://mozilla.org/MPL/2.0/>.

import argparse
from collections import defaultdict
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
import csv
import datetime
import dns.resolver
import json
import logging
import multiprocessing
from nassl._nassl import OpenSSLError
import os
import re
import socket
import time
from sslyze.errors import (
    ConnectionToServerFailed,
    ConnectionToServerTimedOut,
    ServerRejectedConnection,
    ServerTlsConfigurationNotSupported,
)
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner import Scanner, ServerScanRequest
from sslyze.scanner.server_scan_request import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

RUN_TIME_TIMESTAMP = int(time.time())

logging.basicConfig()
LOGGER = logging.getLogger()


def _emit_stats(
    endpoint: str, metric: str, fields: Dict[str, float], tags: Dict[str, str]
):
    """
    Emit stats in influx format to a UDP endpoint.

    :param endpoint: A string with a format of <dns endpoint>:<port>
    :param metric: the name of the metric to produce
    :param fields: a dictionary of fields and their values
    :param tags: a dictionary of tags and their values
    """
    endpoint, port = endpoint.split(":")
    tag_str = ",".join([f"{k}={v}" for k, v in tags.items()])
    field_str = ",".join([f"{k}={v}" for k, v in fields.items()])
    batch = f"{metric},{tag_str} {field_str}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(batch.encode("utf-8"), (endpoint, int(port)))
    except Exception as e:
        LOGGER.error(f"Failed to send ({batch}) to {endpoint}:{port} :: {e}")


def parse_dns_dict(
    dns_export: Dict[str, List[Dict]],
    zone_name: str,
    dns_resolver: Optional[dns.resolver.Resolver] = None,
    name_filters: Optional[List] = [],
) -> Dict[str, Set[str]]:
    """
    Given a Dict containing A and CNAME records for any number of zones,
    parse the A and CNAME records for each.

    Returns a dict of {IP: {name_0, name_1, ... name_n}} items

    :param dns_export: A Dict of items of format
        {"zone_name": [dns_record_0, dns_record_1, ...]}
    :type dns_export: Dict[str, List[Dict]]
    :return: A lookup table from an IP address to the names bound to it
        (according to the provided dns resolver)
    :rtype: Dict[str, Set[str]], Dict[int, int, int, int]
    """
    stats = {
        "cname_records_total": 0,
        "a_records_total": 0,
        "filtered_records_total": 0,
        "ns_exceptions_total": 0,
    }

    ip_to_names = defaultdict(lambda: set())
    name_to_ips = defaultdict(lambda: set())

    domain_a_records = list()
    domain_cname_records = list()

    LOGGER.info("Processing/Filtering DNS records...")
    for record in dns_export:

        # Pull all A and CNAME records,
        # but do not process them yet

        if record["type"] == "A":
            domain_a_records.append(record)
            stats["a_records_total"] += 1

        elif record["type"] == "CNAME":
            domain_cname_records.append(record)
            stats["cname_records_total"] += 1

    # Process the A records first,
    # so we can populate a name -> IP mapping
    for a_record in domain_a_records:
        if a_record["name"] == "@":
            fqdn = zone_name

        else:
            fqdn = "%s.%s" % (a_record["name"], zone_name)

        if not fqdn.startswith("*") and any(f.search(fqdn) for f in name_filters):
            LOGGER.debug(f"Filtering A record {fqdn} from processing")
            stats["filtered_records_total"] += 1
            continue

        # Note that wildcard DNS entries will appear
        # with a leading star.
        #
        # But since they're wildcard, the star is a valid subdomain!
        # Thus, we can test on it and ignore other subdomains
        name_to_ips[fqdn].add(a_record["target"])
        ip_to_names[a_record["target"]].add(fqdn)

    # Now that we have a populated name -> IP mapping,
    # resolve all of the CNAMEs with as few network name lookups as possible
    for cname_record in domain_cname_records:
        if cname_record["name"] == "@":
            fqdn = zone_name

        else:
            fqdn = "%s.%s" % (cname_record["name"], zone_name)

        if not fqdn.startswith("*") and any(f.search(fqdn) for f in name_filters):
            LOGGER.debug(f"Filtering CNAME record {fqdn} from processing")
            stats["filtered_records_total"] += 1
            continue

        if cname_record["target"] == "@":
            target = zone_name

        elif cname_record["target"].endswith("."):
            target = cname_record["target"][:-1]
        else:
            target = ".".join((cname_record["target"], zone_name))

        # TODO let's say that the CNAME target here is for
        # wildcard-target.subdomain.domain.com
        #
        # And an A record is set for *.subdomain.domain.com
        #
        # As of now, we'll have "*.subdomain.domain.com" in name_to_ips
        # So we'll need to use a DNS lookup to find out what
        # wildcard-target.subdomain.domain.com resolves to,
        # when we _should_ be able to figure it out ourselves.

        if target in name_to_ips:
            cname_ips = name_to_ips[target]

        # TODO if we can't find it, somehow check if it's over a wildcard
        # A record (or don't bother)

        else:
            cname_ips = resolve_cname_ips(target)
            if not cname_ips:
                stats["ns_exceptions_total"] += 1

        for ip in cname_ips:
            ip_to_names[ip].add(fqdn)

    return ip_to_names, stats


def resolve_cname_ips(
    fqdn: str, dns_resolver: Optional[dns.resolver.Resolver] = None
) -> Set[str]:
    """
    Resolve all of the IPs that we can get to from a single CNAME.
    If the CNAME points to another CNAME,
    this will resolve all parts of the chain

    :param fqdn: The FQDN to resolve
    :type fqdn: str
    :param dns_resolver: An optoinal pre-configured DNS resolver,
        for using user-specified nameservers
    :type dns_resolver: Optional[dns.resolver.Resolver]
    :return: A set of the IPs returned by the DNS lookup
    :rtype: Set[str]
    """

    try:

        if dns_resolver is None:
            lookup_res = dns.resolver.resolve(fqdn)

        else:
            lookup_res = dns_resolver.resolve(fqdn)

    # There's nothing we can do about DNS errors
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
    ) as dns_exception:
        LOGGER.info(f"DNS exception resolving {fqdn}: {dns_exception}")
        return set()

    return {answer.to_text() for answer in lookup_res}


def sslyze_scan_all_hosts(
    hosts_to_check: List[Tuple], max_workers: Optional[int] = None
) -> Iterable[ServerScanResult]:
    """
    Given a list of (ip, port, hostname) tuples,
    scan all of those that pass a connectivity test.
    This returns an iteratror of results from the scanner.

    :param hosts_to_check: A list of (ip, port, hostname) tuples
    :type hosts_to_check: List[Tuple]
    :param max_workers: The number of threads to use while scanning
        defaults to the number of system threads + 2
    :type max_workers: Optional[int]
    :return: the scanner's results, from scanner.get_results()
    :rtype: Iterable[ServerScanResult]
    """

    scanner = Scanner()
    scan_reqs = list()

    server_locations = [
        ServerNetworkLocationViaDirectConnection(
            ip_address=ip, port=port, hostname=host
        )
        for (ip, port, host) in hosts_to_check
    ]
    conn_tester = ServerConnectivityTester()
    LOGGER.info("starting TLS scans")

    # Default to number of system threads + 2
    if max_workers is None:
        max_workers = multiprocessing.cpu_count() + 2

    with ThreadPoolExecutor(max_workers=max_workers) as thread_pool:
        futures = [
            thread_pool.submit(conn_tester.perform, server_location)
            for server_location in server_locations
        ]
        for completed_future in as_completed(futures):
            try:
                server_connectivity_info = completed_future.result()
                scan_reqs.append(
                    ServerScanRequest(
                        server_info=server_connectivity_info,
                        scan_commands={ScanCommand.CERTIFICATE_INFO},
                    )
                )

            except ServerTlsConfigurationNotSupported as ssl_config_exception:
                si = ssl_config_exception.server_location
                host_info_str = f"{si.ip_address}:{si.port} - {si.hostname}"
                err_msg = f"{host_info_str}: {ssl_config_exception.error_message}"

                # incompatible cipher offerings shouldn't be loudly alerted on
                if (
                    "could not find a TLS version and cipher suite supported by the server"
                    in ssl_config_exception.error_message
                ):
                    LOGGER.debug(err_msg)
                else:
                    LOGGER.error(err_msg)

            except OpenSSLError:
                # TODO the exception does not include IP / port / hostname info
                # so there's not much we can do
                #
                # This exception should raise an alert,
                # but with it being multi-threaded, there's no good way
                # of tracking with connection tests raised this exception
                continue

            except (
                ConnectionToServerTimedOut,
                ConnectionToServerFailed,
                ServerRejectedConnection,
                ServerTlsConfigurationNotSupported,
            ):
                # We don't care about hostnames/IPs that aren't operational
                continue

    scanner.start_scans(scan_reqs)

    # return an iterator which may not be completed just yet
    return scanner.get_results()


def get_cert_warnings(
    scan_result: ServerScanResult, minimum_time_to_expiration: int
) -> List[Dict[str, Union[int, str]]]:
    """
    Given a single result from a Scanner,
    perform checks that if failed, should trigger a warning

    :param scan_result: A single result from an SSLyze Scanner
    :type scan_result: ServerScanResult
    :param minimum_time_to_expiration: The minimum acceptable remaining time
        until a certificate expires, in seconds
    :type minumum_time_to_expiration: int
    :return: A list of warnings in dict format
    :rtype: List[Dict[str, Union[int, str]]]
    """

    si = scan_result.server_info.server_location

    cert_warnings = list()

    for cert_deployment in scan_result.scan_commands_results[
        "certificate_info"
    ].certificate_deployments:
        for cert in cert_deployment.received_certificate_chain:
            not_after = cert.not_valid_after.timestamp()

            if RUN_TIME_TIMESTAMP + minimum_time_to_expiration > not_after:
                expiration_msg = 'certificate "%s" expiring at %s' % (
                    cert.subject.rfc4514_string(),
                    datetime.datetime.fromtimestamp(not_after).isoformat(),
                )

                cert_warnings.append(expiration_msg)

    # Construct dict entries of the certs from their warning messages
    return [
        {
            "ip_address": si.ip_address,
            "port": si.port,
            "fqdn": si.hostname,
            "status": "warning",
            "message": err,
        }
        for err in cert_warnings
    ]


def get_cert_errors(scan_result: ServerScanResult) -> List[str]:
    """
    Given a single result from a Scanner,
    perform checks which if failed, should trigger an error

    :param scan_result: A single result from an SSLyze Scanner
    :type scan_result: ServerScanResult
    :return: A list of errors found with this cert/chain
    :rtype: List[str]
    """

    si = scan_result.server_info.server_location
    cert_errors = list()

    # If there were exceptions while scanning, return them
    if scan_result.scan_commands_errors:
        for (
            scan_plugin_name,
            scan_command_error,
        ) in scan_result.scan_commands_errors.items():
            cert_errors.append(scan_command_error.reason.name)

    # SSLyze returned no internal errors -
    # is there anything wrong with the cert itself?
    else:
        for cert_deployment in scan_result.scan_commands_results[
            "certificate_info"
        ].certificate_deployments:

            # First check if the cert matches the hostname
            if not cert_deployment.leaf_certificate_subject_matches_hostname:
                cert_errors.append("subject does not match hostname")

            # check if the chain is in a valid order
            if not cert_deployment.received_chain_has_valid_order:
                cert_errors.append("certificate chain does not have valid order")

            # Now see what the trust stores think about this cert
            #
            # If there's a consensus, simply report one instance of it
            trust_results = set()
            for trust_res in cert_deployment.path_validation_results:
                trust_results.add(trust_res.openssl_error_string)

            consensus = len(trust_results) == 1

            # if there is a consensus,
            # report what the first trust store had to say
            if (
                consensus
                and not cert_deployment.path_validation_results[
                    0
                ].was_validation_successful
            ):
                verify_string = cert_deployment.path_validation_results[
                    0
                ].openssl_error_string
                cert_errors.append(verify_string)

            # if there's not a consensus, report all error instances
            else:
                for result in cert_deployment.path_validation_results:

                    # There's no issue, so we don't care
                    if result.was_validation_successful:
                        continue

                    else:
                        store_name = result.trust_store.name
                        error_reason = result.openssl_error_string

                        cert_errors.append("%s - %s" % (store_name, error_reason))

    # Construct dict entries of the certs from their error messages
    return [
        {
            "ip_address": si.ip_address,
            "port": si.port,
            "fqdn": si.hostname,
            "status": "error",
            "message": err,
        }
        for err in cert_errors
    ]


def fetch_dns_records(nameserver_address: str, zone: str) -> List[Dict[str, str]]:
    """

    :param nameserver_address: The IP address of the DNS server from which
        to request a zone transfer for the provided zone
    :type nameserver_address: str
    :param zone: The zone to request a zone transfer for
    :type zone: str
    :return: A list of A and CNAME records for the given zone,
        represented in dict format
    :rtype: List[Dict[str, str]]
    """
    zone_records = list()
    transfer_res = dns.zone.from_xfr(dns.query.inbound_xfr(nameserver_address, zone))

    for record_type in ["A", "CNAME"]:
        for target, ttl, data in transfer_res.iterate_rdatas(record_type):
            zone_records.append(
                {
                    "type": record_type,
                    "name": str(target),
                    "ttl": ttl,
                    "target": str(data),
                }
            )

    return zone_records


def get_cert_findings(
    ip_to_names: Dict[str, Set[str]], ssl_ports: List[int], min_time_to_expiration: int
) -> List[Dict]:
    """
    Main function to check certificates for all DNS records that we found

    :param ip_to_names: A lookup dict of format
        {IP address: {fqdn_0, fqdn_1, ...}}
    :type ip_to_names: Dict[str, Set[str]]
    :param ssl_ports: A list of ports to check when scanning
    :type ssl_ports: List[int]
    :param min_time_to_expiration: The minimum number of seconds
        of certificate validity to not consider it close to expiration
    :type min_time_to_expiration: int
    :return: All certificate findings (warnings and errors)
    :rtype: List[Dict]
    """

    ssl_hosts = {ip: ssl_ports for ip in ip_to_names.keys()}
    cert_findings = list()
    scan_queue = list()

    for ip, names in ip_to_names.items():
        for name in names:
            for port in ssl_hosts[ip]:
                scan_queue.append((ip, port, name))

    scan_results = sslyze_scan_all_hosts(scan_queue)
    LOGGER.info("Completed TLS scans")
    for scan_result in scan_results:
        result_errors = get_cert_errors(scan_result)
        cert_findings.extend(result_errors)

        # Only check for warnings if there aren't errors
        if not result_errors:
            cert_findings.extend(get_cert_warnings(scan_result, min_time_to_expiration))

    return cert_findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output-csv",
        type=str,
        default=None,
        help="If set, output a CSV of all detected certificate"
        " warnings/errors that were discovered",
    )
    parser.add_argument(
        "--from-zones-json",
        type=str,
        default=None,
        help="If set, load zone information from the provided JSON file "
        "instead of requesting zone transfers from nameservers at runtime",
    )
    parser.add_argument(
        "--stat-endpoint",
        default="localhost:8081",
        help="endpoint to emit influx-style stats to",
    )
    parser.add_argument(
        "-n", "--name-filters", action="append", help="add filters to DNS entries"
    )

    args = parser.parse_args()

    if not os.path.exists("config.json"):
        print("Exiting - a configuration file must be provided " 'in "config.json"')
        exit(1)

    with open("config.json", "r") as f:
        config = json.load(f)

    LOGGER.setLevel(config.get("log_level", logging.WARNING))

    if args.get("name_filters", []):
        name_filters = [re.compile(f) for f in args.get("name_filters", [])]
    else:
        name_filters = []

    # Initialize a custom nameserver if configured
    resolver = dns.resolver.Resolver()
    lookup_nameservers = config.get("lookup_nameservers", None)
    if lookup_nameservers:
        resolver.nameservers = lookup_nameservers

    zone_records = dict()

    if args.from_zones_json:
        with open(args.from_zones_json, "r") as f:
            zone_records = json.load(f)

    else:
        for nameserver, zones in config.get("nameserver_zones", dict()).items():
            for zone in zones:
                zone_records[zone] = fetch_dns_records(nameserver, zone)
    all_stats = dict()

    for zone in zone_records.keys():
        start_process = time.time()
        # get a mapping of IP addresses to the names they serve
        ip_to_names, zone_stats = parse_dns_dict(
            zone_records[zone], zone, resolver, name_filters
        )

        # Default to 30 days as the minium allowed time to not alert on
        # a certificate being close to expiration
        cert_findings = get_cert_findings(
            ip_to_names,
            config.get("ssl_ports", [443]),
            config.get("min_time_to_expiration", 2592000),
        )

        zone_stats["cert_warnings_total"] = 0
        zone_stats["cert_errors_total"] = 0
        # Raise warnings and errors for our gathered findings
        for result in cert_findings:
            alert_str = "%s:%s - %s - %s" % (
                result["ip_address"],
                result["port"],
                result["fqdn"],
                result["message"],
            )

            if result["status"] == "warning":
                LOGGER.warning(alert_str)
                zone_stats["cert_warnings_total"] += 1

            elif result["status"] == "error":
                LOGGER.error(alert_str)
                zone_stats["cert_errors_total"] += 1

        zone_stats["process_time_secs"] = time.time() - start_process
        if args.output_csv:
            if cert_findings:
                with open(args.output_csv, "w") as f:
                    dw = csv.DictWriter(f, fieldnames=cert_findings[0].keys())
                    dw.writeheader()
                    dw.writerows(cert_findings)
            else:
                LOGGER.info("No results to write to CSV")

        all_stats[zone] = zone_stats

    # we emit all stats at the end of the run to make stats generally line up for all zones
    for zone, stats in all_stats.items():
        _emit_stats(args["stat_endpoint"], "dns", stats, {"zone": zone})


if __name__ == "__main__":
    main()
