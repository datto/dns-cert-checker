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

from collections import defaultdict
from typing import Dict, List, Optional, Set

import boto3
import dns

from .zone_data_source import ZoneDataSource


class Route53ZoneDataSource(ZoneDataSource):
    def __init__(
        self,
        config: Dict,
        zones: Optional[List[str]] = None,
        discover_zones: Optional[bool] = False,
    ):

        self.DNS_RECORD_TYPES = ["A", "CNAME"]
        self.discover_private_zones = config.get("discover_private_zones", False)

        # set up the boto client before calling super's init
        self.boto_client = boto3.client(
            "route53",
            aws_access_key_id=config["aws_access_key_id"],
            aws_secret_access_key=config["aws_secret_access_key"],
            aws_session_token=config["aws_session_token"],
        )

        # TODO check if our client can view zones/records!

        # now get a mapping of zone names to their ResourceIds
        self.zone_name_to_resource_ids = defaultdict(lambda: list())

        hosted_zone_paginator = self.boto_client.get_paginator("list_hosted_zones")
        for page in hosted_zone_paginator.paginate():
            page_zones = page["HostedZones"]
            for zone in page_zones:
                self.zone_name_to_resource_ids[zone["Name"][:-1]].append(
                    zone["Id"].split("/")[-1]
                )

        super(Route53ZoneDataSource, self).__init__(config, zones, discover_zones)

    def normalize_record_name(self, resource_record_name: str, zone_name: str) -> str:
        """
        Given a resource record name from Route53,
        reformat it to a "BIND-comatible" name.

        It performs the following modifications:
            * truncate the trailing period
            * truncate the zone name from the end of record[Name]
            * replace \\052 with * (for wildcards)
            * replace an entry to just the zone name with "@"

        :param resource_record_name: The "Name" attribute of a resource record
        :type resource_record_name: str
        :param zone_name: The resource record's DNS zone, as a string
        :type zone_name: str
        :return: A bind-compatible "name" attribute for this resource record
        :rtype: str
        """

        return (
            resource_record_name[:-1]
            .replace("\\052", "*")
            .replace("." + zone_name, "")
            .replace(zone_name, "@")
        )

    def get_all_zones(self) -> Set[str]:
        """
        If discover_zones is True, return all zones seen
        under this datasource.
        Else, return only the zones provided by
        the configuration's `zone` list.

        :return: A list of zones provided by this ZoneDataSource
        :rtype: Set[str]
        """

        discovered_zones = set()
        hosted_zone_paginator = self.boto_client.get_paginator("list_hosted_zones")
        for page in hosted_zone_paginator.paginate():
            page_zones = page["HostedZones"]
            for zone in page_zones:

                # skip private zones by default
                if zone["Config"]["PrivateZone"] and not self.discover_private_zones:
                    continue

                discovered_zones.add(zone["Name"][:-1])  # truncate last period

        return self.zones | discovered_zones

    def get_zone_contents(self, zone: str) -> List[Dict]:
        """
        Returns the contents of a zone as a list of DNS records dicts

        :param zone: The zone name whose records to fetch (eg. example.com)
        :type zone: str
        :return: A list of DNS records under the given zone
        :rtype: List[Dict]
        """

        zone_records = list()

        # a given zone might be under multiple ResourceIds
        zone_ids = self.zone_name_to_resource_ids.get(zone, None)

        if zone_ids is None:
            raise Exception(f'Invalid ZoneId "{zone}"')

        for zone_id in zone_ids:
            zone_resource_record_paginator = self.boto_client.get_paginator(
                "list_resource_record_sets"
            )

            for page in zone_resource_record_paginator.paginate(HostedZoneId=zone_id):
                for resource_record in page["ResourceRecordSets"]:

                    if resource_record["Type"] not in self.DNS_RECORD_TYPES:
                        continue

                    # not all records have a "ResourceRecords" section
                    for target in resource_record.get("ResourceRecords", list()):
                        zone_records.append(
                            {
                                "type": resource_record["Type"],
                                "name": self.normalize_record_name(
                                    resource_record["Name"], zone
                                ),
                                "ttl": resource_record["TTL"],
                                "target": target["Value"],
                            }
                        )

                    alias_target = resource_record.get("AliasTarget", None)
                    if alias_target is not None:
                        # Route53 offers dynamic records through aliases,
                        # which makes getting a BIND-compatible zone representation
                        # kinda difficult.
                        #
                        # We see that this record exists, and will now ask an
                        # external nameserver about what it says about this record
                        dns_res = dns.resolver.resolve(
                            resource_record["Name"], resource_record["Type"]
                        )
                        for entry in dns_res:
                            zone_records.append(
                                {
                                    "type": resource_record["Type"],
                                    "name": self.normalize_record_name(
                                        resource_record["Name"], zone
                                    ),
                                    "ttl": None,  # TODO can we get this value?
                                    "target": entry.address,
                                }
                            )

        return zone_records
