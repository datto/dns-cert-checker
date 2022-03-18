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

from typing import Dict, List, Optional, Set

import dns.query
import dns.resolver
import dns.zone

from .zone_data_source import ZoneDataSource


class BindZoneDataSource(ZoneDataSource):
    def __init__(
        self,
        config: Dict,
        zones: Optional[List[str]] = None,
        discover_zones: Optional[bool] = False,
    ):

        super(BindZoneDataSource, self).__init__(config, zones, discover_zones)
        self.server_ip = config["server_ip"]
        self.server_port = config.get("server_port", 53)
        self.DNS_RECORD_TYPES = ["A", "CNAME"]

    def get_all_zones(self) -> Set[str]:
        """
        If discover_zones is True, return all zones seen
        under this datasource.
        Else, return only the zones provided by
        the configuration's `zone` list.

        :return: A list of zones provided by this ZoneDataSource
        :rtype: Set[str]
        """

        # Since BIND servers can't tell you what zones they serve,
        # we can only know what we know
        return self.zones

    def get_zone_contents(self, zone: str) -> List[Dict]:
        """
        Returns the contents of a zone as a list of DNS records dicts

        :param zone: The zone name whose records to fetch (eg. example.com)
        :type zone: str
        :return: A list of DNS records under the given zone
        :rtype: List[Dict]
        """

        zone_records = list()

        zone_xfr_results = dns.zone.from_xfr(
            dns.query.xfr(self.server_ip, zone, port=self.server_port)
        )

        for record_type in self.DNS_RECORD_TYPES:
            for n, ttl, data in zone_xfr_results.iterate_rdatas(record_type):
                zone_records.append(
                    {
                        "type": record_type,
                        "name": str(n),
                        "ttl": ttl,
                        "target": str(data),
                    }
                )

        return zone_records
