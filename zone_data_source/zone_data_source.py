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


class ZoneDataSource:
    def __init__(self, config: Dict, zones: Optional[List[str]] = None, discover_zones: Optional[bool] = False):
        if zones is None:
            self.zones = set()
        else:
            self.zones = set(zones)

        if discover_zones:
            self.zones |= self.get_all_zones()

    def get_all_zones(self) -> Set[str]:
        """

        If discover_zones is True, return all zones seen
        under this datasource.
        Else, return only the zones provided by
        the configuration's `zone` list.

        :return: A list of zones provided by this ZoneDataSource
        :rtype: Set[str]
        """

        raise NotImplementedError()

    def get_zone_contents(self, zone: str) -> List[Dict]:
        """
        Returns the contents of a zone as a list of DNS records dicts

        :return: A list of DNS records under the given zone
        :rtype: List[Dict]
        """

        raise NotImplementedError()

    def get_all_zone_contents(self) -> Dict[str, List[Dict]]:
        """
        Returns a dict of {zone_name: [zone_result_0, ..., zone_result_n]}
        items for each zone in self.zones

        :return: A mapping of each zone to the zone's records,
            as determined by this ZoneDataSource.
        :rtype: Dict[str, List[Dict]]
        """

        res = dict()

        for zone in self.zones:
            res[zone] = self.get_zone_contents(zone)

        return res
