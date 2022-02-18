#!/usr/bin/env python3

# This file is part of DNS Certificate Checker.
#
# Given a valid config, fetch A and CNAME records for all configured DNS zones
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
import json
import dns_cert_checker


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        default=None,
        help="If set, output the zone JSON to the named file. "
        "If not set, outputs to stdout",
    )

    args = parser.parse_args()

    with open("config.json", "r") as f:
        config = json.load(f)

    all_zone_records = dns_cert_checker.fetch_all_zone_records(config['zone_data_sources'])

    if args.output_file:
        with open(args.output_file, "w") as f:
            json.dump(all_zone_records, f, indent=4)

    else:
        print(json.dumps(all_zone_records, indent=4))


if __name__ == "__main__":
    main()
