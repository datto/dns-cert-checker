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

import os

from .zone_data_source import ZoneDataSource
from .bind import BindZoneDataSource

name_to_class = {
    "BIND": BindZoneDataSource
}

pkg_dir = os.path.dirname(os.path.abspath(__file__))

__all__ = [
    fname[:-3] for fname in os.listdir(pkg_dir)
]
