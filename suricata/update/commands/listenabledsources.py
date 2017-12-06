# Copyright (C) 2017 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import logging

from suricata.update import config
from suricata.update import sources

logger = logging.getLogger()

def register(parser):
    parser.set_defaults(func=list_enabled_sources)

def list_enabled_sources():

    found = False

    # First list sources from the main config.
    config_sources = config.get("sources")
    if config_sources:
        found = True
        print("From %s:" % (config.filename))
        for source in config_sources:
            print("  - %s" % (source))

    # And local files.
    local = config.get("local")
    if local:
        found = True
        print("Local files/directories:")
        for filename in local:
            print("  - %s" % (filename))

    enabled_sources = sources.get_enabled_sources()
    if enabled_sources:
        found = True
        print("Enabled sources:")
        for source in enabled_sources.values():
            print("  - %s" % (source["source"]))

    # If no enabled sources were found, log it.
    if not found:
        logger.warning("No enabled sources.")
