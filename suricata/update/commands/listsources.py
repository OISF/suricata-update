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

from suricata.update import sources

logger = logging.getLogger()

def register(parser):
    parser.set_defaults(func=list_sources)

def list_sources(config):
    if not sources.source_index_exists(config):
        logger.warning(
            "Source index does not exist, please run: "
            "suricata-update update-sources")
        return 1
    index = sources.load_source_index(config)
    for name, source in index.get_sources().items():
        print("Name: %s" % (name))
        print("  Vendor: %s" % (source["vendor"]))
        print("  Summary: %s" % (source["summary"]))
        print("  License: %s" % (source["license"]))
        if "tags" in source:
            print("  Tags: %s" % ", ".join(source["tags"]))
