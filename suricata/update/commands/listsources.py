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
from suricata.update import util
from suricata.update.commands.updatesources import update_sources

logger = logging.getLogger()

def register(parser):
    parser.set_defaults(func=list_sources)

def list_sources():
    if not sources.source_index_exists(config):
        logger.info("No source index found, running update-sources")
        update_sources()
    index = sources.load_source_index(config)
    for name, source in index.get_sources().items():
        print("%s: %s" % (util.bright_cyan("Name"), util.bright_magenta(name)))
        print("  %s: %s" % (
            util.bright_cyan("Vendor"), util.bright_magenta(source["vendor"])))
        print("  %s: %s" % (
            util.bright_cyan("Summary"), util.bright_magenta(source["summary"])))
        print("  %s: %s" % (
            util.bright_cyan("License"), util.bright_magenta(source["license"])))
        if "tags" in source:
            print("  %s: %s" % (
                util.bright_cyan("Tags"),
                util.bright_magenta(", ".join(source["tags"]))))
        if "replaces" in source:
            print("  %s: %s" % (
                util.bright_cyan("Replaces"),
                util.bright_magenta(", ".join(source["replaces"]))))
        if "parameters" in source:
            print("  %s: %s" % (
                util.bright_cyan("Parameters"),
                util.bright_magenta(", ".join(source["parameters"]))))
