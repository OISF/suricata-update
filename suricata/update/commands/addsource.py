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
    parser.add_argument("name", metavar="<name>", help="Name of source")
    parser.add_argument("url", metavar="<url>", help="Source URL")
    parser.set_defaults(func=add_source)

def add_source():
    args = config.args()

    if args.name:
        name = args.name
    else:
        while True:
            name = raw_input("Name of source: ").strip()
            if name:
                break

    if sources.source_name_exists(name):
        logger.error("A source with name %s already exists.", name)
        return 1

    if args.url:
        url = args.url
    else:
        while True:
            url = raw_input("URL: ").strip()
            if url:
                break

    source_config = sources.SourceConfiguration(name, url=url)
    sources.save_source_config(source_config)
