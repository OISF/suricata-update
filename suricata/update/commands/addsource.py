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

try:
    input = raw_input
except:
    pass

logger = logging.getLogger()


def register(parser):
    parser.add_argument("name", metavar="<name>", nargs="?",
                        help="Name of source")
    parser.add_argument("url", metavar="<url>", nargs="?", help="Source URL")
    parser.add_argument("--http-header", metavar="<http-header>",
                        help="Additional HTTP header to add to requests")
    parser.add_argument("--no-checksum", action="store_false",
                        help="Skips downloading the checksum URL")
    parser.set_defaults(func=add_source)


def add_source():
    args = config.args()

    if args.name:
        name = args.name
    else:
        while True:
            name = input("Name of source: ").strip()
            if name:
                break

    if sources.source_name_exists(name):
        logger.error("A source with name %s already exists.", name)
        return 1

    if args.url:
        url = args.url
    else:
        while True:
            url = input("URL: ").strip()
            if url:
                break

    checksum = args.no_checksum

    header = args.http_header if args.http_header else None

    source_config = sources.SourceConfiguration(
        name, header=header, url=url, checksum=checksum)
    sources.save_source_config(source_config)
