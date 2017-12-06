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

import os
import logging

from suricata.update import config
from suricata.update import sources

logger = logging.getLogger()

def register(parser):
    parser.add_argument("name")
    parser.set_defaults(func=remove_source)

def remove_source():
    name = config.args().name

    enabled_source_filename = sources.get_enabled_source_filename(name)
    if os.path.exists(enabled_source_filename):
        logger.debug("Deleting file %s.", enabled_source_filename)
        os.remove(enabled_source_filename)
        logger.info("Source %s removed, previously enabled.", name)
        return 0

    disabled_source_filename = sources.get_disabled_source_filename(name)
    if os.path.exists(disabled_source_filename):
        logger.debug("Deleting file %s.", disabled_source_filename)
        os.remove(disabled_source_filename)
        logger.info("Source %s removed, previously disabled.", name)
        return 0

    logger.warning("Source %s does not exist.", name)
    return 1
