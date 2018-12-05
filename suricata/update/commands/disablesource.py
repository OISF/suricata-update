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
    parser.set_defaults(func=disable_source)

def disable_source():
    name = config.args().name
    filename = sources.get_enabled_source_filename(name)
    if not os.path.exists(filename):
        logger.debug("Filename %s does not exist.", filename)
        logger.warning("Source %s is not enabled.", name)
        return 0
    logger.debug("Renaming %s to %s.disabled.", filename, filename)
    os.rename(filename, "%s.disabled" % (filename))
    logger.info("Source %s has been disabled", name)
