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
import io

from suricata.update import config
from suricata.update import sources
from suricata.update import net
from suricata.update import exceptions

logger = logging.getLogger()

def register(parser):
    parser.set_defaults(func=update_sources)

def update_sources():
    local_index_filename = sources.get_index_filename()
    with io.BytesIO() as fileobj:
        url = sources.get_source_index_url()
        logger.info("Downloading %s", url)
        try:
            net.get(url, fileobj)
        except Exception as err:
            raise exceptions.ApplicationError(
                "Failed to download index: %s: %s" % (url, err))
        if not os.path.exists(config.get_cache_dir()):
            try:
                os.makedirs(config.get_cache_dir())
            except Exception as err:
                logger.error("Failed to create directory %s: %s",
                             config.get_cache_dir(), err)
                return 1
        with open(local_index_filename, "wb") as outobj:
            outobj.write(fileobj.getvalue())
        logger.info("Saved %s", local_index_filename)
