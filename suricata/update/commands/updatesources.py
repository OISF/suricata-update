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
import yaml

from suricata.update import config
from suricata.update import sources
from suricata.update import net
from suricata.update import exceptions

logger = logging.getLogger()


def register(parser):
    parser.set_defaults(func=update_sources)


def compare_sources(initial_content, final_content):
    initial_sources = initial_content.get("sources")
    final_sources = final_content.get("sources")
    added_sources = {source: final_sources[source]
                     for source in final_sources if source not in initial_sources}
    removed_sources = {source: initial_sources[source]
                       for source in initial_sources if source not in final_sources}
    if initial_content == final_content:
        logger.info("No change in sources")
        return
    if added_sources:
        for source in added_sources:
            logger.info("Source %s was added", source)
    if removed_sources:
        for source in removed_sources:
            logger.info("Source %s was removed", source)
    for source in set(initial_sources) & set(final_sources):
        if initial_sources[source] != final_sources[source]:
            logger.info("Source %s was changed", source)


def update_sources():
    local_index_filename = sources.get_index_filename()
    with open(local_index_filename) as stream:
        initial_content = yaml.safe_load(stream)
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
        with open(local_index_filename) as stream:
            final_content = yaml.safe_load(stream)
        compare_sources(initial_content, final_content)
        logger.info("Saved %s", local_index_filename)
