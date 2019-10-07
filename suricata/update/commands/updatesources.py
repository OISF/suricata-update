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

import io
import logging
import os

import yaml
from suricata.update import config, exceptions, net, sources

logger = logging.getLogger()


def register(parser):
    parser.set_defaults(func=update_sources)


def get_initial_content():
    initial_content = None
    if os.path.exists(local_index_filename):
        with open(local_index_filename, "r") as stream:
            initial_content = yaml.safe_load(stream)
    return initial_content


def get_sources(before, after):
    all_sources = {source: after[source]
        for source in after if source not in before}
    return all_sources


def log_sources(sources_map):
    for name, all_sources in sources_map.items():
        if not all_sources:
            continue
        for source in all_sources:
            logger.info("Source %s was %s", source, name)


def compare_sources(initial_content, final_content):
    if not initial_content:
        logger.info("Adding all sources")
        return
    if initial_content == final_content:
        logger.info("No change in sources")
        return
    initial_sources = initial_content.get("sources")
    final_sources = final_content.get("sources")
    added_sources = get_sources(before=initial_sources, after=final_sources)
    removed_sources = get_sources(before=final_sources, after=initial_sources)
    log_sources(sources_map={"added": added_sources,
                        "removed": removed_sources})
    for source in set(initial_sources) & set(final_sources):
        if initial_sources[source] != final_sources[source]:
            logger.info("Source %s was changed", source)


def write_and_compare(initial_content, fileobj):
    try:
        with open(local_index_filename, "wb") as outobj:
            outobj.write(fileobj.getvalue())
    except IOError as ioe:
        logger.error("Failed to open directory: %s", ioe)
        return 1
    with open(local_index_filename, "rb") as stream:
        final_content = yaml.safe_load(stream)
    compare_sources(initial_content, final_content)
    logger.info("Saved %s", local_index_filename)


def update_sources():
    global local_index_filename
    local_index_filename = sources.get_index_filename()
    initial_content = get_initial_content()
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
        write_and_compare(initial_content=initial_content, fileobj=fileobj)
