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

import yaml

from suricata.update import config
from suricata.update import sources

try:
    input = raw_input
except:
    pass

logger = logging.getLogger()

default_source = "et/open"

def register(parser):
    parser.add_argument("name")
    parser.add_argument("params", nargs="*", metavar="param=val")
    parser.set_defaults(func=enable_source)

def enable_source():
    name = config.args().name
    update_params = False

    # Check if source is already enabled.
    enabled_source_filename = sources.get_enabled_source_filename(name)
    if os.path.exists(enabled_source_filename):
        logger.warning("The source %s is already enabled.", name)
        update_params = True

    # First check if this source was previous disabled and then just
    # re-enable it.
    disabled_source_filename = sources.get_disabled_source_filename(name)
    if os.path.exists(disabled_source_filename):
        logger.info("Re-enabling previously disabled source for %s.", name)
        os.rename(disabled_source_filename, enabled_source_filename)
        update_params = True

    if not os.path.exists(sources.get_index_filename()):
        logger.warning("Source index does not exist, will use bundled one.")
        logger.warning("Please run suricata-update update-sources.")

    source_index = sources.load_source_index(config)

    if not name in source_index.get_sources():
        logger.error("Unknown source: %s", name)
        return 1

    # Parse key=val options.
    opts = {}
    for param in config.args().params:
        key, val = param.split("=", 1)
        opts[key] = val

    params = {}
    if update_params:
        source = yaml.safe_load(open(sources.get_enabled_source_filename(name), "rb"))
    else:
        source = source_index.get_sources()[name]

    if "params" in source:
        params = source["params"]
        for old_param in source["params"]:
            if old_param in opts and source["params"][old_param] != opts[old_param]:
                logger.info("Updating source parameter '%s': '%s' -> '%s'." % (
                    old_param, source["params"][old_param], opts[old_param]))
                params[old_param] = opts[old_param]

    if "subscribe-url" in source:
        print("The source %s requires a subscription. Subscribe here:" % (name))
        print("  %s" % source["subscribe-url"])

    if "parameters" in source:
        for param in source["parameters"]:
            if param in opts:
                params[param] = opts[param]
            else:
                prompt = source["parameters"][param]["prompt"]
                while True:
                    r = input("%s (%s): " % (prompt, param))
                    r = r.strip()
                    if r:
                        break
                params[param] = r.strip()

    if "checksum" in source:
        checksum = source["checksum"]
    else:
        checksum = source.get("checksum", True)

    new_source = sources.SourceConfiguration(
        name, params=params, checksum=checksum)

    # If the source directory does not exist, create it. Also create
    # the default rule-source of et/open, unless the source being
    # enabled replaces it.
    source_directory = sources.get_source_directory()
    if not os.path.exists(source_directory):
        try:
            logger.info("Creating directory %s", source_directory)
            os.makedirs(source_directory)
        except Exception as err:
            logger.error(
                "Failed to create directory %s: %s", source_directory, err)
            return 1

        if "replaces" in source and default_source in source["replaces"]:
            logger.debug(
                "Not enabling default source as selected source replaces it")
        elif new_source.name == default_source:
            logger.debug(
                "Not enabling default source as selected source is the default")
        else:
            logger.info("Enabling default source %s", default_source)
            if not source_index.get_source_by_name(default_source):
                logger.error("Default source %s not in index", default_source)
            else:
                default_source_config = sources.SourceConfiguration(
                    default_source)
                write_source_config(default_source_config, True)

    write_source_config(new_source, True)
    logger.info("Source %s enabled", new_source.name)

    if "replaces" in source:
        for replaces in source["replaces"]:
            filename = sources.get_enabled_source_filename(replaces)
            if os.path.exists(filename):
                logger.info(
                    "Removing source %s as its replaced by %s", replaces,
                    new_source.name)
                logger.debug("Deleting %s", filename)
                os.unlink(filename)

def write_source_config(config, enabled):
    if enabled:
        filename = sources.get_enabled_source_filename(config.name)
    else:
        filename = sources.get_disabled_source_filename(config.name)
    with open(filename, "w") as fileobj:
        logger.debug("Writing %s", filename)
        fileobj.write(yaml.safe_dump(config.dict(), default_flow_style=False))
