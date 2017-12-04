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

from suricata.update import sources

logger = logging.getLogger()

def register(parser):
    parser.add_argument("name")
    parser.add_argument("params", nargs="*", metavar="param=val")
    parser.set_defaults(func=enable_source)
    
def enable_source(config):
    name = config.args.name

    # Check if source is already enabled.
    enabled_source_filename = sources.get_enabled_source_filename(name)
    if os.path.exists(enabled_source_filename):
        logger.error("The source %s is already enabled.", name)
        return 1

    # First check if this source was previous disabled and then just
    # re-enable it.
    disabled_source_filename = sources.get_disabled_source_filename(name)
    if os.path.exists(disabled_source_filename):
        logger.info("Re-enabling previous disabled source for %s.", name)
        os.rename(disabled_source_filename, enabled_source_filename)
        return 0

    if not os.path.exists(sources.get_index_filename(config)):
        logger.warning(
            "Source index does not exist, "
            "try running suricata-update update-sources.")
        return 1

    source_index = sources.load_source_index(config)
    
    if not name in source_index.get_sources():
        logger.error("Unknown source: %s", name)
        return 1

    # Parse key=val options.
    opts = {}
    for param in config.args.params:
        key, val = param.split("=", 1)
        opts[key] = val

    source = source_index.get_sources()[name]

    if "subscribe-url" in source:
        print("The source %s requires a subscription. Subscribe here:" % (name))
        print("  %s" % source["subscribe-url"])

    params = {}
    if "parameters" in source:
        for param in source["parameters"]:
            if param in opts:
                params[param] = opts[param]
            else:
                prompt = source["parameters"][param]["prompt"]
                while True:
                    r = raw_input("%s (%s): " % (prompt, param))
                    r = r.strip()
                    if r:
                        break
                params[param] = r.strip()
    new_source = sources.SourceConfiguration(name, params=params).dict()

    if not os.path.exists(sources.get_source_directory()):
        try:
            logger.info("Creating directory %s", sources.get_source_directory())
            os.makedirs(sources.get_source_directory())
        except Exception as err:
            logger.error("Failed to create directory %s: %s",
                         sources.get_source_directory(), err)
            return 1

    filename = os.path.join(
        sources.get_source_directory(), "%s.yaml" % (sources.safe_filename(name)))
    logger.info("Writing %s", filename)
    with open(filename, "w") as fileobj:
        fileobj.write(yaml.dump(new_source, default_flow_style=False))
