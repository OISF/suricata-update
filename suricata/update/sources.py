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
import argparse

import yaml

from suricata.update import net
from suricata.update import util

logger = logging.getLogger()

DEFAULT_SOURCE_INDEX_URL = "https://raw.githubusercontent.com/jasonish/suricata-intel-index/master/index.yaml"
SOURCE_INDEX_FILENAME = "index.yaml"

def get_source_index_url(config):
    if os.getenv("SOURCE_INDEX_URL"):
        return os.getenv("SOURCE_INDEX_URL")
    return DEFAULT_SOURCE_INDEX_URL

def update_sources(config):
    source_cache_filename = os.path.join(
        config.get_cache_dir(), SOURCE_INDEX_FILENAME)
    source_templates = {}
    with io.BytesIO() as fileobj:
        try:
            url = get_source_index_url(config)
            logger.debug("Downloading %s", url)
            net.get(get_source_index_url(config), fileobj)
        except Exception as err:
            raise Exception("Failed to download index: %s: %s" % (url, err))
        with open(source_cache_filename, "w") as outobj:
            outobj.write(fileobj.getvalue())
        logger.debug("Saved %s", source_cache_filename)

def load_sources(config):
    sources_cache_filename = os.path.join(
        config.get_cache_dir(), SOURCE_INDEX_FILENAME)
    if os.path.exists(sources_cache_filename):
        index = yaml.load(open(sources_cache_filename).read())
        return index["sources"]
    return {}

def list_sources(config):
    sources = load_sources(config)
    if not sources:
        logger.error("No sources exist. Try running update-sources.")
        return
    for name, source in sources.items():
        print("Name: %s" % (name))
        print("  Vendor: %s" % (source["vendor"]))
        print("  Description: %s" % (source["description"]))
        print("  License: %s" % (source["license"]))

def enable_source(config):
    name = config.args.name
    sources = load_sources(config)
    if not config.args.name in sources:
        logger.error("Unknown source: %s", config.args.name)
        return 1

    # Parse key=val options.
    opts = {}
    for opt in config.args.params:
        key, val = opt.params("=", 1)
        opts[key] = val

    source = sources[config.args.name]
    params = {}
    if "parameters" in source:
        for param in source["parameters"]:
            if param in opts:
                params[param] = opts[param]
            else:
                prompt = source["parameters"][param]["prompt"]
                r = raw_input("%s (%s): " % (prompt, param))
                params[param] = r.strip()
    new_source = {
        "source": name,
    }
    if params:
        new_source["params"] = params
    new_sources = [new_source]
    config.save_new_source(new_source)
