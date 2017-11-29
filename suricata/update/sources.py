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
from suricata.update import loghandler

logger = logging.getLogger()

DEFAULT_SOURCE_INDEX_URL = "https://raw.githubusercontent.com/jasonish/suricata-intel-index/master/index.yaml"
SOURCE_INDEX_FILENAME = "index.yaml"
ENABLED_SOURCE_DIRECTORY = "/var/lib/suricata/update/sources"

def get_index_filename(config):
    return os.path.join(config.get_cache_dir(), SOURCE_INDEX_FILENAME)

def get_enabled_source_filename(name):
    return os.path.join(ENABLED_SOURCE_DIRECTORY, "%s.yaml" % (
        safe_filename(name)))

def get_disabled_source_filename(name):
    return os.path.join(ENABLED_SOURCE_DIRECTORY, "%s.yaml.disabled" % (
        safe_filename(name)))

def source_name_exists(name):
    """Return True if a source already exists with name."""
    if os.path.exists(get_enabled_source_filename(name)) or \
       os.path.exists(get_disabled_source_filename(name)):
        return True
    return False

def source_index_exists(config):
    """Return True if the source index file exists."""
    return os.path.exists(get_index_filename(config))

def save_source_config(source_config):
    with open(get_enabled_source_filename(source_config.name), "wb") as fileobj:
        fileobj.write(yaml.safe_dump(
            source_config.dict(), default_flow_style=False))

class SourceConfiguration:

    def __init__(self, name, url=None, params={}):
        self.name = name
        self.url = url
        self.params = params

    def dict(self):
        d = {
            "source": self.name,
        }
        if self.url:
            d["url"] = self.url
        if self.params:
            d["params"] = self.params
        return d

class Index:

    def __init__(self, filename):
        self.filename = filename
        self.index = {}
        self.reload()

    def reload(self):
        index = yaml.load(open(self.filename, "rb"))
        self.index = index

    def resolve_url(self, name, params={}):
        if not name in self.index["sources"]:
            raise Exception("Source name not in index: %s" % (name))
        source = self.index["sources"][name]
        try:
            return source["url"] % params
        except KeyError as err:
            raise Exception("Missing URL parameter: %s" % (str(err.args[0])))

    def get_sources(self):
        return self.index["sources"]

def load_source_index(config):
    return Index(get_index_filename(config))

def get_enabled_sources():
    """Return a map of enabled sources, keyed by name."""
    if not os.path.exists(ENABLED_SOURCE_DIRECTORY):
        return {}
    sources = {}
    for dirpath, dirnames, filenames in os.walk(ENABLED_SOURCE_DIRECTORY):
        for filename in filenames:
            if filename.endswith(".yaml"):
                path = os.path.join(dirpath, filename)
                source = yaml.load(open(path, "rb"))
                sources[source["source"]] = source

                if "params" in source:
                    for param in source["params"]:
                        if param.startswith("secret"):
                            loghandler.add_secret(source["params"][param], param)

    return sources

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
        if not os.path.exists(config.get_cache_dir()):
            try:
                os.makedirs(config.get_cache_dir())
            except Exception as err:
                logger.error("Failed to create directory %s: %s",
                             config.get_cache_dir(), err)
                return 1
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

def enable_source(config):
    name = config.args.name

    # Check if source is already enabled.
    enabled_source_filename = os.path.join(
        ENABLED_SOURCE_DIRECTORY, "%s.yaml" % (safe_filename(name)))
    if os.path.exists(enabled_source_filename):
        logger.error("The source %s is already enabled.", name)
        return 1

    # First check if this source was previous disabled and then just
    # re-enable it.
    disabled_source_filename = os.path.join(
        ENABLED_SOURCE_DIRECTORY, "%s.yaml.disabled" % (safe_filename(name)))
    if os.path.exists(disabled_source_filename):
        logger.info("Re-enabling previous disabled source for %s.", name)
        os.rename(disabled_source_filename, enabled_source_filename)
        return 0

    if not os.path.exists(get_index_filename(config)):
        logger.warning(
            "Source index does not exist, "
            "try running suricata-update update-sources.")
        return 1

    sources = load_sources(config)
    if not config.args.name in sources:
        logger.error("Unknown source: %s", config.args.name)
        return 1

    # Parse key=val options.
    opts = {}
    for param in config.args.params:
        key, val = param.split("=", 1)
        opts[key] = val

    source = sources[config.args.name]

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
    new_source = SourceConfiguration(name, params=params).dict()

    if not os.path.exists(ENABLED_SOURCE_DIRECTORY):
        try:
            logger.info("Creating directory %s", ENABLED_SOURCE_DIRECTORY)
            os.makedirs(ENABLED_SOURCE_DIRECTORY)
        except Exception as err:
            logger.error("Failed to create directory %s: %s",
                         ENABLED_SOURCE_DIRECTORY, err)
            return 1

    filename = os.path.join(
        ENABLED_SOURCE_DIRECTORY, "%s.yaml" % (safe_filename(name)))
    logger.info("Writing %s", filename)
    with open(filename, "w") as fileobj:
        fileobj.write(yaml.dump(new_source, default_flow_style=False))

def disable_source(config):
    name = config.args.name
    filename = os.path.join(ENABLED_SOURCE_DIRECTORY, "%s.yaml" % (
        safe_filename(name)))
    if not os.path.exists(filename):
        logger.debug("Filename %s does not exist.", filename)
        logger.warning("Source %s is not enabled.", name)
        return 1
    logger.debug("Renaming %s to %s.disabled.", filename, filename)
    os.rename(filename, "%s.disabled" % (filename))

def remove_source(config):
    name = config.args.name

    enabled_source_filename = get_enabled_source_filename(name)
    if os.path.exists(enabled_source_filename):
        logger.debug("Deleting file %s.", enabled_source_filename)
        os.remove(enabled_source_filename)
        logger.info("Source %s removed, previously enabled.", name)
        return 0

    disabled_source_filename = get_disabled_source_filename(name)
    if os.path.exists(disabled_source_filename):
        logger.debug("Deleting file %s.", disabled_source_filename)
        os.remove(disabled_source_filename)
        logger.info("Source %s removed, previously disabled.", name)
        return 0
    
    logger.warning("Source %s does not exist.", name)
    return 1

def safe_filename(name):
    """Utility function to make a source short-name safe as a
    filename."""
    name = name.replace("/", "-")
    return name

