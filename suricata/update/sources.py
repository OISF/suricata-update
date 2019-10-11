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

import sys
import os
import logging
import io
import argparse

import yaml

from suricata.update import config
from suricata.update import net
from suricata.update import util
from suricata.update import loghandler
from suricata.update.data.index import index as bundled_index

logger = logging.getLogger()

DEFAULT_SOURCE_INDEX_URL = "https://www.openinfosecfoundation.org/rules/index.yaml"
SOURCE_INDEX_FILENAME = "index.yaml"

DEFAULT_ETOPEN_URL = "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz"

def get_source_directory():
    """Return the directory where source configuration files are kept."""
    return os.path.join(config.get_state_dir(), config.SOURCE_DIRECTORY)

def get_index_filename():
    return os.path.join(config.get_cache_dir(), SOURCE_INDEX_FILENAME)

def get_enabled_source_filename(name):
    return os.path.join(get_source_directory(), "%s.yaml" % (
        safe_filename(name)))

def get_disabled_source_filename(name):
    return os.path.join(get_source_directory(), "%s.yaml.disabled" % (
        safe_filename(name)))

def source_name_exists(name):
    """Return True if a source already exists with name."""
    if os.path.exists(get_enabled_source_filename(name)) or \
       os.path.exists(get_disabled_source_filename(name)):
        return True
    return False

def source_index_exists(config):
    """Return True if the source index file exists."""
    return os.path.exists(get_index_filename())

def get_source_index_url():
    if os.getenv("SOURCE_INDEX_URL"):
        return os.getenv("SOURCE_INDEX_URL")
    return DEFAULT_SOURCE_INDEX_URL

def save_source_config(source_config):
    if not os.path.exists(get_source_directory()):
        logger.info("Creating directory %s", get_source_directory())
        os.makedirs(get_source_directory())
    with open(get_enabled_source_filename(source_config.name), "w") as fileobj:
        fileobj.write(yaml.safe_dump(
            source_config.dict(), default_flow_style=False))

class SourceConfiguration:

    def __init__(self, name, header=None, url=None,
                 params={}, checksum=True):
        self.name = name
        self.url = url
        self.params = params
        self.header = header
        self.checksum = checksum

    def dict(self):
        d = {
            "source": self.name,
        }
        if self.url:
            d["url"] = self.url
        if self.params:
            d["params"] = self.params
        if self.header:
            d["http-header"] = self.header
        if self.checksum:
            d["checksum"] = self.checksum
        return d

class Index:

    def __init__(self, filename):
        self.filename = filename
        self.index = {}
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            index = yaml.safe_load(open(self.filename, "rb"))
            self.index = index
        else:
            self.index = bundled_index

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

    def get_source_by_name(self, name):
        if name in self.index["sources"]:
            return self.index["sources"][name]
        return None

    def get_versions(self):
        try:
            return self.index["versions"]
        except KeyError:
            logger.error("Version information not in index. Please update with suricata-update update-sources.")
            sys.exit(1)

def load_source_index(config):
    return Index(get_index_filename())

def get_enabled_sources():
    """Return a map of enabled sources, keyed by name."""
    if not os.path.exists(get_source_directory()):
        return {}
    sources = {}
    for dirpath, dirnames, filenames in os.walk(get_source_directory()):
        for filename in filenames:
            if filename.endswith(".yaml"):
                path = os.path.join(dirpath, filename)
                source = yaml.safe_load(open(path, "rb"))
                sources[source["source"]] = source

                if "params" in source:
                    for param in source["params"]:
                        if param.startswith("secret"):
                            loghandler.add_secret(source["params"][param], param)

    return sources

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

def get_etopen_url(params):
    if os.getenv("ETOPEN_URL"):
        return os.getenv("ETOPEN_URL") % params
    return DEFAULT_ETOPEN_URL % params
