# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2015-2017 Jason Ish
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

import os.path
import logging

import yaml

import suricata.update.engine
from suricata.update.exceptions import ApplicationError

try:
    from suricata.config import defaults
    has_defaults = True
except:
    has_defaults = False

logger = logging.getLogger()

DEFAULT_DATA_DIRECTORY = "/var/lib/suricata"

# Cache directory - relative to the data directory.
CACHE_DIRECTORY = os.path.join("update", "cache")

# Source directory - relative to the data directory.
SOURCE_DIRECTORY = os.path.join("update", "sources")

# Configuration keys.
DATA_DIRECTORY_KEY = "data-directory"
CACHE_DIRECTORY_KEY = "cache-directory"
IGNORE_KEY = "ignore"
DISABLE_CONF_KEY = "disable-conf"
ENABLE_CONF_KEY = "enable-conf"
MODIFY_CONF_KEY = "modify-conf"
DROP_CONF_KEY = "drop-conf"
LOCAL_CONF_KEY = "local"
OUTPUT_KEY = "output"
DIST_RULE_DIRECTORY_KEY = "dist-rule-directory"

if has_defaults:
    DEFAULT_UPDATE_YAML_PATH = os.path.join(defaults.sysconfdir, "update.yaml")
else:
    DEFAULT_UPDATE_YAML_PATH = "/etc/suricata/update.yaml"

DEFAULT_SURICATA_YAML_PATH = [
    "/etc/suricata/suricata.yaml",
    "/usr/local/etc/suricata/suricata.yaml",
    "/etc/suricata/suricata-debian.yaml"
]

if has_defaults:
    DEFAULT_DIST_RULE_PATH = [
        defaults.datarulesdir,
        "/etc/suricata/rules",
    ]
else:
    DEFAULT_DIST_RULE_PATH = [
        "/etc/suricata/rules",
    ]

DEFAULT_CONFIG = {
    "disable-conf": "/etc/suricata/disable.conf",
    "enable-conf": "/etc/suricata/enable.conf",
    "drop-conf": "/etc/suricata/drop.conf",
    "modify-conf": "/etc/suricata/modify.conf",
    "sources": [],
    LOCAL_CONF_KEY: [],

    # The default file patterns to ignore.
    "ignore": [
        "*deleted.rules",
    ],
}

_args = None
_config = {}

# The filename the config was read from, if any.
filename = None

def has(key):
    """Return true if a configuration key exists."""
    return key in _config

def set(key, value):
    """Set a configuration value."""
    _config[key] = value

def get(key):
    """Get a configuration value."""
    if key in _config:
        return _config[key]
    return None

def set_state_dir(directory):
    _config[DATA_DIRECTORY_KEY] = directory

def get_state_dir():
    """Get the data directory. This is more of the Suricata state
    directory than a specific Suricata-Update directory, and is used
    as the root directory for Suricata-Update data.
    """
    if os.getenv("DATA_DIRECTORY"):
        return os.getenv("DATA_DIRECTORY")
    if DATA_DIRECTORY_KEY in _config:
        return _config[DATA_DIRECTORY_KEY]
    return DEFAULT_DATA_DIRECTORY

def set_cache_dir(directory):
    """Set an alternate cache directory."""
    _config[CACHE_DIRECTORY_KEY] = directory

def get_cache_dir():
    """Get the cache directory."""
    if CACHE_DIRECTORY_KEY in _config:
        return _config[CACHE_DIRECTORY_KEY]
    return os.path.join(get_state_dir(), CACHE_DIRECTORY)

def get_output_dir():
    """Get the rule output directory."""
    if OUTPUT_KEY in _config:
        return _config[OUTPUT_KEY]
    return os.path.join(get_state_dir(), "rules")

def args():
    """Return sthe parsed argument object."""
    return _args

def get_arg(key):
    key = key.replace("-", "_")
    if hasattr(_args, key):
        val = getattr(_args, key)
        if val not in [[], None]:
            return val
    return None

def init(args):
    global _args
    global filename

    _args = args
    _config.update(DEFAULT_CONFIG)

    if args.config:
        logger.info("Loading %s", args.config)
        with open(args.config, "rb") as fileobj:
            config = yaml.safe_load(fileobj)
            if config:
                _config.update(config)
                filename = args.config
    elif os.path.exists(DEFAULT_UPDATE_YAML_PATH):
        logger.info("Loading %s", DEFAULT_UPDATE_YAML_PATH)
        with open(DEFAULT_UPDATE_YAML_PATH, "rb") as fileobj:
            config = yaml.safe_load(fileobj)
            if config:
                _config.update(config)
                filename = DEFAULT_UPDATE_YAML_PATH

    # Apply command line arguments to the config.
    for arg in vars(args):
        if arg == "local":
            for local in args.local:
                logger.debug("Adding local ruleset to config: %s", local)
                _config[LOCAL_CONF_KEY].append(local)
        elif arg == "data_dir" and args.data_dir:
            logger.debug("Setting data directory to %s", args.data_dir)
            _config[DATA_DIRECTORY_KEY] = args.data_dir
        elif getattr(args, arg) is not None:
            key = arg.replace("_", "-")
            val = getattr(args, arg)
            logger.debug("Setting configuration value %s -> %s", key, val)
            _config[key] = val

    # Find and set the path to suricata if not provided.
    if "suricata" in _config:
        if not os.path.exists(_config["suricata"]):
            raise ApplicationError(
                "Configured path to suricata does not exist: %s" % (
                    _config["suricata"]))
    else:
        suricata_path = suricata.update.engine.get_path()
        if not suricata_path:
            logger.warning("No suricata application binary found on path.")
        else:
            _config["suricata"] = suricata_path

    if "suricata" in _config:
        build_info = suricata.update.engine.get_build_info(_config["suricata"])

        # Set the first suricata.yaml to check for to the one in the
        # --sysconfdir provided by build-info.
        if not "suricata_conf" in _config and "sysconfdir" in build_info:
            DEFAULT_SURICATA_YAML_PATH.insert(
                0, os.path.join(
                    build_info["sysconfdir"], "suricata/suricata.yaml"))

        # Amend the path to look for Suricata provided rules based on
        # the build info. As we are inserting at the front, put the
        # highest priority path last.
        if "sysconfdir" in build_info:
            DEFAULT_DIST_RULE_PATH.insert(
                0, os.path.join(build_info["sysconfdir"], "suricata/rules"))
        if "datarootdir" in build_info:
            DEFAULT_DIST_RULE_PATH.insert(
                0, os.path.join(build_info["datarootdir"], "suricata/rules"))

        # Set the data-directory prefix to that of the --localstatedir
        # found in the build-info.
        if not DATA_DIRECTORY_KEY in _config and "localstatedir" in build_info:
            data_directory = os.path.join(
                build_info["localstatedir"], "lib/suricata")
            logger.info("Using data-directory %s.", data_directory)
            _config[DATA_DIRECTORY_KEY] = data_directory

    # If suricata-conf not provided on the command line or in the
    # configuration file, look for it.
    if not "suricata-conf" in _config:
        for conf in DEFAULT_SURICATA_YAML_PATH:
            if os.path.exists(conf):
                logger.info("Using Suricata configuration %s" % (conf))
                _config["suricata-conf"] = conf
                break

    if not DIST_RULE_DIRECTORY_KEY in _config:
        for path in DEFAULT_DIST_RULE_PATH:
            if os.path.exists(path):
                logger.info("Using %s for Suricata provided rules.", path)
                _config[DIST_RULE_DIRECTORY_KEY] = path
                break
