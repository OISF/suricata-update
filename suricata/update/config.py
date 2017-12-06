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

logger = logging.getLogger()

DEFAULT_STATE_DIRECTORY = "/var/lib/suricata"

# Configuration keys.
STATE_DIRECTORY_KEY = "state-directory"
CACHE_DIRECTORY_KEY = "cache-directory"
IGNORE_KEY = "ignore"
DISABLE_CONF_KEY = "disable-conf"
ENABLE_CONF_KEY = "enable-conf"
MODIFY_CONF_KEY = "modify-conf"
DROP_CONF_KEY = "drop-conf"
LOCAL_CONF_KEY = "local"

DEFAULT_UPDATE_YAML_PATH = "/etc/suricata/update.yaml"

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

def set(key, value):
    """Set a configuration value."""
    _config[key] = value

def get(key):
    """Get a configuration value."""
    if key in _config:
        return _config[key]
    return None

def set_state_dir(directory):
    _config[STATE_DIRECTORY_KEY] = directory

def get_state_dir():
    if STATE_DIRECTORY_KEY in _config:
        return _config[STATE_DIRECTORY_KEY]
    return DEFAULT_STATE_DIRECTORY

def set_cache_dir(directory):
    """Set an alternate cache directory."""
    _config[CACHE_DIRECTORY_KEY] = directory

def get_cache_dir():
    """Get the cache directory."""
    if CACHE_DIRECTORY_KEY in _config:
        return _config[CACHE_DIRECTORY_KEY]
    return os.path.join(_args.output, ".cache")

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

    _args = args
    _config.update(DEFAULT_CONFIG)

    if args.config:
        logger.info("Loading %s", args.config)
        with open(args.config, "rb") as fileobj:
            config = yaml.load(fileobj)
            if config:
                _config.update(config)
    elif os.path.exists(DEFAULT_UPDATE_YAML_PATH):
        logger.info("Loading %s", DEFAULT_UPDATE_YAML_PATH)
        with open(DEFAULT_UPDATE_YAML_PATH, "rb") as fileobj:
            config = yaml.load(fileobj)
            if config:
                _config.update(config)

    # Apply command line arguments to the config.

    for arg in vars(args):
        if arg == "local":
            for local in args.local:
                logger.debug("Adding local ruleset to config: %s", local)
                _config[LOCAL_CONF_KEY].append(local)
        elif arg == "data_dir":
            logger.debug("Setting data directory to %s", args.data_dir)
            _config[DATA_DIRECTORY_KEY] = args.data_dir
        elif getattr(args, arg):
            _config[arg.replace("_", "-")] = getattr(args, arg)
