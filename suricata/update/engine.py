# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2015 Jason Ish
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

# This module contains functions for interacting with the Suricata
# application (aka the engine).

from __future__ import print_function

import os
import os.path
import subprocess
import re
import logging
import yaml
from collections import namedtuple

logger = logging.getLogger()

SuricataVersion = namedtuple(
    "SuricataVersion", ["major", "minor", "patch", "full", "short", "raw"])

class Configuration:
    """An abstraction over the Suricata configuration file."""

    def __init__(self, conf):
        self.conf = conf

    def keys(self):
        return self.conf.keys()

    def is_true(self, key, truthy=[]):
        if not key in self.conf:
            logger.warning(
                "Suricata configuration key does not exist: %s" % (key))
            return False
        if key in self.conf:
            val = self.conf[key]
            if val.lower() in ["1", "yes", "true"] + truthy:
                return True
        return False

    @classmethod
    def load(cls, config_filename, suricata_path=None):
        env = {
            "SC_LOG_FORMAT": "%t - <%d> -- ",
            "SC_LOG_LEVEL": "Error",
            "ASAN_OPTIONS": "detect_leaks=0",
        }
        if not suricata_path:
            suricata_path = get_path()
        if not suricata_path:
            raise Exception("Suricata program could not be found.")
        if not os.path.exists(suricata_path):
            raise Exception("Suricata program %s does not exist.", suricata_path)
        configuration_dump = subprocess.check_output(
            [suricata_path, "-c", config_filename, "--dump-config"],
            env=env)
        conf = {}
        for line in configuration_dump.splitlines():
            try:
                key, val = line.decode().split(" = ")
                conf[key] = val
            except:
                logger.warning("Failed to parse: %s", line)
        return cls(conf)

def get_path(program="suricata"):
    """Find Suricata in the shell path."""
    for path in os.environ["PATH"].split(os.pathsep):
        if not path:
            continue
        suricata_path = os.path.join(path, program)
        logger.debug("Testing path: %s" % (path))
        if os.path.exists(suricata_path):
            logger.debug("Found %s." % (path))
            return suricata_path
    return None

def parse_version(buf):
    m = re.search("((\d+)\.(\d+)(\.(\d+))?([\w\-]+)?)", str(buf).strip())
    if m:
        full = m.group(1)
        major = int(m.group(2))
        minor = int(m.group(3))
        if not m.group(5):
            patch = 0
        else:
            patch = int(m.group(5))
        short = "%s.%s" % (major, minor)
        return SuricataVersion(
            major=major, minor=minor, patch=patch, short=short, full=full,
            raw=buf)
    return None

def get_version(path=None):
    """Get a SuricataVersion named tuple describing the version.

    If no path argument is found, the envionment PATH will be
    searched.
    """
    if not path:
        path = get_path("suricata")
    if not path:
        return None
    output = subprocess.check_output([path, "-V"])
    if output:
        return parse_version(output)
    return None

def test_configuration(path, rule_filename=None):
    """Test the Suricata configuration with -T."""
    test_command = [
        path,
        "-T",
        "-l", "/tmp",
    ]
    if rule_filename:
        test_command += ["-S", rule_filename]

    # This makes the Suricata output look just like suricata-udpate
    # output.
    env = {
        "SC_LOG_FORMAT": "%t - <%d> -- ",
        "SC_LOG_LEVEL": "Warning",
        "ASAN_OPTIONS": "detect_leaks=0",
    }

    rc = subprocess.Popen(test_command, env=env).wait()
    if rc == 0:
        return True
    return False
