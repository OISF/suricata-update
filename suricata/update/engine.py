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

import sys
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

def get_build_info(suricata):
    build_info = {
        "features": [],
    }
    build_info_output = subprocess.check_output([suricata, "--build-info"])
    for line in build_info_output.decode("utf-8").split("\n"):
        line = line.strip()
        if line.startswith("--prefix"):
            build_info["prefix"] = line.split()[-1].strip()
        elif line.startswith("--sysconfdir"):
            build_info["sysconfdir"] = line.split()[-1].strip()
        elif line.startswith("--localstatedir"):
            build_info["localstatedir"] = line.split()[-1].strip()
        elif line.startswith("--datarootdir"):
            build_info["datarootdir"] = line.split()[-1].strip()
        elif line.startswith("Features:"):
            build_info["features"] = line.split()[1:]
        elif line.startswith("This is Suricata version"):
            build_info["version"] = parse_version(line)

    if not "prefix" in build_info:
        logger.warning("--prefix not found in build-info.")
    if not "sysconfdir" in build_info:
        logger.warning("--sysconfdir not found in build-info.")
    if not "localstatedir" in build_info:
        logger.warning("--localstatedir not found in build-info.")

    return build_info

class Configuration:
    """An abstraction over the Suricata configuration file."""

    def __init__(self, conf, build_info = {}):
        self.conf = conf
        self.build_info = build_info

    def keys(self):
        return self.conf.keys()

    def has_key(self, key):
        return key in self.conf

    def get(self, key):
        return self.conf.get(key, None)

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
        env = build_env()
        env["SC_LOG_LEVEL"] = "Error"
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
        build_info = get_build_info(suricata_path)
        return cls(conf, build_info)

def get_path(program="suricata"):
    """Find Suricata in the shell path."""
    # First look for Suricata relative to suricata-update.
    relative_path = os.path.join(os.path.dirname(sys.argv[0]), "suricata")
    if os.path.exists(relative_path):
        logger.debug("Found suricata at %s" % (relative_path))
        return relative_path

    # Otherwise look for it in the path.
    for path in os.environ["PATH"].split(os.pathsep):
        if not path:
            continue
        suricata_path = os.path.join(path, program)
        logger.debug("Looking for %s in %s" % (program, path))
        if os.path.exists(suricata_path):
            logger.debug("Found %s." % (suricata_path))
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

def get_version(path):
    """Get a SuricataVersion named tuple describing the version.

    If no path argument is found, the envionment PATH will be
    searched.
    """
    if not path:
        return None
    output = subprocess.check_output([path, "-V"])
    if output:
        return parse_version(output)
    return None

def test_configuration(suricata_path, suricata_conf=None, rule_filename=None):
    """Test the Suricata configuration with -T."""
    test_command = [
        suricata_path,
        "-T",
        "-l", "/tmp",
    ]
    if suricata_conf:
        test_command += ["-c", suricata_conf]
    if rule_filename:
        test_command += ["-S", rule_filename]

    env = build_env()
    env["SC_LOG_LEVEL"] = "Warning"

    logger.debug("Running %s; env=%s", " ".join(test_command), str(env))
    rc = subprocess.Popen(test_command, env=env).wait()
    if rc == 0:
        return True
    return False

def build_env():
    env = os.environ.copy()
    env["SC_LOG_FORMAT"] = "%t - <%d> -- "
    env["SC_LOG_LEVEL"] = "Error"
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    return env
