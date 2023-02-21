# Copyright (C) 2017-2019 Open Information Security Foundation
# Copyright (c) 2011 Jason Ish
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

""" Module for parsing Snort-like rules.

Parsing is done using regular expressions and the job of this module
is to do its best at parsing out fields of interest from the rule
rather than perform a sanity check.

The methods that parse multiple rules for a provided input
(parse_file, parse_fileobj) return a list of rules instead of dict
keyed by ID as its not the job of this module to detect or deal with
duplicate signature IDs.
"""

from __future__ import print_function

from suricata.update import fileparser

import sys
import re
import logging
import io

logger = logging.getLogger(__name__)

# Compile a re pattern for basic iprep directive matching
iprep_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                           r"(?P<raw>"
                           # r"(?P<header>[^()]+)"
                           r"(?P<ip>\d+\.\d+\.\d+\.\d+),"
                           r"(?P<category>\d+),"
                           r"(?P<reputation_score>\d+)"
                           r"$)")

ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.("
                        r"25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.("
                        r"25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.("
                        r"25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$")

class Iprep(dict):
    """ Class representing an iprep directive

    The iprep directive is a class that also acts like a dictionary.

    Dictionary fields:

    - **group**: The group the rule belongs to, typically the filename.
    - **enabled**: True if rule is enabled (uncommented), False is
      disabled (commented)
    - **ip**: The ip address of the directive.
    - **category**: The IP is an IPv4 address in the quad-dotted notation or an IPv6 address. Both IP types support
      networks in CIDR notation.
    - **reputation_score**: The reputation score is the confidence that this IP is in the specified category,
      represented by a number between 1 and 127 (0 means no data).

    :param enabled: Optional parameter to set the enabled state of the rule
    :param group: Optional parameter to set the group (filename) of the rule

    """

    def __init__(self, enabled=None, group=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self['ip'] = None
        self['category'] = None
        self['reputation_score'] = None
        self["group"] = group

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the directive.

        :returns: A tuple (ip, category, reputation_score) representing the ID of the directive
        :rtype: A tuple of 2 ints and one str
        """
        return (str(self.ip), int(self.category), int(self.reputation_score))

    @property
    def idstr(self):
        """Return the ip, category, and reputation score of the iprep directive as a string formatted like:
        '[IP:CAT:REP]'"""
        return "[%s:%s:%s]" % (str(self.ip), str(self.category), str(self.reputation_score))

    def __str__(self):
        """ The string representation of the directive.

        If the directive is disabled it will be returned as commented out.
        """
        return self.format()

    def format(self):
        return "{0}{1},{2},{3}".format(u"" if self["enabled"] else u"# ",
                                       self['ip'],
                                       self['category'],
                                       self['reputation_score'])


class BadIprepError(Exception):
    """Raises exception when an invalid Iprep is created"""


def parse(buf, group=None):
    """ Parse a single iprep directive from a string buffer.

    :param buf:  A string buffer containing a single iprep derective

    :returns: An instance of a :py:class:`.Iprep` representing the parsed iprep directive
    """

    if type(buf) == type(b""):
        buf = buf.decode("utf-8")
    buf = buf.strip()

    m = iprep_pattern.match(buf)
    if not m:
        return None

    if m.group("enabled") == "#":
        enabled = False
    else:
        enabled = True

    # header = m.group("header").strip()

    iprep = Iprep(enabled=enabled, group=group)

    iprep['ip'] = m.group('ip')

    if not ip_pattern.search(iprep['ip']):
        logging.error("Invalid iprep IP address. {0}".format(iprep['ip']))
        raise BadIprepError

    iprep['category'] = int(m.group('category'))

    iprep['reputation_score'] = int(m.group('reputation_score'))

    if not 0 <= iprep['reputation_score'] <= 127:
        raise BadIprepError("Invalid reputation score of {0}".format(iprep['reputation_score']))

    iprep["raw"] = m.group("raw").strip()

    return iprep


def parse_fileobj(fileobj, group=None):
    """ Parse multiple ipreps from a file like object.

    Note: At this time ipreps must exist on one line.

    :param fileobj: A file like object to parse rules from.

    :returns: A list of :py:class:`.Iprep` instances, one for each rule parsed
    """
    return fileparser.parse_fileobj(fileobj, parse, group)


def parse_file(filename, group=None):
    """ Parse multiple ipreps from the provided filename.

    :param filename: Name of file to parse ipreps from

    :returns: A list of :py:class:`.Iprep` instances, one for each iprep parsed
    """
    with io.open(filename, encoding="utf-8") as fileobj:
        return parse_fileobj(fileobj, group)
