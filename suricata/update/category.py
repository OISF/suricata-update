# Copyright (C) 2017-2019 Open Information Security Foundation
# Copyright (c) 2020 Michael Schem
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

""" Module for parsing categories.txt files.

Parsing is done using regular expressions and the job of the module is
to do its best at parsing out fields of interest from the categories file
rather than perform a sanity check.

"""

from __future__ import print_function

from suricata.update import fileparser

import io
import re
import logging

logger = logging.getLogger(__name__)

# Compile a re pattern for basic iprep directive matching
category_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                              r"(?P<id>\d+),"
                              r"(?P<short_name>\w+),"
                              r"(?P<description>.*$)")

class Category(dict):
    """ Class representing an iprep category

    The category class also acts like a dictionary.

    Dictionary fields:

    - **enabled**: True if the category is enabled (uncommented), false is
      disabled (commented)
    - **id**: The maximum value for the category id is hard coded at 60
      currently (Suricata 5.0.3).
    - **short_name**: The shortname that refers to the category.
    - **description**: A description of the category.

    :param enabled: Optional parameter to set the enabled state of the category

    """

    def __init__(self, enabled=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self["id"] = None
        self["short_name"] = None
        self["description"] = None

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the category.

        :returns: An int ID of the category
        :rtype: int
        """
        return int(self["id"])

    @property
    def idstr(self):
        """Return the gid and sid of the rule as a string formatted like:
        '[id]'"""
        return "[%s]" % str(self.id)

    def __str__(self):
        """ The string representation of the category.

        If the category is disabled it will be returned as commented out.
        """
        return self.format()

    def format(self):
        return "{0}{1},{2},{3}".format(u"" if self["enabled"] else u"# ",
                                       self['id'],
                                       self['short_name'],
                                       self['description'])


def parse(buf, group=None):
    """ Parse a single Iprep category from a string buffer.

    :param buf: A string buffer containing a single Iprep category.

    :returns: An instance of a :py:class:`.Category` representing the parsed Iprep category
    """

    if type(buf) == type(b""):
        buf = buf.decode("utf-8")
    buf = buf.strip()

    m = category_pattern.match(buf)
    if not m:
        return None

    if m.group("enabled") == "#":
        enabled = False
    else:
        enabled = True

    # header = m.group("header").strip()

    category = Category(enabled=enabled)

    category["id"] = int(m.group("id").strip())

    if not 0 < category["id"] < 60:
        logging.error("Category id of {0}, not valid. Id is required to be between 0 and 60.".format(category["id"]))
        return None

    category["short_name"] = m.group("short_name").strip()

    category["description"] = m.group("description").strip()

    return category


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

