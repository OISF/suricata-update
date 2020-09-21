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

""" Module for files with either rules, ipreps, or category files.

Parse funcitons

"""

from __future__ import print_function

import sys
import re
import logging
import io


logger = logging.getLogger(__name__)


def parse_fileobj(fileobj, parse, group=None):
    """ Parse multiple line based items from a file like object.

    Note: At this point items must exist on one line

    :param fileobj: A file like object to parse items from.
    :param parse: A function used to parse items.

    :returns: A list of :py:class:`.Rule`, :py:class:`.Iprep`, or :py:class:`.Category`
    instances depending on what parsing function is passed in.
    """
    items = []
    buf = ""
    for line in fileobj:
        try:
            if type(line) == type(b""):
                line = line.decode()
        except:
            pass
        if line.rstrip().endswith("\\"):
            buf = "%s%s " % (buf, line.rstrip()[0:-1])
            continue
        buf = buf + line
        try:
            item = parse(buf, group)
            if item:
                items.append(item)
        except Exception as err:
            logger.error("Failed to parse: %s: %s", buf.rstrip(), err)
        buf = ""
    return items


def parse_file(filename, group=None):
    """ Parse multiple rules from the provided filename.

    :param filename: Name of file to parse ipreps from

    :returns: A list of .rules files or :py:class:`.Iprep` instances
    for .list files, one for each rule parsed
    """
    with io.open(filename, encoding="utf-8") as fileobj:
        return parse_fileobj(fileobj, group)
