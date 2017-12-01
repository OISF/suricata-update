# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2013 Jason Ish
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

""" Module for utility functions that don't really fit anywhere else. """

import hashlib
import tempfile
import atexit
import shutil
import zipfile

def md5_hexdigest(filename):
    """ Compute the MD5 checksum for the contents of the provided filename.

    :param filename: Filename to computer MD5 checksum of.

    :returns: A string representing the hex value of the computed MD5.
    """
    return hashlib.md5(open(filename).read().encode()).hexdigest()

def mktempdir(delete_on_exit=True):
    """ Create a temporary directory that is removed on exit. """
    tmpdir = tempfile.mkdtemp("suricata-update")
    if delete_on_exit:
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    return tmpdir

class ZipArchiveReader:

    def __init__(self, zipfile):
        self.zipfile = zipfile
        self.names = self.zipfile.namelist()

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.zipfile.close()

    def next(self):
        if self.names:
            name = self.names.pop(0)
            if name.endswith("/"):
                # Is a directory, ignore
                return self.next()
            return name
        raise StopIteration

    def open(self, name):
        return self.zipfile.open(name)

    def read(self, name):
        return self.zipfile.read(name)

    @classmethod
    def from_fileobj(cls, fileobj):
        zf = zipfile.ZipFile(fileobj)
        return cls(zf)

GREEN = "\x1b[32m"
BLUE = "\x1b[34m"
REDB = "\x1b[1;31m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
YELLOWB = "\x1b[1;33m"
ORANGE = "\x1b[38;5;208m"
BRIGHT_MAGENTA = "\x1b[1;35m"
BRIGHT_CYAN = "\x1b[1;36m"
RESET = "\x1b[0m"

def blue(msg):
    return "%s%s%s" % (BLUE, msg, RESET)

def bright_magenta(msg):
    return "%s%s%s" % (BRIGHT_MAGENTA, msg, RESET)

def bright_cyan(msg):
    return "%s%s%s" % (BRIGHT_CYAN, msg, RESET)
