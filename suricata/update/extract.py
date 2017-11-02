# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2017 Jason Ish
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

import tarfile
from zipfile import ZipFile

def extract_tar(filename):
    files = {}

    tf = tarfile.open(filename, mode="r:*")

    try:
        while True:
            member = tf.next()
            if member is None:
                break
            if not member.isfile():
                continue
            fileobj = tf.extractfile(member)
            if fileobj:
                files[member.name] = fileobj.read()
    finally:
        tf.close()

    return files

def extract_zip(filename):
    files = {}

    with ZipFile(filename) as reader:
        for name in reader.namelist():
            if name.endswith("/"):
                continue
            files[name] = reader.read(name)
    
    return files

def try_extract(filename):
    try:
        return extract_tar(filename)
    except:
        pass

    try:
        return extract_zip(filename)
    except:
        pass
    
    return None
