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

from __future__ import print_function

import unittest
import tempfile

from suricata.update import util

class Md5TestCase(unittest.TestCase):

    def test_hexdigest(self):
        test_file = tempfile.NamedTemporaryFile()
        test_file.write(b"This is a test.")
        test_file.flush()
        self.assertEqual(
            "120ea8a25e5d487bf68b5f7096440019",
            util.md5_hexdigest(test_file.name))
