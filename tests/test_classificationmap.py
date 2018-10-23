# Copyright (C) 2017 Open Information Security Foundation
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

import unittest

from suricata.update.maps import ClassificationMap

class ClassificationMapTestCase(unittest.TestCase):

    test_filename = "tests/classification.config"

    def test_load_from_file(self):
        m = ClassificationMap(open(self.test_filename))

        # Classifications are indexed at 1.
        self.assertEqual(None, m.get(0))

        c = m.get(1)
        self.assertEqual("not-suspicious", c["name"])
        self.assertEqual("Not Suspicious Traffic", c["description"])
        self.assertEqual(3, c["priority"])

        c = m.get(34)
        self.assertEqual("default-login-attempt", c["name"])
        self.assertEqual("Attempt to login by a default username and password",
                          c["description"])
        self.assertEqual(2, c["priority"])

        c = m.get_by_name("unknown")
        self.assertTrue(c is not None)
        self.assertEqual("unknown", c["name"])
        self.assertEqual("Unknown Traffic", c["description"])
        self.assertEqual(3, c["priority"])
