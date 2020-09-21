# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2011-2020 Michael Schem
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

import suricata.update.category

class CategoryTestCase(unittest.TestCase):

    def test_parse1(self):
        category = suricata.update.category.parse("3,IntelData,Threat Intelligence Data")
        self.assertEqual(category.enabled, True)
        self.assertEqual(category.id, 3)
        self.assertEqual(category.short_name, "IntelData")
        self.assertEqual(category.description, "Threat Intelligence Data")
        self.assertEqual(category.idstr, "[3]")
        self.assertEqual(str(category), "3,IntelData,Threat Intelligence Data")

    def test_bad_id(self):
        category = suricata.update.category.parse("61,IntelData,Threat Intelligence Data")
        self.assertEqual(category, None)

    def test_disabled_category(self):
        category = suricata.update.category.parse("# 3,IntelData,Threat Intelligence Data")
        self.assertEqual(category.enabled, False)

        category = suricata.update.category.parse("#3,IntelData,Threat Intelligence Data")
        self.assertEqual(category.enabled, False)
