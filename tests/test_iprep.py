# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2011-2013 Michael Schem
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

import sys
import unittest
import io
import tempfile

import suricata.update.iprep


class RuleTestCase(unittest.TestCase):

    def test_parse_iprep_parse(self):
        """ Test parsing an iprep directive."""
        iprep_string = u"52.0.161.90,3,1"
        iprep = suricata.update.iprep.parse(iprep_string)
        self.assertIsNotNone(iprep)
        self.assertTrue(iprep['raw'] == "52.0.161.90,3,1")
        self.assertTrue(iprep['ip'] == "52.0.161.90")
        self.assertTrue(iprep['category'] == 3)
        self.assertTrue(iprep['reputation_score'] == 1)
        self.assertTrue(str(iprep) == iprep_string)

    def test_parse_disabled_iprep_parse(self):
        """ Test parsing a disabled iprep directive."""
        iprep_string = u"# 52.0.161.90,3,127"
        iprep = suricata.update.iprep.parse(iprep_string)
        self.assertIsNotNone(iprep)
        self.assertTrue(iprep['raw'] == "52.0.161.90,3,127")
        self.assertTrue(iprep['ip'] == "52.0.161.90")
        self.assertTrue(iprep['category'] == 3)
        self.assertTrue(iprep['reputation_score'] == 127)
        self.assertTrue(str(iprep) == iprep_string)

    def test_parse_bad_iprep_score(self):
        """ Test parsing a iprep directive with a bad reputation_score """
        iprep_string = u"52.0.161.90,3,150"
        self.assertRaises(
            suricata.update.iprep.BadIprepError,
            suricata.update.iprep.parse, iprep_string)

    def test_parse_bad_ip_addresss(self):
        """ Test parsing of a iprep with a bad IP Address """
        bad_iprep_string = u"52.0.161.300,3,150"
        self.assertRaises(
            suricata.update.iprep.BadIprepError,
            suricata.update.iprep.parse, bad_iprep_string
        )

    def test_parse_fileobj(self):
        """ Test parsing a file like object containing ipreps """
        ipreps_buf = u"""52.0.161.90,3,125\n
                        52.0.161.91,3,126\n
                        52.0.161.92,3,127\n
                        """
        fileobj = io.StringIO()
        fileobj.write(u"%s\n" % ipreps_buf)
        fileobj.seek(0)
        ipreps = suricata.update.iprep.parse_fileobj(fileobj,suricata.update.iprep.parse)
        self.assertEqual(len(ipreps), 3)
