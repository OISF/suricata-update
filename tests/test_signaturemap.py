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

from suricata.update import maps

class SignatureMapTestCase(unittest.TestCase):

    def test_load_generator_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_generator_map(open("tests/gen-msg.map"))

        sig = sigmap.get(1, 1)
        self.assertTrue(sig is not None)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(1, sig["sid"])
        self.assertEqual("snort general alert", sig["msg"])

        sig = sigmap.get(139, 1)
        self.assertTrue(sig is not None)
        self.assertEqual(139, sig["gid"])
        self.assertEqual(1, sig["sid"])
        self.assertEqual(
            "sensitive_data: sensitive data global threshold exceeded",
            sig["msg"])

    def test_load_signature_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_signature_map(open("tests/sid-msg.map"))

        # Get a basic signature.
        sig = sigmap.get(1, 2000356)
        self.assertTrue(sig is not None)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(2000356, sig["sid"])
        self.assertEqual("ET POLICY IRC connection", sig["msg"])
        self.assertEqual(len(sig["ref"]), 1)
        self.assertEqual("url,doc.emergingthreats.net/2000356", sig["ref"][0])

        # Try again but with a gid of 3.
        self.assertEqual(sig, sigmap.get(3, 2000356))

        # This signature has multiple refs.
        sig = sigmap.get(1, 2000373)
        self.assertEqual(3, len(sig["ref"]))

        sig = sigmap.get(1, 71918985)
        self.assertEqual(
            "SN: Inbound TCP traffic from suspect network (AS29073 - NL)",
            sig["msg"])

    def test_load_signature_v2_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_signature_map(open("tests/sid-msg-v2.map"))

        sig = sigmap.get(1, 2495)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(2495, sig["sid"])
        self.assertEqual("misc-attack", sig["classification"])
        self.assertEqual(0, sig["priority"])
        self.assertEqual(
            "GPL NETBIOS SMB DCEPRC ORPCThis request flood attempt",
            sig["msg"])
        self.assertEqual(4, len(sig["ref"]))
