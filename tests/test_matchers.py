# Copyright (C) 2018 Open Information Security Foundation
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

import os
import io
import unittest

import suricata.update.rule
from suricata.update import main
import suricata.update.extract

class GroupMatcherTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_match(self):
        rule = suricata.update.rule.parse(self.rule_string, "rules/malware.rules")
        matcher = main.parse_rule_match("group: malware.rules")
        self.assertEqual(
            matcher.__class__, suricata.update.main.GroupMatcher)
        self.assertTrue(matcher.match(rule))

        # Test match of just the group basename.
        matcher = main.parse_rule_match("group: malware")
        self.assertEqual(
            matcher.__class__, suricata.update.main.GroupMatcher)
        self.assertTrue(matcher.match(rule))

class FilenameMatcherTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_match(self):
        rule = suricata.update.rule.parse(self.rule_string, "rules/trojan.rules")
        matcher = main.parse_rule_match("filename: */trojan.rules")
        self.assertEqual(
            matcher.__class__, suricata.update.main.FilenameMatcher)
        self.assertTrue(matcher.match(rule))

class LoadMatchersTestCase(unittest.TestCase):

    def test_trailing_comment(self):
        """Test loading matchers with a trailing comment."""
        matchers = main.parse_matchers(io.StringIO(u"""filename: */trojan.rules
re:.# This is a comment*
1:100 # Trailing comment.
"""))
        self.assertEqual(
            matchers[0].__class__, suricata.update.main.FilenameMatcher)
        self.assertEqual(
            matchers[1].__class__, suricata.update.main.ReRuleMatcher)
        self.assertEqual(
            matchers[2].__class__, suricata.update.main.IdRuleMatcher)

class IdRuleMatcherTestCase(unittest.TestCase):

    def test_parse_single_sid(self):
        matcher = main.IdRuleMatcher.parse("123")
        self.assertIsNotNone(matcher)
        self.assertEqual(1, len(matcher.signatureIds))

    def test_parse_single_gidsid(self):
        matcher = main.IdRuleMatcher.parse("1:123")
        self.assertIsNotNone(matcher)
        self.assertEqual(1, len(matcher.signatureIds))

    def test_parse_multi_sid(self):
        matcher = main.IdRuleMatcher.parse("1,2,3")
        self.assertIsNotNone(matcher)
        self.assertEqual(3, len(matcher.signatureIds))

    def test_parse_multi_gidsid(self):
        matcher = main.IdRuleMatcher.parse("1:1000,2:2000,    3:3000, 4:4000")
        self.assertIsNotNone(matcher)
        self.assertEqual(4, len(matcher.signatureIds))

    def test_parse_multi_mixed(self):
        matcher = main.IdRuleMatcher.parse("1:1000, 2000, 3:3000, 4000")
        self.assertIsNotNone(matcher)
        self.assertEqual(4, len(matcher.signatureIds))

    def test_parse_invalid(self):
        matcher = main.IdRuleMatcher.parse("a")
        self.assertIsNone(matcher)

        matcher = main.IdRuleMatcher.parse("1, a")
        self.assertIsNone(matcher)

        matcher = main.IdRuleMatcher.parse("1a")
        self.assertIsNone(matcher)

        matcher = main.IdRuleMatcher.parse("1:a")
        self.assertIsNone(matcher)
