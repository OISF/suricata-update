# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2015 Jason Ish
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
from suricata.update import matchers as matchers_mod

class TestRulecat(unittest.TestCase):

    def test_extract_tar(self):
        files = suricata.update.extract.extract_tar(
            "tests/emerging.rules.tar.gz")
        self.assertTrue(len(files) > 0)

    def test_extract_zip(self):
        files = suricata.update.extract.extract_zip(
            "tests/emerging.rules.zip")
        self.assertTrue(len(files) > 0)

    def test_try_extract(self):
        files = suricata.update.extract.try_extract(
            "tests/emerging.rules.zip")
        self.assertTrue(len(files) > 0)

        files = suricata.update.extract.try_extract(
            "tests/emerging.rules.tar.gz")
        self.assertTrue(len(files) > 0)

        files = suricata.update.extract.try_extract(
            "tests/emerging-current_events.rules")
        self.assertIsNone(files)

class TestFetch(unittest.TestCase):

    def test_check_checksum(self):
        """Test that we detect when the checksum are the same. This is mainly
        to catch issues between Python 2 and 3.
        """
        fetch = main.Fetch()
        url = "file://%s/emerging.rules.tar.gz" % (
            os.path.dirname(os.path.realpath(__file__)))
        local_file = "%s/emerging.rules.tar.gz" % (
            os.path.dirname(os.path.realpath(__file__)))

        # The URL passed to check_checksum is actually a tuple:
        #    (url, custom-header, has checksum url)
        net_arg = (url, None, True)

        r = fetch.check_checksum(local_file, net_arg)
        self.assertTrue(r)

class ThresholdProcessorTestCase(unittest.TestCase):

    processor = main.ThresholdProcessor()

    def test_extract_regex(self):
        processor = main.ThresholdProcessor()

        line = "suppress re:java"
        self.assertEqual("java", processor.extract_regex(line))
        
        line = 'suppress re:"vulnerable java version"'
        self.assertEqual(
            "vulnerable java version", processor.extract_regex(line))

        line = "suppress re:java, track <by_src|by_dst>, ip <ip|subnet>"
        self.assertEqual("java", processor.extract_regex(line))
    
        line = 'suppress re:"vulnerable java version", track <by_src|by_dst>, ip <ip|subnet>'
        self.assertEqual(
            "vulnerable java version", processor.extract_regex(line))

        line = 'threshold re:"vulnerable java version", type threshold, track by_dst, count 1, seconds 10'
        self.assertEqual(
            "vulnerable java version", processor.extract_regex(line))

    def test_replace(self):
        rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule = suricata.update.rule.parse(rule_string)

        line = "suppress re:windows"
        self.assertEqual(
            "suppress gen_id 1, sig_id 2020757",
            self.processor.replace(line, rule))

        bad_line = "nothing to match"
        self.assertEqual(
            "nothing to match",
            self.processor.replace(bad_line, rule)
        )

        line = 'threshold re:"ET MALWARE Windows", type threshold, ' \
               'track by_dst, count 1, seconds 10'
        self.assertEqual("threshold gen_id 1, sig_id 2020757, type threshold, track by_dst, count 1, seconds 10", self.processor.replace(line, rule))

        line = 'threshold re:malware, type threshold, track by_dst, count 1, ' \
               'seconds 10'
        self.assertEqual(
            "threshold gen_id 1, sig_id 2020757, type threshold, "
            "track by_dst, count 1, seconds 10",
            self.processor.replace(line, rule))

class ModifyRuleFilterTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_id_match(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = '2020757 "\|0d 0a\|" "|ff ff|"'
        rule_filter = matchers_mod.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.run(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

    def test_re_match(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "\|0d 0a\|" "|ff ff|"'
        rule_filter = matchers_mod.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.run(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

    def test_re_backref_one(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "(alert)(.*)" "drop\\2"'
        rule_filter = matchers_mod.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.run(rule0)
        expected = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        self.assertEqual(str(rule1), expected)

    def test_re_backref_two(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "(alert)(.*)(from_server)(.*)" "drop\\2to_client\\4"'
        rule_filter = matchers_mod.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.run(rule0)
        expected = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        self.assertEqual(str(rule1), expected)

    def test_drop_to_alert(self):
        rule_in = suricata.update.rule.parse(self.rule_string)
        self.assertIsNotNone(rule_in)

        f = matchers_mod.ModifyRuleFilter.parse(
            'group:emerging-trojan.rules "^alert" "drop"')
        self.assertIsNotNone(f)

        rule_out = f.run(rule_in)
        self.assertTrue(rule_out.format().startswith("drop"))

    def test_oinkmaster_backticks(self):
        f = matchers_mod.ModifyRuleFilter.parse(
            '* "^drop(.*)noalert(.*)" "alert${1}noalert${2}"')
        rule_in ="""drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; noalert; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule_out = f.run(suricata.update.rule.parse(rule_in))
        self.assertEqual("""alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; noalert; classtype:trojan-activity; sid:2020757; rev:2;)""", rule_out.format())

    def test_oinkmaster_backticks_not_noalert(self):
        f = matchers_mod.ModifyRuleFilter.parse(
            'modifysid * "^drop(.*)noalert(.*)" | "alert${1}noalert${2}"')
        rule_in ="""drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule_out = f.run(suricata.update.rule.parse(rule_in))
        self.assertEqual(rule_in, rule_out.format())

    def test_oinkmaster_modify_group_name(self):
        """Test an Oinkmaster style modification line using a group name."""
        f = matchers_mod.ModifyRuleFilter.parse(
            'modifysid botcc.rules "^alert" | "drop"')
        rule_in ="""alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule = suricata.update.rule.parse(rule_in, "rules/botcc.rules")
        rule_out = f.run(rule)
        self.assertTrue(rule_out.format().startswith("drop"))

class DropRuleFilterTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_enabled_rule(self):
        rule0 = suricata.update.rule.parse(self.rule_string, "rules/malware.rules")
        id_matcher = matchers_mod.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = matchers_mod.DropRuleFilter(id_matcher)
        rule1 = drop_filter.run(rule0)
        self.assertEqual("drop", rule1.action)
        self.assertTrue(rule1.enabled)
        self.assertTrue(str(rule1).startswith("drop"))

    def test_disabled_rule(self):
        rule0 = suricata.update.rule.parse(
            "# " + self.rule_string, "rules/malware.rules")
        id_matcher = matchers_mod.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = matchers_mod.DropRuleFilter(id_matcher)
        rule1 = drop_filter.run(rule0)
        self.assertEqual("drop", rule1.action)
        self.assertFalse(rule1.enabled)
        self.assertTrue(str(rule1).startswith("# drop"))
        
    def test_drop_noalert(self):
        """ Test the rules with "noalert" are not marked as drop. """

        rule_without_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule_with_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; flowbits: noalert; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule = suricata.update.rule.parse(rule_without_noalert)
        matcher = matchers_mod.IdRuleMatcher.parse("2016659")
        rule_filter = matchers_mod.DropRuleFilter(matcher)
        self.assertTrue(rule_filter.match(rule))

        rule = suricata.update.rule.parse(rule_with_noalert)
        matcher = matchers_mod.IdRuleMatcher.parse("2016659")
        rule_filter = matchers_mod.DropRuleFilter(matcher)
        self.assertFalse(rule_filter.match(rule))


class DummySuriConf(dict):
    def __getattr__(self, val):
        return self[val]


class ClassificationConfigMergeTestCase(unittest.TestCase):
    test_fname1 = "tests/classification1.config"
    test_fname2 = "tests/classification2.config"

    def test_merge_classification_files(self):
        """ Test if the two files get merged properly and priority is maintained"""
        suriconf = DummySuriConf()
        suriconf["build_info"] = {}
        with open(self.test_fname1) as fp:
            test_file1 = fp.read()
        with open(self.test_fname2) as fp:
            test_file2 = fp.read()
        files = [("test_file1", test_file1.encode()),
                ("test_file2", test_file2.encode())]
        cdict = main.load_classification(suriconf, files)

        # Number of classifications in classification1.config: 42
        # Number of classifications in classification2.config: 44 (2 new)
        self.assertEqual(44, len(cdict))

        # classification1.config:
        # config classification: misc-attack,Misc Attack,2
        #
        # classification2.config:
        # config classification: misc-attack,Misc Attack,5
        self.assertEqual("5", cdict["misc-attack"][1])
