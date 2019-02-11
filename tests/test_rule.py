# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2011-2013 Jason Ish
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

import suricata.update.rule

class RuleTestCase(unittest.TestCase):

    def test_parse1(self):
        # Some mods have been made to this rule (flowbits) for the
        # purpose of testing.
        rule = suricata.update.rule.parse("""alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"; flow:established,to_server; content:"setup."; fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; classtype:trojan-activity; sid:2014929; rev:1;)""")
        self.assertEqual(rule.enabled, True)
        self.assertEqual(rule.action, "alert")
        self.assertEqual(rule.direction, "->")
        self.assertEqual(rule.sid, 2014929)
        self.assertEqual(rule.rev, 1)
        self.assertEqual(rule.msg, "ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip")
        self.assertEqual(len(rule.metadata), 2)
        self.assertEqual(rule.metadata[0], "stage")
        self.assertEqual(rule.metadata[1], "hostile_download")
        self.assertEqual(len(rule.flowbits), 2)
        self.assertEqual(rule.flowbits[0], "isset,somebit")
        self.assertEqual(rule.flowbits[1], "unset,otherbit")
        self.assertEqual(rule.classtype, "trojan-activity")

    def test_disable_rule(self):
        rule_buf = """# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = suricata.update.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEqual(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")
        self.assertEqual(str(rule), rule_buf)

    def test_parse_rule_double_commented(self):
        rule_buf = """## alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = suricata.update.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEqual(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_parse_rule_comments_and_spaces(self):
        rule_buf = """## #alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = suricata.update.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEqual(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_toggle_rule(self):
        rule_buf = """# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = suricata.update.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        rule.enabled = True
        self.assertEqual(str(rule), """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_parse_fileobj(self):
        rule_buf = ("""# alert tcp $HOME_NET any -> $EXTERNAL_NET any """
                    """(msg:"some message";)""")
        fileobj = io.StringIO()
        for i in range(2):
            fileobj.write(u"%s\n" % rule_buf)
        fileobj.seek(0)
        rules = suricata.update.rule.parse_fileobj(fileobj)
        self.assertEqual(2, len(rules))

    def test_parse_file(self):
        rule_buf = ("""# alert tcp $HOME_NET any -> $EXTERNAL_NET any """
                    """(msg:"some message";)""")
        tmp = tempfile.NamedTemporaryFile()
        for i in range(2):
            tmp.write(("%s\n" % rule_buf).encode())
        tmp.flush()
        rules = suricata.update.rule.parse_file(tmp.name)
        self.assertEqual(2, len(rules))

    def test_parse_file_with_unicode(self):
        rules = suricata.update.rule.parse_file("./tests/rule-with-unicode.rules")

    def test_parse_decoder_rule(self):
        rule_string = """alert ( msg:"DECODE_NOT_IPV4_DGRAM"; sid:1; gid:116; rev:1; metadata:rule-type decode; classtype:protocol-command-decode;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertEqual(rule["direction"], None)

    def test_multiline_rule(self):
        rule_string = u"""
alert dnp3 any any -> any any (msg:"SURICATA DNP3 Request flood detected"; \
      app-layer-event:dnp3.flooded; sid:2200104; rev:1;)
"""
        rules = suricata.update.rule.parse_fileobj(io.StringIO(rule_string))
        self.assertEqual(len(rules), 1)

    def test_parse_nomsg(self):
        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertEqual("", rule["msg"])

    def test_noalert(self):
        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertFalse(rule["noalert"])

        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; flowbits:noalert; sid:10000000; rev:1;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertTrue(rule["noalert"])

    def test_parse_message_with_semicolon(self):
        rule_string = u"""alert ip any any -> any any (msg:"TEST RULE\; and some"; content:"uid=0|28|root|29|"; tag:session,5,packets; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.msg, "TEST RULE\; and some")

        # Look for the expected content.
        self.assertEqual("TEST RULE\; and some", rule["msg"])

    def test_parse_message_with_colon(self):
        rule_string = u"""alert tcp 93.174.88.0/21 any -> $HOME_NET any (msg:"SN: Inbound TCP traffic from suspect network (AS29073 - NL)"; flags:S; reference:url,https://suspect-networks.io/networks/cidr/13/; threshold: type limit, track by_dst, seconds 30, count 1; classtype:misc-attack; sid:71918985; rev:1;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertEqual(
            rule.msg,
            "SN: Inbound TCP traffic from suspect network (AS29073 - NL)")

    def test_parse_multiple_metadata(self):
        # metadata: former_category TROJAN;
        # metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Onion_Domain, tag Ransomware, signature_severity Major, created_at 2017_08_08, malware_family Crypton, malware_family Nemesis, performance_impact Low, updated_at 2017_08_08;
        rule_string = u"""alert udp $HOME_NET any -> any 53 (msg:"ET TROJAN CryptON/Nemesis/X3M Ransomware Onion Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|10|yvvu3fqglfceuzfu"; fast_pattern; distance:0; nocase; metadata: former_category TROJAN; reference:url,blog.emsisoft.com/2017/05/01/remove-cry128-ransomware-with-emsisofts-free-decrypter/; reference:url,www.cyber.nj.gov/threat-profiles/ransomware-variants/crypt-on; classtype:trojan-activity; sid:2024525; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Onion_Domain, tag Ransomware, signature_severity Major, created_at 2017_08_08, malware_family Crypton, malware_family Nemesis, performance_impact Low, updated_at 2017_08_08;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertTrue("former_category TROJAN" in rule.metadata)
        self.assertTrue("updated_at 2017_08_08" in rule.metadata)

    def test_parse_option_missing_end(self):
        """Test parsing a rule where the last option is missing a
        semicolon. This was responsible for an infinite loop. """
        rule_buf = u"""alert icmp any any -> $HOME_NET any (msg:"ICMP test detected"; gid:0; sid:10000001; rev:1; classtype: icmp-event; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop)"""
        self.assertRaises(
            suricata.update.rule.NoEndOfOptionError,
            suricata.update.rule.parse, rule_buf)

    def test_parse_addr_list(self):
        """Test parsing rules where the addresses and parts are lists with
        spaces."""
    
        rule = suricata.update.rule.parse("""alert any [$HOME_NET, $OTHER_NET] any -> any any (msg:"TEST"; sid:1; rev:1;)""")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["source_addr"], "[$HOME_NET, $OTHER_NET]")

        rule = suricata.update.rule.parse("""alert any [$HOME_NET, $OTHER_NET] [1, 2, 3] -> any any (msg:"TEST"; sid:1; rev:1;)""")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["source_port"], "[1, 2, 3]")

        rule = suricata.update.rule.parse("""alert any [$HOME_NET, $OTHER_NET] [1,2,3] -> [!$XNET, $YNET] any (msg:"TEST"; sid:1; rev:1;)""")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["dest_addr"], "[!$XNET, $YNET]")

        rule = suricata.update.rule.parse("""alert any [$HOME_NET, $OTHER_NET] [1,2,3] -> [!$XNET, $YNET] [!2200, 5500] (msg:"TEST"; sid:1; rev:1;)""")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["dest_port"], "[!2200, 5500]")
        
    def test_parse_no_rev(self):
        """Test that a rule with no revision gets assigned the default
        revision of 0."""
        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000;)"""
        rule = suricata.update.rule.parse(rule_string)
        self.assertEqual(0, rule["rev"])
