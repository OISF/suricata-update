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

"""Module for separating out matchers code."""
import fnmatch
import os
import logging
import sys
import shlex
import re



sys.path.insert(0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import suricata.update.loghandler

# Initialize logging, use colour if on a tty.
if len(logging.root.handlers) == 0 and os.isatty(sys.stderr.fileno()):
    logger = logging.getLogger()
    logger.setLevel(level=logging.INFO)
    logger.addHandler(suricata.update.loghandler.SuriColourLogHandler())
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - <%(levelname)s> - %(message)s")
    logger = logging.getLogger()



class AllRuleMatcher(object):
    """Matcher object to match all rules. """

    def match(self, rule):
        return True

    @classmethod
    def parse(cls, buf):
        if buf.strip() == "*":
            return cls()
        return None

class ProtoRuleMatcher:
    """A rule matcher that matches on the protocol of a rule."""

    def __init__(self, proto):
        self.proto = proto

    def match(self, rule):
        return rule.proto == self.proto

class IdRuleMatcher(object):
    """Matcher object to match an idstools rule object by its signature
    ID."""

    def __init__(self, generatorId=None, signatureId=None):
        self.signatureIds = []
        if generatorId and signatureId:
            self.signatureIds.append((generatorId, signatureId))

    def match(self, rule):
        for (generatorId, signatureId) in self.signatureIds:
            if generatorId == rule.gid and signatureId == rule.sid:
                return True
        return False

    @classmethod
    def parse(cls, buf):
        matcher = cls()

        for entry in buf.split(","):
            entry = entry.strip()

            parts = entry.split(":", 1)
            if not parts:
                return None
            if len(parts) == 1:
                try:
                    signatureId = int(parts[0])
                    matcher.signatureIds.append((1, signatureId))
                except:
                    return None
            else:
                try:
                    generatorId = int(parts[0])
                    signatureId = int(parts[1])
                    matcher.signatureIds.append((generatorId, signatureId))
                except:
                    return None

        return matcher

class FilenameMatcher(object):
    """Matcher object to match a rule by its filename. This is similar to
    a group but has no specifier prefix.
    """

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if hasattr(rule, "group") and rule.group is not None:
            return fnmatch.fnmatch(rule.group, self.pattern)
        return False

    @classmethod
    def parse(cls, buf):
        if buf.startswith("filename:"):
            try:
                group = buf.split(":", 1)[1]
                return cls(group.strip())
            except:
                pass
        return None
class GroupMatcher(object):
    """Matcher object to match an idstools rule object by its group (ie:
    filename).

    The group is just the basename of the rule file with or without
    extension.

    Examples:
    - emerging-shellcode
    - emerging-trojan.rules

    """

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if hasattr(rule, "group") and rule.group is not None:
            if fnmatch.fnmatch(os.path.basename(rule.group), self.pattern):
                return True
            # Try matching against the rule group without the file
            # extension.
            if fnmatch.fnmatch(
                    os.path.splitext(
                        os.path.basename(rule.group))[0], self.pattern):
                return True
        return False

    @classmethod
    def parse(cls, buf):
        if buf.startswith("group:"):
            try:
                logger.debug("Parsing group matcher: %s" % (buf))
                group = buf.split(":", 1)[1]
                return cls(group.strip())
            except:
                pass
        if buf.endswith(".rules"):
            return cls(buf.strip())
        return None

class ReRuleMatcher(object):
    """Matcher object to match an idstools rule object by regular
    expression."""

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if self.pattern.search(rule.raw):
            return True
        return False

    @classmethod
    def parse(cls, buf):
        if buf.startswith("re:"):
            try:
                logger.debug("Parsing regex matcher: %s" % (buf))
                patternstr = buf.split(":", 1)[1].strip()
                pattern = re.compile(patternstr, re.I)
                return cls(pattern)
            except:
                pass
        return None

def parse_rule_match(match):
    matcher = AllRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = IdRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = ReRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = FilenameMatcher.parse(match)
    if matcher:
        return matcher

    matcher = GroupMatcher.parse(match)
    if matcher:
        return matcher

    return None

class ModifyRuleFilter(object):
    """Filter to modify an idstools rule object.
    Important note: This filter does not modify the rule inplace, but
    instead returns a new rule object with the modification.
    """

    def __init__(self, matcher, pattern, repl):
        self.matcher = matcher
        self.pattern = pattern
        self.repl = repl

    def match(self, rule):
        return self.matcher.match(rule)

    def filter(self, rule):
        modified_rule = self.pattern.sub(self.repl, rule.format())
        parsed = suricata.update.rule.parse(modified_rule, rule.group)
        if parsed is None:
            logger.error("Modification of rule %s results in invalid rule: %s",
                         rule.idstr, modified_rule)
            return rule
        return parsed

    @classmethod
    def parse(cls, buf):
        tokens = shlex.split(buf)
        if len(tokens) == 3:
            matchstring, a, b = tokens
        elif len(tokens) > 3 and tokens[0] == "modifysid":
            matchstring, a, b = tokens[1], tokens[2], tokens[4]
        else:
            raise Exception("Bad number of arguments.")
        matcher = parse_rule_match(matchstring)
        if not matcher:
            raise Exception("Bad match string: %s" % (matchstring))
        pattern = re.compile(a)

        # Convert Oinkmaster backticks to Python.
        b = re.sub("\$\{(\d+)\}", "\\\\\\1", b)

        return cls(matcher, pattern, b)

def parse_matchers(fileobj):
    matchers = []

    for line in fileobj:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.rsplit(" #")[0]
        matcher =parse_rule_match(line)
        if not matcher:
            logger.warn("Failed to parse: \"%s\"" % (line))
        else:
            matchers.append(matcher)

    return matchers

def load_matchers(filename):
    with open(filename) as fileobj:
        return parse_matchers(fileobj)
