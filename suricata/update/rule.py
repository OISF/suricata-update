# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2011 Jason Ish
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

""" Module for parsing Snort-like rules.

Parsing is done using regular expressions and the job of this module
is to do its best at parsing out fields of interest from the rule
rather than perform a sanity check.

The methods that parse multiple rules for a provided input
(parse_file, parse_fileobj) return a list of rules instead of dict
keyed by ID as its not the job of this module to detect or deal with
duplicate signature IDs.
"""

from __future__ import print_function

import sys
import re
import logging
import io

logger = logging.getLogger(__name__)

# Rule actions we expect to see.
actions = (
    "alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")

# Compiled regular expression to detect a rule and break out some of
# its parts.
rule_pattern = re.compile(
    r"^(?P<enabled>#)*[\s#]*"      # Enabled/disabled
    r"(?P<raw>"
    r"(?P<header>"
    r"(?P<action>%s)\s*"        # Action
    r"(?P<proto>[^\s]*)\s*"     # Protocol
    r"[^\s]*\s*"                # Source address(es)
    r"[^\s]*\s*"                # Source port
    r"(?P<direction>[-><]+)\s*"	# Direction
    r"[^\s]*\s*"		        # Destination address(es)
    r"[^\s]*"                   # Destination port
    r")"                        # End of header.
    r"\s*"                      # Trailing spaces after header.
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

# Another compiled pattern to detect preprocessor rules.  We could
# construct the general rule re to pick this up, but its much faster
# this way.
decoder_rule_pattern = re.compile(
    r"^(?P<enabled>#)*[\s#]*"	# Enabled/disabled
    r"(?P<raw>"
    r"(?P<action>%s)\s*"	    # Action
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

class NoEndOfOptionError(Exception):
    """Exception raised when the end of option terminator (semicolon) is
    missing."""
    pass

class Rule(dict):
    """Class representing a rule.

    The Rule class is a class that also acts like a dictionary.

    Dictionary fields:

    - **group**: The group the rule belongs to, typically the filename.
    - **enabled**: True if rule is enabled (uncommented), False is
      disabled (commented)
    - **action**: The action of the rule (alert, pass, etc) as a
      string
    - **proto**: The protocol of the rule.
    - **direction**: The direction string of the rule.
    - **gid**: The gid of the rule as an integer
    - **sid**: The sid of the rule as an integer
    - **rev**: The revision of the rule as an integer
    - **msg**: The rule message as a string
    - **flowbits**: List of flowbit options in the rule
    - **metadata**: Metadata values as a list
    - **references**: References as a list
    - **classtype**: The classification type
    - **priority**: The rule priority, 0 if not provided
    - **raw**: The raw rule as read from the file or buffer

    :param enabled: Optional parameter to set the enabled state of the rule
    :param action: Optional parameter to set the action of the rule
    :param group: Optional parameter to set the group (filename) of the rule

    """

    def __init__(self, enabled=None, action=None, group=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self["action"] = action
        self["proto"] = None
        self["direction"] = None
        self["group"] = group
        self["gid"] = 1
        self["sid"] = None
        self["rev"] = None
        self["msg"] = None
        self["flowbits"] = []
        self["metadata"] = []
        self["references"] = []
        self["classtype"] = None
        self["priority"] = 0

        self["options"] = []

        self["raw"] = None

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the rule.

        :returns: A tuple (gid, sid) representing the ID of the rule
        :rtype: A tuple of 2 ints
        """
        return (int(self.gid), int(self.sid))

    @property
    def idstr(self):
        """Return the gid and sid of the rule as a string formatted like:
        '[GID:SID]'"""
        return "[%s:%s]" % (str(self.gid), str(self.sid))

    def brief(self):
        """ A brief description of the rule.

        :returns: A brief description of the rule
        :rtype: string
        """
        return "%s[%d:%d] %s" % (
            "" if self.enabled else "# ", self.gid, self.sid, self.msg)

    def __hash__(self):
        return self["raw"].__hash__()

    def __str__(self):
        """ The string representation of the rule.

        If the rule is disabled it will be returned as commented out.
        """
        return self.format()

    def format(self):
        return u"%s%s" % (u"" if self.enabled else u"# ", self.raw)

    def rebuild_options(self):
        """ Rebuild the rule options from the list of options."""
        options = []
        for option in self.options:
            if option["value"] is None:
                options.append(option["name"])
            else:
                options.append("%s:%s" % (option["name"], option["value"]))
        return "%s;" % "; ".join(options)

def remove_option(rule, name):
    rule["options"] = [
        option for option in rule["options"] if option["name"] != name]
    new_rule_string = "%s%s (%s)" % (
        "" if rule.enabled else "# ",
        rule["header"].strip(),
        rule.rebuild_options());
    return parse(new_rule_string, rule["group"])

def add_option(rule, name, value, index=None):
    option = {
        "name": name,
        "value": value,
    }
    if index is None:
        rule["options"].append(option)
    else:
        rule["options"].insert(index, option)
    new_rule_string = "%s%s (%s)" % (
        "" if rule.enabled else "# ",
        rule["header"].strip(),
        rule.rebuild_options())
    return parse(new_rule_string, rule["group"])

def find_opt_end(options):
    """ Find the end of an option (;) handling escapes. """
    offset = 0

    while True:
        i = options[offset:].find(";")
        if options[offset + i - 1] == "\\":
            offset += 2
        else:
            return offset + i

def parse(buf, group=None):
    """ Parse a single rule for a string buffer.

    :param buf: A string buffer containing a single Snort-like rule

    :returns: An instance of of :py:class:`.Rule` representing the parsed rule
    """

    if type(buf) == type(b""):
        buf = buf.decode("utf-8")

    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return

    rule = Rule(enabled=True if m.group("enabled") is None else False,
                action=m.group("action"),
                group=group)

    rule["header"] = m.groupdict().get("header", None)
    rule["proto"] = m.groupdict().get("proto", None)
    rule["direction"] = m.groupdict().get("direction", None)

    options = m.group("options")

    while True:
        if not options:
            break
        index = find_opt_end(options)
        if index < 0:
            raise NoEndOfOptionError("no end of option")
        option = options[:index].strip()
        options = options[index + 1:].strip()

        if option.find(":") > -1:
            name, val = [x.strip() for x in option.split(":", 1)]
        else:
            name = option
            val = None

        rule["options"].append({
            "name": name,
            "value": val,
        })

        if name in ["gid", "sid", "rev"]:
            rule[name] = int(val)
        elif name == "metadata":
            if not name in rule:
                rule[name] = []
            rule[name] += [v.strip() for v in val.split(",")]
        elif name == "flowbits":
            rule.flowbits.append(val)
        elif name == "reference":
            rule.references.append(val)
        elif name == "msg":
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            rule[name] = val
        else:
            rule[name] = val

    if rule["msg"] is None:
        rule["msg"] = ""

    rule["raw"] = m.group("raw").strip()

    return rule

def parse_fileobj(fileobj, group=None):
    """ Parse multiple rules from a file like object.

    Note: At this time rules must exist on one line.

    :param fileobj: A file like object to parse rules from.

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    rules = []
    buf = ""
    for line in fileobj:
        try:
            if type(line) == type(b""):
                line = line.decode()
        except:
            pass
        if line.rstrip().endswith("\\"):
            buf = "%s%s " % (buf, line.rstrip()[0:-1])
            continue
        buf = buf + line
        try:
            rule = parse(buf, group)
            if rule:
                rules.append(rule)
        except Exception as err:
            logger.error("Failed to parse rule: %s: %s", buf.rstrip(), err)
        buf = ""
    return rules

def parse_file(filename, group=None):
    """ Parse multiple rules from the provided filename.

    :param filename: Name of file to parse rules from

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    with io.open(filename, encoding="utf-8") as fileobj:
        return parse_fileobj(fileobj, group)

class FlowbitResolver(object):

    setters = ["set", "setx", "unset", "toggle"]
    getters = ["isset", "isnotset"]

    def __init__(self):
        self.enabled = []

    def resolve(self, rules):
        required = self.get_required_flowbits(rules)
        enabled = self.set_required_flowbits(rules, required)
        if enabled:
            self.enabled += enabled
            return self.resolve(rules)
        return self.enabled

    def set_required_flowbits(self, rules, required):
        enabled = []
        for rule in [rule for rule in rules.values() if not rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in required:
                    rule.enabled = True
                    enabled.append(rule)
        return enabled

    def get_required_rules(self, rulemap, flowbits, include_enabled=False):
        """Returns a list of rules that need to be enabled in order to satisfy
        the list of required flowbits.

        """
        required = []

        for rule in [rule for rule in rulemap.values()]:
            if not rule:
                continue
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in flowbits:
                    if rule.enabled and not include_enabled:
                        continue
                    required.append(rule)

        return required

    def get_required_flowbits(self, rules):
        required_flowbits = set()
        for rule in [rule for rule in rules.values() if rule and rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.getters:
                    required_flowbits.add(value)
        return required_flowbits

    def parse_flowbit(self, flowbit):
        tokens = flowbit.split(",", 1)
        if len(tokens) == 1:
            return tokens[0], None
        elif len(tokens) == 2:
            return tokens[0], tokens[1]
        else:
            raise Exception("Flowbit parse error on %s" % (flowbit))

def enable_flowbit_dependencies(rulemap):
    """Helper function to resolve flowbits, wrapping the FlowbitResolver
    class. """
    resolver = FlowbitResolver()
    return resolver.resolve(rulemap)

def format_sidmsgmap(rule):
    """ Format a rule as a sid-msg.map entry. """
    try:
        return " || ".join([str(rule.sid), rule.msg] + rule.references)
    except:
        logger.error("Failed to format rule as sid-msg.map: %s" % (str(rule)))
        return None

def format_sidmsgmap_v2(rule):
    """ Format a rule as a v2 sid-msg.map entry.

    eg:
    gid || sid || rev || classification || priority || msg || ref0 || refN
    """
    try:
        return " || ".join([
            str(rule.gid), str(rule.sid), str(rule.rev),
            "NOCLASS" if rule.classtype is None else rule.classtype,
            str(rule.priority), rule.msg] + rule.references)
    except:
        logger.error("Failed to format rule as sid-msg-v2.map: %s" % (
            str(rule)))
        return None
