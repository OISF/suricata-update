# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2015-2017 Jason Ish
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
import re
import os.path
import logging
import argparse
import shlex
import time
import hashlib
import fnmatch
import subprocess
import types
import shutil
import glob
import io

try:
    import yaml
except:
    print("error: pyyaml is required")
    sys.exit(1)

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import suricata.update.rule
import suricata.update.engine
import suricata.update.net
from suricata.update import configs
from suricata.update.loghandler import SuriColourLogHandler
from suricata.update import extract
from suricata.update import util

# Initialize logging, use colour if on a tty.
if len(logging.root.handlers) == 0 and os.isatty(sys.stderr.fileno()):
    logger = logging.getLogger()
    logger.setLevel(level=logging.INFO)
    logger.addHandler(SuriColourLogHandler())
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - <%(levelname)s> - %(message)s")
    logger = logging.getLogger()

# If Suricata is not found, default to this version.
DEFAULT_SURICATA_VERSION = "4.0"

# Template URL for Emerging Threats Pro rules.
ET_PRO_URL = ("https://rules.emergingthreatspro.com/"
              "%(code)s/"
              "suricata%(version)s/"
              "etpro.rules.tar.gz")

# Template URL for Emerging Threats Open rules.
ET_OPEN_URL = ("https://rules.emergingthreats.net/open/"
               "suricata%(version)s/"
               "emerging.rules.tar.gz")

# The default filename to use for the output rule file. This is a
# single file concatenating all input rule files together.
DEFAULT_OUTPUT_RULE_FILENAME = "suricata.rules"

class AllRuleMatcher(object):
    """Matcher object to match all rules. """

    def match(self, rule):
        return True

    @classmethod
    def parse(cls, buf):
        if buf.strip() == "*":
            return cls()
        return None

class IdRuleMatcher(object):
    """Matcher object to match an idstools rule object by its signature
    ID."""

    def __init__(self, generatorId, signatureId):
        self.generatorId = generatorId
        self.signatureId = signatureId

    def match(self, rule):
        return self.generatorId == rule.gid and self.signatureId == rule.sid

    @classmethod
    def parse(cls, buf):
        logger.debug("Parsing ID matcher: %s" % (buf))
        try:
            signatureId = int(buf)
            return cls(1, signatureId)
        except:
            pass
        try:
            generatorString, signatureString = buf.split(":")
            generatorId = int(generatorString)
            signatureId = int(signatureString)
            return cls(generatorId, signatureId)
        except:
            pass
        return None

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
            raise Exception("Bad match string: %s" % (tokens[0]))
        pattern = re.compile(a)

        # Convert Oinkmaster backticks to Python.
        b = re.sub("\$\{(\d+)\}", "\\\\\\1", b)

        return cls(matcher, pattern, b)

class DropRuleFilter(object):
    """ Filter to modify an idstools rule object to a drop rule. """

    def __init__(self, matcher):
        self.matcher = matcher

    def is_noalert(self, rule):
        for option in rule.options:
            if option["name"] == "flowbits" and option["value"] == "noalert":
                return True
        return False

    def match(self, rule):
        if self.is_noalert(rule):
            return False
        return self.matcher.match(rule)

    def filter(self, rule):
        drop_rule = suricata.update.rule.parse(re.sub("^\w+", "drop", rule.raw))
        drop_rule.enabled = rule.enabled
        return drop_rule

class Fetch(object):

    def __init__(self, args):
        self.args = args

    def check_checksum(self, tmp_filename, url):
        try:
            checksum_url = url + ".md5"
            local_checksum = hashlib.md5(
                open(tmp_filename, "rb").read()).hexdigest().strip()
            remote_checksum_buf = io.BytesIO()
            logger.info("Checking %s." % (checksum_url))
            suricata.update.net.get(checksum_url, remote_checksum_buf)
            remote_checksum = remote_checksum_buf.getvalue().decode().strip()
            logger.debug("Local checksum=|%s|; remote checksum=|%s|" % (
                local_checksum, remote_checksum))
            if local_checksum == remote_checksum:
                os.utime(tmp_filename, None)
                return True
        except Exception as err:
            logger.warning("Failed to check remote checksum: %s" % err)
        return False

    def progress_hook(self, content_length, bytes_read):
        if self.args.quiet:
            return
        if not content_length or content_length == 0:
            percent = 0
        else:
            percent = int((bytes_read / float(content_length)) * 100)
        buf = " %3d%% - %-30s" % (
            percent, "%d/%d" % (bytes_read, content_length))
        sys.stdout.write(buf)
        sys.stdout.flush()
        sys.stdout.write("\b" * 38)

    def progress_hook_finish(self):
        sys.stdout.write("\n")
        sys.stdout.flush()

    def url_basename(self, url):
        """ Return the base filename of the URL. """
        filename = os.path.basename(url).split("?", 1)[0]
        return filename

    def get_tmp_filename(self, url):
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        return os.path.join(
            self.args.cache_dir,
            "%s-%s" % (url_hash, self.url_basename(url)))

    def fetch(self, url):
        tmp_filename = self.get_tmp_filename(url)
        if not self.args.force and os.path.exists(tmp_filename):
            if time.time() - os.stat(tmp_filename).st_mtime < (60 * 15):
                logger.info(
                    "Last download less than 15 minutes ago. Not downloading %s.",
                    url)
                return self.extract_files(tmp_filename)
            if self.check_checksum(tmp_filename, url):
                logger.info("Remote checksum has not changed. Not fetching.")
                return self.extract_files(tmp_filename)
        if not os.path.exists(self.args.cache_dir):
            os.makedirs(self.args.cache_dir, mode=0o770)
        logger.info("Fetching %s." % (url))
        try:
            suricata.update.net.get(
                url,
                open(tmp_filename, "wb"),
                progress_hook=self.progress_hook)
        except:
            if os.path.exists(tmp_filename):
                os.unlink(tmp_filename)
            raise
        if not self.args.quiet:
            self.progress_hook_finish()
        logger.info("Done.")
        return self.extract_files(tmp_filename)

    def run(self, url=None, files=None):
        if files is None:
            files = {}
        if url:
            try:
                files.update(self.fetch(url))
            except Exception as err:
                logger.error("Failed to fetch %s: %s", url, err)
        else:
            for url in self.args.url:
                files.update(self.fetch(url))
        return files

    def extract_files(self, filename):
        files = extract.try_extract(filename)
        if files:
            return files

        # The file is not an archive, treat it as an individual file.
        basename = os.path.basename(filename).split("-", 1)[1]
        files = {}
        files[basename] = open(filename, "rb").read()
        return files

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

    matcher = GroupMatcher.parse(match)
    if matcher:
        return matcher

    matcher = FilenameMatcher.parse(match)
    if matcher:
        return matcher

    return None

def load_filters(filename):

    filters = []

    with open(filename) as fileobj:
        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            filter = ModifyRuleFilter.parse(line)
            if filter:
                filters.append(filter)
            else:
                log.error("Failed to parse modify filter: %s" % (line))

    return filters

def load_drop_filters(filename):
    
    matchers = load_matchers(filename)
    filters = []

    for matcher in matchers:
        filters.append(DropRuleFilter(matcher))

    return filters

def load_matchers(filename):

    matchers = []

    with open(filename) as fileobj:
        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            matcher = parse_rule_match(line)
            if not matcher:
                logger.warn("Failed to parse: \"%s\"" % (line))
            else:
                matchers.append(matcher)

    return matchers

def load_local(local, files):
    """Load local files into the files dict."""
    if os.path.isdir(local):
        for dirpath, dirnames, filenames in os.walk(local):
            for filename in filenames:
                if filename.endswith(".rules"):
                    path = os.path.join(local, filename)
                    load_local(path, files)
    else:
        local_files = glob.glob(local)
        if len(local_files) == 0:
            local_files.append(local)
        for filename in local_files:
            logger.info("Loading local file %s" % (filename))
            if filename in files:
                logger.warn(
                    "Local file %s overrides existing file of same name." % (
                        filename))
            try:
                with open(filename, "rb") as fileobj:
                    files[filename] = fileobj.read()
            except Exception as err:
                logger.error("Failed to open %s: %s" % (filename, err))

def load_dist_rules(files):
    """Load the rule files provided by the Suricata distribution."""

    # In the future hopefully we can just pull in all files from
    # /usr/share/suricata/rules, but for now pull in the set of files
    # known to have been provided by the Suricata source.
    filenames = [
        "app-layer-events.rules",
        "decoder-events.rules",
        "dnp3-events.rules",
        "dns-events.rules",
        "files.rules",
        "http-events.rules",
        "modbus-events.rules",
        "nfs-events.rules",
        "ntp-events.rules",
        "smtp-events.rules",
        "stream-events.rules",
        "tls-events.rules",
    ]

    dist_rule_path = "/etc/suricata/rules"

    if not os.path.exists(dist_rule_path):
        logger.warning("Distribution rule directory not found: %s",
                       dist_rule_path)
        return

    if os.path.exists(dist_rule_path):
        if not os.access(dist_rule_path, os.R_OK):
            logger.warning("Distribution rule path not readable: %s",
                           dist_rule_path)
            return
        for filename in filenames:
            path = os.path.join(dist_rule_path, filename)
            if not os.path.exists(path):
                continue
            if not os.access(path, os.R_OK):
                logger.warning("Distribution rule file not readable: %s",
                               path)
                continue
            logger.info("Loading distribution rule file %s", path)
            try:
                with open(path, "rb") as fileobj:
                    files[path] = fileobj.read()
            except Exception as err:
                logger.error("Failed to open %s: %s" % (path, err))
                sys.exit(1)

def build_report(prev_rulemap, rulemap):
    """Build a report of changes between 2 rulemaps.

    Returns a dict with the following keys that each contain a list of
    rules.
    - added
    - removed
    - modified
    """
    report = {
        "added": [],
        "removed": [],
        "modified": []
    }

    for key in rulemap:
        rule = rulemap[key]
        if not rule.id in prev_rulemap:
            report["added"].append(rule)
        elif rule.format() != prev_rulemap[rule.id].format():
            report["modified"].append(rule)
    for key in prev_rulemap:
        rule = prev_rulemap[key]
        if not rule.id in rulemap:
            report["removed"].append(rule)

    return report

def write_merged(filename, rulemap):

    if not args.quiet:
        prev_rulemap = {}
        if os.path.exists(filename):
            prev_rulemap = build_rule_map(
                suricata.update.rule.parse_file(filename))
        report = build_report(prev_rulemap, rulemap)
        enabled = len([rule for rule in rulemap.values() if rule.enabled])
        logger.info("Writing rules to %s: total: %d; enabled: %d; "
                    "added: %d; removed %d; modified: %d" % (
                        filename,
                        len(rulemap),
                        enabled,
                        len(report["added"]),
                        len(report["removed"]),
                        len(report["modified"])))
    
    with io.open(filename, encoding="utf-8", mode="w") as fileobj:
        for rule in rulemap:
            print(rulemap[rule].format(), file=fileobj)

def write_to_directory(directory, files, rulemap):
    if not args.quiet:
        previous_rulemap = {}
        for filename in files:
            outpath = os.path.join(
                directory, os.path.basename(filename))
            if os.path.exists(outpath):
                previous_rulemap.update(build_rule_map(
                    suricata.update.rule.parse_file(outpath)))
        report = build_report(previous_rulemap, rulemap)
        enabled = len([rule for rule in rulemap.values() if rule.enabled])
        logger.info("Writing rule files to directory %s: total: %d; "
                    "enabled: %d; added: %d; removed %d; modified: %d" % (
                        directory,
                        len(rulemap),
                        enabled,
                        len(report["added"]),
                        len(report["removed"]),
                        len(report["modified"])))

    for filename in sorted(files):
        outpath = os.path.join(
            directory, os.path.basename(filename))
        logger.debug("Writing %s." % outpath)
        if not filename.endswith(".rules"):
            open(outpath, "wb").write(files[filename])
        else:
            content = []
            for line in io.StringIO(files[filename].decode("utf-8")):
                rule = suricata.update.rule.parse(line)
                if not rule:
                    content.append(line.strip())
                else:
                    content.append(rulemap[rule.id].format())
            io.open(outpath, encoding="utf-8", mode="w").write(
                u"\n".join(content))

def write_yaml_fragment(filename, files):
    logger.info(
        "Writing YAML configuration fragment: %s" % (filename))
    with open(filename, "w") as fileobj:
        print("%YAML 1.1", file=fileobj)
        print("---", file=fileobj)
        print("rule-files:", file=fileobj)
        for fn in sorted(files):
            if fn.endswith(".rules"):
                print("  - %s" % os.path.basename(fn), file=fileobj)

def write_sid_msg_map(filename, rulemap, version=1):
    logger.info("Writing %s." % (filename))
    with io.open(filename, encoding="utf-8", mode="w") as fileobj:
        for key in rulemap:
            rule = rulemap[key]
            if version == 2:
                formatted = suricata.update.rule.format_sidmsgmap_v2(rule)
                if formatted:
                    print(formatted, file=fileobj)
            else:
                formatted = suricata.update.rule.format_sidmsgmap(rule)
                if formatted:
                    print(formatted, file=fileobj)

def build_rule_map(rules):
    """Turn a list of rules into a mapping of rules.

    In case of gid:sid conflict, the rule with the higher revision
    number will be used.
    """
    rulemap = {}

    for rule in rules:
        if rule.id not in rulemap:
            rulemap[rule.id] = rule
        else:
            if rule["rev"] > rulemap[rule.id]["rev"]:
                rulemap[rule.id] = rule

    return rulemap

def dump_sample_configs():

    for filename in configs.filenames:
        if os.path.exists(filename):
            logger.info("File already exists, not dumping %s." % (filename))
        else:
            logger.info("Creating %s." % (filename))
            shutil.copy(os.path.join(configs.directory, filename), filename)

def resolve_flowbits(rulemap, disabled_rules):
    flowbit_resolver = suricata.update.rule.FlowbitResolver()
    flowbit_enabled = set()
    while True:
        flowbits = flowbit_resolver.get_required_flowbits(rulemap)
        logger.debug("Found %d required flowbits.", len(flowbits))
        required_rules = flowbit_resolver.get_required_rules(rulemap, flowbits)
        logger.debug(
            "Found %d rules to enable to for flowbit requirements",
            len(required_rules))
        if not required_rules:
            logger.debug("All required rules enabled.")
            break
        for rule in required_rules:
            if not rule.enabled and rule in disabled_rules:
                logger.debug(
                    "Enabling previously disabled rule for flowbits: %s" % (
                        rule.brief()))
            rule.enabled = True
            flowbit_enabled.add(rule)
    logger.info("Enabled %d rules for flowbit dependencies." % (
        len(flowbit_enabled)))

class ThresholdProcessor:

    patterns = [
        re.compile("\s+(re:\"(.*)\")"),
        re.compile("\s+(re:(.*?)),.*"),
        re.compile("\s+(re:(.*))"),
    ]

    def extract_regex(self, buf):
        for pattern in self.patterns:
            m = pattern.search(buf)
            if m:
                return m.group(2)

    def extract_pattern(self, buf):
        regex = self.extract_regex(buf)
        if regex:
            return re.compile(regex, re.I)

    def replace(self, threshold, rule):
        for pattern in self.patterns:
            m = pattern.search(threshold)
            if m:
                return threshold.replace(
                    m.group(1), "gen_id %d, sig_id %d" % (rule.gid, rule.sid))
        return thresold

    def process(self, filein, fileout, rulemap):
        count = 0
        for line in filein:
            line = line.rstrip()
            if not line or line.startswith("#"):
                print(line, file=fileout)
                continue
            pattern = self.extract_pattern(line)
            if not pattern:
                print(line, file=fileout)
            else:
                for rule in rulemap.values():
                    if rule.enabled:
                        if pattern.search(rule.format()):
                            count += 1
                            print("# %s" % (rule.brief()), file=fileout)
                            print(self.replace(line, rule), file=fileout)
                            print("", file=fileout)
        logger.info("Generated %d thresholds to %s." % (count, fileout.name))

class FileTracker:
    """Used to check if files are modified.

    Usage: Add files with add(filename) prior to modification. Test
    with any_modified() which will return True if any of the checksums
    have been modified.

    """

    def __init__(self):
        self.hashes = {}

    def add(self, filename):
        checksum = self.md5(filename)
        logger.debug("Recording file %s with hash '%s'.", filename, checksum)
        self.hashes[filename] = checksum

    def md5(self, filename):
        if not os.path.exists(filename):
            return ""
        else:
            return hashlib.md5(open(filename, "rb").read()).hexdigest()

    def any_modified(self):
        for filename in self.hashes:
            if self.md5(filename) != self.hashes[filename]:
                return True
        return False

def resolve_etpro_url(etpro, suricata_version):
    mappings = {
        "code": etpro,
        "version": "",
    }

    mappings["version"] = "-%d.%d.%d" % (suricata_version.major,
                                      suricata_version.minor,
                                      suricata_version.patch)

    return ET_PRO_URL % mappings

def resolve_etopen_url(suricata_version):
    mappings = {
        "version": "",
    }

    mappings["version"] = "-%d.%d.%d" % (suricata_version.major,
                                         suricata_version.minor,
                                         suricata_version.patch)

    return ET_OPEN_URL % mappings

def ignore_file(ignore_files, filename):
    if not ignore_files:
        return False
    for pattern in ignore_files:
        if fnmatch.fnmatch(os.path.basename(filename), pattern):
            return True
    return False

class Config:

    DEFAULT_LOCATIONS = [
        "/etc/suricata/update.yaml",
    ]

    DEFAULTS = {
        "disable-conf": "/etc/suricata/disable.conf",
        "enable-conf": "/etc/suricata/enable.conf",
        "drop-conf": "/etc/suricata/drop.conf",
        "modify-conf": "/etc/suricata/modify.conf",
        "sources": [],
        "local": [],
    }

    def __init__(self, args):
        self.args = args
        self.config = {}
        self.config.update(self.DEFAULTS)

    def load(self):
        if self.args.config:
            with open(self.args.config) as fileobj:
                config = yaml.load(fileobj)
                if config:
                    self.config.update(config)
            return
        for path in self.DEFAULT_LOCATIONS:
            if os.path.exists(path):
                with open(path) as fileobj:
                    config = yaml.load(fileobj)
                    if config:
                        self.config.update(config)

    def get_arg(self, key):
        """Return the value for a command line argument. To be compatible
        with the configuration file, hypens are converted to underscores."""
        key = key.replace("-", "_")
        if hasattr(self.args, key) and getattr(self.args, key) != None:
            val = getattr(self.args, key)
            if not val in [[], None]:
                return getattr(self.args, key)
        return None

    def get(self, key):
        """Get a configuration file preferring the value provided on the
        command line, then checking the configuration file."""
        val = self.get_arg(key)
        if val:
            return val

        if key in self.config:
            return self.config[key]

        return None

    def set(self, key, val):
        self.config[key] = val

def test_suricata(config, suricata_path):
    if not suricata_path:
        logger.info("No suricata application binary found, skipping test.")
        return True

    if config.get("no-test"):
        logger.info("Skipping test, disabled by configuration.")
        return True

    if config.get("test-command"):
        test_command = config.get("test-command")
        logger.info("Testing Suricata configuration with: %s" % (
            test_command))
        env = {
            "SURICATA_PATH": suricata_path,
            "OUTPUT_DIR": config.get("output"),
        }
        if not config.get("no-merge"):
            env["OUTPUT_FILENAME"] = os.path.join(
                config.get("output"), DEFAULT_OUTPUT_RULE_FILENAME)
        rc = subprocess.Popen(test_command, shell=True, env=env).wait()
        if rc != 0:
            return False
    else:
        logger.info("Testing with suricata -T.")
        if not config.get("no-merge"):
            if not suricata.update.engine.test_configuration(
                    suricata_path, os.path.join(
                        config.get("output"), DEFAULT_OUTPUT_RULE_FILENAME)):
                return False
        else:
            if not suricata.update.engine.test_configuration(
                    suricata_path):
                return False

    return True

def copytree(src, dst):
    """A shutil.copytree like function that will copy the files from one
    tree to another even if the path exists.

    """

    for dirpath, dirnames, filenames in os.walk(src):
        for filename in filenames:
            src_path = os.path.join(dirpath, filename)
            dst_path = os.path.join(dst, src_path[len(src) + 1:])
            if not os.path.exists(os.path.dirname(dst_path)):
                os.makedirs(os.path.dirname(dst_path), mode=0o770)
            shutil.copy2(src_path, dst_path)

def load_sources(config, suricata_version):
    files = {}

    urls = []

    # If --etopen was provided on the command line, add it.
    if config.get("etopen"):
        urls.append(resolve_etopen_url(suricata_version))

    # If --etpro was provided on the command line, add it.
    if config.get("etpro"):
        urls.append(resolve_etpro_url(config.get("etpro"), suricata_version))

    # Add any URLs added with the --url command line parameter.
    if config.args.url:
        for url in config.args.url:
            urls.append(url)

    if config.get("sources"):
        for source in config.get("sources"):
            if not "type" in source:
                logger.error("Source is missing a type: %s", str(source))
                continue
            if source["type"] == "url":
                urls.append(source["url"])
            elif source["type"] == "etopen":
                urls.append(resolve_etopen_url(suricata_version))
            elif source["type"] == "etpro":
                if "code" in source:
                    code = source["code"]
                else:
                    code = config.get("etpro")
                if not code:
                    logger.error("ET-Pro source specified without code: %s",
                                 str(source))
                else:
                    urls.append(resolve_etpro_url(code, suricata_version))
            else:
                logger.error("Unknown source type: %s", source["type"])

    # Converting the URLs to a set removed dupes.
    urls = set(urls)

    # Now download each URL.
    for url in urls:
        Fetch(config.args).run(url, files)

    # Now load local rules specified in the configuration file.
    for local in config.config["local"]:
        load_local(local, files)

    # And the local rules specified on the command line.
    for local in config.args.local:
        load_local(local, files)

    return files

def main():
    global args

    suricata_path = suricata.update.engine.get_path()

    # Support the Python argparse style of configuration file.
    parser = argparse.ArgumentParser(fromfile_prefix_chars="@")

    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Be more verbose")
    parser.add_argument("-c", "--config", metavar="<filename>",
                        help="Configuration file")
    parser.add_argument("-o", "--output", metavar="<directory>",
                        dest="output", default="/var/lib/suricata/rules",
                        help="Directory to write rules to")
    parser.add_argument("--cache-dir", default="/var/lib/suricata/cache",
                        metavar="<directory>", help="set the cache directory")
    parser.add_argument("--suricata", metavar="<path>",
                        help="Path to Suricata program")
    parser.add_argument("--suricata-version", metavar="<version>",
                        help="Override Suricata version")
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force operations that might otherwise be skipped")
    parser.add_argument("--yaml-fragment", metavar="<filename>",
                        help="Output YAML fragment for rule inclusion")
    parser.add_argument("--url", metavar="<url>", action="append",
                        default=[],
                        help="URL to use instead of auto-generating one (can be specified multiple times)")
    parser.add_argument("--local", metavar="<path>", action="append",
                        default=[],
                        help="Local rule files or directories (can be specified multiple times)")
    parser.add_argument("--sid-msg-map", metavar="<filename>",
                        help="Generate a sid-msg.map file")
    parser.add_argument("--sid-msg-map-2", metavar="<filename>",
                        help="Generate a v2 sid-msg.map file")

    parser.add_argument("--disable-conf", metavar="<filename>",
                        help="Filename of rule disable filters")
    parser.add_argument("--enable-conf", metavar="<filename>",
                        help="Filename of rule enable filters")
    parser.add_argument("--modify-conf", metavar="<filename>",
                        help="Filename of rule modification filters")
    parser.add_argument("--drop-conf", metavar="<filename>",
                        help="Filename of drop rules filters")

    parser.add_argument("--ignore", metavar="<pattern>", action="append",
                        default=[],
                        help="Filenames to ignore (can be specified multiple times; default: *deleted.rules)")
    parser.add_argument("--no-ignore", action="store_true", default=False,
                        help="Disables the ignore option.")

    parser.add_argument("--threshold-in", metavar="<filename>",
                        help="Filename of rule thresholding configuration")
    parser.add_argument("--threshold-out", metavar="<filename>",
                        help="Output of processed threshold configuration")

    parser.add_argument("--dump-sample-configs", action="store_true",
                        default=False,
                        help="Dump sample config files to current directory")
    parser.add_argument("--etpro", metavar="<etpro-code>",
                        help="Use ET-Pro rules with provided ET-Pro code")
    parser.add_argument("--etopen", action="store_true",
                        help="Use ET-Open rules (default)")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                       help="Be quiet, warning and error messages only")
    parser.add_argument("--reload-command", metavar="<command>",
                        help="Command to run after update if modified")
    parser.add_argument("--no-reload", action="store_true", default=False,
                        help="Disable reload")
    parser.add_argument("-T", "--test-command", metavar="<command>",
                        help="Command to test Suricata configuration")
    parser.add_argument("--no-test", action="store_true", default=False,
                        help="Disable testing rules with Suricata")
    parser.add_argument("-V", "--version", action="store_true", default=False,
                        help="Display version")

    parser.add_argument("--no-merge", action="store_true", default=False,
                        help="Do not merge the rules into a single file")

    # The Python 2.7 argparse module does prefix matching which can be
    # undesirable. Reserve some names here that would match existing
    # options to prevent prefix matching.
    parser.add_argument("--disable", default=False, help=argparse.SUPPRESS)
    parser.add_argument("--enable", default=False, help=argparse.SUPPRESS)
    parser.add_argument("--modify", default=False, help=argparse.SUPPRESS)
    parser.add_argument("--drop", default=False, help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Error out if any reserved/unimplemented arguments were set.
    unimplemented_args = [
        "disable",
        "enable",
        "modify",
        "drop",
    ]
    for arg in unimplemented_args:
        if getattr(args, arg):
            logger.error("--%s not implemented", arg)
            return 1

    if args.version:
        print("suricata-update version %s" % suricata.update.version)
        return 0

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.quiet:
        logger.setLevel(logging.WARNING)

    logger.debug("This is suricata-update version %s; Python: %s" % (
        suricata.update.version,
        sys.version.replace("\n", "- ")))

    if args.dump_sample_configs:
        return dump_sample_configs()

    config = Config(args)
    try:
        config.load()
    except Exception as err:
        logger.error("Failed to load configuration: %s" % (err))
        return 1

    # If --no-ignore was provided, make sure args.ignore is
    # empty. Otherwise if no ignores are provided, set a sane default.

    if args.no_ignore:
        config.set("ignore", [])
    elif not config.get("ignore"):
        config.set("ignore", ["*deleted.rules"])

    # Check for Suricata binary...
    if args.suricata:
        if not os.path.exists(args.suricata):
            logger.error("Specified path to suricata does not exist: %s",
                     args.suricata)
            return 1
        suricata_path = args.suricata
    else:
        suricata_path = suricata.update.engine.get_path()
        if not suricata_path:
            logger.warning("No suricata application binary found on path.")

    if args.suricata_version:
        # The Suricata version was passed on the command line, parse it.
        suricata_version = suricata.update.engine.parse_version(
            args.suricata_version)
        if not suricata_version:
            logger.error("Failed to parse provided Suricata version: %s" % (
                args.suricata_version))
            return 1
        logger.info("Forcing Suricata version to %s." % (suricata_version.full))
    elif suricata_path:
        suricata_version = suricata.update.engine.get_version(args.suricata)
        if suricata_version:
            logger.info("Found Suricata version %s at %s." % (
                str(suricata_version.full), suricata_path))
        else:
            logger.error("Failed to get Suricata version.")
            return 1
    else:
        logger.info(
            "Using default Suricata version of %s", DEFAULT_SURICATA_VERSION)
        suricata_version = suricata.update.engine.parse_version(
            DEFAULT_SURICATA_VERSION)

    file_tracker = FileTracker()

    disable_matchers = []
    enable_matchers = []
    modify_filters = []
    drop_filters = []

    # Load user provided disable filters.
    disable_conf_filename = config.get("disable-conf")
    if disable_conf_filename and os.path.exists(disable_conf_filename):
        logger.info("Loading %s.", disable_conf_filename)
        disable_matchers += load_matchers(disable_conf_filename)

    # Load user provided enable filters.
    enable_conf_filename = config.get("enable-conf")
    if enable_conf_filename and os.path.exists(enable_conf_filename):
        logger.info("Loading %s.", enable_conf_filename)
        enable_matchers += load_matchers(enable_conf_filename)

    # Load user provided modify filters.
    modify_conf_filename = config.get("modify-conf")
    if modify_conf_filename and os.path.exists(modify_conf_filename):
        logger.info("Loading %s.", modify_conf_filename)
        modify_filters += load_filters(modify_conf_filename)

    # Load user provided drop filters.
    drop_conf_filename = config.get("drop-conf")
    if drop_conf_filename and os.path.exists(drop_conf_filename):
        logger.info("Loading %s.", drop_conf_filename)
        drop_filters += load_drop_filters(drop_conf_filename)

    # Check that the cache directory exists and is writable.
    if not os.path.exists(args.cache_dir):
        try:
            os.makedirs(args.cache_dir, mode=0o770)
        except Exception as err:
            logger.warning(
                "Cache directory does exist and could not be created. /var/tmp will be used instead.")
            args.cache_dir = "/var/tmp"

    files = load_sources(config, suricata_version)

    load_dist_rules(files)

    # Remove ignored files.
    for filename in list(files.keys()):
        if ignore_file(config.get("ignore"), filename):
            logger.info("Ignoring file %s" % (filename))
            del(files[filename])

    rules = []
    for filename in files:
        if not filename.endswith(".rules"):
            continue
        logger.debug("Parsing %s." % (filename))
        rules += suricata.update.rule.parse_fileobj(
            io.BytesIO(files[filename]), filename)

    rulemap = build_rule_map(rules)
    logger.info("Loaded %d rules." % (len(rules)))

    # Counts of user enabled and modified rules.
    enable_count = 0
    modify_count = 0
    drop_count = 0

    # List of rules disabled by user. Used for counting, and to log
    # rules that are re-enabled to meet flowbit requirements.
    disabled_rules = []

    for key, rule in rulemap.items():

        for matcher in disable_matchers:
            if rule.enabled and matcher.match(rule):
                logger.debug("Disabling: %s" % (rule.brief()))
                rule.enabled = False
                disabled_rules.append(rule)

        for matcher in enable_matchers:
            if not rule.enabled and matcher.match(rule):
                logger.debug("Enabling: %s" % (rule.brief()))
                rule.enabled = True
                enable_count += 1

        for filter in drop_filters:
            if filter.match(rule):
                rulemap[rule.id] = filter.filter(rule)
                drop_count += 1

    # Apply modify filters.
    for fltr in modify_filters:
        for key, rule in rulemap.items():
            if fltr.match(rule):
                new_rule = fltr.filter(rule)
                if new_rule and new_rule.format() != rule.format():
                    rulemap[rule.id] = new_rule
                    modify_count += 1

    logger.info("Disabled %d rules." % (len(disabled_rules)))
    logger.info("Enabled %d rules." % (enable_count))
    logger.info("Modified %d rules." % (modify_count))
    logger.info("Dropped %d rules." % (drop_count))

    # Fixup flowbits.
    resolve_flowbits(rulemap, disabled_rules)

    # Don't allow an empty output directory.
    if not args.output:
        logger.error("No output directory provided.")
        return 1

    # Check that output directory exists.
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output, mode=0o770)
        except Exception as err:
            logger.error(
                "Output directory does not exist and could not be created: %s",
                args.output)
            return 1

    # Check that output directory is writable.
    if not os.access(args.output, os.W_OK):
        logger.error("Output directory is not writable: %s", args.output)
        return 1

    # Backup the output directory.
    logger.info("Backing up current rules.")
    backup_directory = util.mktempdir()
    shutil.copytree(args.output, os.path.join(
        backup_directory, "backup"))

    if not args.no_merge:
        # The default, write out a merged file.
        output_filename = os.path.join(
            args.output, DEFAULT_OUTPUT_RULE_FILENAME)
        file_tracker.add(output_filename)
        write_merged(os.path.join(output_filename), rulemap)
    else:
        for filename in files:
            file_tracker.add(
                os.path.join(args.output, os.path.basename(filename)))
        write_to_directory(args.output, files, rulemap)

    if args.yaml_fragment:
        file_tracker.add(args.yaml_fragment)
        write_yaml_fragment(args.yaml_fragment, files)

    if args.sid_msg_map:
        write_sid_msg_map(args.sid_msg_map, rulemap, version=1)
    if args.sid_msg_map_2:
        write_sid_msg_map(args.sid_msg_map_2, rulemap, version=2)

    if args.threshold_in and args.threshold_out:
        file_tracker.add(args.threshold_out)
        threshold_processor = ThresholdProcessor()
        threshold_processor.process(
            open(args.threshold_in), open(args.threshold_out, "w"), rulemap)

    if not args.force and not file_tracker.any_modified():
        logger.info("No changes detected, exiting.")
        return 0

    if not test_suricata(config, suricata_path):
        logger.error("Suricata test failed, aborting.")
        logger.error("Restoring previous rules.")
        copytree(os.path.join(backup_directory, "backup"), args.output)
        return 1

    if not args.no_reload and config.get("reload-command"):
        logger.info("Running %s." % (config.get("reload-command")))
        rc = subprocess.Popen(config.get("reload-command"), shell=True).wait()
        if rc != 0:
            logger.error("Reload command exited with error: %d", rc)

    logger.info("Done.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
