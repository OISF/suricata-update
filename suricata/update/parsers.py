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

# This module contains functions for command line parsers for
# suricata-update

import argparse
import sys
from suricata.update import commands, config

from suricata.update.version import version

try:
    from suricata.update.revision import revision
except:
    revision = None

default_update_yaml = config.DEFAULT_UPDATE_YAML_PATH

# Global arguments - command line options for suricata-update
global_arg = [
    (("-v", "--verbose"),
     {'action': 'store_true', 'default': None,
      'help': "Be more verbose"}),
    (("-q", "--quiet"),
     {'action': 'store_true', 'default': None,
      'help': "Be quiet, warning and error messages only"}),
    (("-D", "--data-dir"),
     {'metavar': '<directory>', 'dest': 'data_dir',
      'help': "Data directory (default: /var/lib/suricata)"}),
    (("-c", "--config"),
     {'metavar': '<filename>',
      'help': "configuration file (default: %s)" % (default_update_yaml)}),
    (("--suricata-conf",),
     {'metavar': '<filename>',
      'help': "configuration file (default: /etc/suricata/suricata.yaml)"}),
    (("--suricata",),
     {'metavar': '<path>',
      'help': "Path to Suricata program"}),
    (("--suricata-version",),
     {'metavar': '<version>',
      'help': "Override Suricata version"}),
    (("--user-agent",),
     {'metavar': '<user-agent>',
      'help': "Set custom user-agent string"}),
    (("--no-check-certificate",),
     {'action': 'store_true', 'default': None,
      'help': "Disable server SSL/TLS certificate verification"}),
    (("-V", "--version"),
     {'action': 'store_true', 'default': False,
      'help': "Display version"})
]

# Update arguments - command line options for suricata-update
update_arg = [
    (("-o", "--output"),
     {'metavar': '<directory>', 'dest': 'output',
      'help': "Directory to write rules to"}),
    (("-f", "--force"),
     {'action': 'store_true', 'default': False,
      'help': "Force operations that might otherwise be skipped"}),
    (("--yaml-fragment",),
     {'metavar': '<filename>',
      'help': "Output YAML fragment for rule inclusion"}),
    (("--url",),
     {'metavar': '<url>', 'action': 'append', 'default': [],
      'help': "URL to use instead of auto-generating one "
              "(can be specified multiple times)"}),
    (("--local",),
     {'metavar': '<path>', 'action': 'append', 'default': [],
      'help': "Local rule files or directories "
              "(can be specified multiple times)"}),
    (("--sid-msg-map",),
     {'metavar': '<filename>',
      'help': "Generate a sid-msg.map file"}),
    (("--sid-msg-map-2",),
     {'metavar': '<filename>',
      'help': "Generate a v2 sid-msg.map file"}),

    (("--disable-conf",),
     {'metavar': '<filename>',
      'help': "Filename of rule disable filters"}),
    (("--enable-conf",),
     {'metavar': '<filename>',
      'help': "Filename of rule enable filters"}),
    (("--modify-conf",),
     {'metavar': '<filename>',
      'help': "Filename of rule modification filters"}),
    (("--drop-conf",),
     {'metavar': '<filename>',
      'help': "Filename of drop rule filters"}),

    (("--ignore",),
     {'metavar': '<pattern>', 'action': 'append', 'default': None,
      'help': "Filenames to ignore "
              "(can be specified multiple times; default: *deleted.rules)"}),
    (("--no-ignore",),
     {'action': 'store_true', 'default': False,
      'help': "Disables the ignore option."}),
    (("--threshold-in",),
     {'metavar': '<filename>',
      'help': "Filename of rule thresholding configuration"}),
    (("--threshold-out",),
     {'metavar': '<filename>',
      'help': "Output of processed threshold configuration"}),
    (("--dump-sample-configs",),
     {'action': 'store_true', 'default': False,
      'help': "Dump sample config files to current directory"}),
    (("--etopen",),
     {'action': 'store_true',
      'help': "Use ET-Open rules (default)"}),
    (("--reload-command",),
     {'metavar': '<command>',
      'help': "Command to run after update if modified"}),
    (("--no-reload",),
     {'action': 'store_true', 'default': False,
      'help': "Disable reload"}),
    (("-T", "--test-command"),
     {'metavar': '<command>',
      'help': "Command to test Suricata configuration"}),
    (("--no-test",),
     {'action': 'store_true', 'default': False,
      'help': "Disable testing rules with Suricata"}),
    (("--no-merge",),
     {'action': 'store_true', 'default': False,
      'help': "Do not merge the rules into a single file"}),
    (("--offline",),
     {'action': 'store_true',
      'help': "Run offline using most recent cached rules"}),

    # Hidden argument, --now to bypass the timebased bypass of
    # updating a ruleset.
    (("--now",),
     {'default': False, 'action': 'store_true', 'help': argparse.SUPPRESS}),

    # The Python 2.7 argparse module does prefix matching which can be
    # undesirable. Reserve some names here that would match existing
    # options to prevent prefix matching.
    (("--disable",),
     {'default': False, 'help': argparse.SUPPRESS}),
    (("--enable",),
     {'default': False, 'help': argparse.SUPPRESS}),
    (("--modify",),
     {'default': False, 'help': argparse.SUPPRESS}),
    (("--drop",),
     {'default': False, 'help': argparse.SUPPRESS})
]


def parse_global():
    global_parser = argparse.ArgumentParser(add_help=False)

    for arg, opts in global_arg:
        global_parser.add_argument(*arg, **opts)

    return global_parser


def parse_update(subparsers, global_parser):
    # The "update" (default) sub-command parser.
    update_parser = subparsers.add_parser(
        "update", add_help=True, parents=[global_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    for arg, opts in update_arg:
        update_parser.add_argument(*arg, **opts)

    return update_parser


def parse_commands(subparsers, global_parser):
    commands.listsources.register(subparsers.add_parser(
        "list-sources", parents=[global_parser]))
    commands.listenabledsources.register(subparsers.add_parser(
        "list-enabled-sources", parents=[global_parser]))
    commands.addsource.register(subparsers.add_parser(
        "add-source", parents=[global_parser]))
    commands.updatesources.register(subparsers.add_parser(
        "update-sources", parents=[global_parser]))
    commands.enablesource.register(subparsers.add_parser(
        "enable-source", parents=[global_parser]))
    commands.disablesource.register(subparsers.add_parser(
        "disable-source", parents=[global_parser]))
    commands.removesource.register(subparsers.add_parser(
        "remove-source", parents=[global_parser]))
    commands.checkversions.register(subparsers.add_parser(
        "check-versions", parents=[global_parser]))


def parse_arg():
    global_parser = parse_global()
    global_args, rem = global_parser.parse_known_args()

    if global_args.version:
        revision_string = " (rev: %s)" % (revision) if revision else ""
        print("suricata-update version {}{}".format(version, revision_string))
        sys.exit(0)

    if not rem or rem[0].startswith("-"):
        rem.insert(0, "update")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand", metavar="<command>")
    update_parser = parse_update(subparsers, global_parser)

    update_parser.epilog = r"""other commands:
    update-sources             Update the source index
    list-sources               List available sources
    enable-source              Enable a source from the index
    disable-source             Disable an enabled source
    remove-source              Remove an enabled or disabled source
    list-enabled-sources       List all enabled sources
    add-source                 Add a new source by URL
    check-versions             Check version of suricata-update
"""

    parse_commands(subparsers, global_parser)

    args = parser.parse_args(rem)

    # Merge global args into args.
    for arg in vars(global_args):
        if not hasattr(args, arg):
            setattr(args, arg, getattr(global_args, arg))
        elif hasattr(args, arg) and getattr(args, arg) is None:
            setattr(args, arg, getattr(global_args, arg))

    return args
